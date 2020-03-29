// =================================================================================
// File:    plugin-loki.js
//
// Authors: Jarle Elshaug
//          Jeffrey Gilbert (visualjeff)
//
// Purpose: SCIM endpoint locally at the ScimGateway
//          - Demonstrate userprovisioning towards a document-oriented database
//          - Using LokiJS (http://lokijs.org) for a fast, in-memory document-oriented database with persistence
//          - Two predefined test users loaded when using in-memory only (no persistence)
//          - Supporting explore, create, delete, modify and list users (including groups)
//
// Supported attributes:
//
// GlobalUser   Template            Scim        Endpoint
// ------------------------------------------------------
// All attributes are supported, note multivalue "type" must be unique
//
// NOTE: Default configuration file setting {"persistence": false} gives an inMemory adapter for testing purposes
//       having two predifiend users loaded. Using {"persistence": true} gives an persistence file store located in
//       config directory with name according to configuration setting {"dbname": "loki.db"} and no no testusers loaded.
//
//       LokiJS are well suited for handling large dataloads
//
// =================================================================================

'use strict'

const Loki = require('lokijs')

// mandatory plugin initialization - start
const path = require('path')
let ScimGateway = null
try {
  ScimGateway = require('scimgateway')
} catch (err) {
  ScimGateway = require('./scimgateway')
}
const scimgateway = new ScimGateway()
const pluginName = path.basename(__filename, '.js')
const configDir = path.join(__dirname, '..', 'config')
const configFile = path.join(`${configDir}`, `${pluginName}.json`)
const validScimAttr = [] // empty array - all attrbutes are supported by endpoint
let config = require(configFile).endpoint
config = scimgateway.processExtConfig(pluginName, config) // add any external config process.env and process.file
// mandatory plugin initialization - end

// let endpointPasswordExample = scimgateway.getPassword('endpoint.password', configFile); // example how to encrypt configfile having "endpoint.password"

let dbname = (config.dbname ? config.dbname : 'loki.db')
dbname = path.join(`${configDir}`, `${dbname}`)
const db = new Loki(dbname, {
  env: 'NODEJS',
  autoload: config.persistence === true,
  autoloadCallback: loadHandler,
  autosave: config.persistence === true,
  autosaveInterval: 10000, // 10 seconds
  adapter: (config.persistence === true) ? new Loki.LokiFsAdapter() : new Loki.LokiMemoryAdapter()
})

if (db.options.autoload === false) loadHandler()

function loadHandler () {
  let users = db.getCollection('users')
  if (users === null) { // if database do not exist it will be empty so intitialize here
    users = db.addCollection('users', {
      unique: ['id', 'userName']
    })
  }

  let groups = db.getCollection('groups')
  if (groups === null) {
    groups = db.addCollection('groups', {
      unique: ['displayName']
    })
  }

  if (db.options.autoload === false) { // not using persistence (physical database) => load testusers
    scimgateway.testmodeusers.forEach(function (record) {
      if (record.meta) delete record.meta
      users.insert(record)
    })
    scimgateway.testmodegroups.forEach(function (record) {
      groups.insert(record)
    })
  }

  // =================================================
  // exploreUsers
  // =================================================
  scimgateway.exploreUsers = async (baseEntity, attributes, startIndex, count) => {
    const action = 'exploreUsers'
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`)
    const ret = { // itemsPerPage will be set by scimgateway
      Resources: [],
      totalResults: null
    }

    const users = db.getCollection('users')

    if (!startIndex && !count) { // client request without paging
      startIndex = 1
      count = users.data.length
      if (count > 500) count = 500
    }

    const arrAttr = attributes.split(',')
    users.mapReduce(
      function (obj) {
        if (!attributes) return stripLoki(obj)
        else {
          let retObj = obj
          if (arrAttr.length > 0) { // return according to attributes (userName or externalId should normally be included and id=userName/externalId)
            const o = {}
            for (let i = 0; i < arrAttr.length; i++) {
              const key = arrAttr[i].split('.')[0] // title => title, name.familyName => name
              if (retObj[key]) o[key] = retObj[key]
            }
            retObj = o
          }
          return retObj
        }
      },
      function (array) {
        for (let i = 0; i < array.length; i++) { // remove empty objects
          if (JSON.stringify(array[i]) === '{}') {
            array.splice(i, 1)
            i--
          }
        }
        Array.prototype.push.apply(ret.Resources, array.slice(startIndex - 1, startIndex - 1 + count))
        ret.totalResults = array.length
      }
    )
    return ret // all explored users
  }

  // =================================================
  // exploreGroups
  // =================================================
  scimgateway.exploreGroups = async (baseEntity, attributes, startIndex, count) => {
    const action = 'exploreGroups'
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`)
    const ret = { // itemsPerPage will be set by scimgateway
      Resources: [],
      totalResults: null
    }

    const groups = db.getCollection('groups')

    if (!startIndex && !count) { // client request without paging
      startIndex = 1
      count = groups.data.length
    }

    groups.mapReduce(
      function (obj) {
        return { // returning displayname and id
          displayName: obj.displayName,
          id: obj.id
        }
      },
      function (array) {
        Array.prototype.push.apply(ret.Resources, array.slice(startIndex - 1, startIndex - 1 + count))
        ret.totalResults = array.length
      }
    )
    return ret // all explored groups
  }

  // =================================================
  // getUser
  // =================================================
  scimgateway.getUser = async (baseEntity, getObj, attributes) => {
    // getObj = { filter: <filterAttribute>, identifier: <identifier> }
    // e.g: getObj = { filter: 'userName', identifier: 'bjensen'}
    // filter: userName and id must be supported
    // (they are most often considered as "the same type of attribute" where identifier = UserID )
    // Note, the value of id attribute returned will be used by modifyUser and deleteUser
    const action = 'getUser'
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" ${getObj.filter}=${getObj.identifier} attributes=${attributes}`)

    const findObj = {}
    findObj[getObj.filter] = getObj.identifier // { userName: 'bjensen } / { externalId: 'bjensen } / { id: 'bjensen } / { 'emails.value': 'jsmith@example.com'} / { 'phoneNumbers.value': '555-555-5555'}

    const users = db.getCollection('users')
    const userObj = users.findOne(findObj)

    if (!userObj) return null // no user found
    if (!attributes) return stripLoki(userObj) // user with all attributes
    else { // return according to attributes
      const ret = {}
      const arrAttr = attributes.split(',')
      for (let i = 0; i < arrAttr.length; i++) {
        const attr = arrAttr[i].split('.') // title / name.familyName / emails.value
        if (userObj[attr[0]]) {
          if (attr.length === 1) ret[attr[0]] = userObj[attr[0]]
          else if (userObj[attr[0]][attr[1]]) { // name.familyName
            if (!ret[attr[0]]) ret[attr[0]] = {}
            ret[attr[0]][attr[1]] = userObj[attr[0]][attr[1]]
          } else if (Array.isArray(userObj[attr[0]])) { // emails.value / phoneNumbers.type
            if (!ret[attr[0]]) ret[attr[0]] = []
            const arr = userObj[attr[0]]
            for (let j = 0; j < arr.length; j++) {
              if (arr[j][attr[1]]) {
                const index = ret[attr[0]].findIndex(el => (el.value && arr[j].value && el.value === arr[j].value))
                let o
                if (index < 0) {
                  o = {}
                  if (arr[j].value) o.value = arr[j].value // new, always include value
                } else o = ret[attr[0]][index] // existing
                o[attr[1]] = arr[j][attr[1]]
                if (index < 0) ret[attr[0]].push(o)
                else ret[attr[0]][index] = o
              }
            }
          }
        }
      }
      if (JSON.stringify(ret) === '{}') return stripLoki(userObj) // user with all attributes when specified attributes not found
      ret.meta = userObj.meta // version, date created and modified
      return stripLoki(ret)
    }
  }

  // =================================================
  // createUser
  // =================================================
  scimgateway.createUser = async (baseEntity, userObj) => {
    const action = 'createUser'
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" userObj=${JSON.stringify(userObj)}`)
    const notValid = scimgateway.notValidAttributes(userObj, validScimAttr) // We should check for unsupported endpoint attributes
    if (notValid) {
      const err = new Error(`unsupported scim attributes: ${notValid} ` + `(supporting only these attributes: ${validScimAttr.toString()})`)
      throw err
    }

    const users = db.getCollection('users')

    if (userObj.password) delete userObj.password // exclude password db not ecrypted
    for (var key in userObj) { // convert to multivalue array
      if (!Array.isArray(userObj[key]) && scimgateway.isMultivalue('User', key)) {
        const arr = []
        for (var el in userObj[key]) {
          userObj[key][el].type = el
          arr.push(userObj[key][el]) // create
        }
        userObj[key] = arr
      }
    }

    userObj.id = userObj.userName // for loki-plugin (scim endpoint) id is mandatory and set to userName
    try {
      users.insert(userObj)
    } catch (err) {
      if (err.message && err.message.startsWith('Duplicate key')) {
        err.name = 'DuplicateKeyError' // gives scimgateway statuscode 409 instead of default 500
      }
      throw err
    }
    return null
  }

  // =================================================
  // deleteUser
  // =================================================
  scimgateway.deleteUser = async (baseEntity, id) => {
    const action = 'deleteUser'
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)
    const users = db.getCollection('users')
    const userObj = users.findOne({
      id: id
    })
    if (userObj && typeof userObj !== 'undefined') {
      users.remove(userObj)
      return null
    } else {
      const err = new Error('Failed to delete user with id=' + id)
      throw err
    }
  }

  // =================================================
  // modifyUser
  // =================================================
  scimgateway.modifyUser = async (baseEntity, id, attrObj) => {
    const action = 'modifyUser'
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)
    const notValid = scimgateway.notValidAttributes(attrObj, validScimAttr) // We should check for unsupported endpoint attributes
    if (notValid) {
      const err = new Error(`unsupported scim attributes: ${notValid} ` +
          `(supporting only these attributes: ${validScimAttr.toString()})`
      )
      throw err
    }
    if (attrObj.password) delete attrObj.password // exclude password db not ecrypted

    const users = db.getCollection('users')
    const userObj = users.findOne({ id: id })

    if (typeof userObj === 'undefined') {
      const err = new Error(`Failed to find user with id=${id}`)
      throw err
    } else {
      var arrUser = []
      arrUser = userObj
      for (var key in attrObj) {
        if (Array.isArray(attrObj[key])) { // standard, not using type (e.g groups)
          attrObj[key].forEach(function (el) {
            if (el.operation === 'delete') {
              arrUser[key].find(function (e, i) {
                if ((e.value === el.value) && el.value) { // groups
                  arrUser[key].splice(i, 1) // delete
                  if (arrUser[key].length < 1) delete arrUser[key]
                  return true
                } else return false
              })
            } else { // add
              if (!arrUser[key]) arrUser[key] = []
              arrUser[key].push(el)
            }
          })
        } else if (scimgateway.isMultivalue('User', key)) { // customized using type instead of array (e.g mails, phones, entitlements, roles)
          for (var el in attrObj[key]) {
            attrObj[key][el].type = el
            if (attrObj[key][el].operation && attrObj[key][el].operation === 'delete') { // delete multivalue
              arrUser[key].find(function (e, i) {
                if (e.type === el) {
                  arrUser[key].splice(i, 1) // delete
                  if (arrUser[key].length < 1) delete arrUser[key]
                  return true
                } else return false
              })
            } else { // modify/create multivalue
              if (!arrUser[key]) arrUser[key] = []
              var found = arrUser[key].find(function (e, i) {
                if (e.type === el) {
                  for (const k in attrObj[key][el]) {
                    arrUser[key][i][k] = attrObj[key][el][k]
                  }
                  return true
                } else return false
              })
              if (!found) arrUser[key].push(attrObj[key][el]) // create
            }
          }
        } else {
          // None multi value attribute
          if (typeof (attrObj[key]) !== 'object') {
            if (attrObj[key] === '') delete arrUser[key]
            else arrUser[key] = attrObj[key]
          } else {
            // name.formatted=Mary Lee Bianchi
            // name.givenName=Mary
            // name.middleName=Lee
            // name.familyName=Bianchi
            if (!arrUser[key]) arrUser[key] = attrObj[key] // e.g name object does not exist
            else {
              for (var sub in attrObj[key]) { // attributes to be cleard located in meta.attributes eg: {"meta":{"attributes":["name.familyName","profileUrl","title"]}
                if (sub === 'attributes' && Array.isArray(attrObj[key][sub])) {
                  attrObj[key][sub].forEach(function (element) {
                    var arrSub = element.split('.')
                    if (arrSub.length === 2) arrUser[arrSub[0]][arrSub[1]] = '' // eg. name.familyName
                    else arrUser[element] = ''
                  })
                } else {
                  if (attrObj[key][sub] === '') delete arrUser[key][sub]
                  else arrUser[key][sub] = attrObj[key][sub]
                }
              }
            }
          }
        }
      }
      users.update(arrUser) // persistence
      return null
    }
  }

  // =================================================
  // getGroup
  // =================================================
  scimgateway.getGroup = async (baseEntity, getObj, attributes) => {
    // getObj = { filter: <filterAttribute>, identifier: <identifier> }
    // e.g: getObj = { filter: 'displayName', identifier: 'GroupA' }
    // filter: displayName and id must be supported
    // (they are most often considered as "the same type of attribute" where identifier = GroupName)
    // Note, the value of id attribute returned will be used by deleteGroup, getGroupMembers and modifyGroup
    const action = 'getGroup'
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" ${getObj.filter}=${getObj.identifier} attributes=${attributes}`)

    const findObj = {}
    findObj[getObj.filter] = getObj.identifier // { displayName: 'GroupA' }

    const retObj = {}
    const groups = db.getCollection('groups')
    const groupObj = groups.findOne(findObj)

    if (!groupObj) return null // no group found
    // not parsing attributes in this example, returning what's mandatory for most IdP's
    retObj[getObj.filter] = groupObj[getObj.filter] // incase none of below (e.g. externalId)
    retObj.displayName = groupObj.displayName // mandatory
    retObj.id = groupObj.displayName // mandatory - value same as displayName
    retObj.externalId = groupObj.externalId
    retObj.members = groupObj.members // comment out this line if using "users are member of group"
    return retObj
  }

  // =================================================
  // getGroupMembers
  // =================================================
  scimgateway.getGroupMembers = async (baseEntity, id, attributes) => {
    const action = 'getGroupMembers'
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" user id=${id} attributes=${attributes}`)
    const arrRet = []
    const groups = db.getCollection('groups')
    // find all groups user is member of
    groups.data.forEach(function (el) {
      if (el.members) {
        var userFound = el.members.find(function (element) {
          if (element.value === id) {
            return true
          } else return false
        })
        if (userFound) {
          var userGroup = {
            displayName: el.displayName, // displayName is mandatory
            members: [{ value: id }] // only includes current user (not all members)
          }
          arrRet.push(userGroup)
        }
      }
    })
    return arrRet
  }

  // =================================================
  // getGroupUsers
  // =================================================
  scimgateway.getGroupUsers = async (baseEntity, groupName, attributes) => {
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "getGroupUsers" groupName=${groupName} attributes=${attributes}`)
    const arrRet = []
    const users = db.getCollection('users')
    users.data.forEach((user) => {
      if (user.groups) {
        user.groups.forEach((group) => {
          if (group.value === groupName) {
            arrRet.push({
              userName: user.userName
            })
          }
        })
      }
    })
    return arrRet
  }

  // =================================================
  // createGroup
  // =================================================
  scimgateway.createGroup = async (baseEntity, groupObj) => {
    const action = 'createGroup'
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" groupObj=${JSON.stringify(groupObj)}`)
    const groups = db.getCollection('groups')
    groupObj.id = groupObj.displayName // for loki-plugin (scim endpoint) id is mandatory and set to displayName
    groups.insert(groupObj)
    return null
  }

  // =================================================
  // deleteGroup
  // =================================================
  scimgateway.deleteGroup = async (baseEntity, id) => {
    const action = 'deleteGroup'
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)
    const groups = db.getCollection('groups')
    const groupObj = groups.findOne({
      id: id
    })
    if (groupObj && typeof groupObj !== 'undefined') {
      groups.remove(groupObj)
      return null
    } else {
      const err = new Error('Failed to delete group with id=' + id)
      throw err
    }
  }

  // =================================================
  // modifyGroup
  // =================================================
  scimgateway.modifyGroup = async (baseEntity, id, attrObj) => {
    const action = 'modifyGroup'
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)

    if (!attrObj.members) {
      throw new Error(`plugin handling "${action}" only supports modification of members`)
    }
    if (!Array.isArray(attrObj.members)) {
      throw new Error(`plugin handling "${action}" error: ${JSON.stringify(attrObj)} - correct syntax is { "members": [...] }`)
    }

    const groups = db.getCollection('groups')
    const groupObj = groups.findOne({ id: id })
    if (!groupObj) {
      const err = new Error('Failed to find group with id=' + id)
      throw err
    }

    attrObj.members.forEach(function (el) {
      if (el.operation && el.operation === 'delete') { // delete member from group
        if (!el.value) groupObj.members = [] // members=[{"operation":"delete"}] => no value, delete all members
        else {
          groupObj.members.find(function (element, index) {
            if (element.value === el.value) {
              groupObj.members.splice(index, 1) // delete
              if (groupObj.members.length < 1) delete groupObj.members
              return true
            } else return false
          })
        }
      } else { // Add member to group
        var newMember = {
          display: el.value,
          value: el.value
        }
        if (!groupObj.members) groupObj.members = []
        groupObj.members.push(newMember)
      }
    })


    groups.update(groupObj)
    return null
  }

  function stripLoki (obj) { // remove loki meta data and insert scim
    const retObj = JSON.parse(JSON.stringify(obj)) // new object - don't modify loki source
    if (retObj.meta) {
      if (retObj.meta.created) retObj.meta.created = new Date(retObj.meta.created).toISOString()
      delete retObj.meta.lastModified // test users loaded
      if (retObj.meta.updated) {
        retObj.meta.lastModified = new Date(retObj.meta.updated).toISOString()
        delete retObj.meta.updated
      }
      if (retObj.meta.revision !== undefined) {
        retObj.meta.version = retObj.meta.revision
        delete retObj.meta.revision
      }
    }
    delete retObj.$loki
    return retObj
  }

  //
  // Cleanup on exit
  //
  process.on('SIGTERM', () => { // kill
    db.close()
  })
  process.on('SIGINT', () => { // Ctrl+C
    db.close()
  })
} // loadHandler
