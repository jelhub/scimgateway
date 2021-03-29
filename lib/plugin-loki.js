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
}

if (db.options.autoload === false) loadHandler()

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
  const usersArr = users.chain().data()

  if (!startIndex && !count) { // client request without paging
    startIndex = 1
    count = usersArr.length
    if (count > 500) count = 500
  }

  const arr = usersArr.map(obj => { return stripLoki(obj) }) // includes all user attributes but groups - user attribute groups automatically handled by scimgateway
  const usersDelta = arr.slice(startIndex - 1, startIndex - 1 + count)
  Array.prototype.push.apply(ret.Resources, usersDelta)
  ret.totalResults = usersDelta.length
  return ret // all explored users
}

// =================================================
// exploreGroups
// =================================================
scimgateway.exploreGroups = async (baseEntity, attributes, startIndex, count) => {
  const action = 'exploreGroups'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`)

  // const arrAttr = attributes.split(',')
  const ret = { // itemsPerPage will be set by scimgateway
    Resources: [],
    totalResults: null
  }
  const groups = db.getCollection('groups')
  const groupsArr = groups.chain().data()

  if (!startIndex && !count) { // client request without paging
    startIndex = 1
    count = groupsArr.length
  }

  const arr = groupsArr.map(obj => { return stripLoki(obj) }) // includes all groups attributes (also members)
  const groupsDelta = arr.slice(startIndex - 1, startIndex - 1 + count)
  Array.prototype.push.apply(ret.Resources, groupsDelta)
  ret.totalResults = groupsDelta.length
  return ret // all explored groups
}

// =================================================
// getUser
// =================================================
scimgateway.getUser = async (baseEntity, getObj, attributes) => {
  // getObj = { filter: <filterAttribute>, identifier: <identifier> }
  // e.g: getObj = { filter: 'userName', identifier: 'bjensen'}
  // filter: userName and id must be supported
  // (they are most often considered as "the same" where identifier = UserID )
  // Note, the value of id attribute returned will be used by modifyUser and deleteUser
  // attributes: if not blank, attributes listed should be returned
  // Should normally return all supported user attributes having id and userName as mandatory
  // SCIM Gateway will automatically filter response according to the attributes list
  const action = 'getUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" ${getObj.filter}=${getObj.identifier} attributes=${attributes}`)

  const findObj = {}
  findObj[getObj.filter] = getObj.identifier // { userName: 'bjensen } / { externalId: 'bjensen } / { id: 'bjensen } / { 'emails.value': 'jsmith@example.com'} / { 'phoneNumbers.value': '555-555-5555'}

  const users = db.getCollection('users')
  const userObj = users.findOne(findObj)
  if (!userObj) return null // no user found
  return stripLoki(userObj) // includes all user attributes but groups - user attribute groups automatically handled by scimgateway
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

            let exists = false
            if (el.value) {
              exists = arrUser[key].find(function (e, i) {
                if ((e.value === el.value) && el.value) return true
                else return false
              })
            }
            if (!exists) arrUser[key].push(el)
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
  // (they are most often considered as "the same" where identifier = GroupName)
  // Note, the value of id attribute returned will be used by deleteGroup, getGroupMembers and modifyGroup
  // attributes: if not blank, attributes listed should be returned
  // Should normally return all supported group attributes having id, displayName and members as mandatory
  // members may be skipped if attributes is not blank and do not contain members or members.value
  const action = 'getGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" ${getObj.filter}=${getObj.identifier} attributes=${attributes}`)

  const findObj = {}
  findObj[getObj.filter] = getObj.identifier // { displayName: 'GroupA' }

  const groups = db.getCollection('groups')
  const groupObj = groups.findOne(findObj)
  if (!groupObj) return null // no group found
  return stripLoki(groupObj) // includes all group attributes (also members)
}

// =================================================
// getGroupMembers
// =================================================
scimgateway.getGroupMembers = async (baseEntity, id, attributes) => {
  // return all groups the user is member of having attributes included e.g: members.value,id,displayName
  // method used when "users member of group", if used - getUser must treat user attribute groups as virtual readOnly attribute
  // "users member of group" is SCIM default and this method should normally have some logic
  const action = 'getGroupMembers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" user id=${id} attributes=${attributes}`)
  const arrRet = []
  const groups = db.getCollection('groups')

  groups.data.forEach(el => {
    if (el.members) {
      var userFound = el.members.find(function (element) {
        if (element.value === id) {
          return true
        } else return false
      })
      if (userFound) {
        let arrAttr = []
        if (attributes) arrAttr = attributes.split(',')
        const userGroup = {}
        arrAttr.forEach(attr => {
          if (el[attr]) userGroup[attr] = el[attr] // id, displayName, members.value
        })
        userGroup.members = [{ value: id }] // only includes current user (not all members)
        arrRet.push(userGroup) // { id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }
      }
    }
  })
  return arrRet
}

// =================================================
// getGroupUsers
// =================================================
scimgateway.getGroupUsers = async (baseEntity, id, attributes) => {
  // return array of all users that is member of this group id having attributes included e.g: groups.value,userName
  // method used when "group member of users", if used - getGroup must treat group attribute members as virtual readOnly attribute
  const action = 'getGroupUsers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attributes=${attributes}`)
  const arrRet = []
  const users = db.getCollection('users')
  users.data.forEach((user) => {
    if (user.groups) {
      user.groups.forEach((group) => {
        if (group.value === id) {
          arrRet.push( // {userName: "bjensen", groups: [{value: <group id>}]} - value only includes current group id
            {
              userName: user.userName,
              groups: [{ value: id }]
            }
          )
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
  if (!groupObj.members) groupObj.members = []

  const usersNotExist = []

  await attrObj.members.forEach(async function (el) {
    if (el.operation && el.operation === 'delete') { // delete member from group
      if (!el.value) groupObj.members = [] // members=[{"operation":"delete"}] => no value, delete all members
      else {
        groupObj.members.find(function (element, index) {
          if (element.value === el.value) {
            groupObj.members.splice(index, 1) // delete
            return true
          } else return false
        })
      }
    } else { // Add member to group
      if (el.value) { // check if user exist
        const usrObj = { filter: 'id', identifier: el.value }
        const usr = await scimgateway.getUser(baseEntity, usrObj, 'id')
        if (!usr) {
          usersNotExist.push(el.value)
          return
        }
      }
      var newMember = {
        display: el.value,
        value: el.value
      }
      let exists = false
      if (el.value) {
        exists = groupObj.members.find(function (e, i) {
          if ((e.value === el.value) && el.value) return true
          else return false
        })
      }
      if (!exists) groupObj.members.push(newMember)
    }
  })

  groups.update(groupObj)

  if (usersNotExist.length > 0) throw new Error(`can't use ${action} including none existing user(s): ${usersNotExist.toString()}`)
  return null
}

// =================================================
// helpers
// =================================================

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
