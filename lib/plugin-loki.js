// =================================================================================
// File:    plugin-loki.js
//
// Authors: Jarle Elshaug
//          Jeffrey Gilbert (visualjeff)
//
// Purpose: SCIM Gateway becomes a standalone SCIM endpoint
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
scimgateway.authPassThroughAllowed = false // true enables auth passThrough (no scimgateway authentication). scimgateway instead includes ctx (ctx.request.header) in plugin methods. Note, requires plugin-logic for handling/passing ctx.request.header.authorization to be used in endpoint communication
// mandatory plugin initialization - end

// let endpointPasswordExample = scimgateway.getPassword('endpoint.password', configFile); // example how to encrypt configfile having "endpoint.password"

let users
let groups
const validFilterOperators = ['eq', 'ne', 'aeq', 'dteq', 'gt', 'gte', 'lt', 'lte', 'between', 'jgt', 'jgte', 'jlt', 'jlte', 'jbetween', 'regex', 'in', 'nin', 'keyin', 'nkeyin', 'definedin', 'undefinedin', 'contains', 'containsAny', 'type', 'finite', 'size', 'len', 'exists']

let dbname = (config.dbname ? config.dbname : 'loki.db')
dbname = path.join(`${configDir}`, `${dbname}`)
const db = new Loki(dbname, {
  env: 'NODEJS',
  autoload: config.persistence !== false,
  autoloadCallback: loadHandler,
  autosave: config.persistence !== false,
  autosaveInterval: 10000, // 10 seconds
  adapter: (config.persistence !== false) ? new Loki.LokiFsAdapter() : new Loki.LokiMemoryAdapter()
})

function loadHandler () {
  users = db.getCollection('users')
  if (users === null) { // if database do not exist it will be empty so intitialize here
    users = db.addCollection('users', {
      unique: ['id', 'userName']
    })
  }

  groups = db.getCollection('groups')
  if (groups === null) {
    groups = db.addCollection('groups', {
      unique: ['displayName']
    })
  }

  if (db.options.autoload === false) { // not using persistence (physical database) => load testusers
    scimgateway.testmodeusers.forEach(record => {
      if (record.meta) delete record.meta
      users.insert(record)
    })
    scimgateway.testmodegroups.forEach(record => {
      if (record.meta) delete record.meta
      groups.insert(record)
    })
  }
}

if (db.options.autoload === false) loadHandler()

// =================================================
// getUsers
// =================================================
scimgateway.getUsers = async (baseEntity, getObj, attributes, ctx) => {
  //
  // "getObj" = { attribute: <>, operator: <>, value: <>, rawFilter: <>, startIndex: <>, count: <> }
  // rawFilter is always included when filtering
  // attribute, operator and value are included when requesting unique object or simpel filtering
  // See comments in the "mandatory if-else logic - start"
  //
  // "attributes" is array of attributes to be returned - if empty, all supported attributes should be returned
  // Should normally return all supported user attributes having id and userName as mandatory
  // id and userName are most often considered as "the same" having value = <UserID>
  // Note, the value of returned 'id' will be used as 'id' in modifyUser and deleteUser
  // scimgateway will automatically filter response according to the attributes list
  //
  const action = 'getUsers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes}`)

  if (getObj.operator) { // convert to plugin supported syntax
    switch (getObj.operator) {
      case 'co':
        getObj.operator = '$contains'
        break
      case 'ge':
        getObj.operator = '$gte'
        break
      case 'le':
        getObj.operator = '$lte'
        break
      case 'sw':
        getObj.operator = '$regex'
        getObj.value = new RegExp(`^${getObj.value}.*`)
        break
      case 'ew':
        getObj.operator = '$regex'
        getObj.value = new RegExp(`.*${getObj.value}$`)
        break
      default:
        if (!validFilterOperators.includes(getObj.operator)) {
          const err = new Error(`${action} error: filter operator '${getObj.operator}' is not valid, valid operators for this endpoint are: ${validFilterOperators}` + ',co,ge,le,sw,ew')
          err.name = 'invalidFilter' // maps to scimType error handling
          throw err
        }
        getObj.operator = '$' + getObj.operator
    }
  }

  let usersArr

  // mandatory if-else logic - start
  if (getObj.operator) { // note, loki using prefix '$'
    if (getObj.operator === '$eq' && ['id', 'userName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      const queryObj = {}
      queryObj[getObj.attribute] = getObj.value // { userName: 'bjensen } / { externalId: 'bjensen } / { id: 'bjensen }
      usersArr = users.find(queryObj)
    } else if (getObj.operator === '$eq' && getObj.attribute === 'group.value') {
      // optional - only used when groups are member of users, not default behavior - correspond to getGroupUsers() in versions < 4.x.x
      const queryObj = {}
      queryObj[getObj.attribute] = getObj.value
      usersArr = users.chain().find(queryObj).data()
    } else {
      // optional - simpel filtering
      const dt = Date.parse(getObj.value)
      if (!isNaN(dt)) { // date string to timestamp
        getObj.value = dt
      }
      const queryObj = {}
      queryObj[getObj.attribute] = {}
      queryObj[getObj.attribute][getObj.operator] = getObj.value
      usersArr = users.chain().find(queryObj).data() // {name.familyName: { $eq: "Jensen" } }
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all users to be returned - correspond to exploreUsers() in versions < 4.x.x
    usersArr = users.chain().data()
  }
  // mandatory if-else logic - end

  if (!usersArr) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  if (!getObj.startIndex) getObj.startIndex = 1
  if (!getObj.count) getObj.count = 200

  const ret = {
    Resources: [],
    totalResults: null // total number of objects when using paging (ref. startIndex/count)
  }

  const arr = usersArr.map(obj => { return stripLoki(obj) }) // all attributes included - virtual attribute groups automatically handled by scimgateway
  const delta = arr.slice(getObj.startIndex - 1, getObj.startIndex - 1 + getObj.count) // supporting paging "light"
  Array.prototype.push.apply(ret.Resources, delta)
  ret.totalResults = arr.length // set to maximum, will be corrected if needed by scimgateway
  return ret
}

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj, ctx) => {
  const action = 'createUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" userObj=${JSON.stringify(userObj)}`)

  const notValid = scimgateway.notValidAttributes(userObj, validScimAttr) // We should check for unsupported endpoint attributes
  if (notValid) {
    throw new Error(`${action} error: unsupported scim attributes: ${notValid} (supporting only these attributes: ${validScimAttr.toString()})`)
  }

  if (userObj.password) delete userObj.password // exclude password db not ecrypted
  for (const key in userObj) {
    if (!Array.isArray(userObj[key]) && scimgateway.isMultiValueTypes(key)) { // true if attribute is "type converted object" => convert to standard array
      const arr = []
      for (const el in userObj[key]) {
        userObj[key][el].type = el
        if (el === 'undefined') delete userObj[key][el].type // type "undefined" reverted back to original blank
        arr.push(userObj[key][el]) // create
      }
      userObj[key] = arr
    }
  }

  if (userObj.userName) userObj.id = userObj.userName // id set to userName or externalId
  else if (userObj.externalId) userObj.id = userObj.externalId
  else throw new Error(`${action} error: missing mandatory userName or externalId`)

  try {
    users.insert(userObj)
    return null
  } catch (err) {
    const newErr = new Error(`${action} error: ${err.message}`)
    if (err.message && err.message.startsWith('Duplicate key')) {
      newErr.name = 'uniqueness' // maps to scimType error handling
    }
    throw newErr
  }
}

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id, ctx) => {
  const action = 'deleteUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)

  const res = users.find({ id: id })
  if (res.length !== 1) throw new Error(`${action} error: failed for user id=${id}`)
  const userObj = res[0]
  users.remove(userObj)
  return null
}

// =================================================
// modifyUser
// =================================================
scimgateway.modifyUser = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)

  const notValid = scimgateway.notValidAttributes(attrObj, validScimAttr) // We should check for unsupported endpoint attributes
  if (notValid) {
    throw new Error(`${action} error: unsupported scim attributes: ${notValid} (supporting only these attributes: ${validScimAttr.toString()})`)
  }
  if (attrObj.password) delete attrObj.password // exclude password db not ecrypted

  const res = users.find({ id: id })
  if (res.length === 0) throw new Error(`${action} error: user id=${id} - user does not exist`)
  if (res.length > 1) throw new Error(`${action} error: user id=${id} - user is not unique, more than one have been found`)
  const userObj = res[0]

  for (const key in attrObj) {
    if (Array.isArray(attrObj[key])) { // standard, not using type (e.g groups)
      attrObj[key].forEach(el => {
        if (el.operation === 'delete') {
          userObj[key] = userObj[key].filter(e => e.value !== el.value)
          if (userObj[key].length < 1) delete userObj[key]
        } else { // add
          if (!userObj[key]) userObj[key] = []
          let exists
          if (el.value) exists = userObj[key].find(e => e.value && e.value === el.value && e.type === el.type) // allowing same value on different type (type not mandatory)
          if (!exists) userObj[key].push(el)
        }
      })
    } else if (scimgateway.isMultiValueTypes(key)) { // "type converted object" logic and original blank type having type "undefined"
      if (!attrObj[key]) delete userObj[key] // blank or null
      for (const el in attrObj[key]) {
        attrObj[key][el].type = el
        if (attrObj[key][el].operation && attrObj[key][el].operation === 'delete') { // delete multivalue
          let type = el
          if (type === 'undefined') type = undefined
          userObj[key] = userObj[key].filter(e => e.type !== type)
          if (userObj[key].length < 1) delete userObj[key]
        } else { // modify/create multivalue
          if (!userObj[key]) userObj[key] = []
          const found = userObj[key].find((e, i) => {
            if (e.type === el || (!e.type && el === 'undefined')) {
              for (const k in attrObj[key][el]) {
                userObj[key][i][k] = attrObj[key][el][k]
                if (k === 'type' && attrObj[key][el][k] === 'undefined') delete userObj[key][i][k] // don't store with type "undefined"
              }
              return true
            } else return false
          })
          if (attrObj[key][el].type && attrObj[key][el].type === 'undefined') delete attrObj[key][el].type // don't store with type "undefined"
          if (!found) userObj[key].push(attrObj[key][el]) // create
        }
      }
    } else {
      // None multi value attribute
      if (typeof (attrObj[key]) !== 'object' || attrObj[key] === null) {
        if (attrObj[key] === '' || attrObj[key] === null) delete userObj[key]
        else userObj[key] = attrObj[key]
      } else {
        // name.familyName=Bianchi
        if (!userObj[key]) userObj[key] = {} // e.g name object does not exist
        for (const sub in attrObj[key]) { // attributes to be cleard located in meta.attributes eg: {"meta":{"attributes":["name.familyName","profileUrl","title"]}
          if (sub === 'attributes' && Array.isArray(attrObj[key][sub])) {
            attrObj[key][sub].forEach(element => {
              const arrSub = element.split('.')
              if (arrSub.length === 2) userObj[arrSub[0]][arrSub[1]] = '' // e.g. name.familyName
              else userObj[element] = ''
            })
          } else {
            if (Object.prototype.hasOwnProperty.call(attrObj[key][sub], 'value') &&
            attrObj[key][sub].value === '') delete userObj[key][sub] // object having blank value attribute e.g. {"manager": {"value": "",...}}
            else if (attrObj[key][sub] === '') delete userObj[key][sub]
            else {
              if (!userObj[key]) userObj[key] = {} // may have been deleted by length check below
              userObj[key][sub] = attrObj[key][sub]
            }
            if (Object.keys(userObj[key]).length < 1) delete userObj[key]
          }
        }
      }
    }
  }
  users.update(userObj) // needed for persistence
  return null
}

// =================================================
// getGroups
// =================================================
scimgateway.getGroups = async (baseEntity, getObj, attributes, ctx) => {
  //
  // "getObj" = { attribute: <>, operator: <>, value: <>, rawFilter: <>, startIndex: <>, count: <> }
  // rawFilter is always included when filtering
  // attribute, operator and value are included when requesting unique object or simpel filtering
  // See comments in the "mandatory if-else logic - start"
  //
  // "attributes" is array of attributes to be returned - if empty, all supported attributes should be returned
  // Should normally return all supported group attributes having id, displayName and members as mandatory
  // id and displayName are most often considered as "the same" having value = <GroupName>
  // Note, the value of returned 'id' will be used as 'id' in modifyGroup and deleteGroup
  // scimgateway will automatically filter response according to the attributes list
  //
  const action = 'getGroups'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes}`)

  if (getObj.operator) { // convert to plugin supported syntax
    switch (getObj.operator) {
      case 'co':
        getObj.operator = '$contains'
        break
      case 'ge':
        getObj.operator = '$gte'
        break
      case 'le':
        getObj.operator = '$lte'
        break
      case 'sw':
        getObj.operator = '$regex'
        getObj.value = new RegExp(`^${getObj.value}.*`)
        break
      case 'ew':
        getObj.operator = '$regex'
        getObj.value = new RegExp(`.*${getObj.value}$`)
        break
      default:
        if (!validFilterOperators.includes(getObj.operator)) {
          const err = new Error(`${action} error: filter operator '${getObj.operator}' is not valid, valid operators for this endpoint are: ${validFilterOperators}` + ',co,ge,le,sw,ew')
          err.name = 'invalidFilter' // maps to scimType error handling
          throw err
        }
        getObj.operator = '$' + getObj.operator
    }
  }

  let groupsArr

  // mandatory if-else logic - start
  if (getObj.operator) { // note, loki using prefix '$'
    if (getObj.operator === '$eq' && ['id', 'displayName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique group to be returned - correspond to getGroup() in versions < 4.x.x
      const queryObj = {}
      queryObj[getObj.attribute] = getObj.value // { displayName: 'Employees' } / { externalId: 'Employees' } / { id: 'Employees' }
      groupsArr = groups.find(queryObj)
    } else if (getObj.operator === '$eq' && getObj.attribute === 'members.value') {
      // mandatory - return all groups the user 'id' (getObj.value) is member of - correspond to getGroupMembers() in versions < 4.x.x
      // Resources = [{ id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }]
      const queryObj = {}
      queryObj[getObj.attribute] = getObj.value
      groupsArr = groups.chain().find(queryObj).data()
    } else {
      // optional - simpel filtering
      const dt = Date.parse(getObj.value)
      if (!isNaN(dt)) { // date string to timestamp
        getObj.value = dt
      }
      const queryObj = {}
      queryObj[getObj.attribute] = {}
      queryObj[getObj.attribute][getObj.operator] = getObj.value
      groupsArr = groups.chain().find(queryObj).data()
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all groups to be returned - correspond to exploreUsers() in versions < 4.x.x
    groupsArr = groups.chain().data()
  }
  // mandatory if-else logic - end

  if (!groupsArr) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  if (!getObj.startIndex) getObj.startIndex = 1
  if (!getObj.count) getObj.count = 200

  const ret = {
    Resources: [],
    totalResults: null // total number of objects when using paging (ref. startIndex/count)
  }

  const arr = groupsArr.map(obj => { return stripLoki(obj) }) // all attributes included
  const delta = arr.slice(getObj.startIndex - 1, getObj.startIndex - 1 + getObj.count) // supporting paging "light"
  Array.prototype.push.apply(ret.Resources, delta)
  ret.totalResults = arr.length // set to maximum, will be corrected if needed by scimgateway
  return ret
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj, ctx) => {
  const action = 'createGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" groupObj=${JSON.stringify(groupObj)}`)

  if (groupObj.externalId) groupObj.id = groupObj.externalId // for loki-plugin (scim endpoint) id is mandatory and set to displayName
  else groupObj.id = groupObj.displayName

  try {
    groups.insert(groupObj)
    return null
  } catch (err) {
    const newErr = new Error(`${action} error: ${err.message}`)
    if (err.message && err.message.startsWith('Duplicate key')) {
      newErr.name = 'uniqueness' // maps to scimType error handling
    }
    throw newErr
  }
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id, ctx) => {
  const action = 'deleteGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)

  const res = groups.find({ id: id })
  if (res.length !== 1) throw new Error(`${action} error: failed for id=${id}`)
  const groupObj = res[0]
  groups.remove(groupObj)
  return null
}

// =================================================
// modifyGroup
// =================================================
scimgateway.modifyGroup = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)

  if (!attrObj.members) {
    throw new Error(`${action} error: only supports modification of members`)
  }
  if (!Array.isArray(attrObj.members)) {
    throw new Error(`${action} error: ${JSON.stringify(attrObj)} - correct syntax is { "members": [...] }`)
  }

  const res = groups.find({ id: id })
  if (res.length === 0) throw new Error(`${action} error: group id=${id} - group does not exist`)
  if (res.length > 1) throw new Error(`${action} error: group id=${id} - group is not unique, more than one have been found`)
  const groupObj = res[0]

  if (!groupObj.members) groupObj.members = []
  const usersNotExist = []

  await attrObj.members.forEach(async el => {
    if (el.operation && el.operation === 'delete') { // delete member from group
      if (!el.value) groupObj.members = [] // members=[{"operation":"delete"}] => no value, delete all members
      else groupObj.members = groupObj.members.filter(element => element.value !== el.value)
    } else { // Add member to group
      if (el.value) {
        const getObj = { attribute: 'id', operator: 'eq', value: el.value }
        const usrs = await scimgateway.getUsers(baseEntity, getObj, 'id,displayName', ctx) // check if user exist
        if (usrs && usrs.Resources && usrs.Resources.length === 1 && usrs.Resources[0].id === el.value) {
          const newMember = {
            display: usrs.Resources[0].displayName || el.value,
            value: el.value
          }
          const exists = groupObj.members.some(e => (e.value === el.value))
          if (!exists) groupObj.members.push(newMember)
        } else usersNotExist.push(el.value)
      }
    }
  })

  groups.update(groupObj)

  if (usersNotExist.length > 0) throw new Error(`${action} error: failed for id=${groupObj.id} - includes none existing members: ${usersNotExist.toString()}`)
  return null
}

// =================================================
// helpers
// =================================================

const stripLoki = (obj) => { // remove loki meta data and insert scim
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
