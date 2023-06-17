// =================================================================================
// File:    plugin-mongodb.js
//
// Authors: Jarle Elshaug
//          Filipe Ribeiro (KEEP SOLUTIONS)
//          Miguel Ferreira (KEEP SOLUTIONS)
//
// Purpose: SCIM Gateway becomes a standalone SCIM endpoint
//          - Same as plugin-loki but using MongoDB
//          - Demonstrate userprovisioning towards local/remote MongoDB document-oriented database
//          - configuration "endpoint.entity" gives multi tenant or multi endpoint flexibilty through baseEntity in URL
//          - { "persistence": false } deletes any existing users/groups and loads predefined test users/groups
//          - baseUrl is mongodb connection uri without "username:password"
//              syntax: mongodb://host1[:port1][,...hostN[:portN]][/[defaultauthdb][?options]]
//              e.g: mongodb://localhost:27017/db?tls=true&tlsInsecure=true
//
// Supported attributes:
//
// GlobalUser   Template            Scim        Endpoint
// ------------------------------------------------------
// All attributes are supported, note multivalue "type" must be unique
//
// =================================================================================

'use strict'

const MongoClient = require('mongodb').MongoClient

// mandatory plugin initialization - start
const path = require('path')
let ScimGateway = null
try {
  ScimGateway = require('./scimgateway')
} catch (err) {
  ScimGateway = require('scimgateway')
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

const validFilterOperators = ['eq', 'ne', 'aeq', 'dteq', 'gt', 'gte', 'lt', 'lte', 'between', 'jgt', 'jgte', 'jlt', 'jlte', 'jbetween', 'regex', 'in', 'nin', 'keyin', 'nkeyin', 'definedin', 'undefinedin', 'contains', 'containsAny', 'type', 'finite', 'size', 'len', 'exists']

async function loadHandler (baseEntity, ctx) {
  const action = 'loadHander'

  const clientIdentifier = getClientIdentifier(ctx)
  if (config.entity[baseEntity].isLoaded) { // loadHandler only once
    if (!clientIdentifier) return clientIdentifier // not using Auth PassThrough
    if (config.entity[baseEntity][clientIdentifier]) return clientIdentifier // authenticated
    throw new Error('{"error":"Access denied","statusCode":401}') // string: "statusCode":401 ensure gateway returns 401
  }

  if (!config.entity[baseEntity].baseUrl) { // mongodb://host1[:port1][,...hostN[:portN]][/[defaultauthdb][?options]] - e.g: mongodb://localhost:27017/db?tls=true&tlsInsecure=true
    throw new Error(`${action} error: configuration entity.${baseEntity}.baseUrl is missing`)
  }
  const arr = config.entity[baseEntity].baseUrl.split('//')
  if (arr.length !== 2 || arr[0] !== 'mongodb:') throw new Error('error: configuration baseUrls is not using expected format mongodb://hostname:port')

  let username
  let password
  if (ctx?.request?.header?.authorization) { // Auth PassThrough
    const [user, secret] = getCtxAuth(ctx)
    if (user) username = user
    else username = config.entity[baseEntity].username // bearer token, using username from configuration
    password = secret
  } else {
    username = config.entity[baseEntity].username
    password = scimgateway.getPassword(`endpoint.entity.${baseEntity}.password`, configFile)
  }
  const dbConn = `${arr[0]}//${encodeURIComponent(username)}:${encodeURIComponent(password)}@${arr[1]}` // percent encoded username/password
  const client = new MongoClient(dbConn, { useUnifiedTopology: true })

  const dbName = config.entity[baseEntity].database ? config.entity[baseEntity].database : 'scim'
  let db
  let users
  let groups

  try {
    await client.connect()
    db = await client.db(dbName)

    const clientIdentifier = getClientIdentifier(ctx)
    if (!config.entity[baseEntity][clientIdentifier]) config.entity[baseEntity][clientIdentifier] = {}
    config.entity[baseEntity][clientIdentifier].client = client
    config.entity[baseEntity].db = db

    if (await isMongoCollection(baseEntity, 'users')) users = await db.collection('users')
    else {
      users = await db.collection('users')
      users.createIndex({ id: 1 }, { unique: true })
    }
    if (await isMongoCollection(baseEntity, 'groups')) groups = await db.collection('groups')
    else {
      groups = await db.collection('groups')
      groups.createIndex({ id: 1 }, { unique: true })
    }
  } catch (error) {
    if (clientIdentifier && error.message.includes('Authentication')) {
      throw new Error('{"error":"Access denied","statusCode":401}') // string: "statusCode":401 ensure gateway returns 401
    }
    throw new Error(`${action} error: failed to connect to database '${client.s.options.dbName}' - ${error.message}`)
  }

  if (config.entity[baseEntity].persistence === false && process.env.NODE_ENV !== 'production') {
    await dropMongoCollection(baseEntity, 'users')
    await dropMongoCollection(baseEntity, 'groups')

    try {
      users = await db.collection('users')
      users.createIndex({ id: 1 }, { unique: true })
      groups = await db.collection('groups')
      groups.createIndex({ id: 1 }, { unique: true })
    } catch (error) {
      throw new Error(`${action} error: failed to get collections for database '${client.s.options.dbName}' - ${error.message}`)
    }

    for (let record of scimgateway.testmodeusers) {
      try {
        record = encodeDotDate(record)
        const now = Date.now()
        record.meta = {
          created: now,
          version: 0
        }

        await users.insertOne(record)
      } catch (error) {
        throw new Error(`${action} error: failed to insert user for database '${client.s.options.dbName}' - ${error.message}`)
      }
    }

    for (let record of scimgateway.testmodegroups) {
      try {
        record = encodeDotDate(record)
        const now = Date.now()
        record.meta = {
          created: now,
          version: 0
        }
        await groups.insertOne(record)
      } catch (error) {
        throw new Error(`${action} error: failed to insert group for database '${client.s.options.dbName}' - ${error.message}`)
      }
    }
  }
  if (!config.entity[baseEntity][clientIdentifier]) config.entity[baseEntity][clientIdentifier] = {}
  config.entity[baseEntity][clientIdentifier].collection = {}
  config.entity[baseEntity][clientIdentifier].collection.users = users
  config.entity[baseEntity][clientIdentifier].collection.groups = groups
  config.entity[baseEntity].isLoaded = true
  return clientIdentifier
}

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

  const clientIdentifier = await loadHandler(baseEntity, ctx) // includes Auth PassThrough logic and loaded only once

  if (getObj.operator) { // convert to plugin supported syntax
    switch (getObj.operator) {
      case 'co':
        getObj.operator = '$regex'
        getObj.value = new RegExp(`.*${getObj.value}.*`)
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

  const users = config.entity[baseEntity][clientIdentifier].collection.users
  let findObj

  // mandatory if-else logic - start
  if (getObj.operator) { // note, using prefix '$'
    if (getObj.operator === '$eq' && ['id', 'userName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      findObj = {}
      if (getObj.attribute === 'id') findObj[getObj.attribute] = getObj.value
      else findObj[getObj.attribute] = new RegExp(`^${getObj.value}$`, 'i') // case insensitive
    } else if (getObj.operator === '$eq' && getObj.attribute === 'group.value') {
      // optional - only used when groups are member of users, not default behavior - correspond to getGroupUsers() in versions < 4.x.x
      findObj = { groups: { value: getObj.value } }
    } else {
      // optional - simpel filtering
      const dt = Date.parse(getObj.value)
      if (!isNaN(dt)) { // date string to timestamp
        getObj.value = dt
      }
      findObj = {}
      findObj[getObj.attribute] = {}
      findObj[getObj.attribute][getObj.operator] = getObj.value
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all users to be returned - correspond to exploreUsers() in versions < 4.x.x
    findObj = {}
  }
  // mandatory if-else logic - end

  if (!findObj) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  if (!getObj.startIndex) getObj.startIndex = 1
  if (!getObj.count) getObj.count = 200

  const ret = {
    Resources: [],
    totalResults: null
  }

  try {
    const projection = attributes.length > 0 ? getProjectionFromAttributes(attributes) : { _id: 0 }
    const usersArr = await users.find(findObj, { projection: projection }).sort({ _id: 1 }).skip(getObj.startIndex - 1).limit(getObj.count).toArray()
    const totalResults = await users.countDocuments(findObj, { projection: projection })
    const arr = usersArr.map((obj) => {
      const o = decodeDotDate(obj)
      if (o.meta && o.meta.version !== undefined) {
        o.meta.version = `W/"${o.meta.version}"`
      }
      return o
    }) // virtual attribute groups automatically handled by scimgateway
    Array.prototype.push.apply(ret.Resources, arr)
    ret.totalResults = totalResults
    return ret
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj, ctx) => {
  const action = 'createUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" userObj=${JSON.stringify(userObj)}`)

  const clientIdentifier = await loadHandler(baseEntity, ctx) // includes Auth PassThrough logic and loaded only once

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

  if (!userObj.meta) {
    const now = Date.now()
    userObj.meta = {
      version: 0,
      created: now,
      lastModified: now
    }
  }
  userObj = encodeDotDate(userObj)

  try {
    const users = config.entity[baseEntity][clientIdentifier].collection.users
    await users.insertOne(userObj)
    return null
  } catch (err) {
    const newErr = new Error(`${action} error: ${err.message}`)
    if (err.message && err.message.includes('duplicate key')) {
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

  const clientIdentifier = await loadHandler(baseEntity, ctx) // includes Auth PassThrough logic and loaded only once

  const users = config.entity[baseEntity][clientIdentifier].collection.users
  try {
    /*
    const now = Date.now()
    const userObj = {
      id: id,
      meta: {
        lastModified: now
      },
      deleted: 1
    }
    await users.replaceOne({ id: id }, userObj) // allowing none unique id, then do not use: users.createIndex({ id: 1 }, { unique: true })
    */
    await users.deleteOne({ id: id })
    return null
  } catch (err) {
    throw new Error(`${action} error: failed for user id=${id} - ${err.message}`)
  }
}

// =================================================
// modifyUser
// =================================================
scimgateway.modifyUser = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)

  const clientIdentifier = await loadHandler(baseEntity, ctx) // includes Auth PassThrough logic and loaded only once

  const notValid = scimgateway.notValidAttributes(attrObj, validScimAttr) // We should check for unsupported endpoint attributes
  if (notValid) {
    throw new Error(`${action} error: unsupported scim attributes: ${notValid} (supporting only these attributes: ${validScimAttr.toString()})`)
  }
  if (attrObj.password) delete attrObj.password // exclude password db not ecrypted

  let res

  try {
    const users = config.entity[baseEntity][clientIdentifier].collection.users
    res = await users.find({ id }, { projection: { _id: 0 } }).toArray()
    if (res.length === 0) throw new Error('user does not exist')
    if (res.length > 1) throw new Error('user is not unique, more than one have been found')
  } catch (error) {
    throw new Error(`${action} error: could not find user with id=${id} - ${error.message}`)
  }

  let userObj = decodeDotDate(res[0])

  for (const key in attrObj) {
    if (Array.isArray(attrObj[key])) { // standard, not using type (e.g roles/groups) or skipTypeConvert=true
      const delArr = attrObj[key].filter(el => el.operation === 'delete')
      const addArr = attrObj[key].filter(el => (!el.operation || el.operation !== 'delete'))
      if (!userObj[key]) userObj[key] = []
      // delete
      userObj[key] = userObj[key].filter(el => {
        if (delArr.findIndex(e => e.value === el.value) >= 0) return false
        return true
      })
      // add
      addArr.forEach(el => {
        if (Object.prototype.hasOwnProperty.call(el, 'primary')) {
          if (el.primary === true || (typeof el.primary === 'string' && el.primary.toLowerCase() === 'true')) {
            const index = userObj[key].findIndex(e => e.primary === el.primary)
            if (index >= 0) {
              if (key === 'roles') userObj[key].splice(index, 1) // roles, delete existing role having primary attribute true (new role with primary will be added)
              else userObj[key][index].primary = undefined // remove primary attribute, only one primary
            }
          }
        }
        userObj[key].push(el)
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
          if (attrObj[key][el].primary) { // remove any existing primary attribute, should only have one primary set
            const primVal = attrObj[key][el].primary
            if (primVal === true || (typeof primVal === 'string' && primVal.toLowerCase() === 'true')) {
              const index = userObj[key].findIndex(e => e.primary === primVal)
              if (index >= 0) {
                userObj[key][index].primary = undefined
              }
            }
          }
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

  if (!userObj.meta) {
    const now = Date.now()
    userObj.meta = {
      version: 0,
      created: now,
      lastModified: now
    }
  } else {
    const now = Date.now()
    userObj.meta.lastModified = now
    userObj.meta.version += 1
  }
  userObj = encodeDotDate(userObj)

  try {
    const users = config.entity[baseEntity][clientIdentifier].collection.users
    await users.replaceOne({ id: id }, userObj)
    return null
  } catch (err) {
    throw new Error(`${action} error: failed for user id=${id} - ${err.message}`)
  }
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

  const clientIdentifier = await loadHandler(baseEntity, ctx) // includes Auth PassThrough logic and loaded only once

  if (getObj.operator) { // convert to plugin supported syntax
    switch (getObj.operator) {
      case 'co':
        getObj.operator = '$regex'
        getObj.value = new RegExp(`.*${getObj.value}.*`)
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

  let findObj

  // mandatory if-else logic - start
  if (getObj.operator) { // note, loki using prefix '$'
    if (getObj.operator === '$eq' && ['id', 'displayName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique group to be returned - correspond to getGroup() in versions < 4.x.x
      findObj = {}
      if (getObj.attribute === 'id') findObj[getObj.attribute] = getObj.value
      else findObj[getObj.attribute] = new RegExp(`^${getObj.value}$`, 'i') // case insensitive
    } else if (getObj.operator === '$eq' && getObj.attribute === 'members.value') {
      // mandatory - return all groups the user 'id' (getObj.value) is member of - correspond to getGroupMembers() in versions < 4.x.x
      // Resources = [{ id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }]
      findObj = { members: { $elemMatch: { value: getObj.value } } }
    } else {
      // optional - simpel filtering
      const dt = Date.parse(getObj.value)
      if (!isNaN(dt)) { // date string to timestamp
        getObj.value = dt
      }
      findObj = {}
      findObj[getObj.attribute] = {}
      findObj[getObj.attribute][getObj.operator] = getObj.value
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all groups to be returned - correspond to exploreUsers() in versions < 4.x.x
    findObj = {}
  }
  // mandatory if-else logic - end

  if (!findObj) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)
  if (!getObj.startIndex) getObj.startIndex = 1
  if (!getObj.count) getObj.count = 200

  const ret = {
    Resources: [],
    totalResults: null
  }

  try {
    const projection = attributes.length > 0 ? getProjectionFromAttributes(attributes) : { _id: 0 }
    const groups = config.entity[baseEntity][clientIdentifier].collection.groups
    const groupsArr = await groups.find(findObj, { projection: projection }).sort({ _id: 1 }).skip(getObj.startIndex - 1).limit(getObj.count).toArray()
    const totalResults = await groups.countDocuments(findObj, { projection: projection })
    const arr = groupsArr.map((obj) => {
      return decodeDotDate(obj)
    })
    Array.prototype.push.apply(ret.Resources, arr)
    ret.totalResults = totalResults
    return ret
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj, ctx) => {
  const action = 'createGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" groupObj=${JSON.stringify(groupObj)}`)

  const clientIdentifier = await loadHandler(baseEntity, ctx) // includes Auth PassThrough logic and loaded only once

  if (!groupObj.meta) {
    const now = Date.now()
    groupObj.meta = {
      version: 0,
      created: now,
      lastModified: now
    }
  }
  if (groupObj.externalId) groupObj.id = groupObj.externalId // for loki-plugin (scim endpoint) id is mandatory and set to displayName
  else groupObj.id = groupObj.displayName
  groupObj = encodeDotDate(groupObj)

  try {
    const groups = config.entity[baseEntity][clientIdentifier].collection.groups
    await groups.insertOne(groupObj)
    return null
  } catch (err) {
    const newErr = new Error(`${action} error: ${err.message}`)
    if (err.message && err.message.includes('duplicate key')) {
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

  const clientIdentifier = await loadHandler(baseEntity, ctx) // includes Auth PassThrough logic and loaded only once

  const groups = config.entity[baseEntity][clientIdentifier].collection.groups
  try {
    /*
    const now = Date.now()
    const groupObj = {
      id: id,
      meta: {
        lastModified: now
      },
      deleted: 1
    }
    await groups.replaceOne({ id: id }, groupObj) // allowing none unique id, then do not use: groups.createIndex({ id: 1 }, { unique: true })
    */
    await groups.deleteOne({ id: id })
    return null
  } catch (err) {
    throw new Error(`${action} error: failed for id=${id} - ${err.message}`)
  }
}

// =================================================
// modifyGroup
// =================================================
scimgateway.modifyGroup = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)

  const clientIdentifier = await loadHandler(baseEntity, ctx) // includes Auth PassThrough logic and loaded only once

  const users = config.entity[baseEntity][clientIdentifier].collection.users
  const groups = config.entity[baseEntity][clientIdentifier].collection.groups
  let res
  let isModified = false

  try {
    res = await groups.find({ id: id }, { projection: { _id: 0 } }).toArray()
    if (res.length === 0) throw new Error('group does not exist')
    if (res.length > 1) throw new Error('group is not unique, more than one have been found')
  } catch (err) {
    throw new Error(`${action} error: group id=${id} - ${err.message}`)
  }

  let groupObj = decodeDotDate(res[0])
  if (!groupObj.members) groupObj.members = []
  const usersNotExist = []

  if (attrObj.members) {
    if (!Array.isArray(attrObj.members)) {
      throw new Error(`${action} error: ${JSON.stringify(attrObj)} - correct syntax is { "members": [...] }`)
    }
    for (const el of attrObj.members) {
      if (el.operation && el.operation === 'delete') {
      // delete member from group
        if (!el.value) {
        // members=[{"operation":"delete"}] => no value, delete all members
          await groups.updateOne({ id: groupObj.id }, { $set: { members: [] } })
          scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} deleted all members`)
          isModified = true
        } else {
          await groups.updateMany({ id: groupObj.id }, { $pull: { members: { value: el.value } } })
          scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} deleted from group: ${el.value}`)
          isModified = true
        }
      } else { // Add member to group
        if (el.value) {
          let usrs = []
          try {
            usrs = await users.find({ id: el.value }, { projection: { _id: 0 } }).toArray() // check if user exist
          } catch (err) {
            throw new Error(`${action} error: failed to find group id=${id} - ${err.message}`)
          }
          if (usrs.length === 1 && usrs[0].id === el.value) {
            if (!groupObj.members.some((element) => element.value === el.value)) {
              await groups.updateMany({ id: groupObj.id }, { $push: { members: { display: usrs[0].displayName || el.value, value: el.value } } })
              scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} added member to group: ${el.value}`)
              isModified = true
            }
          } else usersNotExist.push(el.value)
        }
      }
    }
  }

  delete attrObj.members
  if (Object.keys(attrObj).length > 0) { // displayName/externalId
    await groups.updateOne({ id: groupObj.id }, { $set: attrObj })
    isModified = true
  }

  if (!groupObj.meta) {
    const now = Date.now()
    groupObj.meta = {
      version: 0,
      created: now,
      lastModified: now
    }
  } else {
    const now = Date.now()
    groupObj.meta.lastModified = now
    groupObj.meta.version += 1
  }
  groupObj = encodeDotDate(groupObj)
  try {
    if (isModified) await groups.updateOne({ id: groupObj.id }, { $set: { meta: groupObj.meta } })
    if (usersNotExist.length > 0) throw new Error(`includes none existing members: ${usersNotExist.toString()}`)
    return null
  } catch (err) {
    throw new Error(`${action} error: failed for id=${groupObj.id} - ${err.message}`)
  }
}

// =================================================
// helpers
// =================================================

const getClientIdentifier = (ctx) => {
  if (!ctx?.request?.header?.authorization) return undefined
  const [user, secret] = getCtxAuth(ctx)
  return `${encodeURIComponent(user)}_${encodeURIComponent(secret)}` // user_password or undefined_password
}

//
// getCtxAuth returns username/secret from ctx header when using Auth PassThrough
//
const getCtxAuth = (ctx) => {
  if (!ctx?.request?.header?.authorization) return []
  const [authType, authToken] = (ctx.request.header.authorization || '').split(' ') // [0] = 'Basic' or 'Bearer'
  let username, password
  if (authType === 'Basic') [username, password] = (Buffer.from(authToken, 'base64').toString() || '').split(':')
  if (username) return [username, password] // basic auth
  else return [undefined, authToken] // bearer auth
}

const decodeDotDate = (obj) => { // replace dot with unicode
  const retObj = JSON.parse(JSON.stringify(obj)) // new object - don't modify source
  Object.keys(retObj).forEach(function (key) {
    if (key.includes('·')) {
      retObj[key.replace(/\·/g, '.')] = retObj[key] // eslint-disable-line
      delete retObj[key]
    }
  })
  if (retObj.meta) { // date string to timestamp
    if (retObj.meta.created) retObj.meta.created = new Date(retObj.meta.created).toISOString()
    if (retObj.meta.lastModified) retObj.meta.lastModified = new Date(retObj.meta.lastModified).toISOString()
  }
  return retObj
}

const encodeDotDate = (obj) => {
  const retObj = JSON.parse(JSON.stringify(obj)) // new object - don't modify source
  if (retObj._id) delete retObj._id
  Object.keys(retObj).forEach(function (key) { // replace dot with unicode
    if (key.includes('.')) {
      retObj[key.replace(/\./g, '·')] = retObj[key]
      delete retObj[key]
    }
  })
  if (retObj.meta) { // date string to timestamp
    if (retObj.meta.created) {
      const dt = Date.parse(retObj.meta.created)
      if (!isNaN(dt)) {
        retObj.meta.created = dt
      }
    }
    if (retObj.meta.lastModified) {
      const dt = Date.parse(retObj.meta.lastModified)
      if (!isNaN(dt)) {
        retObj.meta.lastModified = dt
      }
    }
  }
  return retObj
}

function getProjectionFromAttributes (attributes) {
  const projection = {}
  attributes.forEach((attr) => {
    projection[attr] = 1
  })
  return projection
}

async function isMongoCollection (baseEntity, collection) {
  try {
    if (!config.entity[baseEntity].db.listCollections) return false
    const colls = await config.entity[baseEntity].db.listCollections({ name: collection }).toArray()
    if (colls.length === 1) return true
    return false
  } catch (error) {
    throw new Error(`Failed to check collection '${collection}' - ${error.message}`)
  }
}

async function dropMongoCollection (baseEntity, collection) {
  try {
    if (await isMongoCollection(baseEntity, collection)) {
      await config.entity[baseEntity].db.dropCollection(collection)
    }
  } catch (error) {
    throw new Error(`Failed to drop collection '${collection}' - ${error.message}`)
  }
}

//
// Cleanup on exit
//
process.on('SIGTERM', () => {
  // kill
  for (const baseEntity in config.entity) {
    for (const key in config.entity[baseEntity]) {
      if (config.entity[baseEntity][key].client) {
        config.entity[baseEntity][key].client.close()
      }
    }
  }
})
process.on('SIGINT', () => {
  // Ctrl+C
  for (const baseEntity in config.entity) {
    for (const key in config.entity[baseEntity]) {
      if (config.entity[baseEntity][key].client) {
        config.entity[baseEntity][key].client.close()
      }
    }
  }
})

// connect MongoDb and load users/groups
if (!config.entity) throw new Error('error: configuration entity is missing')
if (!scimgateway.authPassThroughAllowed) { // not using Auth PassThrough, loading db handler at startup using username/password from config
  for (const baseEntity in config.entity) {
    loadHandler(baseEntity)
  }
}
