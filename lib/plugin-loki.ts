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

import Loki from 'lokijs'
import path from 'node:path'

// start - mandatory plugin initialization
import { ScimGateway } from 'scimgateway'
const scimgateway = new ScimGateway()
const config = scimgateway.getConfig()
scimgateway.authPassThroughAllowed = false
// end - mandatory plugin initialization

const configDir = scimgateway.configDir
const validFilterOperators = ['eq', 'ne', 'aeq', 'dteq', 'gt', 'gte', 'lt', 'lte', 'between', 'jgt', 'jgte', 'jlt', 'jlte', 'jbetween', 'regex', 'in', 'nin', 'keyin', 'nkeyin', 'definedin', 'undefinedin', 'contains', 'containsAny', 'type', 'finite', 'size', 'len', 'exists']
const dbNames: string[] = []
for (const baseEntity in config.entity) {
  let dbname = config.entity[baseEntity].dbname || 'loki.db'
  if (dbNames.includes(dbname)) {
    scimgateway.logError(baseEntity, `initialization error: database '${dbname}' is already used by another baseEntity configuration`)
    continue
  }
  dbNames.push(dbname)
  dbname = path.join(`${configDir}`, `${dbname}`)
  const isPersisence = config.entity[baseEntity].persistence !== false

  const loadHandler = () => {
    let users = db.getCollection('users')
    if (users === null) { // if database do not exist it will be empty so intitialize here
      users = db.addCollection('users', {
        unique: ['id', 'userName'],
      })
    }

    let groups = db.getCollection('groups')
    if (groups === null) {
      groups = db.addCollection('groups', {
        unique: ['displayName'],
      })
    }

    if (!isPersisence) { // load testusers
      scimgateway.getTestModeUsers().forEach((record) => {
        const r: any = scimgateway.copyObj(record)
        if (r.meta) delete r.meta
        users.insert(r)
      })
      scimgateway.getTestModeGroups().forEach((record) => {
        const r: any = scimgateway.copyObj(record)
        if (r.meta) delete r.meta
        groups.insert(r)
      })
    }

    config.entity[baseEntity].users = users
    config.entity[baseEntity].groups = groups
  }

  const db = new Loki(dbname, {
    env: 'NA', // avoid default NODEJS
    autoload: isPersisence,
    autoloadCallback: isPersisence ? loadHandler : undefined,
    autosave: isPersisence,
    autosaveInterval: 10000, // 10 seconds
    adapter: isPersisence ? new Loki.LokiFsAdapter() : new Loki.LokiMemoryAdapter(),
  })
  config.entity[baseEntity].db = db

  if (!isPersisence) loadHandler()
}

// =================================================
// getUsers
// =================================================
scimgateway.getUsers = async (baseEntity, getObj, attributes, ctx) => {
  const action = 'getUsers'
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes} passThrough=${ctx ? 'true' : 'false'}`)

  if (!config.entity[baseEntity]) throw new Error(`unsupported baseEntity=${baseEntity}`)
  const users = config.entity[baseEntity].users

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

  let usersArr: Record<string, any>[] | undefined

  // mandatory if-else logic - start
  if (getObj.operator) { // note, loki using prefix '$'
    if (getObj.operator === '$eq' && ['id', 'userName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      const queryObj: any = {}
      if (getObj.attribute === 'id') queryObj[getObj.attribute] = getObj.value
      else queryObj[getObj.attribute] = { $regex: [`^${getObj.value}$`, 'i'] } // case insensitive
      // new RegExp(`^${getObj.value}$`, 'i')
      usersArr = users.find(queryObj)
    } else if (getObj.operator === '$eq' && getObj.attribute === 'group.value') {
      // optional - only used when groups are member of users, not default behavior - correspond to getGroupUsers() in versions < 4.x.x
      const queryObj: any = {}
      queryObj[getObj.attribute] = getObj.value
      usersArr = users.chain().find(queryObj).data()
    } else {
      // optional - simpel filtering
      if (typeof getObj.value === 'string' && (getObj.value.includes('-') || getObj.value.includes('/'))) {
        const dt = Date.parse(getObj.value) // date string to timestamp
        if (!isNaN(dt)) getObj.value = dt
      }
      const queryObj: any = {}
      if (getObj.attribute.startsWith('urn:')) { // extension schema
        const pos = getObj.attribute.lastIndexOf(':')
        const arr = getObj.attribute.substring(pos + 1).split('.')
        const schema = getObj.attribute.substring(0, pos) + ':' + arr[0]
        const attrs = arr.slice(1)

        usersArr = users.chain().where((obj: any) => {
          if (!obj[schema]) return false
          let val = obj[schema]
          for (const key of attrs) {
            if (val === undefined) break
            val = val[key]
          }

          if (val === undefined) return false
          if (getObj.operator === '$regex') return getObj.value.test(val)
          if (getObj.operator === '$contains') return val.includes(getObj.value)
          if (getObj.operator === '$eq') return val === getObj.value
          if (getObj.operator === '$ne') return val !== getObj.value
          if (getObj.operator === '$gte') return val >= getObj.value
          if (getObj.operator === '$lte') return val <= getObj.value
          if (getObj.operator === '$gt') return val > getObj.value
          if (getObj.operator === '$lt') return val < getObj.value
          return false
        }).data()
      } else {
        queryObj[getObj.attribute] = {}
        queryObj[getObj.attribute][getObj.operator] = getObj.value
        usersArr = users.chain().find(queryObj).data()
      }
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    // note, advanced filtering "light" using and/or (not combined) is handled by scimgateway through plugin simpel filtering above
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all users to be returned - correspond to exploreUsers() in versions < 4.x.x
    usersArr = users.chain().data()
  }
  // mandatory if-else logic - end

  if (!usersArr) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  if (!getObj.startIndex) getObj.startIndex = 1
  if (!getObj.count) getObj.count = 200

  const ret: any = {
    Resources: [],
    totalResults: null, // total number of objects when using paging (ref. startIndex/count)
  }

  const arr = usersArr.map((obj) => { return stripLoki(obj) }) // all attributes included - virtual attribute groups automatically handled by scimgateway
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
  scimgateway.logDebug(baseEntity, `handling ${action} userObj=${JSON.stringify(userObj)} passThrough=${ctx ? 'true' : 'false'}`)

  if (!config.entity[baseEntity]) throw new Error(`unsupported baseEntity=${baseEntity}`)
  const users = config.entity[baseEntity].users

  if (userObj.password) delete userObj.password // exclude password db not ecrypted
  for (const key in userObj) {
    if (!Array.isArray(userObj[key]) && scimgateway.isMultiValueTypes(key)) { // true if attribute is "type converted object" => convert to standard array
      const arr: string[] = []
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
    await users.insert(userObj)
    return null
  } catch (err: any) {
    const newErr = new Error(`${action} error: ${err.message}`)
    if (err.message && err.message.startsWith('Duplicate key')) {
      newErr.name += '#409' // customErrorCode
    }
    throw newErr
  }
}

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id, ctx) => {
  const action = 'deleteUser'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} passThrough=${ctx ? 'true' : 'false'}`)

  if (!config.entity[baseEntity]) throw new Error(`unsupported baseEntity=${baseEntity}`)
  const users = config.entity[baseEntity].users
  const res = users.find({ id: id })
  if (res.length !== 1) throw new Error(`${action} error: failed for user id=${id}`)
  const userObj = res[0]
  await users.remove(userObj)
  return null
}

// =================================================
// modifyUser
// =================================================
scimgateway.modifyUser = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyUser'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} attrObj=${JSON.stringify(attrObj)} passThrough=${ctx ? 'true' : 'false'}`)

  if (!config.entity[baseEntity]) throw new Error(`unsupported baseEntity=${baseEntity}`)
  const users = config.entity[baseEntity].users
  if (attrObj.password) delete attrObj.password // exclude password db not ecrypted

  const res = users.find({ id: id })
  if (res.length === 0) throw new Error(`${action} error: user id=${id} - user does not exist`)
  if (res.length > 1) throw new Error(`${action} error: user id=${id} - user is not unique, more than one have been found`)

  let userObj: any = res[0]
  userObj = scimgateway.patchObj(userObj, attrObj) // merge

  await users.update(userObj) // needed for persistence
  return null
}

// =================================================
// getGroups
// =================================================
scimgateway.getGroups = async (baseEntity, getObj, attributes, ctx) => {
  const action = 'getGroups'
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes} passThrough=${ctx ? 'true' : 'false'}`)

  if (!config.entity[baseEntity]) throw new Error(`unsupported baseEntity=${baseEntity}`)
  const groups = config.entity[baseEntity].groups

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

  let groupsArr: Record<string, any>[] | undefined

  // mandatory if-else logic - start
  if (getObj.operator) { // note, loki using prefix '$'
    if (getObj.operator === '$eq' && ['id', 'displayName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique group to be returned - correspond to getGroup() in versions < 4.x.x
      const queryObj: any = {}
      if (getObj.attribute === 'id') queryObj[getObj.attribute] = getObj.value
      else queryObj[getObj.attribute] = { $regex: [`^${getObj.value}$`, 'i'] } // case insensitive
      groupsArr = groups.find(queryObj)
    } else if (getObj.operator === '$eq' && getObj.attribute === 'members.value') {
      // mandatory - return all groups the user 'id' (getObj.value) is member of - correspond to getGroupMembers() in versions < 4.x.x
      // Resources = [{ id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }]
      const queryObj: any = {}
      queryObj[getObj.attribute] = getObj.value
      groupsArr = groups.chain().find(queryObj).data()
    } else {
      // optional - simpel filtering
      const dt = Date.parse(getObj.value)
      if (!isNaN(dt)) { // date string to timestamp
        getObj.value = dt
      }
      const queryObj: any = {}
      queryObj[getObj.attribute] = {}
      queryObj[getObj.attribute][getObj.operator] = getObj.value
      groupsArr = groups.chain().find(queryObj).data()
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    // note, advanced filtering "light" using and/or (not combined) is handled by scimgateway through plugin simpel filtering above
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all groups to be returned - correspond to exploreUsers() in versions < 4.x.x
    groupsArr = groups.chain().data()
  }
  // mandatory if-else logic - end

  if (!groupsArr) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  if (!getObj.startIndex) getObj.startIndex = 1
  if (!getObj.count) getObj.count = 200

  const ret: any = {
    Resources: [],
    totalResults: null, // total number of objects when using paging (ref. startIndex/count)
  }

  const arr = groupsArr.map((obj) => { return stripLoki(obj) }) // all attributes included
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
  scimgateway.logDebug(baseEntity, `handling ${action} groupObj=${JSON.stringify(groupObj)} passThrough=${ctx ? 'true' : 'false'}`)

  if (!config.entity[baseEntity]) throw new Error(`unsupported baseEntity=${baseEntity}`)
  const groups = config.entity[baseEntity].groups
  if (groupObj.externalId) groupObj.id = groupObj.externalId // for loki-plugin (scim endpoint) id is mandatory and set to displayName
  else groupObj.id = groupObj.displayName

  if (groupObj.members) {
    const noneExistingUsers: any = []
    await Promise.all(groupObj.members.map(async (el: any) => {
      if (el.value) {
        const getObj = { attribute: 'id', operator: 'eq', value: el.value }
        const usrs = await scimgateway.getUsers(baseEntity, getObj, ['id', 'displayName'], ctx) // check if user exist
        if (!usrs || !usrs.Resources || usrs.Resources.length !== 1 || usrs.Resources[0].id !== el.value) {
          noneExistingUsers.push(el.value)
        } else if (usrs.Resources[0].displayName) {
          el.display = usrs.Resources[0].displayName
        }
      }
    }))
    if (noneExistingUsers.length > 0) throw new Error(`following user(s) does not exist and can't be member of group: ${noneExistingUsers.join(', ')}`)
  }

  try {
    await groups.insert(groupObj)
    return null
  } catch (err: any) {
    const newErr = new Error(`${action} error: ${err.message}`)
    if (err.message && err.message.startsWith('Duplicate key')) {
      newErr.name += '#409' // customErrorCode
    }
    throw newErr
  }
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id, ctx) => {
  const action = 'deleteGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} passThrough=${ctx ? 'true' : 'false'}`)

  if (!config.entity[baseEntity]) throw new Error(`unsupported baseEntity=${baseEntity}`)
  const groups = config.entity[baseEntity].groups
  const res = groups.find({ id: id })
  if (res.length !== 1) throw new Error(`${action} error: failed for id=${id}`)
  const groupObj = res[0]
  await groups.remove(groupObj)
  return null
}

// =================================================
// modifyGroup
// =================================================
scimgateway.modifyGroup = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} attrObj=${JSON.stringify(attrObj)} passThrough=${ctx ? 'true' : 'false'}`)

  if (!config.entity[baseEntity]) throw new Error(`unsupported baseEntity=${baseEntity}`)
  const groups = config.entity[baseEntity].groups
  const res = groups.find({ id: id })
  if (res.length === 0) throw new Error(`${action} error: group id=${id} - group does not exist`)
  if (res.length > 1) throw new Error(`${action} error: group id=${id} - group is not unique, more than one have been found`)
  const groupObj = res[0]

  if (!groupObj.members) groupObj.members = []
  const usersNotExist: string[] = []

  if (attrObj.members) {
    if (!Array.isArray(attrObj.members)) {
      throw new Error(`${action} error: ${JSON.stringify(attrObj)} - correct syntax is { "members": [...] }`)
    }
    for (const el of attrObj.members) {
      if (el.operation && el.operation === 'delete') { // delete member from group
        if (!el.value) groupObj.members = [] // members=[{"operation":"delete"}] => no value, delete all members
        else {
          groupObj.members = groupObj.members.filter((element: Record<string, any>) => element.value !== el.value)
        }
      } else { // Add member to group
        if (el.value) {
          const getObj = { attribute: 'id', operator: 'eq', value: el.value }
          const usrs: any = await scimgateway.getUsers(baseEntity, getObj, ['id', 'displayName'], ctx) // check if user exist
          if (usrs && usrs.Resources && usrs.Resources.length === 1 && usrs.Resources[0].id === el.value) {
            const newMember = {
              display: usrs.Resources[0].displayName || el.value,
              value: el.value,
            }
            const exists = groupObj.members.some((e: Record<string, any>) => (e.value === el.value))
            if (!exists) groupObj.members.push(newMember)
          } else usersNotExist.push(el.value)
        }
      }
    }
  }

  delete attrObj.members
  for (const key in attrObj) { // displayName/externalId
    groupObj[key] = attrObj[key]
  }

  await groups.update(groupObj)

  if (usersNotExist.length > 0) throw new Error(`${action} error: failed for id=${groupObj.id} - includes none existing users: ${usersNotExist.toString()}`)
  return null
}

// =================================================
// helpers
// =================================================

const stripLoki = (obj: Record<string, any>) => { // remove loki meta data and insert scim
  const retObj = JSON.parse(JSON.stringify(obj)) // new object - don't modify loki source
  if (retObj.meta) {
    delete retObj.meta.lastModified // test users loaded
    if (retObj.meta.created) retObj.meta.created = new Date(retObj.meta.created).toISOString()
    if (retObj.meta.updated) {
      retObj.meta.lastModified = new Date(retObj.meta.updated).toISOString()
      delete retObj.meta.updated
    } else retObj.meta.lastModified = retObj.meta.created
    if (retObj.meta.revision !== undefined) {
      retObj.meta.version = `W/"${retObj.meta.revision}"`
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
  for (const baseEntity in config.entity) {
    if (config.entity[baseEntity].db) config.entity[baseEntity].db.close()
  }
})
process.on('SIGINT', () => { // Ctrl+C
  for (const baseEntity in config.entity) {
    if (config.entity[baseEntity].db) config.entity[baseEntity].db.close()
  }
})
