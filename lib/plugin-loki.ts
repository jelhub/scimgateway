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
// for supporting nodejs running scimgateway package directly, using dynamic import instead of: import { ScimGateway } from 'scimgateway'
// scimgateway also inclues HelperRest: import { ScimGateway, HelperRest } from 'scimgateway'

// start - mandatory plugin initialization
const ScimGateway: typeof import('scimgateway').ScimGateway = await (async () => {
  try {
    return (await import('scimgateway')).ScimGateway
  } catch (err) {
    const source = './scimgateway.ts'
    return (await import(source)).ScimGateway
  }
})()
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
scimgateway.getUsers = async (baseEntity, getObj, attributes) => {
  const action = 'getUsers'
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes}`)

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
      const dt = Date.parse(getObj.value)
      if (!isNaN(dt)) { // date string to timestamp
        getObj.value = dt
      }
      const queryObj: any = {}
      queryObj[getObj.attribute] = {}
      queryObj[getObj.attribute][getObj.operator] = getObj.value
      usersArr = users.chain().find(queryObj).data() // {name.familyName: { $eq: "Jensen" } }
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    //
    // support "or" filter using "eq"
    // e.g.: (id eq "bjensen") or (id eq "jsmith")
    //
    const arr = getObj.rawFilter.split(' or ')
    const getObjArr: any = []

    for (let i = 0; i < arr.length; i++) {
      arr[i] = arr[i].replace(/\(/g, '').replace(/\)/g, '').trim()
      const arrFilter = arr[i].split(' ')
      if (arrFilter.length === 3 || (arrFilter.length > 2 && arrFilter[2].startsWith('"') && arrFilter[arrFilter.length - 1].endsWith('"'))) {
        const o: any = {}
        o.attribute = arrFilter[0] // id
        o.operator = arrFilter[1].toLowerCase() // eq
        o.value = decodeURIComponent(arrFilter.slice(2).join(' ').replace(/"/g, '')) // bjensen
        getObjArr.push(o)
      }
    }

    const o: any = {}
    for (let i = 0; i < getObjArr.length; i++) {
      if (getObjArr[i].operator === 'eq') {
        if (!o[getObjArr[i].attribute]) o[getObjArr[i].attribute] = []
        o[getObjArr[i].attribute].push(getObjArr[i].value)
      } else {
        throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
      }
    } // { id: [ 'bjensen', 'jsmith' ] }

    for (const k in o) {
      const f: any = {}
      f[k] = { $in: o[k] } // { id: { $in: ['bjensen', 'jsmith'] } }
      const u = users.chain().find(f).data()
      if (!usersArr) usersArr = []
      Array.prototype.push.apply(usersArr, u)
    }
    if (!usersArr) throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
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
scimgateway.createUser = async (baseEntity, userObj) => {
  const action = 'createUser'
  scimgateway.logDebug(baseEntity, `handling ${action} userObj=${JSON.stringify(userObj)}`)

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
scimgateway.deleteUser = async (baseEntity, id) => {
  const action = 'deleteUser'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id}`)

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
scimgateway.modifyUser = async (baseEntity, id, attrObj) => {
  const action = 'modifyUser'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} attrObj=${JSON.stringify(attrObj)}`)

  if (!config.entity[baseEntity]) throw new Error(`unsupported baseEntity=${baseEntity}`)
  const users = config.entity[baseEntity].users
  if (attrObj.password) delete attrObj.password // exclude password db not ecrypted

  const res = users.find({ id: id })
  if (res.length === 0) throw new Error(`${action} error: user id=${id} - user does not exist`)
  if (res.length > 1) throw new Error(`${action} error: user id=${id} - user is not unique, more than one have been found`)
  const userObj: any = res[0]

  for (const key in attrObj) {
    if (Array.isArray(attrObj[key])) { // standard, not using type (e.g roles/groups) or skipTypeConvert=true
      const delArr = attrObj[key].filter(el => el.operation === 'delete')
      const addArr = attrObj[key].filter(el => (!el.operation || el.operation !== 'delete'))
      if (!userObj[key] || !Array.isArray(userObj[key])) userObj[key] = []
      // delete
      userObj[key] = userObj[key].filter((el: Record<string, any>) => {
        const index = delArr.findIndex((e) => {
          let elExist = false
          for (const k in el) {
            if (k === 'primary') continue
            if (el[k] !== e[k]) {
              elExist = false
              break
            }
            elExist = true
          }
          return elExist
        })
        if (index >= 0) return false
        else return true
      })
      // add
      addArr.forEach((el) => {
        if (Object.prototype.hasOwnProperty.call(el, 'primary')) {
          if (el.primary === true || (typeof el.primary === 'string' && el.primary.toLowerCase() === 'true')) {
            const index = userObj[key].findIndex((e: Record<string, any>) => e.primary === el.primary)
            if (index >= 0) {
              if (key === 'roles') userObj[key].splice(index, 1) // roles, delete existing role having primary attribute true (new role with primary will be added)
              else userObj[key][index].primary = undefined // remove primary attribute, only one primary
            }
          }
        }
        const index = userObj[key].findIndex((e: Record<string, any>) => { // avoid adding existing
          let elExist = false
          for (const k in el) {
            if (el[k] !== e[k]) {
              elExist = false
              break
            }
            elExist = true
          }
          return elExist
        })
        if (index < 0) userObj[key].push(el)
      })
    } else if (scimgateway.isMultiValueTypes(key)) { // "type converted object" logic and original blank type having type "undefined"
      if (!attrObj[key]) delete userObj[key] // blank or null
      for (const el in attrObj[key]) {
        attrObj[key][el].type = el
        if (attrObj[key][el].operation && attrObj[key][el].operation === 'delete') { // delete multivalue
          let type: any = el
          if (type === 'undefined') type = undefined
          userObj[key] = userObj[key].filter((e: Record<string, any>) => e.type !== type)
          if (userObj[key].length < 1) delete userObj[key]
        } else { // modify/create multivalue
          if (!userObj[key]) userObj[key] = []
          if (attrObj[key][el].primary) { // remove any existing primary attribute, should only have one primary set
            const primVal = attrObj[key][el].primary
            if (primVal === true || (typeof primVal === 'string' && primVal.toLowerCase() === 'true')) {
              const index = userObj[key].findIndex((e: Record<string, any>) => e.primary === primVal)
              if (index >= 0) {
                userObj[key][index].primary = undefined
              }
            }
          }
          const found = userObj[key].find((e: Record<string, any>, i: any) => {
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
      // None multi value attribute, blank will be deleted
      if (typeof (attrObj[key]) === 'object' && attrObj[key] !== null) {
        // name.familyName=Bianchi
        if (!userObj[key]) userObj[key] = {} // e.g name object does not exist
        for (const sub in attrObj[key]) { // attributes to be cleard located in meta.attributes eg: {"meta":{"attributes":["name.familyName","profileUrl","title"]}
          if (!userObj[key]) userObj[key] = {}
          if (Object.prototype.hasOwnProperty.call(attrObj[key][sub], 'value')
            && attrObj[key][sub].value === '') delete userObj[key][sub] // object having blank value attribute e.g. {"manager": {"value": "",...}}
          else if (attrObj[key][sub] === '') delete userObj[key][sub]
          else {
            if (!userObj[key]) userObj[key] = {} // may have been deleted by length check below
            userObj[key][sub] = attrObj[key][sub]
          }
          if (Object.keys(userObj[key]).length < 1) delete userObj[key]
        }
      } else {
        if (attrObj[key] === '') delete userObj[key]
        else userObj[key] = attrObj[key]
      }
    }
  }
  await users.update(userObj) // needed for persistence
  return null
}

// =================================================
// getGroups
// =================================================
scimgateway.getGroups = async (baseEntity, getObj, attributes) => {
  const action = 'getGroups'
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes}`)

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
  scimgateway.logDebug(baseEntity, `handling ${action} groupObj=${JSON.stringify(groupObj)}`)

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
scimgateway.deleteGroup = async (baseEntity, id) => {
  const action = 'deleteGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id}`)

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
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} attrObj=${JSON.stringify(attrObj)}`)

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
