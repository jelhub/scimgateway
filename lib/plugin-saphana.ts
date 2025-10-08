// =================================================================================
// File:    plugin-saphana.js
//
// Author:  Jarle Elshaug
//
// Purpose: SAP Hana user-provisioning for saml enabled users
//
// Prereq:  SAP Hana endpoint is up and running
//
// Supported attributes:
//
// GlobalUser   Template            Scim        Endpoint
// ------------------------------------------------------
// User name    %AC%                userName    USER_NAME
// Suspended    (auto included)     active      ACTIVATE/DEACTIVATE
//
// Currently no other attributes needed for maintaining saml users
// =================================================================================

import hdb from 'hdb' // prereq: bun install hdb

// start - mandatory plugin initialization
import { ScimGateway } from 'scimgateway'
const scimgateway = new ScimGateway()
const config = scimgateway.getConfig()
scimgateway.authPassThroughAllowed = false
// end - mandatory plugin initialization

const endpointHost = config.host
const endpointPort = config.port
const endpointUsername = config.username
const endpointPassword = scimgateway.getSecret('endpoint.password')
const endpointSamlProvider = config.saml_provider
const hdbClient = hdb.createClient({
  host: endpointHost,
  port: endpointPort,
  user: endpointUsername,
  password: endpointPassword,
})

// =================================================
// getUsers
// =================================================
scimgateway.getUsers = async (baseEntity, getObj, attributes, ctx) => {
  const action = 'getUsers'
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes} passThrough=${ctx ? 'true' : 'false'}`)

  let sqlQuery

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'userName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      sqlQuery = `select USER_NAME, USER_DEACTIVATED from SYS.USERS where USER_NAME like '${getObj.value}'`
    } else if (getObj.operator === 'eq' && getObj.attribute === 'group.value') {
      // optional - only used when groups are member of users, not default behavior - correspond to getGroupUsers() in versions < 4.x.x
      throw new Error(`${action} error: not supporting groups member of user filtering: ${getObj.rawFilter}`)
    } else {
      // optional - simpel filtering
      throw new Error(`${action} error: not supporting simpel filtering: ${getObj.rawFilter}`)
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all users to be returned - correspond to exploreUsers() in versions < 4.x.x
    sqlQuery = 'select USER_NAME, USER_DEACTIVATED from SYS.USERS where IS_SAML_ENABLED like \'TRUE\''
  }
  // mandatory if-else logic - end

  if (!sqlQuery) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  try {
    return await new Promise((resolve, reject) => {
      const ret: any = { // itemsPerPage will be set by scimgateway
        Resources: [],
        totalResults: null,
      }

      hdbClient.connect(function (err: any) {
        if (err) {
          const newErr = new Error('exploreUsers hdbcClient.connect: SAP Hana client connect error: ' + err.message)
          return reject(newErr)
        }
        // Find all SAML_ENABLED users
        hdbClient.exec(sqlQuery, function (err: any, rows: any) {
          hdbClient.end()
          if (err) {
            const newErr = new Error('exploreUsers hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
            return reject(newErr)
          }
          for (const row in rows) {
            const scimUser = { // returning userName and id
              userName: rows[row].USER_NAME,
              id: rows[row].USER_NAME,
              active: !JSON.parse((rows[0].USER_DEACTIVATED).toLowerCase()),
            }
            ret.Resources.push(scimUser)
          }
          resolve(ret)
        }) // exec
      }) // connect
    }) // Promise
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj, ctx) => {
  const action = 'createUser'
  scimgateway.logDebug(baseEntity, `handling ${action} userObj=${JSON.stringify(userObj)} passThrough=${ctx ? 'true' : 'false'}`)

  try {
    return await new Promise((resolve, reject) => {
      hdbClient.connect(function (err: any) {
        if (err) {
          const newErr = new Error('createUser hdbcClient.connect: SAP Hana client connect error: ' + err.message)
          return reject(newErr)
        }
        // SAPHana create user do not need any additional provisioning attributes to be included
        // let sqlQuery = 'CREATE USER ' + userObj.userName + ' WITH IDENTITY ANY FOR SAML PROVIDER ' + endpointSamlProvider;
        // let sqlQuery = 'CREATE USER ' + userObj.userName + ' WITH IDENTITY ' + "'" + userObj.userName + "'" + ' FOR SAML PROVIDER ' + endpointSamlProvider;
        let sqlQuery = 'CREATE USER ' + userObj.userName + ' WITH IDENTITY ' + '\'' + userObj.userName + '\'' + ' FOR SAML PROVIDER ' + endpointSamlProvider + ' SET PARAMETER CLIENT = ' + '\'103\''
        hdbClient.exec(sqlQuery, function (err: any) {
          hdbClient.end()
          if (err) {
            const newErr = new Error('createUser hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
            return reject(newErr)
          }
          sqlQuery = 'GRANT NG_REPORTING_ROLE TO ' + userObj.userName
          hdbClient.exec(sqlQuery, function (err: any) {
            hdbClient.end()
            if (err) {
              const newErr = new Error('createUser hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
              return reject(newErr)
            }
            resolve(null) // user created
          }) // exec
        }) // exec
      }) // connect
    }) // Promise
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id, ctx) => {
  const action = 'deleteUser'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} passThrough=${ctx ? 'true' : 'false'}`)

  try {
    return await new Promise((resolve, reject) => {
      hdbClient.connect(function (err: any) {
        if (err) {
          const newErr = new Error('deleteUser hdbcClient.connect: SAP Hana client connect error: ' + err.message)
          return reject(newErr)
        }
        const sqlQuery = 'DROP USER ' + id
        hdbClient.exec(sqlQuery, function (err: any) {
          hdbClient.end()
          if (err) {
            const newErr = new Error('deleteUser hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
            return reject(newErr)
          }
          resolve(null) // successfully deleted
        }) // exec
      }) // connect
    }) // Promise
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// modifyUser
// =================================================
scimgateway.modifyUser = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyUser'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} attrObj=${JSON.stringify(attrObj)} passThrough=${ctx ? 'true' : 'false'}`)

  try {
    return await new Promise((resolve, reject) => {
      let sqlAction = ''
      if (attrObj.active !== undefined) {
        if (sqlAction.length === 0) sqlAction = (attrObj.active === true) ? 'ACTIVATE' : 'DEACTIVATE'
        else sqlAction += (attrObj.active === true) ? ' ACTIVATE' : ' DEACTIVATE'
      } // Add more attribute checks here according supported endpoint attributes

      hdbClient.connect(function (err: any) {
        if (err) {
          const newErr = new Error('modifyUser hdbcClient.connect: SAP Hana client connect error: ' + err.message)
          return reject(newErr)
        }
        const sqlQuery = 'ALTER USER ' + id + ' ' + sqlAction
        hdbClient.exec(sqlQuery, function (err: any) {
          hdbClient.end()
          if (err) {
            const newErr = new Error('modifyUser hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
            return reject(newErr)
          }
          resolve(null) // user successfully updated
        }) // execute
      }) // connect
    }) // Promise
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// getGroups
// =================================================
scimgateway.getGroups = async (baseEntity, getObj, attributes, ctx) => {
  const action = 'getGroups'
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes} passThrough=${ctx ? 'true' : 'false'}`)

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'displayName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
    } else if (getObj.operator === 'eq' && getObj.attribute === 'members.value') {
      // mandatory - return all groups the user 'id' (getObj.value) is member of - correspond to getGroupMembers() in versions < 4.x.x
      // Resources = [{ id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }]
    } else {
      // optional - simpel filtering
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all groups to be returned - correspond to exploreGroups() in versions < 4.x.x
  }
  // mandatory if-else logic - end

  return { Resources: [] } // groups not supported - returning empty Resources
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj, ctx) => {
  const action = 'createGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} groupObj=${JSON.stringify(groupObj)} passThrough=${ctx ? 'true' : 'false'}`)
  throw new Error(`${action} error: ${action} is not supported`)
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id, ctx) => {
  const action = 'deleteGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} passThrough=${ctx ? 'true' : 'false'}`)
  throw new Error(`${action} error: ${action} is not supported`)
}

// =================================================
// modifyGroup
// =================================================
scimgateway.modifyGroup = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} attrObj=${JSON.stringify(attrObj)} passThrough=${ctx ? 'true' : 'false'}`)
  throw new Error(`${action} error: ${action} is not supported`)
}

// =================================================
// helpers
// =================================================

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})
