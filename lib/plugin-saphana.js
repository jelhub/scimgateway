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

'use strict'

const hdb = require('hdb')

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
const validScimAttr = [ // array containing scim attributes supported by our plugin code. Empty array - all attrbutes are supported by endpoint
  'userName', // userName is mandatory
  'active' // active is mandatory
]
let config = require(configFile).endpoint
config = scimgateway.processExtConfig(pluginName, config) // add any external config process.env and process.file
// mandatory plugin initialization - end

const endpointHost = config.host
const endpointPort = config.port
const endpointUsername = config.username
const endpointPassword = scimgateway.getPassword('endpoint.password', configFile)
const endpointSamlProvider = config.saml_provider
const hdbClient = hdb.createClient({
  host: endpointHost,
  port: endpointPort,
  user: endpointUsername,
  password: endpointPassword
})

// =================================================
// getUsers
// =================================================
scimgateway.getUsers = async (baseEntity, getObj, attributes) => {
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
    sqlQuery = "select USER_NAME, USER_DEACTIVATED from SYS.USERS where IS_SAML_ENABLED like 'TRUE'"
  }
  // mandatory if-else logic - end

  if (!sqlQuery) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  try {
    return await new Promise((resolve, reject) => {
      const ret = { // itemsPerPage will be set by scimgateway
        Resources: [],
        totalResults: null
      }

      hdbClient.connect(function (err) {
        if (err) {
          const newErr = new Error('exploreUsers hdbcClient.connect: SAP Hana client connect error: ' + err.message)
          return reject(newErr)
        }
        // Find all SAML_ENABLED users
        hdbClient.exec(sqlQuery, function (err, rows) {
          hdbClient.end()
          if (err) {
            const newErr = new Error('exploreUsers hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
            return reject(newErr)
          }
          for (const row in rows) {
            const scimUser = { // returning userName and id
              userName: rows[row].USER_NAME,
              id: rows[row].USER_NAME,
              active: !JSON.parse((rows[0].USER_DEACTIVATED).toLowerCase())
            }
            ret.Resources.push(scimUser)
          }
          resolve(ret)
        }) // exec
      }) // connect
    }) // Promise
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj) => {
  const action = 'createUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" userObj=${JSON.stringify(userObj)}`)

  try {
    return await new Promise((resolve, reject) => {
      const notValid = scimgateway.notValidAttributes(userObj, validScimAttr)

      if (notValid) {
        const err = new Error(`unsupported scim attributes: ${notValid} (supporting only these attributes: ${validScimAttr.toString()})`)
        return reject(err)
      }

      hdbClient.connect(function (err) {
        if (err) {
          const newErr = new Error('createUser hdbcClient.connect: SAP Hana client connect error: ' + err.message)
          return reject(newErr)
        }
        // SAPHana create user do not need any additional provisioning attributes to be included
        // let sqlQuery = 'CREATE USER ' + userObj.userName + ' WITH IDENTITY ANY FOR SAML PROVIDER ' + endpointSamlProvider;
        // let sqlQuery = 'CREATE USER ' + userObj.userName + ' WITH IDENTITY ' + "'" + userObj.userName + "'" + ' FOR SAML PROVIDER ' + endpointSamlProvider;
        let sqlQuery = 'CREATE USER ' + userObj.userName + ' WITH IDENTITY ' + "'" + userObj.userName + "'" + ' FOR SAML PROVIDER ' + endpointSamlProvider + ' SET PARAMETER CLIENT = ' + "'103'"
        hdbClient.exec(sqlQuery, function (err, rows) {
          hdbClient.end()
          if (err) {
            const newErr = new Error('createUser hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
            return reject(newErr)
          }
          sqlQuery = 'GRANT NG_REPORTING_ROLE TO ' + userObj.userName
          hdbClient.exec(sqlQuery, function (err, rows) {
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
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id) => {
  const action = 'deleteUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)

  try {
    return await new Promise((resolve, reject) => {
      hdbClient.connect(function (err) {
        if (err) {
          const newErr = new Error('deleteUser hdbcClient.connect: SAP Hana client connect error: ' + err.message)
          return reject(newErr)
        }
        const sqlQuery = 'DROP USER ' + id
        hdbClient.exec(sqlQuery, function (err, rows) {
          hdbClient.end()
          if (err) {
            const newErr = new Error('deleteUser hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
            return reject(newErr)
          }
          resolve(null) // successfully deleted
        }) // exec
      }) // connect
    }) // Promise
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// modifyUser
// =================================================
scimgateway.modifyUser = async (baseEntity, id, attrObj) => {
  const action = 'modifyUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)

  try {
    return await new Promise((resolve, reject) => {
      const notValid = scimgateway.notValidAttributes(attrObj, validScimAttr)
      if (notValid) {
        const err = new Error(`unsupported scim attributes: ${notValid} (supporting only these attributes: ${validScimAttr.toString()})`)
        return reject(err)
      }

      let sqlAction = ''
      if (attrObj.active !== undefined) {
        if (sqlAction.length === 0) sqlAction = (attrObj.active === true) ? 'ACTIVATE' : 'DEACTIVATE'
        else sqlAction += (attrObj.active === true) ? ' ACTIVATE' : ' DEACTIVATE'
      } // Add more attribute checks here according supported endpoint attributes

      hdbClient.connect(function (err) {
        if (err) {
          const newErr = new Error('modifyUser hdbcClient.connect: SAP Hana client connect error: ' + err.message)
          return reject(newErr)
        }
        const sqlQuery = 'ALTER USER ' + id + ' ' + sqlAction
        hdbClient.exec(sqlQuery, function (err, rows) {
          hdbClient.end()
          if (err) {
            const newErr = new Error('modifyUser hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
            return reject(newErr)
          }
          resolve(null) // user successfully updated
        }) // execute
      }) // connect
    }) // Promise
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// getGroups
// =================================================
scimgateway.getGroups = async (baseEntity, getObj, attributes) => {
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
scimgateway.createGroup = async (baseEntity, groupObj) => {
  const action = 'createGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" groupObj=${JSON.stringify(groupObj)}`)
  throw new Error(`${action} error: ${action} is not supported`)
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id) => {
  const action = 'deleteGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)
  throw new Error(`${action} error: ${action} is not supported`)
}

// =================================================
// modifyGroup
// =================================================
scimgateway.modifyGroup = async (baseEntity, id, attrObj) => {
  const action = 'modifyGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)
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
