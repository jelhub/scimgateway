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
// exploreUsers
// =================================================
scimgateway.exploreUsers = async (baseEntity, attributes, startIndex, count) => {
  try {
    const action = 'exploreUsers'
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`)

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
        const sqlQuery = "select USER_NAME from SYS.USERS where IS_SAML_ENABLED like 'TRUE'"
        hdbClient.exec(sqlQuery, function (err, rows) {
          hdbClient.end()
          if (err) {
            const newErr = new Error('exploreUsers hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
            return reject(newErr)
          }
          for (const row in rows) {
            const scimUser = { // returning userName and id
              userName: rows[row].USER_NAME,
              id: rows[row].USER_NAME
            }
            ret.Resources.push(scimUser)
          }
          resolve(ret) // all explored users
        }) // exec
      }) // connect
    }) // Promise
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

// =================================================
// exploreGroups
// =================================================
scimgateway.exploreGroups = async (baseEntity, attributes, startIndex, count) => {
  const action = 'exploreGroups'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`)
  return null // groups not implemented
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

  if (getObj.filter !== 'userName' && getObj.filter !== 'externalId' && getObj.filter !== 'id') {
    throw new Error(`plugin do not support handling "${action}" ${getObj.filter}`)
  }

  try {
    return await new Promise((resolve, reject) => {
      hdbClient.connect(function (err) {
        if (err) {
          const newErr = new Error('getUser hdbcClient.connect: SAP Hana client connect error: ' + err.message)
          return reject(newErr)
        }
        const sqlQuery = "select USER_NAME, USER_DEACTIVATED from SYS.USERS where USER_NAME like '" + getObj.identifier + "'"
        hdbClient.exec(sqlQuery, function (err, rows) {
          hdbClient.end()
          if (err) {
            const newErr = new Error('getUser hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
            return reject(newErr)
          }
          if (rows.length !== 1) resolve(null) // user not found
          const userObj = { // userName/externalId and id is mandatory
            userName: rows[0].USER_NAME,
            id: rows[0].USER_NAME,
            active: !JSON.parse((rows[0].USER_DEACTIVATED).toLowerCase())
          }
          resolve(userObj) // not parsing attributes in this example, just returning with userObj defined
        }) // exec
      }) // connect
    }) // Promise
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj) => {
  try {
    const action = 'createUser'
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" userObj=${JSON.stringify(userObj)}`)

    return await new Promise((resolve, reject) => {
      const notValid = scimgateway.notValidAttributes(userObj, validScimAttr)
      if (notValid) {
        const err = new Error('unsupported scim attributes: ' + notValid +
      ' (supporting only these attributes: ' + validScimAttr.toString() + ')'
        )
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
    const newErr = err
    throw newErr
  }
}

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id) => {
  try {
    const action = 'deleteUser'
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)
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
    const newErr = err
    throw newErr
  }
}

// =================================================
// modifyUser
// =================================================
scimgateway.modifyUser = async (baseEntity, id, attrObj) => {
  try {
    const action = 'modifyUser'
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)

    return await new Promise((resolve, reject) => {
      const notValid = scimgateway.notValidAttributes(attrObj, validScimAttr)
      if (notValid) {
        const err = new Error('unsupported scim attributes: ' + notValid +
      ' (supporting only these attributes: ' + validScimAttr.toString() + ')'
        )
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
    const newErr = err
    throw newErr
  }
}

// =================================================
// getGroup
// =================================================
scimgateway.getGroup = async (baseEntity, getObj, attributes) => {
  const action = 'getGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" ${getObj.filter}=${getObj.identifier} attributes=${attributes}`)
  return null // groups not implemented
}

// =================================================
// getGroupMembers
// =================================================
scimgateway.getGroupMembers = async (baseEntity, id, attributes) => {
  const action = 'getGroupMembers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" user id=${id} attributes=${attributes}`)
  const arrRet = []
  return arrRet // groups not implemented
}

// =================================================
// getGroupUsers
// =================================================
scimgateway.getGroupUsers = async (baseEntity, groupName, attributes) => {
  const action = 'getGroupUsers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" groupName=${groupName} attributes=${attributes}`)
  const arrRet = []
  return arrRet
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj) => {
  const action = 'createGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" groupObj=${JSON.stringify(groupObj)}`)
  // groupObj.displayName contains the group to be created
  // if supporting create group we need some endpoint logic here
  const err = new Error(`Create group is not supported by ${pluginName}`)
  throw err
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id) => {
  const action = 'deleteGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)
  // if supporting delete group we need some endpoint logic here
  const err = new Error(`Delete group is not supported by ${pluginName}`)
  throw err
}

// =================================================
// modifyGroup
// =================================================
scimgateway.modifyGroup = async (baseEntity, id, attrObj) => {
  const action = 'modifyGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)
  return null
}

// =================================================
// pre_post_Action
//
// enabled by endpoint configuration:
// actions.preAction/postAction.onAddGroups/onRemoveGroups
// =================================================
scimgateway.pre_post_Action = async (baseEntity, action, jobs) => {
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] pre_post_Action handling "${action}" jobs=${JSON.stringify(jobs)}`)
  if (!Array.isArray(jobs)) return
  if (action !== 'preAction' && action !== 'postAction') return

  jobs.forEach(function (job) {
    if (job.onAddGroup && job.onAddGroup.group_displayName && job.onAddGroup.user_id) {
      if (job.onAddGroup.group_displayName === 'Admins') { // just an example - must correspond with configuration onAddGroups["Admins","xxx"]
        // custom jobs on add group xxx to user goes here...
        scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} onAddGroup group_id=${job.onAddGroup.group_id} group_displayName=${job.onAddGroup.group_displayName}  user_id=${job.onAddGroup.user_id}`)
        console.log(`Some ${action} jobs to do when adding group: ${job.onAddGroup.group_displayName} to user: ${job.onAddGroup.user_id}`)
      }
    } else if (job.onRemoveGroup && job.onRemoveGroup.group_displayName && job.onRemoveGroup.user_id) {
      if (job.onRemoveGroup.group_displayName === 'Employees') { // just an example - must correspond with configuration onRemoveGroups["Employees'","yyy"]
        // custom jobs on remove group from user goes here...
        scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} onRemoveGroup group_id=${job.onRemoveGroup.group_id} group_displayName=${job.onRemoveGroup.group_displayName} user_id=${job.onRemoveGroup.user_id}`)
        console.log(`Some ${action} jobs to do when removing group: ${job.onRemoveGroup.group_displayName} from user: ${job.onRemoveGroup.user_id}`)
      }
    }
  })
  return null // or throw an error
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
