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
  const action = 'exploreUsers'
  scimgateway.logger.debug(`${pluginName} handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`)
  const ret = { // itemsPerPage will be set by scimgateway
    Resources: [],
    totalResults: null
  }

  hdbClient.connect(function (err) {
    if (err) {
      const newErr = new Error('Explore-Users hdbcClient.connect: SAP Hana client connect error: ' + err.message)
      throw newErr
    }
    // Find all SAML_ENABLED users
    const sqlQuery = "select USER_NAME from SYS.USERS where IS_SAML_ENABLED like 'TRUE'"
    hdbClient.exec(sqlQuery, function (err, rows) {
      hdbClient.end()
      if (err) {
        const newErr = new Error('Explore-Users hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
        throw newErr
      }
      for (const row in rows) {
        const scimUser = { // userName and id is mandatory, note: we set id=userName (because update user sends scim id and not userName)
          userName: rows[row].USER_NAME,
          id: rows[row].USER_NAME,
          externalId: rows[row].USER_NAME
        }
        ret.Resources.push(scimUser)
      }
      return ret // all explored users
    }) // exec
  }) // connect
}

// =================================================
// exploreGroups
// =================================================
scimgateway.exploreGroups = async (baseEntity, attributes, startIndex, count) => {
  const action = 'exploreGroups'
  scimgateway.logger.debug(`${pluginName} handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`)
  return null // groups not implemented
}

// =================================================
// getUser
// =================================================
scimgateway.getUser = async (baseEntity, userName, attributes) => {
  const action = 'getUser'
  scimgateway.logger.debug(`${pluginName} handling "${action}" userName=${userName} attributes=${attributes}`)

  hdbClient.connect(function (err) {
    if (err) {
      const newErr = new Error('Get-User hdbcClient.connect: SAP Hana client connect error: ' + err.message)
      throw newErr
    }

    let arrAttr = []
    if (attributes) arrAttr = attributes.split(',')

    if (attributes && arrAttr.length === 2) { // userName and id - user lookup
      const sqlQuery = "select USER_NAME from SYS.USERS where USER_NAME like '" + userName + "'"
      hdbClient.exec(sqlQuery, function (err, rows) {
        hdbClient.end()
        if (err) {
          const newErr = new Error('Get-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
          throw newErr
        }
        if (rows.length === 1) {
          const userObj = { // userName and id is mandatory
            userName: rows[0].USER_NAME,
            id: rows[0].USER_NAME,
            externalId: rows[0].USER_NAME
          }
          return userObj
        } else return null // no user found
      }) // exec
    } else { // all endpoint supported attributes (includes active)
      const sqlQuery = "select USER_NAME, USER_DEACTIVATED from SYS.USERS where USER_NAME like '" + userName + "'"
      hdbClient.exec(sqlQuery, function (err, rows) {
        hdbClient.end()
        if (err) {
          const newErr = new Error('Get-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
          throw newErr
        }
        if (rows.length === 1) {
          const userObj = { // userName and id is mandatory
            userName: rows[0].USER_NAME,
            id: rows[0].USER_NAME,
            externalId: rows[0].USER_NAME,
            active: !JSON.parse((rows[0].USER_DEACTIVATED).toLowerCase())
          }
          return userObj
        } else return null // no user found
      }) // exec
    }
  }) // connect
}

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj) => {
  const action = 'createUser'
  scimgateway.logger.debug(`${pluginName} handling "${action}" userObj=${JSON.stringify(userObj)}`)

  const notValid = scimgateway.notValidAttributes(userObj, validScimAttr)
  if (notValid) {
    const err = new Error('unsupported scim attributes: ' + notValid +
      ' (supporting only these attributes: ' + validScimAttr.toString() + ')'
    )
    throw err
  }

  hdbClient.connect(function (err) {
    if (err) {
      const newErr = new Error('Create-User hdbcClient.connect: SAP Hana client connect error: ' + err.message)
      throw newErr
    }
    // SAPHana create user do not need any additional provisioning attributes to be included
    // let sqlQuery = 'CREATE USER ' + userObj.userName + ' WITH IDENTITY ANY FOR SAML PROVIDER ' + endpointSamlProvider;
    // let sqlQuery = 'CREATE USER ' + userObj.userName + ' WITH IDENTITY ' + "'" + userObj.userName + "'" + ' FOR SAML PROVIDER ' + endpointSamlProvider;
    let sqlQuery = 'CREATE USER ' + userObj.userName + ' WITH IDENTITY ' + "'" + userObj.userName + "'" + ' FOR SAML PROVIDER ' + endpointSamlProvider + ' SET PARAMETER CLIENT = ' + "'103'"
    hdbClient.exec(sqlQuery, function (err, rows) {
      hdbClient.end()
      if (err) {
        const newErr = new Error('Create-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
        throw newErr
      }
      sqlQuery = 'GRANT NG_REPORTING_ROLE TO ' + userObj.userName
      hdbClient.exec(sqlQuery, function (err, rows) {
        hdbClient.end()
        if (err) {
          const newErr = new Error('Create-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
          throw newErr
        }
        return null // user created
      }) // exec
    }) // exec
  }) // connect
}

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id) => {
  const action = 'deleteUser'
  scimgateway.logger.debug(`${pluginName} handling "${action}" id=${id}`)
  hdbClient.connect(function (err) {
    if (err) {
      const newErr = new Error('Delete-User hdbcClient.connect: SAP Hana client connect error: ' + err.message)
      throw newErr
    }
    const sqlQuery = 'DROP USER ' + id
    hdbClient.exec(sqlQuery, function (err, rows) {
      hdbClient.end()
      if (err) {
        const newErr = new Error('Delete-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
        throw newErr
      }
      return null // successfully deleted
    }) // exec
  }) // connect
}

// =================================================
// modifyUser
// =================================================
scimgateway.modifyUser = async (baseEntity, id, attrObj) => {
  const action = 'modifyUser'
  scimgateway.logger.debug(`${pluginName} handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)

  const notValid = scimgateway.notValidAttributes(attrObj, validScimAttr)
  if (notValid) {
    const err = new Error('unsupported scim attributes: ' + notValid +
      ' (supporting only these attributes: ' + validScimAttr.toString() + ')'
    )
    throw err
  }

  let sqlAction = ''
  if (attrObj.active !== undefined) {
    if (sqlAction.length === 0) sqlAction = (attrObj.active === true) ? 'ACTIVATE' : 'DEACTIVATE'
    else sqlAction += (attrObj.active === true) ? ' ACTIVATE' : ' DEACTIVATE'
  } // Add more attribute checks here according supported endpoint attributes

  hdbClient.connect(function (err) {
    if (err) {
      const newErr = new Error('Modify-User hdbcClient.connect: SAP Hana client connect error: ' + err.message)
      throw newErr
    }
    const sqlQuery = 'ALTER USER ' + id + ' ' + sqlAction
    hdbClient.exec(sqlQuery, function (err, rows) {
      hdbClient.end()
      if (err) {
        const newErr = new Error('Modify-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
        throw newErr
      }
      return null // user successfully updated
    }) // execute
  }) // connect
}

// =================================================
// getGroup
// =================================================
scimgateway.getGroup = async (baseEntity, displayName, attributes) => {
  const action = 'getGroup'
  scimgateway.logger.debug(`${pluginName} handling "${action}" displayName=${displayName} attributes=${attributes}`)
  return null // groups not implemented
}

// =================================================
// getGroupMembers
// =================================================
scimgateway.getGroupMembers = async (baseEntity, id, attributes) => {
  const action = 'getGroupMembers'
  scimgateway.logger.debug(`${pluginName} handling "${action}" user id=${id} attributes=${attributes}`)
  const arrRet = []
  return arrRet // groups not implemented
}

// =================================================
// getGroupUsers
// =================================================
scimgateway.getGroupUsers = async (baseEntity, groupName, attributes) => {
  const action = 'getGroupUsers'
  scimgateway.logger.debug(`${pluginName} handling "${action}" groupName=${groupName} attributes=${attributes}`)
  const arrRet = []
  return arrRet
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj) => {
  const action = 'createGroup'
  scimgateway.logger.debug(`${pluginName} handling "${action}" groupObj=${JSON.stringify(groupObj)}`)
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
// modifyGroupMembers
// =================================================
scimgateway.modifyGroupMembers = async (baseEntity, id, members) => {
  const action = 'modifyGroupMembers'
  scimgateway.logger.debug(`${pluginName} handling "${action}" id=${id} members=${JSON.stringify(members)}`)
  return null
}

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})
