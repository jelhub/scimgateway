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
let scimgateway = new ScimGateway()
let pluginName = path.basename(__filename, '.js')
let configDir = path.join(__dirname, '..', 'config')
let configFile = path.join(`${configDir}`, `${pluginName}.json`)
let config = require(configFile).endpoint
let validScimAttr = [   // array containing scim attributes supported by our plugin code. Empty array - all attrbutes are supported by endpoint
  'userName',         // userName is mandatory
  'active'            // active is mandatory
]
config = scimgateway.processExtConfig(pluginName, config) // add any external config process.env and process.file
// mandatory plugin initialization - end

let endpointHost = config.host
let endpointPort = config.port
let endpointUsername = config.username
let endpointPassword = scimgateway.getPassword('endpoint.password', configFile)
let endpointSamlProvider = config.saml_provider
let hdbClient = hdb.createClient({
  host: endpointHost,
  port: endpointPort,
  user: endpointUsername,
  password: endpointPassword
})

// =================================================
// exploreUsers
// =================================================
scimgateway.exploreUsers = async (baseEntity, attributes, startIndex, count) => {
  let action = 'exploreUsers'
  scimgateway.logger.debug(`${pluginName} handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`)
  let ret = { // itemsPerPage will be set by scimgateway
    'Resources': [],
    'totalResults': null
  }

  hdbClient.connect(function (err) {
    if (err) {
      let newErr = new Error('Explore-Users hdbcClient.connect: SAP Hana client connect error: ' + err.message)
      throw newErr
    }
    // Find all SAML_ENABLED users
    let sqlQuery = "select USER_NAME from SYS.USERS where IS_SAML_ENABLED like 'TRUE'"
    hdbClient.exec(sqlQuery, function (err, rows) {
      hdbClient.end()
      if (err) {
        let newErr = new Error('Explore-Users hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
        throw newErr
      }
      for (let row in rows) {
        let scimUser = { // userName and id is mandatory, note: we set id=userName (because update user sends scim id and not userName)
          'userName': rows[row].USER_NAME,
          'id': rows[row].USER_NAME,
          'externalId': rows[row].USER_NAME
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
  let action = 'exploreGroups'
  scimgateway.logger.debug(`${pluginName} handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`)
  return null // groups not implemented
}

// =================================================
// getUser
// =================================================
scimgateway.getUser = async (baseEntity, userName, attributes) => {
  let action = 'getUser'
  scimgateway.logger.debug(`${pluginName} handling "${action}" userName=${userName} attributes=${attributes}`)

  hdbClient.connect(function (err) {
    if (err) {
      let newErr = new Error('Get-User hdbcClient.connect: SAP Hana client connect error: ' + err.message)
      throw newErr
    }

    let arrAttr = []
    if (attributes) arrAttr = attributes.split(',')

    if (attributes && arrAttr.length === 2) { // userName and id - user lookup
      let sqlQuery = "select USER_NAME from SYS.USERS where USER_NAME like '" + userName + "'"
      hdbClient.exec(sqlQuery, function (err, rows) {
        hdbClient.end()
        if (err) {
          let newErr = new Error('Get-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
          throw newErr
        }
        if (rows.length === 1) {
          let userObj = { // userName and id is mandatory
            'userName': rows[0].USER_NAME,
            'id': rows[0].USER_NAME,
            'externalId': rows[0].USER_NAME
          }
          return userObj
        } else return null // no user found
      }) // exec
    } else { // all endpoint supported attributes (includes active)
      let sqlQuery = "select USER_NAME, USER_DEACTIVATED from SYS.USERS where USER_NAME like '" + userName + "'"
      hdbClient.exec(sqlQuery, function (err, rows) {
        hdbClient.end()
        if (err) {
          let newErr = new Error('Get-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
          throw newErr
        }
        if (rows.length === 1) {
          let userObj = { // userName and id is mandatory
            'userName': rows[0].USER_NAME,
            'id': rows[0].USER_NAME,
            'externalId': rows[0].USER_NAME,
            'active': !JSON.parse((rows[0].USER_DEACTIVATED).toLowerCase())
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
  let action = 'createUser'
  scimgateway.logger.debug(`${pluginName} handling "${action}" userObj=${JSON.stringify(userObj)}`)

  let notValid = scimgateway.notValidAttributes(userObj, validScimAttr)
  if (notValid) {
    let err = new Error('unsupported scim attributes: ' + notValid +
      ' (supporting only these attributes: ' + validScimAttr.toString() + ')'
    )
    throw err
  }

  hdbClient.connect(function (err) {
    if (err) {
      let newErr = new Error('Create-User hdbcClient.connect: SAP Hana client connect error: ' + err.message)
      throw newErr
    }
    // SAPHana create user do not need any additional provisioning attributes to be included
    // let sqlQuery = 'CREATE USER ' + userObj.userName + ' WITH IDENTITY ANY FOR SAML PROVIDER ' + endpointSamlProvider;
    // let sqlQuery = 'CREATE USER ' + userObj.userName + ' WITH IDENTITY ' + "'" + userObj.userName + "'" + ' FOR SAML PROVIDER ' + endpointSamlProvider;
    let sqlQuery = 'CREATE USER ' + userObj.userName + ' WITH IDENTITY ' + "'" + userObj.userName + "'" + ' FOR SAML PROVIDER ' + endpointSamlProvider + ' SET PARAMETER CLIENT = ' + "'103'"
    hdbClient.exec(sqlQuery, function (err, rows) {
      hdbClient.end()
      if (err) {
        let newErr = new Error('Create-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
        throw newErr
      }
      sqlQuery = 'GRANT NG_REPORTING_ROLE TO ' + userObj.userName
      hdbClient.exec(sqlQuery, function (err, rows) {
        hdbClient.end()
        if (err) {
          let newErr = new Error('Create-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
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
  let action = 'deleteUser'
  scimgateway.logger.debug(`${pluginName} handling "${action}" id=${id}`)
  hdbClient.connect(function (err) {
    if (err) {
      let newErr = new Error('Delete-User hdbcClient.connect: SAP Hana client connect error: ' + err.message)
      throw newErr
    }
    let sqlQuery = 'DROP USER ' + id
    hdbClient.exec(sqlQuery, function (err, rows) {
      hdbClient.end()
      if (err) {
        let newErr = new Error('Delete-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
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
  let action = 'modifyUser'
  scimgateway.logger.debug(`${pluginName} handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)

  let notValid = scimgateway.notValidAttributes(attrObj, validScimAttr)
  if (notValid) {
    let err = new Error('unsupported scim attributes: ' + notValid +
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
      let newErr = new Error('Modify-User hdbcClient.connect: SAP Hana client connect error: ' + err.message)
      throw newErr
    }
    let sqlQuery = 'ALTER USER ' + id + ' ' + sqlAction
    hdbClient.exec(sqlQuery, function (err, rows) {
      hdbClient.end()
      if (err) {
        let newErr = new Error('Modify-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
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
  let action = 'getGroup'
  scimgateway.logger.debug(`${pluginName} handling "${action}" displayName=${displayName} attributes=${attributes}`)
  return null // groups not implemented
}

// =================================================
// getGroupMembers
// =================================================
scimgateway.getGroupMembers = async (baseEntity, id, attributes) => {
  let action = 'getGroupMembers'
  scimgateway.logger.debug(`${pluginName} handling "${action}" user id=${id} attributes=${attributes}`)
  let arrRet = []
  return arrRet  // groups not implemented
}

// =================================================
// getGroupUsers
// =================================================
scimgateway.getGroupUsers = async (baseEntity, groupName, attributes) => {
  let action = 'getGroupUsers'
  scimgateway.logger.debug(`${pluginName} handling "${action}" groupName=${groupName} attributes=${attributes}`)
  let arrRet = []
  return arrRet
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj) => {
  let action = 'createGroup'
  scimgateway.logger.debug(`${pluginName} handling "${action}" groupObj=${JSON.stringify(groupObj)}`)
  // groupObj.displayName contains the group to be created
  // if supporting create group we need some endpoint logic here
  let err = new Error(`Create group is not supported by ${pluginName}`)
  throw err
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id) => {
  let action = 'deleteGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)
  // if supporting delete group we need some endpoint logic here
  let err = new Error(`Delete group is not supported by ${pluginName}`)
  throw err
}

// =================================================
// modifyGroupMembers
// =================================================
scimgateway.modifyGroupMembers = async (baseEntity, id, members) => {
  let action = 'modifyGroupMembers'
  scimgateway.logger.debug(`${pluginName} handling "${action}" id=${id} members=${JSON.stringify(members)}`)
  return null
}

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => {   // Ctrl+C
})
