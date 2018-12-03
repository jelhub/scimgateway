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
try {
  config = ScimGateway.prototype.processExtConfig(pluginName, config) // external config support process.env and process.file
} catch (err) {
  scimgateway.logger.error(`${pluginName} ${err.message}`)
  scimgateway.logger.error(`${pluginName} stopping...`)
  console.log()
  process.exit(1)
}
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

scimgateway.on('exploreUsers', function (baseEntity, startIndex, count, callback) {
  let action = 'exploreUsers'
  scimgateway.logger.debug(`${pluginName} handling event "${action}"`)
  let ret = { // itemsPerPage will be set by scimgateway
    'Resources': [],
    'totalResults': null
  }

  hdbClient.connect(function (err) {
    if (err) {
      let err = new Error('Explore-Users hdbcClient.connect: SAP Hana client connect error: ' + err.message)
      return callback(err)
    }
    // Find all SAML_ENABLED users
    let sqlQuery = "select USER_NAME from SYS.USERS where IS_SAML_ENABLED like 'TRUE'"
    hdbClient.exec(sqlQuery, function (err, rows) {
      hdbClient.end()
      if (err) {
        let err = new Error('Explore-Users hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
        return callback(err)
      }
      for (let row in rows) {
        let scimUser = { // userName and id is mandatory, note: we set id=userName (because update user sends scim id and not userName)
          'userName': rows[row].USER_NAME,
          'id': rows[row].USER_NAME,
          'externalId': rows[row].USER_NAME
        }
        ret.Resources.push(scimUser)
      }
      callback(null, ret) // all explored users
    }) // exec
  }) // connect
})

scimgateway.on('exploreGroups', function (baseEntity, startIndex, count, callback) {
  let action = 'exploreGroups'
  scimgateway.logger.debug(`${pluginName} handling event "${action}"`)
  callback(null, null) // groups not implemented
})

scimgateway.on('getUser', function (baseEntity, userName, attributes, callback) {
  let action = 'getUser'
  scimgateway.logger.debug(`${pluginName} handling event "${action}" userName=${userName} attributes=${attributes}`)

  hdbClient.connect(function (err) {
    if (err) {
      let err = new Error('Get-User hdbcClient.connect: SAP Hana client connect error: ' + err.message)
      return callback(err)
    }

    let arrAttr = []
    if (attributes) arrAttr = attributes.split(',')

    if (attributes && arrAttr.length == 2) { // userName and id - user lookup
      let sqlQuery = "select USER_NAME from SYS.USERS where USER_NAME like '" + userName + "'"
      hdbClient.exec(sqlQuery, function (err, rows) {
        hdbClient.end()
        if (err) {
          let err = new Error('Get-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
          return callback(err)
        }
        if (rows.length == 1) {
          let userObj = { // userName and id is mandatory
            'userName': rows[0].USER_NAME,
            'id': rows[0].USER_NAME,
            'externalId': rows[0].USER_NAME
          }
          callback(null, userObj)
        } else {
          let err = new Error('Get-User hdbcClient.exec: User not found sqlQuery = ' + sqlQuery)
          return callback(err)
        }
      }) // exec
    } else { // all endpoint supported attributes (includes active)
      let sqlQuery = "select USER_NAME, USER_DEACTIVATED from SYS.USERS where USER_NAME like '" + userName + "'"
      hdbClient.exec(sqlQuery, function (err, rows) {
        hdbClient.end()
        if (err) {
          let err = new Error('Get-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
          return callback(err)
        }
        if (rows.length == 1) {
          let userObj = { // userName and id is mandatory
            'userName': rows[0].USER_NAME,
            'id': rows[0].USER_NAME,
            'externalId': rows[0].USER_NAME,
            'active': !JSON.parse((rows[0].USER_DEACTIVATED).toLowerCase())
          }
          callback(null, userObj)
        } else {
          let err = new Error('Get-User hdbcClient.exec: User not found sqlQuery = ' + sqlQuery)
          return callback(err)
        }
      }) // exec
    }
  }) // connect
})

scimgateway.on('createUser', function (baseEntity, userObj, callback) {
  let action = 'createUser'
  scimgateway.logger.debug(`${pluginName} handling event "${action}" userObj=${JSON.stringify(userObj)}`)

  let notValid = scimgateway.notValidAttributes(userObj, validScimAttr)
  if (notValid) {
    let err = new Error('unsupported scim attributes: ' + notValid +
      ' (supporting only these attributes: ' + validScimAttr.toString() + ')'
    )
    return callback(err)
  }

  hdbClient.connect(function (err) {
    if (err) {
      let err = new Error('Create-User hdbcClient.connect: SAP Hana client connect error: ' + err.message)
      return callback(err)
    }
    // SAPHana create user do not need any additional provisioning attributes to be included
    // let sqlQuery = 'CREATE USER ' + userObj.userName + ' WITH IDENTITY ANY FOR SAML PROVIDER ' + endpointSamlProvider;
    // let sqlQuery = 'CREATE USER ' + userObj.userName + ' WITH IDENTITY ' + "'" + userObj.userName + "'" + ' FOR SAML PROVIDER ' + endpointSamlProvider;
    let sqlQuery = 'CREATE USER ' + userObj.userName + ' WITH IDENTITY ' + "'" + userObj.userName + "'" + ' FOR SAML PROVIDER ' + endpointSamlProvider + ' SET PARAMETER CLIENT = ' + "'103'"
    hdbClient.exec(sqlQuery, function (err, rows) {
      hdbClient.end()
      if (err) {
        let err = new Error('Create-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
        return callback(err)
      }
      sqlQuery = 'GRANT NG_REPORTING_ROLE TO ' + userObj.userName
      hdbClient.exec(sqlQuery, function (err, rows) {
        hdbClient.end()
        if (err) {
          let err = new Error('Create-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
          return callback(err)
        }
        callback(null) // user now created
      }) // exec
    }) // exec
  }) // connect
})

scimgateway.on('deleteUser', function (baseEntity, id, callback) {
  let action = 'deleteUser'
  scimgateway.logger.debug(`${pluginName} handling event "${action}" id=${id}`)
  hdbClient.connect(function (err) {
    if (err) {
      let err = new Error('Delete-User hdbcClient.connect: SAP Hana client connect error: ' + err.message)
      return callback(err)
    }
    let sqlQuery = 'DROP USER ' + id
    hdbClient.exec(sqlQuery, function (err, rows) {
      hdbClient.end()
      if (err) {
        let err = new Error('Delete-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
        return callback(err)
      }
      callback(null) // successfully deleted
    }) // exec
  }) // connect
})

scimgateway.on('modifyUser', function (baseEntity, id, attrObj, callback) {
  let action = 'modifyUser'
  scimgateway.logger.debug(`${pluginName} handling event "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)

  let notValid = scimgateway.notValidAttributes(attrObj, validScimAttr)
  if (notValid) {
    let err = new Error('unsupported scim attributes: ' + notValid +
      ' (supporting only these attributes: ' + validScimAttr.toString() + ')'
    )
    return callback(err)
  }

  let sqlAction = ''
  if (attrObj.active != undefined) {
    if (sqlAction.length === 0) sqlAction = (attrObj.active === true) ? 'ACTIVATE' : 'DEACTIVATE'
    else sqlAction += (attrObj.active === true) ? ' ACTIVATE' : ' DEACTIVATE'
  } // Add more attribute checks here according supported endpoint attributes

  hdbClient.connect(function (err) {
    if (err) {
      let err = new Error('Modify-User hdbcClient.connect: SAP Hana client connect error: ' + err.message)
      return callback(err)
    }
    let sqlQuery = 'ALTER USER ' + id + ' ' + sqlAction
    hdbClient.exec(sqlQuery, function (err, rows) {
      hdbClient.end()
      if (err) {
        let err = new Error('Modify-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery)
        return callback(err)
      }
      callback(null) // user successfully updated
    }) // execute
  }) // connect
})

scimgateway.on('getGroup', function (baseEntity, displayName, attributes, callback) {
  let action = 'getGroup'
  scimgateway.logger.debug(`${pluginName} handling event "${action}" group displayName=${displayName} attributes=${attributes}`)
  callback(null, null) // groups not implemented
})

scimgateway.on('getGroupMembers', function (baseEntity, id, attributes, callback) {
  let action = 'getGroupMembers'
  scimgateway.logger.debug(`${pluginName} handling event "${action}" user id=${id} attributes=${attributes}`)
  let arrRet = []
  callback(null, arrRet)  // groups not implemented
})

scimgateway.on('getGroupUsers', function (baseEntity, groupName, attributes, callback) {
  let action = 'getGroupUsers'
  scimgateway.logger.debug(`${pluginName} handling event "${action}" groupName=${groupName} attributes=${attributes}`)
  let arrRet = []
  callback(null, arrRet)
})

scimgateway.on('createGroup', function (baseEntity, groupObj, callback) {
  let action = 'createGroup'
  scimgateway.logger.debug(`${pluginName} handling event "${action}" groupObj=${JSON.stringify(groupObj)}`)
  // groupObj.displayName contains the group to be created
  // if supporting create group we need some endpoint logic here
  let err = new Error(`Create group is not supported by ${pluginName}`)
  return callback(err)
})

scimgateway.on('deleteGroup', function (baseEntity, id, callback) {
  let action = 'deleteGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}" id=${id}`)
  // if supporting delete group we need some endpoint logic here
  let err = new Error(`Delete group is not supported by ${pluginName}`)
  return callback(err)
})

scimgateway.on('modifyGroupMembers', function (baseEntity, id, members, callback) {
  let action = 'modifyGroupMembers'
  scimgateway.logger.debug(`${pluginName} handling event "${action}" id=${id} members=${JSON.stringify(members)}`)
  callback(null)
})
