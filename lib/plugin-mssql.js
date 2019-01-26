// =================================================================================
// File:    plugin-mssql.js
//
// Author:  Jarle Elshaug
//
// Purpose: SQL user-provisioning
//
// Prereq:
// TABLE [dbo].[User](
//  [UserID] [varchar](50) NOT NULL,
//  [Enabled] [varchar](50) NULL,
//  [Password] [varchar](50) NULL,
//  [FirstName] [varchar](50) NULL,
//  [MiddleName] [varchar](50) NULL,
//  [LastName] [varchar](50) NULL,
//  [Email] [varchar](50) NULL,
//  [MobilePhone] [varchar](50) NULL
// )
//
// Supported attributes:
//
// GlobalUser   Template                                Scim                        Endpoint
// --------------------------------------------------------------------------------------------
// User name    %AC%                                    userName                        UserID
// Suspended    (auto included)                         active                          Enabled
// Password     %P%                                     password                        Password
// First Name   %UF%                                    name.givenName                  FirstName
// Middle Name  %UMN%                                   name.middleName                 MiddleName
// Last Name    %UL%                                    name.familyName                 LastName
// Email        %UE% (Emails, type=Work)                emails.work                     emailAddress
// Phone        %UP% (Phone Numbers, type=Work)         phoneNumbers.work               phoneNumber
//
// =================================================================================

'use strict'

const Connection = require('tedious').Connection
const Request = require('tedious').Request

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
  'active',           // active is mandatory
  'password',
  'name.givenName',
  'name.middleName',
  'name.familyName',
  // "emails",         // accepts all multivalues for this key
  'emails.work',      // accepts multivalues if type value equal work (lowercase)
  // "phoneNumbers",
  'phoneNumbers.work'
]
config = scimgateway.processExtConfig(pluginName, config) // add any external config process.env and process.file
// mandatory plugin initialization - end

let sqlPassword = scimgateway.getPassword('endpoint.connection.password', configFile)
config.connection.password = sqlPassword // Connection using config.connection

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
  let connection = new Connection(config.connection)

  connection.on('connect', function (err) {
    if (err) {
      let e = new Error(`Explore-Users connect: MSSQL client connect error: ${err.message}`)
      throw e
    }
    let sqlQuery = 'select UserID from [User]'
    let request = new Request(sqlQuery, function (err, rowCount, rows) {
      if (err) {
        connection.close()
        let e = new Error(`Explore-Users connect: MSSQL client request: ${sqlQuery} Error: ${err.message}`)
        throw e
      }
      for (let row in rows) {
        let id = rows[row].UserID.value
        let userName = rows[row].UserID.value
        let scimUser = { // userName and id is mandatory, note: we set id=userName (because update user sends scim id and not userName)
          'userName': userName,
          'id': id,
          'externalId': userName
        }
        ret.Resources.push(scimUser)
      }
      connection.close()
      return ret // all explored users
    }) // request
    connection.execSql(request)
  }) // connection
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

  let connection = new Connection(config.connection)

  connection.on('connect', function (err) {
    if (err) {
      let e = new Error(`Explore-Users connect: MSSQL client connect error: ${err.message}`)
      throw e
    }

    let arrAttr = []
    if (attributes) arrAttr = attributes.split(',')

    if (attributes && arrAttr.length === 2) { // userName and id - user lookup
      let sqlQuery = `select UserID from [User] where UserID = '${userName}'`
      let request = new Request(sqlQuery, function (err, rowCount, rows) {
        if (err) {
          connection.close()
          let e = new Error(`Explore-Users connect: MSSQL client request: ${sqlQuery} Error: ${err.message}`)
          throw e
        }
        if (rowCount === 1) {
          let userObj = { // userName and id is mandatory, note: we set id=userName (because update user sends scim id and not userName)
            'userName': rows[0].UserID.value,
            'id': rows[0].UserID.value,
            'externalId': rows[0].UserID.value
          }
          connection.close()
          return userObj
        } else {
          connection.close()
          return null // no user found
        }
      }) // request
      connection.execSql(request)
    } else { // all endpoint supported attributes
      let sqlQuery = `select UserID, Enabled, FirstName, MiddleName, LastName, Email, MobilePhone from [User] where UserID = '${userName}'`
      let request = new Request(sqlQuery, function (err, rowCount, rows) {
        if (err) {
          connection.close()
          let e = new Error(`Explore-Users connect: MSSQL client request: ${sqlQuery} Error: ${err.message}`)
          throw e
        }
        if (rowCount === 1) {
          let userObj = {
            'userName': rows[0].UserID.value,
            'id': rows[0].UserID.value,
            'externalId': rows[0].UserID.value,
            'active': rows[0].Enabled.value,
            'name': {
              'givenName': rows[0].FirstName.value || '',
              'middleName': rows[0].MiddleName.value || '',
              'familyName': rows[0].LastName.value || ''
            },
            'emails': (rows[0].Email.value) ? [{
              'value': rows[0].Email.value,
              'type': 'work'
            }] : null,
            'phoneNumbers': (rows[0].MobilePhone.value) ? [{
              'value': rows[0].MobilePhone.value,
              'type': 'work'
            }] : null
          }
          connection.close()
          return userObj
        } else {
          connection.close()
          return null // no user found
        }
      }) // request
      connection.execSql(request)
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
    let err = new Error(`unsupported scim attributes: ${notValid} ` +
      `(supporting only these attributes: ${validScimAttr.toString()})`
    )
    throw err
  }

  if (!userObj.name) userObj.name = {}
  if (!userObj.emails) userObj.emails = { 'work': {} }
  if (!userObj.phoneNumbers) userObj.phoneNumbers = { 'work': {} }

  let insert = {
    'UserID': `'${userObj.userName}'`,
    'Enabled': (userObj.active) ? `'${userObj.active}'` : `'false'`,
    'Password': (userObj.password) ? `'${userObj.password}'` : null,
    'FirstName': (userObj.name.givenName) ? `'${userObj.name.givenName}'` : null,
    'MiddleName': (userObj.name.middleName) ? `'${userObj.name.middleName}'` : null,
    'LastName': (userObj.name.familyName) ? `'${userObj.name.familyName}'` : null,
    'MobilePhone': (userObj.phoneNumbers.work.value) ? `'${userObj.phoneNumbers.work.value}'` : null,
    'Email': (userObj.emails.work.value) ? `'${userObj.emails.work.value}'` : null
  }

  let connection = new Connection(config.connection)

  connection.on('connect', function (err) {
    if (err) {
      let e = new Error(`Create-Users connect: MSSQL client connect error: ${err.message}`)
      throw e
    }
    let sqlQuery = `insert into [User] (UserID, Enabled, Password, FirstName, MiddleName, LastName, Email, MobilePhone) 
                values (${insert.UserID}, ${insert.Enabled}, ${insert.Password}, ${insert.FirstName}, ${insert.MiddleName}, ${insert.LastName}, ${insert.Email}, ${insert.MobilePhone})`

    let request = new Request(sqlQuery, function (err, rowCount, rows) {
      if (err) {
        connection.close()
        let e = new Error(`Create-Users: MSSQL client request: ${sqlQuery} Error: ${err.message}`)
        throw e
      }
      connection.close()
      return null
    }) // request
    connection.execSql(request)
  }) // connection
}

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id) => {
  let action = 'deleteUser'
  scimgateway.logger.debug(`${pluginName} handling "${action}" id=${id}`)

  let connection = new Connection(config.connection)

  connection.on('connect', function (err) {
    if (err) {
      let e = new Error(`Delete-User connect: MSSQL client connect error: ${err.message}`)
      throw e
    }
    let sqlQuery = `delete from [User] where UserID = '${id}'`
    let request = new Request(sqlQuery, function (err, rowCount, rows) {
      if (err) {
        connection.close()
        let e = new Error(`Delete-User: MSSQL client request: ${sqlQuery} Error: ${err.message}`)
        throw e
      }
      connection.close()
      return null
    }) // request
    connection.execSql(request)
  }) // connection
}

// =================================================
// modifyUser
// =================================================
scimgateway.modifyUser = async (baseEntity, id, attrObj) => {
  let action = 'modifyUser'
  scimgateway.logger.debug(`${pluginName} handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)

  let notValid = scimgateway.notValidAttributes(attrObj, validScimAttr)
  if (notValid) {
    let err = new Error(`unsupported scim attributes: ${notValid} ` +
      `(supporting only these attributes: ${validScimAttr.toString()})`
    )
    throw err
  }

  if (!attrObj.name) attrObj.name = {}
  if (!attrObj.emails) attrObj.emails = { 'work': {} }
  if (!attrObj.phoneNumbers) attrObj.phoneNumbers = { 'work': {} }

  let sql = ''

  if (attrObj.active !== undefined) sql += `Enabled='${attrObj.active}',`
  if (attrObj.password !== undefined) {
    if (attrObj.password === '') sql += 'Password=null,'
    else sql += `Password='${attrObj.password}',`
  }
  if (attrObj.name.givenName !== undefined) {
    if (attrObj.name.givenName === '') sql += 'FirstName=null,'
    else sql += `FirstName='${attrObj.name.givenName}',`
  }
  if (attrObj.name.middleName !== undefined) {
    if (attrObj.name.middleName === '') sql += 'MiddleName=null,'
    else sql += `MiddleName='${attrObj.name.middleName}',`
  }
  if (attrObj.name.familyName !== undefined) {
    if (attrObj.name.familyName === '') sql += 'LastName=null,'
    else sql += `LastName='${attrObj.name.familyName}',`
  }
  if (attrObj.phoneNumbers.work.value !== undefined) {
    if (attrObj.phoneNumbers.work.value === '') sql += 'MobilePhone=null,'
    else sql += `MobilePhone='${attrObj.phoneNumbers.work.value}',`
  }
  if (attrObj.emails.work.value !== undefined) {
    if (attrObj.emails.work.value === '') sql += 'Email=null,'
    else sql += `Email='${attrObj.emails.work.value}',`
  }

  sql = sql.substr(0, sql.length - 1) // remove trailing ","
  let connection = new Connection(config.connection)

  connection.on('connect', function (err) {
    if (err) {
      let e = new Error(`Modify-Users connect: MSSQL client connect error: ${err.message}`)
      throw e
    }
    let sqlQuery = `update [User] set ${sql} where UserID like '${id}'`
    let request = new Request(sqlQuery, function (err, rowCount, rows) {
      if (err) {
        connection.close()
        let e = new Error(`Modify-Users: MSSQL client request: ${sqlQuery} Error: ${err.message}`)
        throw e
      }
      connection.close()
      return null
    }) // request
    connection.execSql(request)
  }) // connection
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
