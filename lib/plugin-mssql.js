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
const scimgateway = new ScimGateway()
const pluginName = path.basename(__filename, '.js')
const configDir = path.join(__dirname, '..', 'config')
const configFile = path.join(`${configDir}`, `${pluginName}.json`)
const validScimAttr = [ // array containing scim attributes supported by our plugin code. Empty array - all attrbutes are supported by endpoint
  'userName', // userName is mandatory
  'active', // active is mandatory
  'password',
  'name.givenName',
  'name.middleName',
  'name.familyName',
  // "emails",         // accepts all multivalues for this key
  'emails.work', // accepts multivalues if type value equal work (lowercase)
  // "phoneNumbers",
  'phoneNumbers.work'
]
let config = require(configFile).endpoint
config = scimgateway.processExtConfig(pluginName, config) // add any external config process.env and process.file
scimgateway.authPassThroughAllowed = false // true enables auth passThrough (no scimgateway authentication). scimgateway instead includes ctx (ctx.request.header) in plugin methods. Note, requires plugin-logic for handling/passing ctx.request.header.authorization to be used in endpoint communication
// mandatory plugin initialization - end

const sqlPassword = scimgateway.getPassword('endpoint.connection.authentication.options.password', configFile)
config.connection.authentication.options.password = sqlPassword // Connection using config.connection

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

  let sqlQuery

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'userName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      sqlQuery = `select * from [User] where UserID = '${getObj.value}'`
    } else if (getObj.operator === 'eq' && getObj.attribute === 'group.value') {
      // optional - only used when groups are member of users, not default behavior - correspond to getGroupUsers() in versions < 4.x.x
      throw new Error(`${action} error: not supporting groups member of user filtering: ${getObj.rawFilter}`)
    } else {
      // optional - simpel filtering
      throw new Error(`${action} error: not supporting simpel filtering: ${getObj.rawFilter}`)
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} not error: supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all users to be returned - correspond to exploreUsers() in versions < 4.x.x
    sqlQuery = 'select * from [User]'
  }
  // mandatory if-else logic - end

  if (!sqlQuery) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  try {
    return await new Promise((resolve, reject) => {
      const ret = { // itemsPerPage will be set by scimgateway
        Resources: [],
        totalResults: null
      }
      const connection = new Connection(config.connection)

      connection.on('connect', function (err) {
        if (err) {
          const e = new Error(`exploreUsers MSSQL client connect error: ${err.message}`)
          return reject(e)
        }
        const request = new Request(sqlQuery, function (err, rowCount, rows) {
          if (err) {
            connection.close()
            const e = new Error(`exploreUsers MSSQL client request: ${sqlQuery} Error: ${err.message}`)
            return reject(e)
          }

          for (const row in rows) {
            const scimUser = {
              id: rows[row].UserID.value ? rows[row].UserID.value : undefined,
              userName: rows[row].UserID.value ? rows[row].UserID.value : undefined,
              active: rows[row].Enabled.value === 'true' || false,
              name: {
                givenName: rows[row].FirstName.value ? rows[row].FirstName.value : undefined,
                middleName: rows[row].MiddleName.value ? rows[row].MiddleName.value : undefined,
                familyName: rows[row].LastName.value ? rows[row].LastName.value : undefined
              },
              phoneNumbers: rows[row].MobilePhone.value ? [{ type: 'work', value: rows[row].MobilePhone.value }] : undefined,
              emails: rows[row].Email.value ? [{ type: 'work', value: rows[row].Email.value }] : undefined
            }
            ret.Resources.push(scimUser)
          }
          connection.close()
          resolve(ret) // all explored users
        }) // request
        connection.execSql(request)
      }) // connection
      connection.connect() // initialize the connection
    }) // Promise
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

  try {
    return await new Promise((resolve, reject) => {
      const notValid = scimgateway.notValidAttributes(userObj, validScimAttr)
      if (notValid) {
        const err = Error(`unsupported scim attributes: ${notValid} (supporting only these attributes: ${validScimAttr.toString()})`)
        return reject(err)
      }

      if (!userObj.name) userObj.name = {}
      if (!userObj.emails) userObj.emails = { work: {} }
      if (!userObj.phoneNumbers) userObj.phoneNumbers = { work: {} }

      const insert = {
        UserID: `'${userObj.userName}'`,
        Enabled: (userObj.active) ? `'${userObj.active}'` : '\'false\'',
        Password: (userObj.password) ? `'${userObj.password}'` : null,
        FirstName: (userObj.name.givenName) ? `'${userObj.name.givenName}'` : null,
        MiddleName: (userObj.name.middleName) ? `'${userObj.name.middleName}'` : null,
        LastName: (userObj.name.familyName) ? `'${userObj.name.familyName}'` : null,
        MobilePhone: (userObj.phoneNumbers.work.value) ? `'${userObj.phoneNumbers.work.value}'` : null,
        Email: (userObj.emails.work.value) ? `'${userObj.emails.work.value}'` : null
      }

      const connection = new Connection(config.connection)

      connection.on('connect', function (err) {
        if (err) {
          const e = new Error(`createUser MSSQL client connect error: ${err.message}`)
          return reject(e)
        }
        const sqlQuery = `insert into [User] (UserID, Enabled, Password, FirstName, MiddleName, LastName, Email, MobilePhone) 
                values (${insert.UserID}, ${insert.Enabled}, ${insert.Password}, ${insert.FirstName}, ${insert.MiddleName}, ${insert.LastName}, ${insert.Email}, ${insert.MobilePhone})`

        const request = new Request(sqlQuery, function (err, rowCount, rows) {
          if (err) {
            connection.close()
            const e = new Error(`createUser MSSQL client request: ${sqlQuery} error: ${err.message}`)
            return reject(e)
          }
          connection.close()
          resolve(null)
        }) // request
        connection.execSql(request)
      }) // connection
      connection.connect() // initialize the connection
    }) // Promise
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id, ctx) => {
  const action = 'deleteUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)

  try {
    return await new Promise((resolve, reject) => {
      const connection = new Connection(config.connection)

      connection.on('connect', function (err) {
        if (err) {
          const e = new Error(`deleteUser MSSQL client connect error: ${err.message}`)
          return reject(e)
        }
        const sqlQuery = `delete from [User] where UserID = '${id}'`
        const request = new Request(sqlQuery, function (err, rowCount, rows) {
          if (err) {
            connection.close()
            const e = new Error(`deleteUser MSSQL client request: ${sqlQuery} error: ${err.message}`)
            return reject(e)
          }
          connection.close()
          resolve(null)
        }) // request
        connection.execSql(request)
      }) // connection
      connection.connect() // initialize the connection
    }) // Promise
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// modifyUser
// =================================================
scimgateway.modifyUser = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)

  try {
    return await new Promise((resolve, reject) => {
      const notValid = scimgateway.notValidAttributes(attrObj, validScimAttr)
      if (notValid) {
        const err = new Error(`unsupported scim attributes: ${notValid} (supporting only these attributes: ${validScimAttr.toString()})`)
        return reject(err)
      }

      if (!attrObj.name) attrObj.name = {}
      if (!attrObj.emails) attrObj.emails = { work: {} }
      if (!attrObj.phoneNumbers) attrObj.phoneNumbers = { work: {} }

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
      const connection = new Connection(config.connection)

      connection.on('connect', function (err) {
        if (err) {
          const e = new Error(`modifyUser MSSQL client connect error: ${err.message}`)
          return reject(e)
        }
        const sqlQuery = `update [User] set ${sql} where UserID like '${id}'`
        const request = new Request(sqlQuery, function (err, rowCount, rows) {
          if (err) {
            connection.close()
            const e = new Error(`modifyUser MSSQL client request: ${sqlQuery} error: ${err.message}`)
            return reject(e)
          }
          connection.close()
          resolve(null)
        }) // request
        connection.execSql(request)
      }) // connection
      connection.connect() // initialize the connection
    }) // Promise
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
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
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" groupObj=${JSON.stringify(groupObj)}`)
  throw new Error(`${action} error: ${action} is not supported`)
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id, ctx) => {
  const action = 'deleteGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)
  throw new Error(`${action} error: ${action} is not supported`)
}

// =================================================
// modifyGroup
// =================================================
scimgateway.modifyGroup = async (baseEntity, id, attrObj, ctx) => {
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
