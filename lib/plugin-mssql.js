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
// mandatory plugin initialization - end

const sqlPassword = scimgateway.getPassword('endpoint.connection.authentication.options.password', configFile)
config.connection.authentication.options.password = sqlPassword // Connection using config.connection

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
      const connection = new Connection(config.connection)

      connection.on('connect', function (err) {
        if (err) {
          const e = new Error(`exploreUsers MSSQL client connect error: ${err.message}`)
          return reject(e)
        }
        const sqlQuery = 'select UserID from [User]'
        const request = new Request(sqlQuery, function (err, rowCount, rows) {
          if (err) {
            connection.close()
            const e = new Error(`exploreUsers MSSQL client request: ${sqlQuery} Error: ${err.message}`)
            return reject(e)
          }
          for (const row in rows) {
            const id = rows[row].UserID.value
            const userName = rows[row].UserID.value
            const scimUser = { // returning userName and id
              userName: userName,
              id: id
            }
            ret.Resources.push(scimUser)
          }
          connection.close()
          resolve(ret) // all explored users
        }) // request
        connection.execSql(request)
      }) // connection
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
      const connection = new Connection(config.connection)

      connection.on('connect', function (err) {
        if (err) {
          const e = new Error(`getUser MSSQL client connect error: ${err.message}`)
          reject(e)
        }

        // all endpoint supported attributes
        const sqlQuery = `select UserID, Enabled, FirstName, MiddleName, LastName, Email, MobilePhone from [User] where UserID = '${getObj.identifier}'`
        const request = new Request(sqlQuery, function (err, rowCount, rows) {
          if (err) {
            connection.close()
            const e = new Error(`Explore-Users connect: MSSQL client request: ${sqlQuery} Error: ${err.message}`)
            return reject(e)
          }
          if (rowCount !== 1) {
            connection.close()
            resolve(null) // user not found
          }

          const userObj = {
            userName: rows[0].UserID.value,
            id: rows[0].UserID.value,
            active: rows[0].Enabled.value,
            name: {
              givenName: rows[0].FirstName.value || '',
              middleName: rows[0].MiddleName.value || '',
              familyName: rows[0].LastName.value || ''
            },
            emails: (rows[0].Email.value) ? [{
              value: rows[0].Email.value,
              type: 'work'
            }] : null,
            phoneNumbers: (rows[0].MobilePhone.value) ? [{
              value: rows[0].MobilePhone.value,
              type: 'work'
            }] : null
          }
          connection.close()

          if (!attributes) resolve(userObj) // return user having all attributtes

          // return according to attributes (can be skipped)
          const ret = {}
          const arrAttr = attributes.split(',')
          for (let i = 0; i < arrAttr.length; i++) {
            const attr = arrAttr[i].split('.') // title / name.familyName / emails.value
            if (userObj[attr[0]]) {
              if (attr.length === 1) ret[attr[0]] = userObj[attr[0]]
              else if (userObj[attr[0]][attr[1]]) { // name.familyName
                if (!ret[attr[0]]) ret[attr[0]] = {}
                ret[attr[0]][attr[1]] = userObj[attr[0]][attr[1]]
              } else if (Array.isArray(userObj[attr[0]])) { // emails.value / phoneNumbers.type
                if (!ret[attr[0]]) ret[attr[0]] = []
                const arr = userObj[attr[0]]
                for (let j = 0; j < arr.length; j++) {
                  if (arr[j][attr[1]]) {
                    const index = ret[attr[0]].findIndex(el => (el.value && arr[j].value && el.value === arr[j].value))
                    let o
                    if (index < 0) {
                      o = {}
                      if (arr[j].value) o.value = arr[j].value // new, always include value
                    } else o = ret[attr[0]][index] // existing
                    o[attr[1]] = arr[j][attr[1]]
                    if (index < 0) ret[attr[0]].push(o)
                    else ret[attr[0]][index] = o
                  }
                }
              }
            }
          }
          resolve(ret)
        })

        connection.execSql(request)
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
        const err = new Error(`unsupported scim attributes: ${notValid} ` +
      `(supporting only these attributes: ${validScimAttr.toString()})`
        )
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
        const err = new Error(`unsupported scim attributes: ${notValid} ` +
      `(supporting only these attributes: ${validScimAttr.toString()})`
        )
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
