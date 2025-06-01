// =================================================================================
// File:    plugin-mssql.js
//
// Author:  Jarle Elshaug
//
// Purpose: SQL user-provisioning
//
// Prereq:
// CREATE TABLE [Users] (
//     [UserID] VARCHAR(50) NOT NULL,
//     [Enabled] VARCHAR(50) NULL,
//     [Password] VARCHAR(50) NULL,
//     [FirstName] VARCHAR(50) NULL,
//     [MiddleName] VARCHAR(50) NULL,
//     [LastName] VARCHAR(50) NULL,
//     [Email] VARCHAR(50) NULL,
//     [MobilePhone] VARCHAR(50) NULL,
//     CONSTRAINT [PK_User]
//         PRIMARY KEY ([UserID])
// );
//
// CREATE TABLE [Groups] (
//     [GroupID] VARCHAR(50) NOT NULL,
//     [Enabled] VARCHAR(50) NULL,
//     CONSTRAINT [PK_Group]
//         PRIMARY KEY ([GroupID])
// );
//
// CREATE TABLE [Users2Group] (
//     [GroupID] VARCHAR(50) NOT NULL,
//     [UserID] VARCHAR(50) NOT NULL,
//     CONSTRAINT [PK_Users2Group]
//         PRIMARY KEY ([GroupID],[UserID]),
//     CONSTRAINT [FK_U2G_Group]
//         FOREIGN KEY ([GroupID])
//         REFERENCES [Groups]([GroupID])
//         ON DELETE CASCADE,
//     CONSTRAINT [FK_U2G_Users]
//         FOREIGN KEY ([UserID])
//         REFERENCES [Users]([UserID])
//         ON DELETE CASCADE
// );
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

import { Connection, Request } from 'tedious'
// for supporting nodejs running scimgateway package directly, using dynamic import instead of: import { ScimGateway } from 'scimgateway'
// scimgateway also inclues HelperRest: import { ScimGateway, HelperRest } from 'scimgateway'

// start - mandatory plugin initialization
const ScimGateway: typeof import('scimgateway').ScimGateway = await (async () => {
  try {
    return (await import('scimgateway')).ScimGateway
  } catch (err: any) {
    const source = './scimgateway.ts'
    return (await import(source)).ScimGateway
  }
})()
const scimgateway = new ScimGateway()
const config = scimgateway.getConfig()
scimgateway.authPassThroughAllowed = false
// end - mandatory plugin initialization

if (config?.connection?.authentication?.options?.password) {
  config.connection.authentication.options.password = scimgateway.getSecret('endpoint.connection.authentication.options.password')
}

// =================================================
// getUsers
// =================================================
scimgateway.getUsers = async (baseEntity, getObj, attributes, ctx) => {
  const action = 'getUsers'
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes}`)

  let sqlQuery

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'userName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      sqlQuery = `select * from [Users] where UserID = '${getObj.value}'`
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
    sqlQuery = 'select * from [Users]'
  }
  // mandatory if-else logic - end

  if (!sqlQuery) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  try {
    return await new Promise(async (resolve) => {
      const ret: any = { // itemsPerPage will be set by scimgateway
        Resources: [],
        totalResults: null,
      }

      const users: any[] = await query(sqlQuery, ctx).catch(err => scimgateway.logWarn(baseEntity, `${action} warning: ${err.message}`))
      for (const user of users) {
        const scimUser = {
          id: user.UserID.value ? user.UserID.value : undefined,
          userName: user.UserID.value ? user.UserID.value : undefined,
          active: user.Enabled.value === 'true' || false,
          name: {
            givenName: user.FirstName.value ? user.FirstName.value : undefined,
            middleName: user.MiddleName.value ? user.MiddleName.value : undefined,
            familyName: user.LastName.value ? user.LastName.value : undefined,
          },
          phoneNumbers: user.MobilePhone.value ? [{ type: 'work', value: user.MobilePhone.value }] : undefined,
          emails: user.Email.value ? [{ type: 'work', value: user.Email.value }] : undefined,
        }
        ret.Resources.push(scimUser)
      }

      resolve(ret) // all explored users
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
  scimgateway.logDebug(baseEntity, `handling ${action} userObj=${JSON.stringify(userObj)}`)

  try {
    return await new Promise(async (resolve) => {
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
        Email: (userObj.emails.work.value) ? `'${userObj.emails.work.value}'` : null,
      }

      const sqlQuery = `insert into [Users] (UserID, Enabled, Password, FirstName, MiddleName, LastName, Email, MobilePhone)
                values (${insert.UserID}, ${insert.Enabled}, ${insert.Password}, ${insert.FirstName}, ${insert.MiddleName}, ${insert.LastName}, ${insert.Email}, ${insert.MobilePhone})`

      await query(sqlQuery, ctx).catch(err => scimgateway.logWarn(baseEntity, `${action} warning: ${err.message}`))

      resolve(null)
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
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id}`)

  try {
    return await new Promise(async (resolve) => {
      const sqlQuery = `delete from [Users] where UserID = '${id}'`
      await query(sqlQuery, ctx).catch(err => scimgateway.logWarn(baseEntity, `${action} warning: ${err.message}`))

      resolve(null)
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
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} attrObj=${JSON.stringify(attrObj)}`)

  try {
    return await new Promise(async (resolve) => {
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

      const sqlQuery = `update [Users] set ${sql} where UserID like '${id}'`
      await query(sqlQuery, ctx).catch(err => scimgateway.logWarn(baseEntity, `${action} warning: ${err.message}`))

      resolve(null)
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
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes}`)

  let sqlQuery

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'displayName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getGroup() in versions < 4.x.x
      sqlQuery = `select * from [Groups] where GroupID = '${getObj.value}'`
    } else if (getObj.operator === 'eq' && getObj.attribute === 'members.value') {
      // mandatory - return all groups the user 'id' (getObj.value) is member of - correspond to getGroupMembers() in versions < 4.x.x
      sqlQuery = `select * from [Groups] join [Users2Group] on Groups.GroupID = Users2Group.GroupID where Users2Group.UserID = '${getObj.value}'`
    } else {
      // optional - simpel filtering
      throw new Error(`${action} error: not supporting simple filtering: ${getObj.rawFilter}`)
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} not error: supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all groups to be returned - correspond to exploreGroups() in versions < 4.x.x
    sqlQuery = 'select * from [Groups]'
  }
  // mandatory if-else logic - end
  if (!sqlQuery) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  try {
    return await new Promise(async (resolve) => {
      const ret: any = { // itemsPerPage will be set by scimgateway
        Resources: [],
        totalResults: null,
      }

      const groups: any[] = await query(sqlQuery, ctx).catch(err => scimgateway.logWarn(baseEntity, `${action} warning: ${err.message}`))

      for (const group of groups) {
        const scimGroup: Record<string, any> = {
          id: group.GroupID.value ? group.GroupID.value : undefined,
          displayName: group.GroupID.value ? group.GroupID.value : undefined,
          active: group.Enabled.value === 'true' || false,
          members: [],
        }

        const sqlQuery = `select UserID from [Users2Group] where GroupID = '${scimGroup.id}'`
        const members = await query(sqlQuery, ctx).catch(err => scimgateway.logWarn(baseEntity, `${action} warning: ${err.message}`))
        for (const member of members) {
          const scimMember = {
            value: member.UserID.value,
            display: member.UserID.value,
          }
          scimGroup.members.push(scimMember)
        }

        ret.Resources.push(scimGroup)
      }

      resolve(ret)
    }) // Promise
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj, ctx) => {
  const action = 'createGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} groupObj=${JSON.stringify(groupObj)}`)

  try {
    return await new Promise(async (resolve) => {
      const insert = {
        GroupID: `'${groupObj.displayName}'`,
        Enabled: (groupObj.active) ? `'${groupObj.active}'` : '\'false\'',
      }

      const sqlQuery = `insert into [Groups] (GroupID, Enabled) values (${insert.GroupID}, ${insert.Enabled})`
      await query(sqlQuery, ctx).catch(err => scimgateway.logWarn(baseEntity, `${action} warning: ${err.message}`))

      if (Array.isArray(groupObj.members) && groupObj.members) {
        for (const member of groupObj.members) {
          const sqlQuery = `insert into [Users2Group] (UserID, GroupID) values ('${member.value}', ${insert.GroupID})`
          await query(sqlQuery, ctx).catch(err => scimgateway.logWarn(baseEntity, `${action} warning: ${err.message}`))
        }
      }

      resolve(null)
    }) // Promise
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id, ctx) => {
  const action = 'deleteGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id}`)

  try {
    return await new Promise(async (resolve) => {
      const sqlQuery = `delete from [Groups] where GroupID = '${id}'`
      await query(sqlQuery, ctx).catch(err => scimgateway.logWarn(baseEntity, `${action} warning: ${err.message}`))

      resolve(null)
    }) // Promise
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// modifyGroup
// =================================================
scimgateway.modifyGroup = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} attrObj=${JSON.stringify(attrObj)}`)

  let sql = ''

  if (attrObj.active !== undefined) sql += `Enabled='${attrObj.active}',`
  sql = sql.substr(0, sql.length - 1) // remove trailing ","

  const queries = []
  if (sql) {
    queries.push(`update [Groups] set ${sql} where GroupID like '${id}'`)
  }

  // This BLINDLY inserts all user/groups and gracefully breaks on PK violation
  // for each existing membership
  if (Array.isArray(attrObj.members) && attrObj.members) {
    for (const member of attrObj.members) {
      if (member.operation == 'delete') {
        queries.push(`delete from [Users2Group] where GroupID='${id}' and UserID='${member.value}'`)
      } else {
        queries.push(`insert into [Users2Group] (UserID, GroupID) values ('${member.value}','${id}')`)
      }
    }
  }

  const sqlQuery = queries.join(';')

  try {
    return await new Promise(async (resolve) => {
      if (sqlQuery) {
        scimgateway.logDebug(baseEntity, `sqlQuery: ${sqlQuery}`)
        await query(sqlQuery, ctx).catch(err => scimgateway.logWarn(baseEntity, `${action} warning: ${err.message}`))
      }

      resolve(null)
    }) // Promise
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// helpers
// =================================================

//
// getCtxAuth returns username/secret from ctx header when using Auth PassThrough
//
const getCtxAuth = (ctx: undefined | Record<string, any>) => {
  if (!ctx?.request?.header?.authorization) return []
  const [authType, authToken] = (ctx.request.header.authorization || '').split(' ') // [0] = 'Basic' or 'Bearer'
  let username, password
  if (authType === 'Basic') [username, password] = (Buffer.from(authToken, 'base64').toString() || '').split(':')
  if (username) return [username, password] // basic auth
  else return [undefined, authToken] // bearer auth
}

const connectionCfg = (ctx: undefined | Record<string, any>) => {
  const connectionCfg = scimgateway.copyObj(config.connection)
  if (ctx?.request?.header?.authorization) { // Auth PassThrough (don't use configuration password)
    if (!connectionCfg.authentication) connectionCfg.authentication = {}
    if (!connectionCfg.authentication.type) connectionCfg.authentication.type = 'default'
    if (!connectionCfg.authentication.options) connectionCfg.authentication.options = {}
    const [username, password] = getCtxAuth(ctx)
    connectionCfg.authentication.options.password = password
    if (username) connectionCfg.authentication.options.userName = username
  }
  return connectionCfg
}

const query: (sql: string, ctx: any) => Promise<any> = (sql, ctx) => new Promise((resolve, reject) => {
  const connection = new Connection(connectionCfg(ctx))

  connection.connect((err) => {
    if (err) {
      const e = new Error(`MSSQL client connect error: ${err.message}`)
      reject(e)
    } else {
      const request = new Request(sql, (err, rowCount, rows) => {
        if (err) {
          connection.close()
          const e = new Error(`MSSQL client request: ${sql} Error: ${err.message}`)
          reject(e)
        } else {
          connection.close()
          resolve(rows)
        }
      })
      connection.execSql(request)
    }
  })
})

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})
