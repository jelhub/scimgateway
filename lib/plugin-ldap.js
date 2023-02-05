// =================================================================================
// File:    plugin-ldap.js
//
// Author:  Jarle Elshaug
//
// Purpose: General ldap plugin having plugin-ldap.json configured for Active Directory.
//          Using endpointMapper for attribute flexibility. Includes some special logic
//          for Active Directory attributes like userAccountControl, unicodePW
//          and objectSid/objectGUID. objectSid/objectGUID can be used in mapper configuration.
//          e.g: replacing config.map.user.dn and config.map.group.dn with
//          config.map.user.objectSid or config.map.user.objectGUID e.g:
//
//          "objectSid": {
//            "mapTo": "id",
//            "type": "string"
//           },
//           "objectGUID": {
//             "mapTo": "userName",
//             "type": "string"
//            },
//            "userPrincipalName": {
//              "mapTo": "externalId",
//              "type": "string"
//             }
//
// Additional user/group filtering for restricting scope may be configured in endpoint.entity.xxx.ldap e.g:
// {
//   ...
//   "userFilter": "(memberOf=CN=grp1,OU=Groups,DC=test,DC=com)(!(memberOf=CN=Domain Admins,CN=Users,DC=test,DC=com))",
//   "groupFilter": "(!(cn=grp2))",
//   ...
//  }
//
// Attributes according to map definition in the configuration file plugin-ldap.json:
//
// GlobalUser   Template                  Scim                                          Endpoint
// -----------------------------------------------------------------------------------------------
// User name    %AC%                      userName                                      sAMAccountName
//                                        id                                            dn
// Suspended     -                        active                                        userAccountControl
// Password     %P%                       password                                      unicodePwd
// First Name   %UF%                      name.givenName                                givenName
// Last Name    %UL%                      name.familyName                               sn
// Full Name    %UN%                      name.formatted                                name
// Job title    %UT%                      title                                         title
//                                        groups.value                                  memberOf
// Emails                                 emails.work.value                             mail
// Phones                                 phoneNumbers.home.value                       homePhone
//                                        phoneNumbers.work.value                       mobile
// Addresses                              addresses.work.postalCode                     postalCode
//                                        addresses.work.streetAddress                  streetAddress
//                                        addresses.work.locality                       l
//                                        addresses.work.region                         st
//                                        addresses.work.country                        co
// Entitlements (for general purposes)    entitlements.description.value                description
//                                        entitlements.lastLogonTimestamp.value         lastLogonTimestamp
//                                        entitlements.homeDirectory.value              homeDirectory
//                                        entitlements.homeDrive.value                  homeDrive
//                                        entitlements.telephoneNumber.value            telephoneNumber
//                                        entitlements.physicalDeliveryOfficeName.value physicalDeliveryOfficeName
// createUser override userBase           entitlements.userBase.value                   N/A
//
// Groups:
//                                        id                                            dn
//                                        displayName                                   cn
//                                        members.value                                 member
//
// =================================================================================

'use strict'

const ldap = require('ldapjs')

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
let config = require(configFile).endpoint
config = scimgateway.processExtConfig(pluginName, config) // add any external config process.env and process.file
scimgateway.authPassThroughAllowed = false // true enables auth passThrough (no scimgateway authentication). scimgateway instead includes ctx (ctx.request.header) in plugin methods. Note, requires plugin-logic for handling/passing ctx.request.header.authorization to be used in endpoint communication
// mandatory plugin initialization - end

const _serviceClient = {}

if (!config.map || !config.map.user) {
  scimgateway.logger.error(`${pluginName} map.user configuration is mandatory`)
  process.exit(1)
}

config.useSID_id = config.map.user.objectSid && config.map.user.objectSid.mapTo === 'id' // AD proprietary SID/GUID
config.useGUID_id = config.map.user.objectGUID && config.map.user.objectGUID.mapTo === 'id'
if (config.useSID_id && config.map.group) {
  if (!config.map.group.objectSid || config.map.group.objectSid.mapTo !== 'id') {
    scimgateway.logger.error(`${pluginName} missing configuration group.objectSid - user and group should be using the same attribute`)
    process.exit(1)
  }
} else if (config.useGUID_id && config.map.group) {
  if (!config.map.group.objectGUID || config.map.group.objectGUID.mapTo !== 'id') {
    scimgateway.logger.error(`${pluginName} missing configuration group.objectGUID - user and group should be using the same attribute`)
    process.exit(1)
  }
}
if (config.map.user.userPrincipalName && config.map.user.userPrincipalName.mapDomain) { // support mapping different inbound/outbound upn domain names
  if (config.map.user.userPrincipalName.mapDomain.inbound && config.map.user.userPrincipalName.mapDomain.outbound) {
    let inbound = config.map.user.userPrincipalName.mapDomain.inbound
    let outbound = config.map.user.userPrincipalName.mapDomain.outbound
    inbound = inbound.startsWith('@') ? inbound : '@' + inbound
    outbound = outbound.startsWith('@') ? outbound : '@' + outbound
    config.upnMapDomain = {
      inbound: inbound, // "test.onmicrosoft.com
      outbound: outbound // "my-company.com"
    }
  }
}

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

  const result = {
    Resources: [],
    totalResults: null
  }

  if (attributes.length < 1) {
    for (const key in config.map.user) { // attributes = 'id,userName,attributes=profileUrl,entitlements,x509Certificates.value,preferredLanguage,addresses,displayName,timezone,name.middleName,roles,locale,title,photos,meta.location,ims,phoneNumbers,emails,meta.version,name.givenName,name.honorificSuffix,name.honorificPrefix,name.formatted,nickName,meta.created,active,externalId,meta.lastModified,name.familyName,userType,groups.value'
      if (config.map.user[key].mapTo) attributes.push(config.map.user[key].mapTo)
    }
  }
  const [attrs] = scimgateway.endpointMapper('outbound', attributes, config.map.user) // SCIM/CustomSCIM => endpoint attribute naming

  const method = 'search'
  const scope = 'sub'
  let base = config.entity[baseEntity].ldap.userBase
  let ldapOptions

  const [userIdAttr, err] = scimgateway.endpointMapper('outbound', 'userName', config.map.user) // e.g. 'userName' => 'sAMAccountName'
  if (err) throw new Error(`${action} error: ${err.message}`)

  // start mandatory if-else logic
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'userName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      if (getObj.attribute === 'id') { // lookup using dn or objectSid/objectGUID (Active Directory)
        if (config.useSID_id) {
          const sid = convertStringToSid(getObj.value) // sid using formatted string instead of default hex
          if (!sid) throw new Error(`${action} error: ${getObj.attribute}=${getObj.value} - attribute having a none valid SID string`)
          base = `<SID=${sid}>`
        } else if (config.useGUID_id) {
          const guid = Buffer.from(getObj.value, 'base64').toString('hex')
          base = `<GUID=${guid}>` // '<GUID=b3975b675d3a21498b4e511e1a8ccb9e>'
        } else base = getObj.value
        ldapOptions = {
          attributes: attrs
        }
      } else {
        const [userIdAttr, err] = scimgateway.endpointMapper('outbound', getObj.attribute, config.map.user) // e.g. 'userName' => 'sAMAccountName'
        if (err) throw new Error(`${action} error: ${err.message}`)
        if (userIdAttr === 'objectSid') {
          const sid = convertStringToSid(getObj.value)
          if (!sid) throw new Error(`${action} error: ${getObj.attribute}=${getObj.value} - attribute having a none valid SID string`)
          base = `<SID=${sid}>`
          ldapOptions = {
            attributes: attrs
          }
        } else if (userIdAttr === 'objectGUID') {
          const guid = Buffer.from(getObj.value, 'base64').toString('hex')
          base = `<GUID=${guid}>`
          ldapOptions = {
            attributes: attrs
          }
        } else { // search instead of lookup
          ldapOptions = {
            filter: `&${getObjClassFilter(baseEntity, 'user')}(${userIdAttr}=${getObj.value})`, // &(objectClass=user)(objectClass=person)(objectClass=organizationalPerson)(objectClass=top)(sAMAccountName=bjensen)
            scope: scope,
            attributes: attrs
          }
          if (config.entity[baseEntity].ldap.userFilter) ldapOptions.filter += config.entity[baseEntity].ldap.userFilter
        }
      }
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
    ldapOptions = {
      filter: `&${getObjClassFilter(baseEntity, 'user')}(${userIdAttr}=*)`,
      scope: scope,
      attributes: attrs
    }
    if (config.entity[baseEntity].ldap.userFilter) ldapOptions.filter += config.entity[baseEntity].ldap.userFilter
  }
  // end mandatory if-else logic

  if (!ldapOptions) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  try {
    const users = await doRequest(baseEntity, method, base, ldapOptions) // ignoring SCIM paging startIndex/count - get all
    result.totalResults = users.length
    result.Resources = await Promise.all(users.map(async (user) => { // Promise.all because of async map
      if (user.name) delete user.name // because mapper converts to SCIM name.xxx

      // endpoint spesific attribute handling
      // "active" must be handled separate
      if (user.userAccountControl !== undefined) { // SCIM "active" - Active Directory
        const userAccountControl = user.userAccountControl// ACCOUNTDISABLE 0x0002
        if ((userAccountControl & 0x0002) === 0x0002) user.userAccountControl = false
        else user.userAccountControl = true
      }

      if (user.memberOf) {
        if (!config.map.group) user.memberOf = [] // empty any values
        else if (config.useSID_id || config.useGUID_id) { // Active Directory - convert memberOf having dn values to objectSid/objectGUID
          const arr = []
          try {
            if (Array.isArray(user.memberOf)) {
              for (let i = 0; i < user.memberOf.length; i++) {
                const id = await dnToSidGuid(baseEntity, user.memberOf[i])
                if (!id) throw new Error(`dnToGuid did not return any objectGUID value for dn=${user.memberOf[i]}`)
                arr.push(id)
              }
              user.memberOf = arr
            } else {
              const id = await dnToSidGuid(baseEntity, user.memberOf)
              if (!id) throw new Error(`dnToGuid did not return any objectGUID value for dn=${user.memberOf}`)
              user.memberOf = [id]
            }
          } catch (err) {
            throw new Error(err.message)
          }
        }
      }

      return scimgateway.endpointMapper('inbound', user, config.map.user)[0] // endpoint attribute naming => SCIM
    }))
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }

  return result
}

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj, ctx) => {
  const action = 'createUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" userObj=${JSON.stringify(userObj)}`)

  let userBase = null
  if (userObj.entitlements && userObj.entitlements.userbase) { // override default userBase (type userbase will be lowercase)
    if (userObj.entitlements.userbase.value) {
      userBase = userObj.entitlements.userbase.value // temporary and not in config.map, will not be sent to endpoint
    }
  }
  if (!userBase) userBase = config.entity[baseEntity].ldap.userBase

  // convert SCIM attributes to endpoint attributes according to config.map
  const [endpointObj, err] = scimgateway.endpointMapper('outbound', userObj, config.map.user)
  if (err) throw new Error(`${action} error: ${err.message}`)

  // endpoint spesific attribute handling
  if (endpointObj.sAMAccountName !== undefined) { // Active Directory
    const userAccountControl = 512 // NORMAL_ACCOUNT
    endpointObj.userAccountControl = userAccountControl ^ 0x0002 // disable user (will be enabled if password provided)
    if (!endpointObj.userPrincipalName) {
      if (endpointObj.mail) endpointObj.userPrincipalName = endpointObj.mail
      else endpointObj.userPrincipalName = endpointObj.sAMAccountName
    }
    userObj.userName = endpointObj.sAMAccountName // ensure user dn based on sAMAccountName
  }

  if (endpointObj.unicodePwd) { // Active Directory - SCIM "password"  - UTF16LE encoded password in quotes
    let pwd = ''
    const str = `"${endpointObj.unicodePwd}"`
    for (let i = 0; i < str.length; i++) {
      pwd += String.fromCharCode(str.charCodeAt(i) & 0xFF, (str.charCodeAt(i) >>> 8) & 0xFF)
    }
    endpointObj.unicodePwd = pwd
    const userAccountControl = 512 // NORMAL_ACCOUNT
    endpointObj.userAccountControl = userAccountControl & (~0x0002) // enable user
    endpointObj.pwdLastSet = 0 // user must change password on next logon
  }

  // endpointObj.objectClass is mandatory and must must match your ldap schema
  endpointObj.objectClass = config.entity[baseEntity].ldap.userObjectClasses // Active Directory: ["user", "person", "organizationalPerson", "top"]

  const method = 'add'
  const base = `${config.entity[baseEntity].ldap.userNamingAttr}=${userObj.userName},${userBase}`
  const ldapOptions = endpointObj

  try {
    await doRequest(baseEntity, method, base, ldapOptions)
    return null
  } catch (err) {
    const newErr = new Error(`${action} error: ${err.message}`)
    if (newErr.message.includes('ENTRY_EXISTS')) newErr.name = 'uniqueness' // maps to scimType error handling
    throw newErr
  }
}

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id, ctx) => {
  const action = 'deleteUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)

  const method = 'del'
  let base
  if (config.useSID_id) {
    const sid = convertStringToSid(id)
    if (!sid) throw new Error(`${action} error: id=${id} - attribute having a none valid SID string`)
    base = `<SID=${sid}>`
  } else if (config.useGUID_id) {
    const guid = Buffer.from(id, 'base64').toString('hex')
    base = `<GUID=${guid}>`
  } else base = id // dn
  const ldapOptions = {}

  try {
    await doRequest(baseEntity, method, base, ldapOptions)
    return null
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

  // groups must be handled separate - using group member of user and not user member of group
  if (attrObj.groups) { // not supported by AD - will fail (not allowing updating users memberOf attribute, must update group instead of user)
    const groups = attrObj.groups
    delete attrObj.groups // make sure to be removed from attrObj

    const [groupsAttr, err] = scimgateway.endpointMapper('outbound', 'groups.value', config.map.user)
    if (err) throw new Error(`${action} error: ${err.message}`)

    const body = { add: { }, remove: { } }
    body.add[groupsAttr] = []
    body.remove[groupsAttr] = []

    for (let i = 0; i < groups.length; i++) {
      const el = groups[i]
      if (el.operation && el.operation === 'delete') { // delete from users group attribute
        body.remove[groupsAttr].push(el.value)
      } else { // add to users group attribute
        body.add[groupsAttr].push(el.value)
      }
    }

    const method = 'modify'
    let base
    if (config.useSID_id) {
      const sid = convertStringToSid(id)
      if (!sid) throw new Error(`${action} error: id=${id} - attribute having a none valid SID string`)
      base = `<SID=${sid}>`
    } else if (config.useGUID_id) {
      const guid = Buffer.from(id, 'base64').toString('hex')
      base = `<GUID=${guid}>`
    } else base = id // dn

    try {
      if (body.add[groupsAttr].length > 0) {
        const ldapOptions = {
          operation: 'add',
          modification: body.add
        }
        await doRequest(baseEntity, method, base, ldapOptions)
      }
      if (body.remove[groupsAttr].length > 0) {
        const ldapOptions = {
          operation: 'delete',
          modification: body.remove
        }
        await doRequest(baseEntity, method, base, ldapOptions)
      }
    } catch (err) {
      throw new Error(`${action} error: ${err.message}`)
    }
  }

  if (JSON.stringify(attrObj) === '{}') return null // only groups included

  // convert SCIM attributes to endpoint attributes according to config.map
  const [endpointObj, err] = scimgateway.endpointMapper('outbound', attrObj, config.map.user)
  if (err) throw new Error(`${action} error: ${err.message}`)

  // endpoint spesific attribute handling
  if (endpointObj.userAccountControl !== undefined) { // SCIM "active" - Active Directory
    // can't use getUser because there is "active" logic overriding original userAccountControl that we want
    // const usr = await scimgateway.getUser(baseEntity, { filter: 'id', identifier: id }, 'active', ctx)
    const activeAttr = 'userAccountControl'
    const method = 'search'
    let base
    if (config.useSID_id) {
      const sid = convertStringToSid(id)
      if (!sid) throw new Error(`${action} error: id=${id} - attribute having a none valid SID string`)
      base = `<SID=${sid}>`
    } else if (config.useGUID_id) {
      const guid = Buffer.from(id, 'base64').toString('hex')
      base = `<GUID=${guid}>`
    } else base = id // dn
    const ldapOptions = {
      attributes: activeAttr
    }

    const users = await doRequest(baseEntity, method, base, ldapOptions)
    if (users.length === 0) throw new Error(`${action} error: ${id} not found`)
    else if (users.length > 1) throw new Error(`${action} error: ${ldapOptions.filter} returned more than one user for ${id}`)
    const usr = users[0]

    let userAccountControl
    if (usr.userAccountControl) userAccountControl = usr.userAccountControl // ACCOUNTDISABLE 0x0002
    else throw new Error(`${action} error: did not retrieve any value for attribute "${activeAttr}/active"`)
    if (attrObj.active === false) userAccountControl = userAccountControl ^ 0x0002 // disable user
    else userAccountControl = userAccountControl = userAccountControl & (~(0x0002 + 0x0010)) // enable user, also turn off any LOCKOUT 0x0010
    endpointObj.userAccountControl = userAccountControl // now converted from active (true/false) to userAccountControl
  }

  if (endpointObj.unicodePwd) { // SCIM "password" - Active Directory - UTF16LE encoded password in quotes
    let pwd = ''
    const str = `"${endpointObj.unicodePwd}"`
    for (let i = 0; i < str.length; i++) {
      pwd += String.fromCharCode(str.charCodeAt(i) & 0xFF, (str.charCodeAt(i) >>> 8) & 0xFF)
    }
    endpointObj.unicodePwd = pwd
  }

  const method = 'modify'
  let base
  if (config.useSID_id) {
    const sid = convertStringToSid(id)
    if (!sid) throw new Error(`${action} error: id=${id} - attribute having a none valid SID string`)
    base = `<SID=${sid}>`
  } else if (config.useGUID_id) {
    const guid = Buffer.from(id, 'base64').toString('hex')
    base = `<GUID=${guid}>`
  } else base = id // dn
  const ldapOptions = {
    operation: 'replace',
    modification: endpointObj
  }

  try {
    await doRequest(baseEntity, method, base, ldapOptions)
    return null
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

  const result = {
    Resources: [],
    totalResults: null
  }

  if (!config.map.group) { // not using groups
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] "${action}" stopped - missing configuration endpoint.map.group`)
    return result
  }

  if (!attributes) {
    for (const key in config.map.group) { // attributes = 'id,displayName,members.value'
      if (config.map.group[key].mapTo) {
        if (attributes) attributes += `,${config.map.group[key].mapTo}`
        else attributes = config.map.group[key].mapTo
      }
    }
  }

  const [attrs] = scimgateway.endpointMapper('outbound', attributes, config.map.group) // SCIM/CustomSCIM => endpoint attribute naming

  const method = 'search'
  const scope = 'sub'
  let base = config.entity[baseEntity].ldap.groupBase
  let ldapOptions

  const [groupDisplayNameAttr, err1] = scimgateway.endpointMapper('outbound', 'displayName', config.map.group) // e.g. 'displayName' => 'cn'
  if (err1) throw new Error(`${action} error: ${err1.message}`)

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'displayName', 'externalId'].includes(getObj.attribute)) {
    // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      if (getObj.attribute === 'id') { // lookup using dn or objectSid/objectGUID (Active Directory)
        if (config.useSID_id) {
          const sid = convertStringToSid(getObj.value) // sid using formatted string instead of default hex
          if (!sid) throw new Error(`${action} error: ${getObj.attribute}=${getObj.value} - attribute having a none valid SID string`)
          base = `<SID=${sid}>`
        } else if (config.useGUID_id) {
          const guid = Buffer.from(getObj.value, 'base64').toString('hex')
          base = `<GUID=${guid}>`
        } else base = getObj.value
        ldapOptions = {
          attributes: attrs
        }
      } else {
        const [groupIdAttr, err] = scimgateway.endpointMapper('outbound', getObj.attribute, config.map.group)
        if (err) throw new Error(`${action} error: ${err.message}`)
        if (groupIdAttr === 'objectSid') {
          const sid = convertStringToSid(getObj.value)
          if (!sid) throw new Error(`${action} error: ${getObj.attribute}=${getObj.value} - attribute having a none valid SID string`)
          base = `<SID=${sid}>`
          ldapOptions = {
            attributes: attrs
          }
        } else if (groupIdAttr === 'objectGUID') {
          const guid = Buffer.from(getObj.value, 'base64').toString('hex')
          base = `<GUID=${guid}>`
          ldapOptions = {
            attributes: attrs
          }
        } else { // search instead of lookup
          ldapOptions = {
            filter: `&${getObjClassFilter(baseEntity, 'group')}(${groupIdAttr}=${getObj.value})`, // &(objectClass=group)(cn=Group1)
            scope: scope,
            attributes: attrs
          }
          if (config.entity[baseEntity].ldap.groupFilter) ldapOptions.filter += config.entity[baseEntity].ldap.groupFilter
        }
      }
    } else if (getObj.operator === 'eq' && getObj.attribute === 'members.value') {
      // mandatory - return all groups the user 'id' (getObj.value) is member of - correspond to getGroupMembers() in versions < 4.x.x
      // Resources = [{ id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }]
      ldapOptions = 'getMemberOfGroups'
    } else {
      // optional - simpel filtering
      throw new Error(`${action} error: not supporting simpel filtering: ${getObj.rawFilter}`)
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
  // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all groups to be returned - correspond to exploreGroups() in versions < 4.x.x
    ldapOptions = {
      filter: `&${getObjClassFilter(baseEntity, 'group')}(${groupDisplayNameAttr}=*)`,
      scope: scope,
      attributes: attrs
    }
    if (config.entity[baseEntity].ldap.groupFilter) ldapOptions.filter += config.entity[baseEntity].ldap.groupFilter
  }
  // mandatory if-else logic - end

  if (!ldapOptions) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  try {
    if (ldapOptions === 'getMemberOfGroups') result.Resources = await getMemberOfGroups(baseEntity, getObj.value)
    else {
      const groups = await doRequest(baseEntity, method, base, ldapOptions)
      result.Resources = await Promise.all(groups.map(async (group) => { // Promise.all because of async map
        if (config.useSID_id || config.useGUID_id) {
          if (group.member) {
            const arr = []
            if (Array.isArray(group.member)) {
              for (let i = 0; i < group.member.length; i++) {
                const id = await dnToSidGuid(baseEntity, group.member[i])
                if (!id) throw new Error(`dnToSidGuid() did not return any ${config.useSID_id ? 'objectSid' : 'objectGUID'} value for dn=${group.member[i]}`)
                arr.push(id)
              }
              group.member = arr
            } else {
              const id = await dnToSidGuid(baseEntity, group.member)
              if (!id) throw new Error(`dnToSidGuid() did not return any ${config.useSID_id ? 'objectSid' : 'objectGUID'} value for ${group.member}`)
              group.member = [id]
            }
          }
        }
        return scimgateway.endpointMapper('inbound', group, config.map.group)[0] // endpoint attribute naming => SCIM
      }))
    }

    result.totalResults = result.Resources.length
    return result
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj, ctx) => {
  const action = 'createGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" groupObj=${JSON.stringify(groupObj)}`)

  if (!config.map.group) throw new Error(`${action} error: missing configuration endpoint.map.group`)

  // convert SCIM attributes to endpoint attributes according to config.map
  const [endpointObj, err] = scimgateway.endpointMapper('outbound', groupObj, config.map.group)
  if (err) throw new Error(`${action} error: ${err.message}`)

  // endpointObj.objectClass is mandatory and must must match your ldap schema
  endpointObj.objectClass = config.entity[baseEntity].ldap.groupObjectClasses // Active Directory: ["group"]

  const method = 'add'
  const base = `${config.entity[baseEntity].ldap.groupNamingAttr}=${groupObj.displayName},${config.entity[baseEntity].ldap.groupBase}`
  const ldapOptions = endpointObj

  try {
    await doRequest(baseEntity, method, base, ldapOptions)
    return null
  } catch (err) {
    const newErr = new Error(`${action} error: ${err.message}`)
    if (newErr.message.includes('ENTRY_EXISTS')) newErr.name = 'uniqueness' // maps to scimType error handling
    throw newErr
  }
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id, ctx) => {
  const action = 'deleteGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)

  if (!config.map.group) throw new Error(`${action} error: missing configuration endpoint.map.group`)
  const method = 'del'
  let base
  if (config.useSID_id) {
    const sid = convertStringToSid(id)
    if (!sid) throw new Error(`${action} error: id=${id} - attribute having a none valid SID string`)
    base = `<SID=${sid}>`
  } else if (config.useGUID_id) {
    const guid = Buffer.from(id, 'base64').toString('hex')
    base = `<GUID=${guid}>`
  } else base = id // dn
  const ldapOptions = {}

  try {
    await doRequest(baseEntity, method, base, ldapOptions)
    return null
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// modifyGroup
// =================================================
scimgateway.modifyGroup = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)

  if (!config.map.group) throw new Error(`${action} error: missing configuration endpoint.map.group`)
  if (!attrObj.members) {
    throw new Error(`${action} error: only supports modification of members`)
  }
  if (!Array.isArray(attrObj.members)) {
    throw new Error(`${action} error: ${JSON.stringify(attrObj)} - correct syntax is { "members": [...] }`)
  }

  const [memberAttr, err1] = scimgateway.endpointMapper('outbound', 'members.value', config.map.group)
  if (err1) throw new Error(`${action} error: ${err1.message}`)

  const body = { add: { }, remove: { } }
  body.add[memberAttr] = []
  body.remove[memberAttr] = []

  for (let i = 0; i < attrObj.members.length; i++) {
    const el = attrObj.members[i]
    if (config.useSID_id || config.useGUID_id) {
      const dn = await sidGuidToDn(baseEntity, el.value)
      if (!dn) throw new Error(`${action} error: sidGuidToDn() did not return any objectGUID value for dn=${el.value}`)
      el.value = dn
    }
    if (el.operation && el.operation === 'delete') { // delete member from group
      body.remove[memberAttr].push(el.value) // endpointMapper returns URI encoded id because some IdP's don't encode id used in GET url e.g. Symantec/Broadcom/CA
    } else { // add member to group
      body.add[memberAttr].push(el.value)
    }
  }

  const method = 'modify'
  let base
  if (config.useSID_id) base = `<SID=${id}>`
  else if (config.useGUID_id) base = `<GUID=${id}>`
  else base = id // dn

  try {
    if (body.add[memberAttr].length > 0) {
      const ldapOptions = { // using ldap lookup (dn) instead of search
        operation: 'add',
        modification: body.add
      }
      await doRequest(baseEntity, method, base, ldapOptions)
    }
    if (body.remove[memberAttr].length > 0) {
      const ldapOptions = { // using ldap lookup (dn) instead of search
        operation: 'delete',
        modification: body.remove
      }
      await doRequest(baseEntity, method, base, ldapOptions)
    }
    return null
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// helpers
// =================================================

//
// getObjClassFilter returns object classes to be included in search
//
const getObjClassFilter = (baseEntity, type) => {
  let filter = ''
  switch (type) {
    case 'user':
      for (let i = 0; i < config.entity[baseEntity].ldap.userObjectClasses.length; i++) {
        filter += `(objectClass=${config.entity[baseEntity].ldap.userObjectClasses[i]})`
      }
      break
    case 'group':
      for (let i = 0; i < config.entity[baseEntity].ldap.groupObjectClasses.length; i++) {
        filter += `(objectClass=${config.entity[baseEntity].ldap.groupObjectClasses[i]})`
      }
      break
  }
  return filter
}

//
// dnToSidGuid is used for Active Directory to return objectGUID based on dn
//
const dnToSidGuid = async (baseEntity, dn) => {
  const method = 'search'
  const ldapOptions = {}
  if (config.useSID_id) ldapOptions.attributes = ['objectSid']
  else if (config.useGUID_id) ldapOptions.attributes = ['objectGUID']
  else throw new Error('dnToSidGuid() invalid call, configuration not using objectSid or objectGUID')

  try {
    const base = dn
    const objects = await doRequest(baseEntity, method, base, ldapOptions)
    if (objects.length !== 1) throw new Error(`did not find unique object having dn=${base}`)
    if (config.useSID_id) return objects[0].objectSid
    else return objects[0].objectGUID
  } catch (err) {
    const newErr = new Error(`dnToSidGuid() ${err.message}`)
    throw newErr
  }
}

//
// guidToDn is used for Active Directory to return dn based on objectGUID
//
const sidGuidToDn = async (baseEntity, id) => {
  const method = 'search'
  const ldapOptions = {
    attributes: ['dn']
  }
  try {
    let base
    if (config.useSID_id) {
      const sid = convertStringToSid(id)
      if (!sid) throw new Error(`sidGuidToDn() error: id=${id} - attribute having a none valid SID string`)
      base = `<SID=${sid}>`
    } else if (config.useGUID_id) {
      const guid = Buffer.from(id, 'base64').toString('hex')
      base = `<GUID=${guid}>`
    } else throw new Error('invalid call to sidGuidToDn(), configuration not using objectSid or objectGUID')
    const objects = await doRequest(baseEntity, method, base, ldapOptions)
    if (objects.length !== 1) throw new Error(`did not find unique object having ${config.useSID_id ? 'objectSid' : 'objectGUID'} =${id}`)
    return objects[0].dn
  } catch (err) {
    const newErr = new Error(`sidGuidToDN() ${err.message}`)
    throw newErr
  }
}

//
// convertSidToString converts hex encoded object SID to a string
// e.g.
// input: 0105000000000005150000002ec85f9ed78d59fa176c9e9c7a040000
// output: S-1-5-21-2657077294-4200173015-2627628055-1146
// ref: https://gist.github.com/Krizzzn/0ae47f280cca9749c67759a9adedc015
//
const pad = function (s) { if (s.length < 2) { return `0${s}` } else { return s } }
const convertSidToString = (buf) => {
  let asc, end
  let i
  if (buf == null) { return null }
  const version = buf[0]
  const subAuthorityCount = buf[1]
  const identifierAuthority = parseInt(((() => {
    const result = []
    for (i = 2; i <= 7; i++) {
      result.push(buf[i].toString(16))
    }
    return result
  })()).join(''), 16)
  let sidString = `S-${version}-${identifierAuthority}`
  try {
    for (i = 0, end = subAuthorityCount - 1, asc = end >= 0; asc ? i <= end : i >= end; asc ? i++ : i--) {
      const subAuthOffset = i * 4
      const tmp =
      pad(buf[11 + subAuthOffset].toString(16)) +
      pad(buf[10 + subAuthOffset].toString(16)) +
      pad(buf[9 + subAuthOffset].toString(16)) +
      pad(buf[8 + subAuthOffset].toString(16))
      sidString += `-${parseInt(tmp, 16)}`
    }
  } catch (err) {
    return null
  }
  return sidString
}

//
// convertStringToSid converts SID string to hex encoded object SID
// e.g.
// input: S-1-5-21-2127521184-1604012920-1887927527-72713
// output: 010500000000000515000000a065cf7e784b9b5fe77c8770091c0100
// ref: https://devblogs.microsoft.com/oldnewthing/20040315-00/?p=40253
//
const convertStringToSid = (sidStr) => {
  const arr = sidStr.split('-')
  if (arr.length !== 8) return null
  try {
    const b0 = 0x0100000000000000n // S-1 = 01
    const b1 = 0x0005000000000000n // seven dashes, seven minus two = 5
    const b2 = BigInt(arr[2]) // 0x5n
    const b02 = b0 | b1 | b2 // big-endian
    const bufBE = Buffer.alloc(8)
    bufBE.writeBigUInt64BE(b02, 0)
    let res = bufBE.toString('hex') // 0105000000000005
    // rest is little-endian
    const bufLE = Buffer.alloc(4)
    for (let i = 3; i < arr.length; i++) {
      const val = parseInt(arr[i], 10 >>> 0) // int32 to unsigned int
      bufLE.writeUInt32LE(val.toString(), 0)
      res += bufLE.toString('hex')
    }
    return res
  } catch (err) {
    return null
  }
}

//
// getMemberOfGroups returns all groups the user is member of
// [{ id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }]
//
const getMemberOfGroups = async (baseEntity, id) => {
  const action = 'getMemberOfGroups'
  if (!config.map.group) throw new Error('missing configuration endpoint.map.group') // not using groups

  let idDn = id
  if (config.useSID_id || config.useGUID_id) { // need dn
    const method = 'search'
    let base
    if (config.useSID_id) {
      const sid = convertStringToSid(id)
      if (!sid) throw new Error(`${action} error: ${id}=${id} - attribute having a none valid SID string`)
      base = `<SID=${sid}>`
    } else {
      const guid = Buffer.from(id, 'base64').toString('hex')
      base = `<GUID=${guid}>`
    }

    const ldapOptions = {
      attributes: ['dn']
    }

    try {
      const users = await doRequest(baseEntity, method, base, ldapOptions)
      if (users.length !== 1) throw new Error(`${action} error: did not find unique user having ${config.useSID_id ? 'objectSid' : 'objectGUID'} =${id}`)
      idDn = users[0].dn
    } catch (err) {
      const newErr = err
      throw newErr
    }
  }

  const attributes = ['id', 'displayName']
  const [attrs, err] = scimgateway.endpointMapper('outbound', attributes, config.map.group) // SCIM/CustomSCIM => endpoint attribute naming
  if (err) throw err
  const [memberAttr, err1] = scimgateway.endpointMapper('outbound', 'members.value', config.map.group)
  if (err1) throw err1

  const method = 'search'
  const scope = 'sub'
  const base = config.entity[baseEntity].ldap.groupBase

  const ldapOptions = {
    filter: `&${getObjClassFilter(baseEntity, 'group')}(${memberAttr}=${idDn})`,
    scope: scope,
    attributes: attrs
  }

  try {
    const groups = await doRequest(baseEntity, method, base, ldapOptions)
    return groups.map((grp) => {
      return { // { id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }
        id: encodeURIComponent(grp[attrs[0]]), // not mandatory, but included anyhow
        displayName: grp[attrs[1]], // displayName is mandatory
        members: [{ value: encodeURIComponent(id) }] // only includes current user
      }
    })
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

//
// getServiceClient returns LDAP client used by doRequest
//
const getServiceClient = async (baseEntity) => {
  const action = 'getServiceClient'
  if (!config.entity[baseEntity].passwordDecrypted) config.entity[baseEntity].passwordDecrypted = scimgateway.getPassword(`endpoint.entity.${baseEntity}.password`, configFile)
  if (!config.entity[baseEntity].baseUrl) config.entity[baseEntity].baseUrl = config.entity[baseEntity].baseUrls[0] // failover logic also updates baseUrl

  if (!_serviceClient[baseEntity]) _serviceClient[baseEntity] = {}

  for (let i = -1; i < config.entity[baseEntity].baseUrls.length; i++) {
    try {
      const cli = await ldap.createClient({
        url: config.entity[baseEntity].baseUrl,
        connectTimeout: 5000,
        tlsOptions: {
          rejectUnauthorized: false
        },
        strictDN: false // false => allows none standard ldap base dn e.g. <SID=...> / <GUID=...>  ref. objectSid/objectGUID
      })
      await new Promise((resolve, reject) => {
        cli.bind(config.entity[baseEntity].username, config.entity[baseEntity].passwordDecrypted, (err, res) => err ? reject(err) : resolve(res))
        cli.on('error', (err) => reject(err))
      })
      return cli // client OK
    } catch (err) {
      const retry = err.message.includes('timeout') || err.message.includes('ECONNREFUSED')
      if (retry && i + 1 < config.entity[baseEntity].baseUrls.length) { // failover logic
        scimgateway.logger.debug(`${pluginName}[${baseEntity}] baseUrl=${config.entity[baseEntity].baseUrl} connection error - starting retry`)
        config.entity[baseEntity].baseUrl = config.entity[baseEntity].baseUrls[i + 1]
      } else {
        if (err.message.includes('AcceptSecurityContext')) err.message = 'LdapErr: connect failure, invalid user/password'
        throw err
      }
    }
  }
  throw new Error(`${action} logic failed for some odd reasons - should not happend...`)
}

//
// doRequest - execute LDAP request
//
// method: "search" or "modify"
// base: <baseDN>
// ldapOptions: according to ldapjs module
// e.g.: {
//         "filter": "&(objectClass=user)(sAMAccountName=*)",
//         "scope": "sub",
//         "attributes": ["sAMAccountName","displayName","mail"]
//       }
//
const doRequest = async (baseEntity, method, base, ldapOptions) => {
  let result = null
  let client = null

  const options = scimgateway.copyObj(ldapOptions)
  if (config.upnMapDomain) {
    for (const key in options) {
      if ((typeof options[key] === 'string') && options[key].includes(config.upnMapDomain.inbound)) {
        const old = options[key]
        options[key] = options[key].replace(config.upnMapDomain.inbound, config.upnMapDomain.outbound)
        scimgateway.logger.debug(`${pluginName}[${baseEntity}] inbound upnMapDomain ${old} => ${options[key]}`)
      }
    }
  }

  try {
    client = await getServiceClient(baseEntity)
    switch (method) {
      case 'search':
        options.paged = { pageSize: 200, pagePause: false } // parse entire directory calling 'page' method for each page
        result = await new Promise((resolve, reject) => {
          const results = []
          client.search(base, options, (err, search) => {
            if (err) {
              return reject(err)
            }
            search.on('searchEntry', (entry) => {
              if (entry.attributes) {
                entry.attributes.find((el, i) => {
                  if (['objectSid', 'objectGUID'].includes(el.type)) { // assume Active Directory - can't use default utf-8 when attribute value is hex
                    const b = Buffer.from(el.buffers[0], 'hex')
                    if (el.type === 'objectSid') {
                      const sidStr = convertSidToString(b) // using string: S-1-5-21-2657077294-4200173015-2627628055-1255
                      if (!sidStr) throw new Error(`doRequest() error: failed to convert SID ${b.toString('hex')} to string}`)
                      entry.attributes[i]._vals = [sidStr]
                    } else {
                      entry.attributes[i]._vals = [b.toString('base64')] // using base64: nitWLrhokUqKl1DywiavXg==
                    }
                  } else if (el.type === 'userPrincipalName' && config.upnMapDomain) {
                    const val = Buffer.from(el.buffers[0], 'hex').toString('utf8')
                    const old = val
                    entry.attributes[i]._vals = [val.replace(config.upnMapDomain.outbound, config.upnMapDomain.inbound)]
                    scimgateway.logger.debug(`${pluginName}[${baseEntity}] outbound upnMapDomain ${old} => ${entry.attributes[i]._vals}`)
                  }
                  return undefined
                })
              }
              results.push(entry.object)
            })

            search.on('page', (entry, cb) => {
              // if (cb) cb() // pagePause = true gives callback
            })
            search.on('error', (err) => {
              if (err.message.includes('LdapErr: DSID-0C0909F2') || err.message.includes('NO_OBJECT')) return resolve([]) // object not found when using base <SID=...> or <GUID=...> ref. objectSid/objectGUID
              reject(err)
            })
            search.on('end', (_) => { resolve(results) })
          })
        })
        break

      case 'modify':
        result = await new Promise((resolve, reject) => {
          const dn = base
          client.modify(dn, options, (err) => {
            if (err) {
              if (options.operation && options.operation === 'add' && options.modification && options.modification.member) {
                if (err.message.includes('ENTRY_EXISTS')) return resolve() // add already existing group to user
              }
              return reject(err)
            }
            resolve()
          })
        })
        break

      case 'add':
        result = await new Promise((resolve, reject) => {
          client.add(base, options, (err) => {
            if (err) {
              return reject(err)
            }
            resolve()
          })
        })
        break

      case 'del':
        result = await new Promise((resolve, reject) => {
          client.del(base, (err) => {
            if (err) {
              return reject(err)
            }
            resolve()
          })
        })
        break

      default:
        throw new Error('unsupported method')
    }
    client.unbind()
  } catch (err) {
    scimgateway.logger.error(`${pluginName}[${baseEntity}] doRequest method=${method} base=${base} ldapOptions=${JSON.stringify(options)} Error Response = ${err.message}`)
    if (client) {
      try { client.destroy() } catch (err) {}
    }
    throw err
  }

  scimgateway.logger.debug(`${pluginName}[${baseEntity}] doRequest method=${method} base=${base} ldapOptions=${JSON.stringify(options)} Response=${JSON.stringify(result)}`)
  return result
} // doRequest

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})
