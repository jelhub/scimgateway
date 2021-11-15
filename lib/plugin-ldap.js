// =================================================================================
// File:    plugin-ldap.js
//
// Author:  Jarle Elshaug
//
// Purpose: General ldap plugin having plugin-ldap.json configured for Active Directory.
//          Using endpointMapper for attribute flexibility. Includes some special logic
//          for Active Directory specific attributes like userAccountControl, unicodePW
//          and objectGUID. objectGUID can also be used as id instead of dn
//          by replacing config.map.user.dn with config.map.user.objectGUID
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
// mandatory plugin initialization - end

const _serviceClient = {}

// =================================================
// getUsers
// =================================================
scimgateway.getUsers = async (baseEntity, getObj, attributes) => {
  //
  // "getObj" = { attribute: <>, operator: <>, value: <>, rawFilter: <>, startIndex: <>, count: <> }
  // rawFilter is always included when filtering - attribute, operator and value are included when requesting unique object or simpel filtering
  // See comments in the "start mandatory if-else logic"
  //
  // "attributes" contains a list of attributes to be returned - if blank, all supported attributes should be returned
  // Should normally return all supported user attributes having id and userName as mandatory
  // id and userName are most often considered as "the same" having value = <UserID>
  // Note, the value of returned 'id' will be used as 'id' in modifyGroup and deleteGroup
  // scimgateway will automatically filter response according to the attributes list
  //
  const action = 'getUsers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes}`)

  const result = {
    Resources: [],
    totalResults: null
  }

  if (!attributes) {
    for (const key in config.map.user) { // attributes = 'id,userName,attributes=profileUrl,entitlements,x509Certificates.value,preferredLanguage,addresses,displayName,timezone,name.middleName,roles,locale,title,photos,meta.location,ims,phoneNumbers,emails,meta.version,name.givenName,name.honorificSuffix,name.honorificPrefix,name.formatted,nickName,meta.created,active,externalId,meta.lastModified,name.familyName,userType,groups.value'
      if (config.map.user[key].mapTo) {
        if (attributes) attributes += `,${config.map.user[key].mapTo}`
        else attributes = config.map.user[key].mapTo
      }
    }
  }
  const [parsedAttr] = scimgateway.endpointMapper('outbound', attributes, config.map.user) // SCIM/CustomSCIM => endpoint attribute naming
  const attrs = parsedAttr.split(',')

  const method = 'search'
  const scope = 'sub'
  let base = config.entity[baseEntity].ldap.userBase
  let ldapOptions

  const [userIdAttr, err] = scimgateway.endpointMapper('outbound', 'userName', config.map.user) // e.g. 'userName' => 'sAMAccountName'
  if (err) throw err

  // start mandatory if-else logic
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'userName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      if (getObj.attribute === 'id') { // using dn or objectGUID (Active Directory) lookup instead of search
        if (config.map.user.objectGUID && config.map.user.objectGUID.mapTo === 'id') base = `<GUID=${getObj.value}>` // '<GUID=b3975b675d3a21498b4e511e1a8ccb9e>'
        else base = getObj.value
        ldapOptions = {
          attributes: attrs
        }
      } else {
        const [userIdAttr, err] = scimgateway.endpointMapper('outbound', getObj.attribute, config.map.user) // e.g. 'userName' => 'sAMAccountName'
        if (err) throw err
        ldapOptions = {
          filter: `&${getObjClassFilter(baseEntity, 'user')}(${userIdAttr}=${getObj.value})`, // &(objectClass=user)(objectClass=person)(objectClass=organizationalPerson)(objectClass=top)(sAMAccountName=bjensen)
          scope: scope,
          attributes: attrs
        }
      }
    } else if (getObj.operator === 'eq' && getObj.attribute === 'group.value') {
      // optional - only used when groups are member of users, not default behavior - correspond to getGroupUsers() in versions < 4.x.x
      throw new Error(`groups member of user filtering not supported: ${getObj.rawFilter}`)
    } else {
      // optional - simpel filtering
      throw new Error(`simpel filtering not supported: ${getObj.rawFilter}`)
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`advanced filtering not supported: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all users to be returned - correspond to exploreUsers() in versions < 4.x.x
    ldapOptions = {
      filter: `&${getObjClassFilter(baseEntity, 'user')}(${userIdAttr}=*)`,
      scope: scope,
      attributes: attrs
    }
  }
  // end mandatory if-else logic

  if (!ldapOptions) throw new Error('mandatory if-else logic not fully implemented')

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
        else if (config.map.group.objectGUID && config.map.group.objectGUID.mapTo === 'id') { // Active Directory using objectGUID - convert memberOf having dn values to objectGUID
          const arr = []
          try {
            if (Array.isArray(user.memberOf)) {
              for (let i = 0; i < user.memberOf.length; i++) {
                const guid = await dnToGuid(baseEntity, user.memberOf[i])
                if (!guid) throw new Error(`${action} dnToGuid did not return any objectGUID value for dn=${user.memberOf[i]}`)
                arr.push(guid)
              }
              user.memberOf = arr
            } else {
              const guid = await dnToGuid(baseEntity, user.memberOf)
              if (!guid) throw new Error(`dnToGuid did not return any objectGUID value for dn=${user.memberOf}`)
              user.memberOf = [guid]
            }
          } catch (err) {
            const newErr = err
            throw newErr
          }
        }
      }

      return scimgateway.endpointMapper('inbound', user, config.map.user)[0] // endpoint attribute naming => SCIM
    }))
  } catch (err) {
    const newErr = err
    throw newErr
  }

  return result
}

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj) => {
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
  if (err) throw err

  // endpoint spesific attribute handling
  if (endpointObj.sAMAccountName !== undefined) { // Active Directory
    const userAccountControl = 512 // NORMAL_ACCOUNT
    endpointObj.userAccountControl = userAccountControl ^ 0x0002 // disable user (will be enabled if password provided)
    if (endpointObj.mail) endpointObj.userPrincipalName = endpointObj.mail
    else endpointObj.userPrincipalName = endpointObj.sAMAccountName
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
    const newErr = new Error(err.message)
    if (newErr.message.includes('ENTRY_EXISTS')) newErr.name = 'uniqueness' // maps to scimType error handling
    throw newErr
  }
}

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id) => {
  const action = 'deleteUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)

  const method = 'del'
  let base
  if (config.map.user.objectGUID && config.map.user.objectGUID.mapTo === 'id') base = `<GUID=${id}>` // AD objectGUID
  else base = id // dn
  const ldapOptions = {}

  try {
    await doRequest(baseEntity, method, base, ldapOptions)
    return null
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

// =================================================
// modifyUser
// =================================================
scimgateway.modifyUser = async (baseEntity, id, attrObj) => {
  const action = 'modifyUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)

  // groups must be handled separate - using group member of user and not user member of group
  if (attrObj.groups) { // not supported by AD - will fail (not allowing updating users memberOf attribute, must update group instead of user)
    const groups = attrObj.groups
    delete attrObj.groups // make sure to be removed from attrObj

    const [groupsAttr, err] = scimgateway.endpointMapper('outbound', 'groups.value', config.map.user)
    if (err) throw err

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
    if (config.map.user.objectGUID && config.map.user.objectGUID.mapTo === 'id') base = `<GUID=${id}>` // AD objectGUID
    else base = id // dn

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
      const newErr = err
      throw newErr
    }
  }

  if (JSON.stringify(attrObj) === '{}') return null // only groups included

  // convert SCIM attributes to endpoint attributes according to config.map
  const [endpointObj, err] = scimgateway.endpointMapper('outbound', attrObj, config.map.user)
  if (err) throw err

  // endpoint spesific attribute handling
  if (endpointObj.userAccountControl !== undefined) { // SCIM "active" - Active Directory
    // can't use getUser because there is "active" logic overriding original userAccountControl that we want
    // const usr = await scimgateway.getUser(baseEntity, { filter: 'id', identifier: id }, 'active')
    const activeAttr = 'userAccountControl'
    const method = 'search'
    let base
    if (config.map.user.objectGUID && config.map.user.objectGUID.mapTo === 'id') base = `<GUID=${id}>` // AD objectGUID
    else base = id // dn
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
  if (config.map.user.objectGUID && config.map.user.objectGUID.mapTo === 'id') base = `<GUID=${id}>` // AD objectGUID
  else base = id // dn
  const ldapOptions = {
    operation: 'replace',
    modification: endpointObj
  }

  try {
    await doRequest(baseEntity, method, base, ldapOptions)
    return null
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

// =================================================
// getGroups
// =================================================
scimgateway.getGroups = async (baseEntity, getObj, attributes) => {
  //
  // "getObj" = { attribute: <>, operator: <>, value: <>, rawFilter: <>, startIndex: <>, count: <> }
  // rawFilter is always included when filtering - attribute, operator and value are included when requesting unique object or simpel filtering
  // See comments in the "mandatory if-else logic - start"
  //
  // "attributes" contains a list of attributes to be returned - if blank, all supported attributes should be returned
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

  const [parsedAttr, err] = scimgateway.endpointMapper('outbound', attributes, config.map.group) // SCIM/CustomSCIM => endpoint attribute naming
  if (err) throw err
  const attrs = parsedAttr.split(',')

  const method = 'search'
  const scope = 'sub'
  let base = config.entity[baseEntity].ldap.groupBase
  let ldapOptions

  const [groupDisplayNameAttr, err1] = scimgateway.endpointMapper('outbound', 'displayName', config.map.group) // e.g. 'displayName' => 'cn'
  if (err1) throw err1

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'displayName', 'externalId'].includes(getObj.attribute)) {
    // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      if (getObj.attribute === 'id') { // using dn or objectGUID (Active Directory) lookup instead of search
        if (config.map.group.objectGUID && config.map.group.objectGUID.mapTo === 'id') base = `<GUID=${getObj.value}>` // '<GUID=b3975b675d3a21498b4e511e1a8ccb9e>'
        else base = getObj.value
        ldapOptions = {
          attributes: attrs
        }
      } else {
        const [groupIdAttr, err] = scimgateway.endpointMapper('outbound', getObj.attribute, config.map.group)
        if (err) throw err
        ldapOptions = {
          filter: `&${getObjClassFilter(baseEntity, 'group')}(${groupIdAttr}=${getObj.value})`, // &(objectClass=group)(cn=Group1)
          scope: scope,
          attributes: attrs
        }
      }
    } else if (getObj.operator === 'eq' && getObj.attribute === 'members.value') {
      // mandatory - return all groups the user 'id' (getObj.value) is member of - correspond to getGroupMembers() in versions < 4.x.x
      // Resources = [{ id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }]
      ldapOptions = 'getMemberOfGroups'
    } else {
    // optional - simpel filtering
      // path = `/Groups?filter=${getObj.attribute} eq "${getObj.value}"${(attributes) ? '&attributes=' + attributes : ''}`
    }
  } else if (getObj.rawFilter) {
  // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`advanced filtering not supported: ${getObj.rawFilter}`)
  } else {
  // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all groups to be returned - correspond to exploreGroups() in versions < 4.x.x
    ldapOptions = {
      filter: `&${getObjClassFilter(baseEntity, 'group')}(${groupDisplayNameAttr}=*)`,
      scope: scope,
      attributes: attrs
    }
  }
  // mandatory if-else logic - end

  if (!ldapOptions) throw new Error('mandatory if-else logic not fully implemented')

  try {
    if (ldapOptions === 'getMemberOfGroups') result.Resources = await getMemberOfGroups(baseEntity, getObj.value)
    else {
      const groups = await doRequest(baseEntity, method, base, ldapOptions)
      result.Resources = await Promise.all(groups.map(async (group) => { // Promise.all because of async map
        if (config.map.user.objectGUID && config.map.user.objectGUID.mapTo === 'id') {
          if (group.member) {
            const arr = []
            if (Array.isArray(group.member)) {
              for (let i = 0; i < group.member.length; i++) {
                const guid = await dnToGuid(baseEntity, group.member[i])
                if (!guid) throw new Error(`dnToGuid did not return any objectGUID value for dn=${group.member[i]}`)
                arr.push(guid)
              }
              group.member = arr
            } else {
              const guid = await dnToGuid(baseEntity, group.member)
              if (!guid) throw new Error(`dnToGuid did not return any objectGUID value for dn=${group.member}`)
              group.member = [guid]
            }
          }
        }
        return scimgateway.endpointMapper('inbound', group, config.map.group)[0] // endpoint attribute naming => SCIM
      }))
    }

    result.totalResults = result.Resources.length
    return result
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj) => {
  const action = 'createGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" groupObj=${JSON.stringify(groupObj)}`)

  if (!config.map.group) throw new Error(`${action} error: missing configuration endpoint.map.group`)

  // convert SCIM attributes to endpoint attributes according to config.map
  const [endpointObj, err] = scimgateway.endpointMapper('outbound', groupObj, config.map.group)
  if (err) throw err

  // endpointObj.objectClass is mandatory and must must match your ldap schema
  endpointObj.objectClass = config.entity[baseEntity].ldap.groupObjectClasses // Active Directory: ["group"]

  const method = 'add'
  const base = `${config.entity[baseEntity].ldap.groupNamingAttr}=${groupObj.displayName},${config.entity[baseEntity].ldap.groupBase}`
  const ldapOptions = endpointObj

  try {
    await doRequest(baseEntity, method, base, ldapOptions)
    return null
  } catch (err) {
    const newErr = new Error(err.message)
    if (newErr.message.includes('ENTRY_EXISTS')) newErr.name = 'uniqueness' // maps to scimType error handling
    throw newErr
  }
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id) => {
  const action = 'deleteGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)

  if (!config.map.group) throw new Error(`${action} error: missing configuration endpoint.map.group`)
  const method = 'del'
  let base
  if (config.map.group.objectGUID && config.map.group.objectGUID.mapTo === 'id') base = `<GUID=${id}>` // AD objectGUID
  else base = id // dn
  const ldapOptions = {}

  try {
    await doRequest(baseEntity, method, base, ldapOptions)
    return null
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

// =================================================
// modifyGroup
// =================================================
scimgateway.modifyGroup = async (baseEntity, id, attrObj) => {
  const action = 'modifyGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)

  if (!config.map.group) throw new Error(`${action} error: missing configuration endpoint.map.group`)
  if (!attrObj.members) {
    throw new Error(`plugin handling "${action}" only supports modification of members`)
  }
  if (!Array.isArray(attrObj.members)) {
    throw new Error(`plugin handling "${action}" error: ${JSON.stringify(attrObj)} - correct syntax is { "members": [...] }`)
  }

  const [memberAttr, err1] = scimgateway.endpointMapper('outbound', 'members.value', config.map.group)
  if (err1) throw err1

  const body = { add: { }, remove: { } }
  body.add[memberAttr] = []
  body.remove[memberAttr] = []

  for (let i = 0; i < attrObj.members.length; i++) {
    const el = attrObj.members[i]
    if (config.map.user.objectGUID && config.map.user.objectGUID.mapTo === 'id') {
      const dn = await guidToDn(baseEntity, el.value)
      if (!dn) throw new Error(`dnToGuid did not return any objectGUID value for dn=${el.value}`)
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
  if (config.map.group.objectGUID && config.map.group.objectGUID.mapTo === 'id') base = `<GUID=${id}>` // AD objectGUID
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
    const newErr = err
    throw newErr
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
// dnToGuid is used for Active Directory to return objectGUID based on dn
//
const dnToGuid = async (baseEntity, dn) => {
  const method = 'search'
  const ldapOptions = {
    attributes: ['objectGUID']
  }
  try {
    const base = dn
    const objects = await doRequest(baseEntity, method, base, ldapOptions)
    if (objects.length !== 1) throw new Error(`did not find unique object having dn=${base}`)
    return objects[0].objectGUID
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

//
// guidToDn is used for Active Directory to return dn based on objectGUID
//
const guidToDn = async (baseEntity, guid) => {
  const method = 'search'
  const ldapOptions = {
    attributes: ['dn']
  }
  try {
    const base = `<GUID=${guid}>`
    const objects = await doRequest(baseEntity, method, base, ldapOptions)
    if (objects.length !== 1) throw new Error(`did not find unique object having objectGUID=${base}`)
    return objects[0].dn
  } catch (err) {
    const newErr = err
    throw newErr
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
  if (config.map.user.objectGUID && config.map.user.objectGUID.mapTo === 'id') { // need dn
    const method = 'search'
    const base = `<GUID=${id}>`
    const ldapOptions = {
      attributes: ['dn']
    }
    try {
      const users = await doRequest(baseEntity, method, base, ldapOptions)
      if (users.length !== 1) throw new Error(`${action} error: did not find unique user having objectGUID=${id}`)
      idDn = users[0].dn
    } catch (err) {
      const newErr = err
      throw newErr
    }
  }

  const attributes = 'id,displayName'
  const [parsedAttr, err] = scimgateway.endpointMapper('outbound', attributes, config.map.group) // SCIM/CustomSCIM => endpoint attribute naming
  if (err) throw err
  const [memberAttr, err1] = scimgateway.endpointMapper('outbound', 'members.value', config.map.group)
  if (err1) throw err1

  const method = 'search'
  const scope = 'sub'
  const base = config.entity[baseEntity].ldap.groupBase
  const attrs = parsedAttr.split(',')

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
    let useStrictDN = true
    if (config.map.user.objectGUID && config.map.user.objectGUID.mapTo === 'id') useStrictDN = false
    try {
      const cli = await ldap.createClient({
        url: config.entity[baseEntity].baseUrl,
        connectTimeout: 5000,
        tlsOptions: {
          rejectUnauthorized: false
        },
        strictDN: useStrictDN // false => supports objectGUID as dn
      })

      await new Promise((resolve, reject) => {
        cli.bind(config.entity[baseEntity].username, config.entity[baseEntity].passwordDecrypted, (err) => err ? reject(err) : resolve())
      })
      return cli // client OK
    } catch (err) {
      if (i + 1 < config.entity[baseEntity].baseUrls.length) { // failover logic
        scimgateway.logger.debug(`${pluginName}[${baseEntity}] baseUrl=${config.entity[baseEntity].baseUrl} connection error but will retry`)
        config.entity[baseEntity].baseUrl = config.entity[baseEntity].baseUrls[i + 1]
      } else {
        const newErr = new Error(`${action} error: ${err.message}`)
        throw newErr
      }
    }
  }
  throw new Error(`${action} error: program logic failed for some odd reasons - should not happend...`)
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
                  if (el.type === 'objectGUID') { // assume Active Directory - can't use default utf-8 when attribute value is hex
                    const hexStr = Buffer.from(el.buffers[0], 'binary').toString('hex')
                    entry.attributes[i]._vals = [hexStr]
                  }
                  return undefined
                })
              }
              results.push(entry.object)
            })

            search.on('page', (entry, cb) => {
              // if (cb) cb() // pagePause = true gives callback
            })
            search.on('error', (err) => reject(err))
            search.on('end', (_) => resolve(results))
          })
        })
        break

      case 'modify':
        result = await new Promise((resolve, reject) => {
          const dn = base
          client.modify(dn, options, (err) => {
            if (err) {
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
    scimgateway.logger.error(`${pluginName}[${baseEntity}] doRequest method=${method} base=${base} ldapOptions=${JSON.stringify(ldapOptions)} Error Response = ${err.message}`)
    const newErr = err
    if (client) {
      try { client.unbind() } catch (err) {}
    }
    throw newErr
  }

  scimgateway.logger.debug(`${pluginName}[${baseEntity}] doRequest method=${method} base=${base} ldapOptions=${JSON.stringify(ldapOptions)} Response=${JSON.stringify(result)}`)
  return result
} // doRequest

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})
