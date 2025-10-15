// =================================================================================
// File:    plugin-ldap.ts
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
// Configuration isOpenLdap true/false decides whether or not OpenLDAP Foundation protocol should
// be used for national characters and special characters in DN.
// For Active Directory, default isOpenLdap=false should be used
//
// Configuration allowModifyDN=true allows DN being changed based on modified mapping or namingAttribute
//
// Note, using Bun version < 1.2.5 and ldaps/TLS, environment must be set before started e.g.:
//   export NODE_EXTRA_CA_CERTS=/package-path/config/certs/ca.pem
//   or
//   export NODE_TLS_REJECT_UNAUTHORIZED=0
//
//   Bun version >= 1.2.5 supports configuration
//         "tls": {
//           "ca": ca-file-name, // located in confg/certs
//           "rejectUnauthorized": true
//         }
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

import ldap from 'ldapjs'
// @ts-expect-error missing type definitions
import { BerReader } from '@ldapjs/asn1'
import fs from 'node:fs'

// start - mandatory plugin initialization
import { ScimGateway } from 'scimgateway'
const scimgateway = new ScimGateway()
const config = scimgateway.getConfig()
scimgateway.authPassThroughAllowed = false
// end - mandatory plugin initialization

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
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes} passThrough=${ctx ? 'true' : 'false'}`)
  if (!config.entity[baseEntity]) throw new Error(`unsupported baseEntity: ${baseEntity}`)

  const result: any = {
    Resources: [],
    totalResults: null,
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
  let ldapOptions: Record<string, any>

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
          attributes: attrs,
        }
      } else {
        const [userIdAttr, err] = scimgateway.endpointMapper('outbound', getObj.attribute, config.map.user) // e.g. 'userName' => 'sAMAccountName'
        if (err) throw new Error(`${action} error: ${err.message}`)
        if (userIdAttr === 'objectSid') {
          const sid = convertStringToSid(getObj.value)
          if (!sid) throw new Error(`${action} error: ${getObj.attribute}=${getObj.value} - attribute having a none valid SID string`)
          base = `<SID=${sid}>`
          ldapOptions = {
            attributes: attrs,
          }
        } else if (userIdAttr === 'objectGUID') {
          const guid = Buffer.from(getObj.value, 'base64').toString('hex')
          base = `<GUID=${guid}>`
          ldapOptions = {
            attributes: attrs,
          }
        } else { // search instead of lookup
          const filter = createAndFilter(baseEntity, 'user', [{ attribute: userIdAttr, value: getObj.value }])
          ldapOptions = {
            filter,
            scope: 'sub',
            attributes: attrs,
          }
        }
      }
      ldapOptions.paged = false
    } else if (getObj.operator === 'eq' && getObj.attribute === 'group.value') {
      // optional - only used when groups are member of users, not default behavior - correspond to getGroupUsers() in versions < 4.x.x
      throw new Error(`${action} error: not supporting groups member of user filtering: ${getObj.rawFilter}`)
    } else {
      // optional - simpel filtering
      if (getObj.operator === 'eq') {
        const [filterAttr, err] = scimgateway.endpointMapper('outbound', getObj.attribute, config.map.user)
        if (err) throw new Error(`${action} error: ${err.message}`)
        const filter = createAndFilter(baseEntity, 'user', [{ attribute: filterAttr, value: getObj.value }])
        ldapOptions = {
          filter,
          scope,
          attributes: attrs,
        }
      } else {
        throw new Error(`${action} error: not supporting simpel filtering: ${getObj.rawFilter}`)
      }
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all users to be returned - correspond to exploreUsers() in versions < 4.x.x
    const filter = createAndFilter(baseEntity, 'user', [{ attribute: userIdAttr, value: '*' }])
    ldapOptions = {
      filter,
      scope,
      attributes: attrs,
    }
  }
  // end mandatory if-else logic

  if (!ldapOptions) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  try {
    const users: any = await doRequest(baseEntity, method, base, ldapOptions, ctx) // ignoring SCIM paging startIndex/count - get all
    result.totalResults = users.length
    result.Resources = await Promise.all(users.map(async (user: any) => { // Promise.all because of async map
      // endpoint spesific attribute handling
      // "active" must be handled separate
      if (user.userAccountControl !== undefined) { // SCIM "active" - Active Directory
        const userAccountControl = user.userAccountControl// ACCOUNTDISABLE 0x0002
        if ((userAccountControl & 0x0002) === 0x0002) user.userAccountControl = false
        else user.userAccountControl = true
      }

      if (user.memberOf) {
        if (!config.map.group) user.memberOf = [] // empty any values
        if (config.useSID_id || config.useGUID_id) { // Active Directory - convert memberOf having dn values to objectSid/objectGUID
          const arr: string[] = []
          try {
            if (Array.isArray(user.memberOf)) {
              for (let i = 0; i < user.memberOf.length; i++) {
                const id = await dnToSidGuid(baseEntity, user.memberOf[i], ctx)
                if (!id) throw new Error(`dnToGuid did not return any objectGUID value for dn=${user.memberOf[i]}`)
                arr.push(id)
              }
              user.memberOf = arr
            } else {
              const id = await dnToSidGuid(baseEntity, user.memberOf, ctx)
              if (!id) throw new Error(`dnToGuid did not return any objectGUID value for dn=${user.memberOf}`)
              user.memberOf = [id]
            }
          } catch (err: any) {
            throw new Error(err.message)
          }
        }
      }

      const scimObj = scimgateway.endpointMapper('inbound', user, config.map.user)[0] // endpoint attribute naming => SCIM
      // if (!scimObj.groups) scimObj.groups = []
      return scimObj
    }))
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }

  return result
}

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj, ctx) => {
  const action = 'createUser'
  scimgateway.logDebug(baseEntity, `handling ${action} userObj=${JSON.stringify(userObj)} passThrough=${ctx ? 'true' : 'false'}`)

  let userBase = null
  if (userObj.entitlements && userObj.entitlements.userbase) { // override default userBase (type userbase will be lowercase)
    if (userObj.entitlements.userbase.value) {
      userBase = userObj.entitlements.userbase.value // temporary and not in config.map, will not be sent to endpoint
    }
  }
  if (!userBase) userBase = config.entity[baseEntity].ldap.userBase

  // convert SCIM attributes to endpoint attributes according to config.map
  const [endpointObj] = scimgateway.endpointMapper('outbound', userObj, config.map.user) // use [endpointObj, err] and if err, throw error to catch non supported attributes

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

  let base = ''
  const [userNamingAttr, scimAttr] = getNamingAttribute(baseEntity, 'user') // ['CN', 'userName']
  const arr = scimAttr.split('.')
  if (arr.length < 2) {
    base = `${userNamingAttr}=${userObj[scimAttr]},${userBase}`
  } else {
    base = `${userNamingAttr}=${userObj[arr[0]][arr[1]]},${userBase}`
  }

  const method = 'add'
  const ldapOptions = endpointObj

  try {
    await doRequest(baseEntity, method, base, ldapOptions, ctx)
    return null
  } catch (err: any) {
    const newErr = new Error(`${action} error: ${err.message}`)
    if (newErr.message.includes('ENTRY_EXISTS')) newErr.name += '#409' // customErrCode
    throw newErr
  }
}

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id, ctx) => {
  const action = 'deleteUser'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} passThrough=${ctx ? 'true' : 'false'}`)

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
    await doRequest(baseEntity, method, base, ldapOptions, ctx)
    return null
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// modifyUser
// =================================================
scimgateway.modifyUser = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyUser'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} attrObj=${JSON.stringify(attrObj)} passThrough=${ctx ? 'true' : 'false'}`)

  // groups must be handled separate - using group member of user and not user member of group
  if (attrObj.groups) { // not supported by AD - will fail (not allowing updating users memberOf attribute, must update group instead of user)
    const groups = attrObj.groups
    delete attrObj.groups // make sure to be removed from attrObj

    const [groupsAttr] = scimgateway.endpointMapper('outbound', 'groups.value', config.map.user)
    const grp: any = { add: {}, remove: {} }
    grp.add[groupsAttr] = []
    grp.remove[groupsAttr] = []

    for (let i = 0; i < groups.length; i++) {
      const el = groups[i]
      if (el.operation && el.operation === 'delete') { // delete from users group attribute
        grp.remove[groupsAttr].push(el.value)
      } else { // add to users group attribute
        grp.add[groupsAttr].push(el.value)
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
      if (grp.add[groupsAttr].length > 0) {
        const ldapOptions = {
          operation: 'add',
          modification: grp.add,
        }
        await doRequest(baseEntity, method, base, ldapOptions, ctx)
      }
      if (grp.remove[groupsAttr].length > 0) {
        const ldapOptions = {
          operation: 'delete',
          modification: grp.remove,
        }
        await doRequest(baseEntity, method, base, ldapOptions, ctx)
      }
    } catch (err: any) {
      throw new Error(`${action} error: ${err.message}`)
    }
  }

  if (Object.keys(attrObj).length < 1) return null // only groups included

  // convert SCIM attributes to endpoint attributes according to config.map
  const [endpointObj] = scimgateway.endpointMapper('outbound', attrObj, config.map.user)

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
    const ldapOptions: any = {
      attributes: activeAttr,
    }

    const users: any = await doRequest(baseEntity, method, base, ldapOptions, ctx)
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

  if (Object.keys(endpointObj).length < 1) return null
  const ldapOptions = {
    operation: 'replace',
    modification: endpointObj,
  }

  try {
    const newDN = checkIfNewDN(baseEntity, base, 'user', attrObj, endpointObj)
    await doRequest(baseEntity, method, base, ldapOptions, ctx)
    if (newDN && config.entity[baseEntity].ldap.allowModifyDN) {
      // modify DN
      await doRequest(baseEntity, 'modifyDN', base, { modification: { newDN } }, ctx)
      // clean up zoombie group members and use the new user DN incase not handled by ldap server
      const [memberAttr] = scimgateway.endpointMapper('outbound', 'members.value', config.map.group)
      if (memberAttr) {
        const grp: any = { add: {}, remove: {} }
        grp.add[memberAttr] = []
        grp.remove[memberAttr] = []
        let r
        try {
          const ob = { attribute: 'members.value', operator: 'eq', value: base } // base is old DN
          const attributes = ['id', 'displayName']
          r = await scimgateway.getGroups(baseEntity, ob, attributes, ctx)
        } catch (err) { } // ignore errors incase method not implemented
        if (r && r.Resources && Array.isArray(r.Resources) && r.Resources.length > 0) {
          for (let i = 0; i < r.Resources.length; i++) {
            if (!r.Resources[i].id) continue
            const grpId = decodeURIComponent(r.Resources[i].id)
            grp.remove[memberAttr] = [base]
            grp.add[memberAttr] = [newDN]
            await Promise.all([
              doRequest(baseEntity, method, grpId, { operation: 'add', modification: grp.add }, ctx),
              doRequest(baseEntity, method, grpId, { operation: 'delete', modification: grp.remove }, ctx),
            ])
          }
        }
        // return full user object to avoid scimgateway doing same getUser() using original id/dn that now will fail
        const getObj = { attribute: 'id', operator: 'eq', value: newDN }
        const res = await scimgateway.getUsers(baseEntity, getObj, [], ctx)
        return res
      }
    }
    return null
  } catch (err: any) {
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
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes} passThrough=${ctx ? 'true' : 'false'}`)
  if (!config.entity[baseEntity]) throw new Error(`unsupported baseEntity: ${baseEntity}`)

  const result: any = {
    Resources: [],
    totalResults: null,
  }

  if (!config?.map?.group || !config.entity[baseEntity]?.ldap?.groupBase) { // not using groups
    scimgateway.logDebug(baseEntity, `${action} skip group handling - missing configuration endpoint.map.group or groupBase`)
    return result
  }

  if (attributes.length < 1) {
    for (const key in config.map.group) {
      if (config.map.group[key].mapTo) {
        attributes.push(config.map.group[key].mapTo)
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
          attributes: attrs,
        }
      } else {
        const [groupIdAttr, err] = scimgateway.endpointMapper('outbound', getObj.attribute, config.map.group)
        if (err) throw new Error(`${action} error: ${err.message}`)
        if (groupIdAttr === 'objectSid') {
          const sid = convertStringToSid(getObj.value)
          if (!sid) throw new Error(`${action} error: ${getObj.attribute}=${getObj.value} - attribute having a none valid SID string`)
          base = `<SID=${sid}>`
          ldapOptions = {
            attributes: attrs,
          }
        } else if (groupIdAttr === 'objectGUID') {
          const guid = Buffer.from(getObj.value, 'base64').toString('hex')
          base = `<GUID=${guid}>`
          ldapOptions = {
            attributes: attrs,
          }
        } else { // search instead of lookup
          const filter = createAndFilter(baseEntity, 'group', [{ attribute: groupIdAttr, value: getObj.value }])
          ldapOptions = {
            filter,
            scope,
            attributes: attrs,
          }
        }
      }
    } else if (getObj.operator === 'eq' && getObj.attribute === 'members.value') {
      // mandatory - return all groups the user 'id' (getObj.value) is member of - correspond to getGroupMembers() in versions < 4.x.x
      // Resources = [{ id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }]
      ldapOptions = 'getMemberOfGroups'
    } else {
      // optional - simpel filtering
      if (getObj.operator === 'eq') {
        const [filterAttr, err] = scimgateway.endpointMapper('outbound', getObj.attribute, config.map.group)
        if (err) throw new Error(`${action} error: ${err.message}`)
        const filter = createAndFilter(baseEntity, 'group', [{ attribute: filterAttr, value: getObj.value }])
        ldapOptions = {
          filter,
          scope,
          attributes: attrs,
        }
      } else {
        throw new Error(`${action} error: not supporting simpel filtering: ${getObj.rawFilter}`)
      }
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all groups to be returned - correspond to exploreGroups() in versions < 4.x.x
    const filter = createAndFilter(baseEntity, 'group', [{ attribute: groupDisplayNameAttr, value: '*' }])
    ldapOptions = {
      filter,
      scope,
      attributes: attrs,
    }
  }
  // mandatory if-else logic - end

  if (!ldapOptions) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  try {
    if (ldapOptions === 'getMemberOfGroups') result.Resources = await getMemberOfGroups(baseEntity, getObj.value, ctx)
    else {
      const groups: any = await doRequest(baseEntity, method, base, ldapOptions, ctx)
      result.Resources = await Promise.all(groups.map(async (group: any) => { // Promise.all because of async map
        if (config.useSID_id || config.useGUID_id) {
          if (group.member) {
            const arr: string[] = []
            if (Array.isArray(group.member)) {
              for (let i = 0; i < group.member.length; i++) {
                const id = await dnToSidGuid(baseEntity, group.member[i], ctx)
                if (!id) throw new Error(`dnToSidGuid() did not return any ${config.useSID_id ? 'objectSid' : 'objectGUID'} value for dn=${group.member[i]}`)
                arr.push(id)
              }
              group.member = arr
            } else {
              const id = await dnToSidGuid(baseEntity, group.member, ctx)
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
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj, ctx) => {
  const action = 'createGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} groupObj=${JSON.stringify(groupObj)} passThrough=${ctx ? 'true' : 'false'}`)

  if (!config.map.group) throw new Error(`${action} error: missing configuration endpoint.map.group`)
  const groupBase = config.entity[baseEntity].ldap.groupBase

  // convert SCIM attributes to endpoint attributes according to config.map
  const [endpointObj] = scimgateway.endpointMapper('outbound', groupObj, config.map.group)

  // endpointObj.objectClass is mandatory and must must match your ldap schema
  endpointObj.objectClass = config.entity[baseEntity].ldap.groupObjectClasses // Active Directory: ["group"]

  let base = ''
  const [groupNamingAttr, scimAttr] = getNamingAttribute(baseEntity, 'group') // ['CN', 'displayName']
  const arr = scimAttr.split('.')
  if (arr.length < 2) {
    base = `${groupNamingAttr}=${groupObj[scimAttr]},${groupBase}`
  } else {
    base = `${groupNamingAttr}=${groupObj[arr[0]][arr[1]]},${groupBase}`
  }

  const method = 'add'
  const ldapOptions = endpointObj

  try {
    await doRequest(baseEntity, method, base, ldapOptions, ctx)
    const res = await scimgateway.getGroups(baseEntity, { attribute: 'id', operator: 'eq', value: base }, [], ctx)
    if (res && Array.isArray(res.Resources) && res.Resources.length === 1) return res.Resources[0]
    else return null
  } catch (err: any) {
    const newErr = new Error(`${action} error: ${err.message}`)
    if (newErr.message.includes('ENTRY_EXISTS')) newErr.name += '#409' // customErrCode
    throw newErr
  }
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id, ctx) => {
  const action = 'deleteGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} passThrough=${ctx ? 'true' : 'false'}`)

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
    await doRequest(baseEntity, method, base, ldapOptions, ctx)
    return null
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// modifyGroup
// =================================================
scimgateway.modifyGroup = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} attrObj=${JSON.stringify(attrObj)} passThrough=${ctx ? 'true' : 'false'}`)

  if (!config.map.group) throw new Error(`${action} error: missing configuration endpoint.map.group`)
  if (attrObj.members && !Array.isArray(attrObj.members)) {
    throw new Error(`${action} error: ${JSON.stringify(attrObj)} - correct syntax is { "members": [...] }`)
  }

  const [memberAttr] = scimgateway.endpointMapper('outbound', 'members.value', config.map.group)
  if (!memberAttr && attrObj.members) throw new Error(`${action} error: missing attribute mapping configuration for group members`)

  const grp: any = { add: {}, remove: {} }
  grp.add[memberAttr] = []
  grp.remove[memberAttr] = []

  for (let i = 0; i < attrObj?.members?.length; i++) {
    const el = attrObj.members[i]
    if (config.useSID_id || config.useGUID_id) {
      const dn = await sidGuidToDn(baseEntity, el.value, ctx)
      if (!dn) throw new Error(`${action} error: sidGuidToDn() did not return any objectGUID value for dn=${el.value}`)
      el.value = dn
    }
    const dnObj = ldapEscDn(config.entity[baseEntity].ldap.isOpenLdap, el.value)
    el.value = dnObj.toString()
    if (el.operation && el.operation === 'delete') { // delete member from group
      grp.remove[memberAttr].push(el.value) // endpointMapper returns URI encoded id because some IdP's don't encode id used in GET url e.g. Symantec/Broadcom/CA
    } else { // add member to group
      grp.add[memberAttr].push(el.value)
    }
  }

  const method = 'modify'
  let base
  if (config.useSID_id) base = `<SID=${id}>`
  else if (config.useGUID_id) base = `<GUID=${id}>`
  else base = id // dn

  try {
    delete attrObj.members
    const [endpointObj] = scimgateway.endpointMapper('outbound', attrObj, config.map.group)
    const newDN = checkIfNewDN(baseEntity, base, 'group', attrObj, endpointObj)
    if (Object.keys(endpointObj).length > 0) {
      const ldapOptions = {
        operation: 'replace',
        modification: endpointObj,
      }
      await doRequest(baseEntity, method, base, ldapOptions, ctx)
    }
    if (grp.add[memberAttr].length > 0) {
      const ldapOptions = { // using ldap lookup (dn) instead of search
        operation: 'add',
        modification: grp.add,
      }
      await doRequest(baseEntity, method, base, ldapOptions, ctx)
    }
    if (grp.remove[memberAttr].length > 0) {
      const ldapOptions = { // using ldap lookup (dn) instead of search
        operation: 'delete',
        modification: grp.remove,
      }
      await doRequest(baseEntity, method, base, ldapOptions, ctx)
    }
    if (newDN && config.entity[baseEntity].ldap.allowModifyDN) {
      await doRequest(baseEntity, 'modifyDN', base, { modification: { newDN } }, ctx)
      const getObj = { attribute: 'id', operator: 'eq', value: newDN }
      const res = await scimgateway.getGroups(baseEntity, getObj, [], ctx)
      return res // return full group object to avoid scimgateway doing same getUser() using original id/dn that now will fail
    }
    return null
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// helpers
// =================================================

const _serviceClient: Record<string, any> = {}

//
// createAndFilter creates AndFilter object to be used as filter instead of standard string filter
// Using AndFilter object for eliminating internal ldapjs escaping problems related to values with some
// combinations of parentheses e.g. ab(c)d
//
const createAndFilter = (baseEntity: string, type: string, arrObj: any) => {
  const objFilters: ldap.PresenceFilter[] | ldap.SubstringFilter[] = []

  // add arrObj
  for (let i = 0; i < arrObj.length; i++) {
    if (arrObj[i].value.indexOf('*') > -1) { // SubstringFilter or PresenceFilter
      const arr = arrObj[i].value.split('*')
      if (arr.length === 2 && !arr[0] && !arr[1]) { // cn=*
        const f = new ldap.PresenceFilter({ attribute: arrObj[i].attribute })
        objFilters.push(f)
      } else { // cn=ab*cd*e
        const fObj: any = {
          attribute: arrObj[i].attribute,
        }
        const arrAny: any = []
        fObj.initial = arr[0]
        if (!fObj.initial) delete fObj.initial
        for (let i = 1; i < arr.length - 1; i++) {
          arrAny.push(arr[i])
        }
        fObj.any = arrAny
        if (arr[arr.length - 1]) {
          fObj.final = arr[arr.length - 1]
        }
        const f = new ldap.SubstringFilter(fObj)
        objFilters.push(f)
      }
    } else { // EqualityFilter cn=abc
      const f = new ldap.EqualityFilter({ attribute: arrObj[i].attribute, value: arrObj[i].value })
      objFilters.push(f)
    }
  }

  // add from configuration objectClass and userFiter/groupFilter
  switch (type) {
    case 'user':
      for (let i = 0; i < config.entity[baseEntity].ldap.userObjectClasses.length; i++) {
        const f = new ldap.EqualityFilter({ attribute: 'objectClass', value: config.entity[baseEntity].ldap.userObjectClasses[i] })
        objFilters.push(f)
      }
      if (config.entity[baseEntity].ldap.userFilter) {
        try {
          const uf = ldap.parseFilter(config.entity[baseEntity].ldap.userFilter)
          objFilters.push(uf)
        } catch (err: any) {
          throw new Error(`configuration ldap.userFilter: ${config.entity[baseEntity].ldap.userFilter} - parseFilter error: ${err.message}`)
        }
      }
      break
    case 'group':
      for (let i = 0; i < config.entity[baseEntity].ldap.groupObjectClasses.length; i++) {
        const f = new ldap.EqualityFilter({ attribute: 'objectClass', value: config.entity[baseEntity].ldap.groupObjectClasses[i] })
        objFilters.push(f)
        if (config.entity[baseEntity].ldap.groupFilter) {
          try {
            const gf = ldap.parseFilter(config.entity[baseEntity].ldap.groupFilter)
            objFilters.push(gf)
          } catch (err: any) {
            throw new Error(`configuration ldap.groupFilter: ${config.entity[baseEntity].ldap.groupFilter} - parseFilter error: ${err.message}`)
          }
        }
      }
      break
  }

  // put all into AndFilter
  const filter = new ldap.AndFilter({
    filters: [
      ...objFilters,
    ],
  })

  return filter
}

//
// dnToSidGuid is used for Active Directory to return objectGUID based on dn
//
const dnToSidGuid = async (baseEntity: string, dn: any, ctx: any): Promise<string> => {
  const method = 'search'
  const ldapOptions: any = {}
  if (config.useSID_id) ldapOptions.attributes = ['objectSid']
  else if (config.useGUID_id) ldapOptions.attributes = ['objectGUID']
  else throw new Error('dnToSidGuid() invalid call, configuration not using objectSid or objectGUID')

  try {
    const base = dn
    const objects: any = await doRequest(baseEntity, method, base, ldapOptions, ctx)
    if (objects.length !== 1) throw new Error(`did not find unique object having dn=${base}`)
    if (config.useSID_id) return objects[0].objectSid
    else return objects[0].objectGUID
  } catch (err: any) {
    const newErr = new Error(`dnToSidGuid() ${err.message}`)
    throw newErr
  }
}

//
// guidToDn is used for Active Directory to return dn based on objectGUID
//
const sidGuidToDn = async (baseEntity: string, id: string, ctx: any): Promise<string> => {
  const method = 'search'
  const ldapOptions = {
    attributes: ['dn'],
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
    const objects: any = await doRequest(baseEntity, method, base, ldapOptions, ctx)
    if (objects.length !== 1) throw new Error(`did not find unique object having ${config.useSID_id ? 'objectSid' : 'objectGUID'} =${id}`)
    return objects[0].dn
  } catch (err: any) {
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
const pad = function (s: any) { if (s.length < 2) { return `0${s}` } else { return s } }
const convertSidToString = (buf: any) => {
  let asc: any, end: any
  let i: number
  if (buf == null) { return null }
  const version = buf[0]
  const subAuthorityCount = buf[1]
  const identifierAuthority = parseInt(((() => {
    const result: any = []
    for (i = 2; i <= 7; i++) {
      result.push(buf[i].toString(16))
    }
    return result
  })()).join(''), 16)
  let sidString = `S-${version}-${identifierAuthority}`
  try {
    for (i = 0, end = subAuthorityCount - 1, asc = end >= 0; asc ? i <= end : i >= end; asc ? i++ : i--) {
      const subAuthOffset = i * 4
      const tmp
        = pad(buf[11 + subAuthOffset].toString(16))
          + pad(buf[10 + subAuthOffset].toString(16))
          + pad(buf[9 + subAuthOffset].toString(16))
          + pad(buf[8 + subAuthOffset].toString(16))
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
const convertStringToSid = (sidStr: string) => {
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
      bufLE.writeUInt32LE(val, 0)
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
const getMemberOfGroups = async (baseEntity: string, id: string, ctx: any) => {
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
      attributes: ['dn'],
    }

    try {
      const users: any = await doRequest(baseEntity, method, base, ldapOptions, ctx)
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

  const filter = createAndFilter(baseEntity, 'group', [{ attribute: memberAttr, value: idDn }])
  const ldapOptions = {
    filter,
    scope,
    attributes: attrs,
  }

  try {
    const groups: any = await doRequest(baseEntity, method, base, ldapOptions, ctx)
    return groups.map((grp: any) => {
      return { // { id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }
        id: encodeURIComponent(grp[attrs[0]]), // not mandatory, but included anyhow
        displayName: grp[attrs[1]], // displayName is mandatory
        members: [{ value: encodeURIComponent(id) }], // only includes current user
      }
    })
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

//
// ldapEscDn will escape DN according to the LDAP standard adjusted to ldapjs behavior
// using OpenLDAP, DN must be escaped - national characters and special ldap characters
// using Active Directory (none OpenLDAP), DN should not be escaped, but DN retrieved from AD is character escaped
//
const ldapEscDn = (isOpenLdap: any, str: string): ldap.DN => {
  if (typeof str !== 'string' || str.length < 1) return new ldap.DN()

  if (!isOpenLdap && str.indexOf('\\') > 0) {
    const conv = str.replace(/\\([0-9A-Fa-f]{2})/g, (_, hex) => {
      const intAscii = parseInt(hex, 16)
      if (intAscii > 128) { // extended ascii - will be unescaped by decodeURIComponent
        return '%' + hex
      } else { // use character escape
        return '\\' + String.fromCharCode(intAscii)
      }
    })
    str = decodeURIComponent(conv)
    str = str.replace(/\\/g, '') // lower ascii may be character escaped e.g. 'cn=Kürt\, Lastname' - see below comma logic
  }

  const arr = str.split(',')
  for (let i = 0; i < arr.length; i++) { // CN=Firstname, Lastname,OU=...
    if (!arr[i]) { // value having comma only
      if (arr[i - 1].charAt(arr[i - 1].length - 1) === '\\') {
        arr[i - 1] = arr[i - 1].substring(0, arr[i - 1].length - 1)
      }
      if (isOpenLdap) arr[i - 1] += '\\,'
      else arr[i - 1] += ','
      arr.splice(i, 1)
      i -= 1
      continue
    }
    const a = arr[i].split('=')
    while (a.length > 2) { // 'uid=Firstname \= Lastname'
      a[1] += '=' + a[2]
      a.splice(2, 1)
    }
    if (a.length < 2 && i > 0) { // value having comma and content
      if (arr[i - 1].charAt(arr[i - 1].length - 1) === '\\') {
        arr[i - 1] = arr[i - 1].substring(0, arr[i - 1].length - 1)
      }
      if (isOpenLdap) arr[i - 1] += `\\,${ldapEsc(a[0])}`
      else arr[i - 1] += `,${a[0]}`
      arr.splice(i, 1)
      i -= 1
      continue
    } else {
      if (isOpenLdap) arr[i] = `${a[0]}=${ldapEsc(a[1])}`
      else arr[i] = `${a[0]}=${a[1]}`
    }
    if (i > 0) break // only escape logic on first, assume sub OU's are correct
  }

  // Using dn object instead of string to ensure all escaping will be OK e.g. 'uid=test \= test,dc=example,dc=com'
  // For non OpenLdap e.g., Active Directory, we must include BER encoding 
  const dn = new ldap.DN()
  for (let i = 0; i < arr.length; i++) {
    const a = arr[i].split('=') // cn=Kürt
    while (a.length > 2) {
      a[1] += '=' + a[2]
      a.splice(2, 1)
    }
    if (a.length === 2) {
      if (i === 0 && !isOpenLdap) {
        const ua = new Uint8Array(Buffer.from(a[1], 'utf-8'))
        const buf = Buffer.from(new Uint8Array([4, ua.length, ...ua]))
        const rdn: any = {}
        rdn[a[0]] = new BerReader(buf)
        dn.push(new ldap.RDN(rdn))
        // new BerReader(Buffer.from([0x04, 0x05, 0x4B, 0xc3, 0xbc, 0x72, 0x74])) // Kürt
        // the leading 04 is the tag for "octet string" and the following 05 is the length in bytes of the string.
      } else {
        const rdn: any = {}
        rdn[a[0]] = a[1]
        dn.push(new ldap.RDN(rdn))
      }
    } else {
      throw new Error('ldapEscDn() invalid DN: ' + str)
    }
  }
  return dn
}

//
// ldapEsc will character escape str according to OpenLDAP DN standard
// Hex encoded escaping (extended and unicode ascii) is not included because
// automatically handled by ldapjs when not using BER encoded DN
//
const ldapEsc = (str: any) => {
  if (!str) return str
  let newStr = ''
  for (let i = 0; i < str.length; i++) {
    let c = str[i]
    let isEsc = false
    if (i > 0 && str[i - 1] === '\\') isEsc = true
    switch (c) {
      case ',':
        if (isEsc) c = ','
        else c = '\\,'
        break
      case ';':
        if (isEsc) c = ';'
        else c = '\\;'
        break
      case '+':
        if (isEsc) c = '+'
        else c = '\\+'
        break
      case '<':
        if (isEsc) c = '<'
        else c = '\\<'
        break
      case '>':
        if (isEsc) c = '>'
        else c = '\\>'
        break
      case '=':
        if (isEsc) c = '='
        else c = '\\='
        break
      case '"':
        if (isEsc) c = '"'
        else c = '\\"'
        break
      case '(':
        if (isEsc) c = '('
        else c = '\\('
        break
      case ')':
        if (isEsc) c = ')'
        else c = '\\)'
        break
      case '#':
        if (isEsc) c = '#'
        else c = '\\#'
        break
    }
    newStr += c
  }
  return newStr
}

//
// berDecodeDn decodes a BER string part of type DN
// OU=#04057573657273,OU=abc,... => OU=users,OU=abc,...
// only using BER on first part of dn
// Having BER decoding for Active Directory, but not for OpenLDAP
//
const berDecodeDn = (dn: any) => {
  if (Object.prototype.toString.call(dn) !== '[object LdapDn]') return dn // OpenLDAP
  const str = dn.toString()
  if (str.indexOf('#') < 1) return str
  const arr = str.split('#')
  if (arr.length === 2) {
    const a = arr[1].split(',')
    if (a.length > 1) {
      const berStr = a[0].substring(4)
      let decoded = ''
      let c = ''
      if (berStr.length % 2 === 0) {
        for (let i = 0; i < berStr.length; i++) {
          c += berStr[i]
          if (c.length === 2) {
            const intAscii = parseInt(c, 16)
            decoded += String.fromCharCode(intAscii)
            c = ''
          }
        }
      }
      if (decoded.length > 0) {
        // convert any extended ascii to utf8
        const isoBytes = Uint8Array.from(decoded, c => c.charCodeAt(0))
        decoded = new TextDecoder('utf-8').decode(isoBytes)
        decoded = decoded.replace(/,/g, '\\,')
        a.splice(0, 1) // remove element 0 from array
        return `${arr[0]}${decoded},${a.join(',')}` // OU=users,OU=abc
      }
    }
  }
  return str
}

const getNamingAttribute = (baseEntity: string, type: string) => {
  let arr
  switch (type) {
    case 'user':
      arr = config.entity[baseEntity]?.ldap?.namingAttribute?.user
      break
    case 'group':
      arr = config.entity[baseEntity]?.ldap?.namingAttribute?.group
      break
    default:
      throw new Error(`getNamingAttribute error: invalid type ${type}`)
  }
  if (!Array.isArray(arr) || arr.length !== 1) throw new Error(`configuration missing namingAttribute definition for ${type}`)
  return [arr[0].attribute, arr[0].mapTo]
}

const checkIfNewDN = (baseEntity: string, base: any, type: string, obj: any, endpointObj: any) => {
  if (typeof obj !== 'object' || Object.keys(obj).length < 1) return ''
  if (typeof endpointObj !== 'object' || Object.keys(endpointObj).length < 1) return ''

  const namingAttr = base.split('=')[0] // cn
  let scimAttr = ''
  if (endpointObj[namingAttr]) { // naming attribute can't be modified, have to use modifyDN()
    delete endpointObj[namingAttr] // modifying original ldapOptions
    if (config.map[type] && config.map[type][namingAttr]) {
      scimAttr = config.map[type][namingAttr].mapTo
    }
    if (!config.entity[baseEntity].ldap.allowModifyDN) {
      throw new Error(`changing ldap Naming Attribute ${namingAttr}/${scimAttr} requires configuration ldap.allowModifyDN=true`)
    }
  }
  if (!scimAttr) { // check if namingAttr is defined as namingAttribute configuration having linked scimAttr
    const [nAttr, sAttr] = getNamingAttribute(baseEntity, type) // ['cn', 'userName']
    if (namingAttr === nAttr) scimAttr = sAttr
  }
  if (!scimAttr) return ''
  // find and return the new DN
  let newNamingValue
  const arr = scimAttr.split('.')
  if (arr.length < 2) {
    if (obj[scimAttr]) newNamingValue = obj[scimAttr]
  } else {
    if (obj[arr[0]] && obj[arr[0]][arr[1]]) newNamingValue = obj[arr[0]][arr[1]]
  }
  if (!newNamingValue) return ''
  const re = '^([a-zA-Z]+=)(.*?)(?=,[a-zA-Z]+=|$)(.*)$'
  const rePattern = new RegExp(re, 'i')
  const a = base.match(rePattern)
  /*
  a[1] 'CN='
  a[2] '<value>'
  a[3] '<rest> e.g.,: ,OU=mycompany,OU=com'
  */
  if (a.length !== 4) return ''
  if (a[1].toLowerCase() !== namingAttr.toLowerCase() + '=') return ''
  if (a[2] === newNamingValue) return ''
  let newDN = a[1] + newNamingValue + a[3]
  return ldapEscDn(config.entity[baseEntity].ldap.isOpenLdap, newDN)
}

//
// getCtxAuth returns username/secret from ctx header when using Auth PassThrough
//
const getCtxAuth = (ctx: any) => {
  if (!ctx?.request?.header?.authorization) return []
  const [authType, authToken] = (ctx.request.header.authorization || '').split(' ') // [0] = 'Basic' or 'Bearer'
  let username, password
  if (authType === 'Basic') [username, password] = (Buffer.from(authToken, 'base64').toString() || '').split(':')
  if (username) return [username, password] // basic auth
  else return [undefined, authToken] // bearer auth
}

//
// getServiceClient returns LDAP client used by doRequest
//
const getServiceClient = async (baseEntity: string, ctx: any) => {
  const action = 'getServiceClient'

  if (!config.entity[baseEntity].baseUrl) config.entity[baseEntity].baseUrl = config.entity[baseEntity].baseUrls[0] // failover logic also updates baseUrl
  if (!_serviceClient[baseEntity]) _serviceClient[baseEntity] = {}
  if (!_serviceClient[baseEntity].tlsOptions) {
    const tlsOptions: Record<string, any> = {
      rejectUnauthorized: config.entity[baseEntity]?.tls?.rejectUnauthorized || false,
      ca: undefined,
    }
    if (config.entity[baseEntity]?.tls?.ca) {
      if (Array.isArray(config.entity[baseEntity].tls.ca)) {
        tlsOptions.ca = []
        for (let i = 0; i < config.entity[baseEntity].tls.ca.length; i++) {
          tlsOptions.ca.append(fs.readFileSync(config.entity[baseEntity].tls.ca[i]))
        }
      } else tlsOptions.ca = fs.readFileSync(config.entity[baseEntity].tls.ca)
      tlsOptions.rejectUnauthorized = true
    }
    if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') tlsOptions.rejectUnauthorized = false
    else if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '1') tlsOptions.rejectUnauthorized = true
    if (process.env.NODE_EXTRA_CA_CERTS) {
      tlsOptions.ca = fs.readFileSync(process.env.NODE_EXTRA_CA_CERTS)
      tlsOptions.rejectUnauthorized = true
    }
    _serviceClient[baseEntity].tlsOptions = tlsOptions
  }

  for (let i = -1; i < config.entity[baseEntity].baseUrls.length; i++) {
    try {
      const cli = await ldap.createClient({
        url: config.entity[baseEntity].baseUrl,
        connectTimeout: 5000,
        tlsOptions: _serviceClient[baseEntity].tlsOptions,
        strictDN: false, // false => allows none standard ldap base dn e.g. <SID=...> / <GUID=...>  ref. objectSid/objectGUID
      })
      await new Promise((resolve, reject) => {
        if (ctx?.request?.header?.authorization) { // using ctx authentication PassThrough
          const [username, password] = getCtxAuth(ctx)
          if (username) cli.bind(username, password, (err, res) => err ? reject(err) : resolve(res)) // basic auth
          else cli.bind(config.entity[baseEntity].username, password, (err, res) => err ? reject(err) : resolve(res)) // bearer token, using username from configuration
        } else cli.bind(config.entity[baseEntity].username, config.entity[baseEntity].password, (err, res) => err ? reject(err) : resolve(res))
        cli.on('error', err => reject(err))
      })
      return cli // client OK
    } catch (err: any) {
      const retry = err.message.includes('timeout') || err.message.includes('ECONNREFUSED')
      if (retry && i + 1 < config.entity[baseEntity].baseUrls.length) { // failover logic
        scimgateway.logDebug(baseEntity, `baseUrl=${config.entity[baseEntity].baseUrl} connection error - starting retry`)
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
const doRequest = async (baseEntity: string, method: string, base: any, options: any, ctx: any) => {
  if (!config.entity[baseEntity]) throw new Error(`unsupported baseEntity: ${baseEntity}`)
  let result: any = null
  let client: any = null
  const dnObj = ldapEscDn(config.entity[baseEntity].ldap.isOpenLdap, base)

  // support having different upn-domain on IdP and target
  if (options.modification && options.modification.userPrincipalName && config.map.user.userPrincipalName && config.map.user.userPrincipalName.mapDomain) {
    if (options.modification.userPrincipalName.endsWith(config.map.user.userPrincipalName.mapDomain.outbound)) {
      const old = options.modification.userPrincipalName
      options.modification.userPrincipalName = options.modification.userPrincipalName.replace(config.map.user.userPrincipalName.mapDomain.outbound, config.map.user.userPrincipalName.mapDomain.inbound)
      scimgateway.logDebug(baseEntity, `inbound upnMapDomain ${old} => ${options.modification.userPrincipalName}`)
    }
  }

  try {
    client = await getServiceClient(baseEntity, ctx)
    switch (method) {
      case 'search':
        if (options.paged !== false) options.paged = { pageSize: 200, pagePause: false } // parse entire directory calling 'page' method for each page
        result = await new Promise((resolve, reject) => {
          const results: any = []

          client.search(dnObj, options, (err: any, search: any) => {
            if (err) {
              return reject(err)
            }

            search.on('searchEntry', (entry: any) => {
              if (!entry.pojo || !entry.pojo.attributes) return
              const obj: any = { dn: entry.pojo.objectName }
              entry.pojo.attributes.map((el: any) => {
                if (el.values.length > 1) obj[el.type] = el.values
                else obj[el.type] = el.values[0]
                return null
              })
              // objectSid/objectGUID - assume Active Directory - can't use default utf-8 when attribute value is hex
              if (obj.objectSid) {
                const b = Buffer.from(obj.objectSid, 'utf-8')
                const sidStr = convertSidToString(b) // using string: S-1-5-21-2657077294-4200173015-2627628055-1255
                if (!sidStr) throw new Error(`doRequest() error: failed to convert SID ${b.toString('hex')} to string}`)
                obj.objectSid = sidStr
              }
              if (obj.objectGUID) {
                const b = Buffer.from(obj.objectGUID, 'utf-8')
                obj.objectGUID = b.toString('base64') // using base64: nitWLrhokUqKl1DywiavXg==
              }
              if (obj.userPrincipalName && config.map.user.userPrincipalName && config.map.user.userPrincipalName.mapDomain) {
                if (obj.userPrincipalName.endsWith(config.map.user.userPrincipalName.mapDomain.inbound)) {
                  const old = obj.userPrincipalName
                  obj.userPrincipalName = obj.userPrincipalName.replace(config.map.user.userPrincipalName.mapDomain.inbound, config.map.user.userPrincipalName.mapDomain.outbound)
                  scimgateway.logDebug(baseEntity, `outbound upnMapDomain ${old} => ${obj.userPrincipalName}`)
                }
              }

              if (obj.dn && obj.dn.indexOf('\\') > 0) {
                // for OpenLDAP ensure dn is not hex escaped e.g.: cn=K\c3\bcrt => cn=Kürt
                // because dn may be be used as value in standard attributes like group memberOf
                obj.dn = obj.dn.replace(/\\\\/g, '\+\|\|_') // temp
                let conv = obj.dn.replace(/\\([0-9A-Fa-f]{2})/g, (_: any, hex: any) => {
                  const intAscii = parseInt(hex, 16)
                  if (intAscii > 127) { // extended ascii - will be unescaped by decodeURIComponent
                    return '%' + hex
                  } else { // use character escape
                    return '\\' + String.fromCharCode(intAscii)
                  }
                })
                conv = conv.replace(/\+\|\|_/g, '\\\\')
                obj.dn = decodeURIComponent(conv)
              }

              results.push(obj)
            })

            /*
            search.on('page', (entry, cb) => {
              // if (cb) cb() // pagePause = true gives callback
            })
            */

            search.on('error', (err: any) => {
              if (err.message.includes('LdapErr: DSID-0C0909F2') || err.message.includes('NO_OBJECT')) return resolve([]) // object not found when using base <SID=...> or <GUID=...> ref. objectSid/objectGUID
              reject(err)
            })

            search.on('end', (_: any) => { resolve(results) })
          })
        })
        break

      case 'modify':
        result = await new Promise((resolve: any, reject: any) => {
          const dn = dnObj
          const changes: any = []
          for (const key in options.modification) {
            const mod: any = {}
            mod.type = key
            if (Array.isArray(options.modification[key])) {
              mod.values = options.modification[key]
              if (mod.values.length > 1) { // delete before replace to keep inbound order
                const multiValueObj = {
                  operation: 'delete',
                  modification: { type: key, values: [] },
                }
                client.modify(dn, multiValueObj, () => { })
              }
            } else {
              if (typeof options.modification[key] === 'string') mod.values = [options.modification[key]]
              else mod.values = [options.modification[key].toString()]
            }
            const change = new ldap.Change({
              operation: options.operation || 'replace',
              modification: mod, // { type: "givenName", values: ["Joe"] }
            })
            changes.push(change)
          }
          client.modify(dn, changes, (err: any) => {
            if (err) {
              if (options.operation && options.operation === 'add') {
                const msg = err.message.toLowerCase()
                if (msg.includes('exists')) return resolve() // "ENTRY_EXISTS" / "Value Exists" - add already existing group to user
              }
              return reject(err)
            }
            resolve()
          })
        })
        break

      case 'modifyDN':
        result = await new Promise((resolve: any, reject: any) => {
          let dn = dnObj.toString() // needed for client.modifyDN...
          let newDN = options?.modification?.newDN
          if (!newDN) return reject(new Error('modifyDN() missing newDN'))
          if (Object.prototype.toString.call(newDN) === '[object LdapDn]') newDN = newDN.toString()
          client.modifyDN(dn, newDN, (err: any) => {
            if (err) {
              return reject(err)
            }
            resolve()
          })
        })
        break

      case 'add':
        result = await new Promise((resolve: any, reject: any) => {
          client.add(dnObj, options, (err: any) => {
            if (err) {
              return reject(err)
            }
            resolve()
          })
        })
        break

      case 'del':
        result = await new Promise((resolve: any, reject: any) => {
          client.del(dnObj, (err: any) => {
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
  } catch (err: any) {
    if (options.filter && typeof options.filter === 'object') {
      options.filter = options.filter.toString()
    }
    scimgateway.logDebug(baseEntity, `doRequest method=${method} base=${berDecodeDn(dnObj)} ldapOptions=${JSON.stringify(options)} Error Response = ${err.message}`)
    if (client) {
      try {
        client.destroy()
      } catch (err) { }
    }
    throw err
  }

  if (options.filter && typeof options.filter === 'object') {
    options.filter = options.filter.toString()
  }
  scimgateway.logDebug(baseEntity, `doRequest method=${method} base=${berDecodeDn(dnObj)} ldapOptions=${JSON.stringify(options)} Response=${JSON.stringify(result)}`)
  return result
} // doRequest

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})

//
// startup initialization
// at the end to ensure scimgatway logger have started
//
if (!config?.map?.user) {
  scimgateway.logError('', 'configuration map.user is missing')
  throw new Error('using exception to exit, please ignore message...')
} else {
  let isOpenLdapFound = false
  for (const key in config.entity) {
    if (config.entity[key]?.ldap?.isOpenLdap === true) {
      isOpenLdapFound = true
      break
    }
  }
  let idFound = false
  let userNameFound = false
  for (const key in config.map.user) {
    if (config.map.user[key].mapTo === 'id') idFound = true
    else if (['userName', 'externalId'].includes(config.map.user[key].mapTo)) userNameFound = true
    if (config.map.user[key]?.type === 'array' && config.map.user[key]?.typeInbound === 'string') {
      if (!Object.prototype.hasOwnProperty.call(config.map.user[key], 'typeOutboundReverse')) {
        config.map.user[key].typeOutboundReverse = !isOpenLdapFound
      }
    }
  }
  if (!idFound || !userNameFound) {
    scimgateway.logError('', 'configuration map.user missing mapTo definition for mandatory id/userName')
    throw new Error('using exception to exit, please ignore message...')
  }
}
if (!config?.map?.group) {
  scimgateway.logInfo('', 'configuration map.group is not defiend and groups will not be supported')
} else {
  let idFound = false
  let displayNameFound = false
  for (const key in config.map.group) {
    if (config.map.group[key].mapTo === 'id') idFound = true
    else if (config.map.group[key].mapTo === 'displayName') displayNameFound = true
    if (idFound && displayNameFound) break
  }
  if ((!idFound || !displayNameFound) && (Object.keys(config.map.group).length > 0)) {
    scimgateway.logError('', 'configuration map.group missing mapTo definition for mandatory id/displayName')
    throw new Error('using exception to exit, please ignore message...')
  }
}

for (const key in config.entity) {
  const userBase = config.entity[key]?.ldap?.userBase
  const groupBase = config.entity[key]?.ldap?.groupBase
  if (!userBase) {
    scimgateway.logError('', `configuration missing mandatory endpoint.entity.${key}.ldap.userBase`)
    throw new Error('using exception to exit, please ignore message...')
  }
  if (!groupBase && config?.map?.group && Object.keys(config.map.group).length > 0) {
    scimgateway.logError('', `configuration missing mandatory endpoint.entity.${key}.ldap.groupBase`)
    throw new Error('using exception to exit, please ignore message...')
  }
  let usrArr = config.entity[key]?.ldap?.namingAttribute?.user
  if (!usrArr || !Array.isArray(usrArr)) { // check for legacy
    const attr = config.entity[key]?.ldap?.userNamingAttr
    if (attr) {
      usrArr = [{ attribute: attr, mapTo: 'userName' }]
      if (!config.entity[key].ldap.namingAttribute) config.entity[key].ldap.namingAttribute = {}
      config.entity[key].ldap.namingAttribute.user = scimgateway.copyObj(usrArr)
    }
  }
  if (!Array.isArray(usrArr) || usrArr.length !== 1) {
    scimgateway.logError('', `configuration missing namingAttribute: endpoint.entity.${key}.ldap.namingAttribute.user`)
    throw new Error('using exception to exit, please ignore message...')
  }
  if (!usrArr[0].attribute || !usrArr[0].mapTo) {
    scimgateway.logError('', `configuration missing attribute/mapTo: endpoint.entity.${key}.ldap.namingAttribute.user`)
    throw new Error('using exception to exit, please ignore message...')
  }
  const [endpointAttr] = scimgateway.endpointMapper('outbound', usrArr[0].mapTo, config.map.user)
  if (!endpointAttr) {
    scimgateway.logError('', `configuration namingAttribute mapTo:${usrArr[0].mapTo} cannot be found in the map user configuration`)
    throw new Error('using exception to exit, please ignore message...')
  }

  let grpArr = config.entity[key]?.ldap?.namingAttribute?.group
  if (config?.map?.group && Object.keys(config.map.group).length > 0) {
    if (!grpArr || !Array.isArray(grpArr)) { // check for legacy
      const attr = config.entity[key]?.ldap?.groupNamingAttr
      if (attr) {
        grpArr = [{ attribute: attr, mapTo: 'displayName' }]
        if (!config.entity[key].ldap.namingAttribute) config.entity[key].ldap.namingAttribute = {}
        config.entity[key].ldap.namingAttribute.group = scimgateway.copyObj(grpArr)
      }
    }
    if (!Array.isArray(grpArr) || grpArr.length !== 1) {
      scimgateway.logError('', `configuration missing namingAttribute: endpoint.entity.${key}.ldap.namingAttribute.group`)
      throw new Error('using exception to exit, please ignore message...')
    }
    if (!grpArr[0].attribute || !grpArr[0].mapTo) {
      scimgateway.logError('', 'configuration missing attribute/mapTo: endpoint.entity.${key}.ldap.namingAttribute.group')
      throw new Error('using exception to exit, please ignore message...')
    }
    const [endpointAttr] = scimgateway.endpointMapper('outbound', grpArr[0].mapTo, config.map.group)
    if (!endpointAttr) {
      scimgateway.logError('', 'configuration namingAttribute mapTo:${grpArr[0].mapTo} cannot be found in the map group configuration')
      throw new Error('using exception to exit, please ignore message...')
    }
  }
}

config.useSID_id = config.map.user.objectSid && config.map.user.objectSid.mapTo === 'id' // AD proprietary SID/GUID
config.useGUID_id = config.map.user.objectGUID && config.map.user.objectGUID.mapTo === 'id'
if (config.useSID_id && config.map.group) {
  if (!config.map.group.objectSid || config.map.group.objectSid.mapTo !== 'id') {
    scimgateway.logError('', 'configuration missing group.objectSid - user and group should be using the same attribute')
    throw new Error('using exception to exit, please ignore message...')
  }
} else if (config.useGUID_id && config.map.group) {
  if (!config.map.group.objectGUID || config.map.group.objectGUID.mapTo !== 'id') {
    scimgateway.logError('', 'configuration missing group.objectGUID - user and group should be using the same attribute')
    throw new Error('using exception to exit, please ignore message...')
  }
}
if (config.map.user.userPrincipalName && config.map.user.userPrincipalName.mapDomain) { // support mapping different inbound/outbound upn domain names
  if (config.map.user.userPrincipalName.mapDomain.inbound && config.map.user.userPrincipalName.mapDomain.outbound) {
    const inbound = config.map.user.userPrincipalName.mapDomain.inbound
    const outbound = config.map.user.userPrincipalName.mapDomain.outbound
    config.map.user.userPrincipalName.mapDomain.inbound = inbound.startsWith('@') ? inbound : '@' + inbound // "@my-company.com"
    config.map.user.userPrincipalName.mapDomain.outbound = outbound.startsWith('@') ? outbound : '@' + outbound // "@test.onmicrosoft.com
  } else delete config.map.user.userPrincipalName.mapDomain
}
