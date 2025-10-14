// =================================================================================
// File:    plugin-scim.js
//
// Author:  Jarle Elshaug
//
// Purpose: REST Webservice user-provisioning using REST endpoint "loki"
//
// Prereq:  plugin-loki is up and running
//
// Supported attributes:
//
// GlobalUser   Template                                Scim                            Endpoint
// -----------------------------------------------------------------------------------------------
// User name    %AC%                                    userName                        userName
// Suspended     -                                      active                          active
// Password     %P%                                     password                        password
// First Name   %UF%                                    name.givenName                  name.givenName
// Last Name    %UL%                                    name.familyName                 name.familyName
// Full Name    %UN%                                    name.formatted                  name.formatted
// Job title    %UT%                                    title                           title
// Email        %UE% (Emails, type=Work)                emails.work                     emails [type eq work]
// Phone        %UP% (Phone Numbers, type=Work)         phoneNumbers.work               phoneNumbers [type eq work]
// Company      %UCOMP% (Entitlements, type=Company)    entitlements.company            entitlements [type eq company]
//
// =================================================================================

// start - mandatory plugin initialization
import { ScimGateway, HelperRest } from 'scimgateway'
const scimgateway = new ScimGateway()
const helper = new HelperRest(scimgateway)
const config = scimgateway.getConfig()
scimgateway.authPassThroughAllowed = false
// end - mandatory plugin initialization

// =================================================
// getUsers
// =================================================
scimgateway.getUsers = async (baseEntity, getObj, attributes, ctx) => {
  const action = 'getUsers'
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes} passThrough=${ctx ? 'true' : 'false'}`)

  const method = 'GET'
  let path
  const body = null

  // start mandatory if-else logic
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'userName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      if (getObj.attribute === 'id') path = `/Users/${getObj.value}?attributes=${attributes.join()}` // GET /Users/bjensen?attributes=
      else path = `/Users?filter=${getObj.attribute} eq "${getObj.value}"${(attributes.length > 0) ? '&attributes=' + attributes.join() : ''}` // GET /Users?filter=userName eq "bjensen"&attributes=userName,active,name.givenName,name.familyName,name.formatted,title,emails,phoneNumbers,entitlements
    } else if (getObj.operator === 'eq' && getObj.attribute === 'group.value') {
      // optional - only used when groups are member of users, not default behavior - correspond to getGroupUsers() in versions < 4.x.x
      path = `/Users?filter=${getObj.attribute} eq "${getObj.value}"${(attributes.length > 0) ? '&attributes=' + attributes.join() : ''}`
    } else {
      // optional - simpel filtering
      path = `/Users?filter=${getObj.attribute} ${getObj.operator} "${getObj.value}"${(attributes.length > 0) ? '&attributes=' + attributes.join() : ''}`
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all users to be returned - correspond to exploreUsers() in versions < 4.x.x
    path = `/Users${(attributes.length > 0 ? '?attributes=' + attributes.join() : '')}`
  }
  // end mandatory if-else logic

  if (!path) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  const ret: any = { // itemsPerPage will be set by scimgateway
    Resources: [],
    totalResults: null,
  }

  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (response.statusCode > 399) {
      throw new Error(`${response.statusMessage} - ${JSON.stringify(response.body)}`)
    } else if (!response.body) {
      throw new Error('got empty response on REST request')
    }

    let responseArr: any = []
    if (Array.isArray(response.body.Resources)) responseArr = response.body.Resources
    else if (!response.body.Resources) {
      if (Array.isArray(response.body)) responseArr = response.body
      else if (typeof (response.body) === 'object' && Object.keys(response.body).length > 0) responseArr = [response.body]
    }

    if (!getObj.startIndex && !getObj.count) { // client request without paging
      getObj.startIndex = 1
      getObj.count = responseArr.length
    }

    for (let i = 0; i < responseArr.length && (i + 1 - getObj.startIndex) < getObj.count; ++i) {
      const userObj: any = responseArr[i]
      if (!userObj || Object.keys(userObj).length < 1) continue

      const objWorkEmail = scimgateway.getArrayObject(userObj, 'emails', 'work') // {"type": "work", "value": "bjensen@example.com"}
      const objWorkPhone = scimgateway.getArrayObject(userObj, 'phoneNumbers', 'work')
      const objCompanyEntitlement = scimgateway.getArrayObject(userObj, 'entitlements', 'company')

      let arrEmail
      let arrPhone
      let arrEntitlement
      if (objWorkEmail) arrEmail = [objWorkEmail]
      if (objWorkPhone) arrPhone = [objWorkPhone]
      if (objCompanyEntitlement) arrEntitlement = [objCompanyEntitlement]

      const retObj = { // scimgateway strips attributes according to attributes list and will also auto include groups if needed
        id: userObj.id ? userObj.id : undefined, // id and userName is mandatory and most often set to the same value
        userName: userObj.userName ? userObj.userName : undefined,
        active: userObj.active === true || userObj.active === false ? userObj.active : undefined,
        name: {
          givenName: userObj.name && userObj.name.givenName ? userObj.name.givenName : undefined,
          familyName: userObj.name && userObj.name.familyName ? userObj.name.familyName : undefined,
          formatted: userObj.name && userObj.name.formatted ? userObj.name.formatted : undefined,
        },
        title: userObj.title ? userObj.title : undefined,
        emails: arrEmail,
        phoneNumbers: arrPhone,
        entitlements: arrEntitlement,
      }

      ret.Resources.push(retObj)
    }

    ret.totalResults = responseArr.length // not needed if client or endpoint do not support paging
    return ret
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj, ctx) => {
  const action = 'createUser'
  scimgateway.logDebug(baseEntity, `handling ${action} userObj=${JSON.stringify(userObj)} passThrough=${ctx ? 'true' : 'false'}`)

  if (!userObj.name) userObj.name = {}
  if (!userObj.emails) userObj.emails = { work: {} }
  if (!userObj.phoneNumbers) userObj.phoneNumbers = { work: {} }
  if (!userObj.entitlements) userObj.entitlements = { company: {} }

  const arrEmail: string[] = []
  const arrPhone: string[] = []
  const arrEntitlement: string[] = []
  if (userObj.emails.work.value) arrEmail.push(userObj.emails.work)
  if (userObj.phoneNumbers.work.value) arrPhone.push(userObj.phoneNumbers.work)
  if (userObj.entitlements.company.value) arrEntitlement.push(userObj.entitlements.company)

  const method = 'POST'
  const path = '/Users'
  const body = {
    userName: userObj.userName,
    active: userObj.active || true,
    password: userObj.password || null,
    name: {
      givenName: userObj.name.givenName || null,
      familyName: userObj.name.familyName || null,
      formatted: userObj.name.formatted || null,
    },
    title: userObj.title || '',
    emails: (arrEmail.length > 0) ? arrEmail : null,
    phoneNumbers: (arrPhone.length > 0) ? arrPhone : null,
    entitlements: (arrEntitlement.length > 0) ? arrEntitlement : null,
  }

  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (response.statusCode > 399) {
      throw new Error(`${response.statusMessage} - ${JSON.stringify(response.body)}`)
    }
    return null
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id, ctx) => {
  const action = 'deleteUser'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} passThrough=${ctx ? 'true' : 'false'}`)

  const method = 'DELETE'
  const path = `/Users/${id}`
  const body = null

  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (response.statusCode > 399) {
      throw new Error(`${response.statusMessage} - ${JSON.stringify(response.body)}`)
    }
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

  if (!attrObj.name) attrObj.name = {}
  if (!attrObj.emails) attrObj.emails = {}
  if (!attrObj.phoneNumbers) attrObj.phoneNumbers = {}
  if (!attrObj.entitlements) attrObj.entitlements = {}

  const arrEmail: string[] = []
  const arrPhone: string[] = []
  const arrEntitlement: string[] = []
  if (attrObj.emails.work) {
    if (!attrObj.emails.work.type) attrObj.emails.work.type = 'work'
    arrEmail.push(attrObj.emails.work)
  }
  if (attrObj.phoneNumbers.work) {
    if (!attrObj.phoneNumbers.work.type) attrObj.phoneNumbers.work.type = 'work'
    arrPhone.push(attrObj.phoneNumbers.work)
  }
  if (attrObj.entitlements.company) {
    if (!attrObj.entitlements.company.type) attrObj.entitlements.company.type = 'work'
    arrEntitlement.push(attrObj.entitlements.company)
  }

  const method = 'PATCH'
  const path = `/Users/${id}`
  let body: any = {} // { userName: id }
  if (attrObj.active === true) body.active = true
  else if (attrObj.active === false) body.active = false

  if (attrObj.password) body.password = attrObj.password

  if (attrObj.name.givenName || attrObj.name.givenName === '') {
    if (!body.name) body.name = {}
    body.name.givenName = attrObj.name.givenName
  }
  if (attrObj.name.familyName || attrObj.name.familyName === '') {
    if (!body.name) body.name = {}
    body.name.familyName = attrObj.name.familyName
  }
  if (attrObj.name.formatted || attrObj.name.formatted === '') {
    if (!body.name) body.name = {}
    body.name.formatted = attrObj.name.formatted
  }
  if (attrObj.title || attrObj.title === '') {
    body.title = attrObj.title
  }
  if (arrEmail.length > 0) {
    body.emails = arrEmail
  }
  if (arrPhone.length > 0) {
    body.phoneNumbers = arrPhone
  }
  if (arrEntitlement.length > 0) {
    body.entitlements = arrEntitlement
  }

  if (!config.entity[baseEntity].scimVersion || config.entity[baseEntity].scimVersion !== '1.1') { // scim 2.0 endpoint
    body = {
      Operations: [
        {
          op: 'replace',
          value: body,
        },
      ],
    }
  }

  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (response.statusCode > 399) {
      throw new Error(`${response.statusMessage} - ${JSON.stringify(response.body)}`)
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
  const action = 'getGroups'
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes} passThrough=${ctx ? 'true' : 'false'}`)

  const method = 'GET'
  let path
  const body = null

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'displayName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      if (getObj.attribute === 'id') path = `/Groups/${getObj.value}?attributes=${attributes.join()}` // GET /Users/bjensen?attributes=
      else path = `/Groups?filter=${getObj.attribute} eq "${getObj.value}"${(attributes.length > 0) ? '&attributes=' + attributes.join() : ''}` // GET /Users?filter=userName eq "bjensen"&attributes=userName,active,name.givenName,name.familyName,name.formatted,title,emails,phoneNumbers,entitlements
    } else if (getObj.operator === 'eq' && getObj.attribute === 'members.value') {
      // mandatory - return all groups the user 'id' (getObj.value) is member of - correspond to getGroupMembers() in versions < 4.x.x
      // Resources = [{ id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }]
      path = `/Groups?filter=${getObj.attribute} eq "${getObj.value}"${(attributes.length > 0) ? '&attributes=' + attributes.join() : ''}`
    } else {
      // optional - simpel filtering
      path = `/Groups?filter=${getObj.attribute} eq "${getObj.value}"${(attributes.length > 0) ? '&attributes=' + attributes.join() : ''}`
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all groups to be returned - correspond to exploreGroups() in versions < 4.x.x
    path = `/Groups${(attributes.length > 0 ? '?attributes=' + attributes.join() : '')}`
  }
  // mandatory if-else logic - end

  if (!path) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  const ret: any = { // itemsPerPage will be set by scimgateway
    Resources: [],
    totalResults: null,
  }

  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (response.statusCode > 399) {
      throw new Error(`${response.statusMessage} - ${JSON.stringify(response.body)}`)
    } else if (!response.body) {
      throw new Error('got empty response on REST request')
    }

    let responseArr: any = []
    if (Array.isArray(response.body.Resources)) responseArr = response.body.Resources
    else if (!response.body.Resources) {
      if (Array.isArray(response.body)) responseArr = response.body
      else if (typeof (response.body) === 'object' && Object.keys(response.body).length > 0) responseArr = [response.body]
    }

    if (!getObj.startIndex && !getObj.count) { // client request without paging
      getObj.startIndex = 1
      getObj.count = responseArr.length
    }

    for (let i = 0; i < responseArr.length && (i + 1 - getObj.startIndex) < getObj.count; ++i) {
      const groupObj = responseArr[i]
      if (!groupObj || Object.keys(groupObj).length < 1) continue

      const retObj = { // scimgateway strips attributes according to attributes list
        id: groupObj.id ? groupObj.id : undefined, // id and displayName is mandatory and most often set to the same value
        displayName: groupObj.displayName ? groupObj.displayName : undefined,
        members: Array.isArray(groupObj.members) ? groupObj.members : undefined,
      }
      ret.Resources.push(retObj)
    }

    ret.totalResults = responseArr.length // not needed if client or endpoint do not support paging
    return ret
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

  const method = 'POST'
  const path = '/Groups'
  const body = { displayName: groupObj.displayName }

  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (response.statusCode > 399) {
      throw new Error(`${response.statusMessage} - ${JSON.stringify(response.body)}`)
    }
    return null
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id, ctx) => {
  const action = 'deleteGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} passThrough=${ctx ? 'true' : 'false'}`)

  const method = 'DELETE'
  const path = `/Groups/${id}`
  const body = null

  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (response.statusCode > 399) {
      throw new Error(`${response.statusMessage} - ${JSON.stringify(response.body)}`)
    }
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

  if (!attrObj.members) {
    throw new Error(`${action} error: only supports modification of members`)
  }
  if (!Array.isArray(attrObj.members)) {
    throw new Error(`${action} error: ${JSON.stringify(attrObj)} - correct syntax is { "members": [...] }`)
  }

  let body: any = {}
  if (config.entity[baseEntity].scimVersion && config.entity[baseEntity].scimVersion === '1.1') { // scim v1.1 endpoint
    body = { members: [] }
    attrObj.members.forEach(function (el) {
      if (el.operation && el.operation === 'delete') { // delete member from group
        // PATCH = /Groups/Admins Body = {"members":[{"operation":"delete","value":"bjensen"}]}
        body.members.push({ operation: 'delete', value: el.value })
      } else { // add member to group/
        // PATCH = /Groups/Admins Body = {"members":[{"value":"bjensen"}]
        body.members.push({ value: el.value })
      }
    })
  } else { // scim 2.0 endpoint
    const addValues: any = []
    const removeValues: any = []
    attrObj.members.forEach(function (el) {
      if (el.operation && el.operation === 'delete') { // delete member from group
        removeValues.push({ value: el.value })
      } else { // add member to group/
        addValues.push({ value: el.value })
      }
    })
    if (addValues.length < 1 && removeValues.length < 1) return null
    body = { Operations: [] }
    if (addValues.length > 0) {
      body.Operations.push(
        {
          op: 'add',
          path: 'members',
          value: addValues,
        },
      )
    }
    if (removeValues.length > 0) {
      body.Operations.push(
        {
          op: 'remove',
          path: 'members',
          value: removeValues,
        },
      )
    }
  }

  const method = 'PATCH'
  const path = `/Groups/${id}`

  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (response.statusCode > 399) {
      throw new Error(`${response.statusMessage} - ${JSON.stringify(response.body)}`)
    }
    return null
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
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
