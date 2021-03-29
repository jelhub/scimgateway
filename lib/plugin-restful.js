// =================================================================================
// File:    plugin-restful.js
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

'use strict'

const http = require('http')
const https = require('https')
const HttpsProxyAgent = require('https-proxy-agent')
const URL = require('url').URL
const querystring = require('querystring')

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
  'userName', // userName or externalId is mandatory
  'active', // active is mandatory for IM
  'password',
  'name.givenName',
  'name.familyName',
  'name.formatted',
  'title',
  // "emails",         // accepts all multivalues for this key
  'emails.work', // accepts multivalues if type value equal work (lowercase)
  // "phoneNumbers",
  'phoneNumbers.work',
  // "entitlements"
  'entitlements.company'
]
let config = require(configFile).endpoint
config = scimgateway.processExtConfig(pluginName, config) // add any external config process.env and process.file
// mandatory plugin initialization - end

const _serviceClient = {}

// =================================================
// exploreUsers
// =================================================
scimgateway.exploreUsers = async (baseEntity, attributes, startIndex, count) => {
  const action = 'exploreUsers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`)
  const ret = { // itemsPerPage will be set by scimgateway
    Resources: [],
    totalResults: null
  }

  const method = 'GET'
  const path = `/Users${(attributes ? '?attributes=' + attributes : '')}`
  const body = null

  try {
    const response = await doRequest(baseEntity, method, path, body)
    if (response.statusCode < 200 || response.statusCode > 299) {
      const err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
      throw (err)
    } else if (!response.body.Resources) {
      const err = new Error(`${action}: Got empty response on REST request`)
      throw (err)
    }
    if (!startIndex && !count) { // client request without paging
      startIndex = 1
      count = response.body.Resources.length
    }

    const arrAttr = attributes.split(',')
    for (let index = startIndex - 1; index < response.body.Resources.length && (index + 1 - startIndex) < count; ++index) {
      const retObj = response.body.Resources[index]
      if (!attributes) ret.Resources.push(retObj)
      else { // return according to attributes (userName or externalId should normally be included and id=userName/externalId)
        let found = false
        const obj = {}
        for (let i = 0; i < arrAttr.length; i++) {
          const key = arrAttr[i].split('.')[0] // title => title, name.familyName => name
          if (retObj[key]) {
            obj[key] = retObj[key]
            found = true
          }
        }
        if (found) ret.Resources.push(obj)
      }
    }
    // not needed if client or endpoint do not support paging
    ret.totalResults = response.body.Resources.length
    ret.startIndex = startIndex
    return ret // all explored users
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

  const arrAttr = attributes.split(',')
  const ret = { // itemsPerPage will be set by scimgateway
    Resources: [],
    totalResults: null
  }

  const method = 'GET'
  const path = '/Groups'
  const body = null

  try {
    const response = await doRequest(baseEntity, method, path, body)
    if (response.statusCode < 200 || response.statusCode > 299) {
      const err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
      throw err
    } else if (!response.body.Resources) {
      const err = new Error(`${action}: Got empty response on REST request`)
      throw err
    }
    if (!startIndex && !count) { // client request without paging
      startIndex = 1
      count = response.body.Resources.length
    }
    for (let index = startIndex - 1; index < response.body.Resources.length && (index + 1 - startIndex) < count; ++index) {
      if (response.body.Resources[index].id && response.body.Resources[index].displayName) {
        const scimGroup = { // displayName and id is mandatory, note: we set id=displayName
          displayName: response.body.Resources[index].displayName,
          id: response.body.Resources[index].id,
          externalId: response.body.Resources[index].displayName
        }
        if (!attributes || (arrAttr.includes('members') || arrAttr.includes('members.value'))) {
          scimGroup.members = response.body.Resources[index].members
        }
        ret.Resources.push(scimGroup)
      }
    }
    // not needed if client or endpoint do not support paging
    ret.totalResults = response.body.Resources.length
    ret.startIndex = startIndex
    return ret // all explored users
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

// =================================================
// getUser
// =================================================
scimgateway.getUser = async (baseEntity, getObj, attributes) => {
  // getObj = { filter: <filterAttribute>, identifier: <identifier> }
  // e.g: getObj = { filter: 'userName', identifier: 'bjensen'}
  // filter: userName and id must be supported
  // (they are most often considered as "the same" where identifier = UserID )
  // Note, the value of id attribute returned will be used by modifyUser and deleteUser
  // attributes: if not blank, attributes listed should be returned
  // Should normally return all supported user attributes having id and userName as mandatory
  // SCIM Gateway will automatically filter response according to the attributes list
  const action = 'getUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" ${getObj.filter}=${getObj.identifier} attributes=${attributes}`)

  /*
  const findObj = {}
  findObj[getObj.filter] = getObj.identifier // { userName: 'bjensen } / { externalId: 'bjensen } / { id: 'bjensen } / { 'emails.value': 'jsmith@example.com'} / { 'phoneNumbers.value': '555-555-5555'}
  */

  const method = 'GET'
  let path
  if (getObj.filter === 'id') path = `/Users/${getObj.identifier}?attributes=${attributes}` // GET /Users/bjensen?attributes=
  else path = `/Users?filter=${getObj.filter} eq "${getObj.identifier}"${(attributes) ? '&attributes=' + attributes : ''}` // GET /Users?filter=userName eq "bjensen"&attributes=userName,active,name.givenName,name.familyName,name.formatted,title,emails,phoneNumbers,entitlements
  const body = null

  try {
    const response = await doRequest(baseEntity, method, path, body)
    if (response.statusCode < 200 || response.statusCode > 299) {
      const err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
      throw err
    } else if (!response.body) {
      const err = new Error(`${action}: Got empty response on REST request`)
      throw err
    }

    let userObj
    if (response.body.Resources && Array.isArray(response.body.Resources) && response.body.Resources.length === 1) userObj = response.body.Resources[0]
    else userObj = response.body
    if (!userObj || Object.keys(userObj).length < 1) return null // user not found

    if (!userObj.name) userObj.name = {}
    if (!userObj.emails) userObj.emails = [{}]
    if (!userObj.phoneNumbers) userObj.phoneNumbers = [{}]
    if (!userObj.entitlements) userObj.entitlements = [{}]

    const objWorkEmail = scimgateway.getArrayObject(userObj, 'emails', 'work')
    const objWorkPhone = scimgateway.getArrayObject(userObj, 'phoneNumbers', 'work')
    const objCompanyEntitlement = scimgateway.getArrayObject(userObj, 'entitlements', 'company')

    let arrEmail = []
    let arrPhone = []
    let arrEntitlement = []
    if (objWorkEmail) arrEmail.push(objWorkEmail)
    else arrEmail = null
    if (objWorkPhone) arrPhone.push(objWorkPhone)
    else arrPhone = null
    if (objCompanyEntitlement) arrEntitlement.push(objCompanyEntitlement)
    else arrEntitlement = null

    const retObj = {
      userName: userObj.userName,
      id: userObj.id,
      active: userObj.active,
      name: {
        givenName: userObj.name.givenName || '',
        familyName: userObj.name.familyName || '',
        formatted: userObj.name.formatted || ''
      },
      title: userObj.title,
      emails: arrEmail,
      phoneNumbers: arrPhone,
      entitlements: arrEntitlement
    }

    // scimgateway will auto include groups if not included by plugin
    // in this use case it's already done when endpoint is scimgateway (plugin-loki)
    // groups can be retrieved using: await scimgateway.getGroupMembers(baseEntity, userObj.id, 'members.value,id,displayName')
    if (userObj.groups && Array.isArray(userObj.groups)) retObj.groups = userObj.groups

    if (!attributes) return retObj // user with all attributes
    // return according to attributes
    const ret = {}
    const arrAttr = attributes.split(',')
    for (let i = 0; i < arrAttr.length; i++) {
      const attr = arrAttr[i].split('.') // title / name.familyName / emails.value
      if (retObj[attr[0]]) {
        if (attr.length === 1) ret[attr[0]] = retObj[attr[0]]
        else if (retObj[attr[0]][attr[1]]) { // name.familyName
          if (!ret[attr[0]]) ret[attr[0]] = {}
          ret[attr[0]][attr[1]] = retObj[attr[0]][attr[1]]
        } else if (Array.isArray(retObj[attr[0]])) { // emails.value / phoneNumbers.type
          if (!ret[attr[0]]) ret[attr[0]] = []
          const arr = retObj[attr[0]]
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
    if (JSON.stringify(ret) === '{}') return retObj // user with all attributes when specified attributes not found
    return ret
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj) => {
  const action = 'createUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" userObj=${JSON.stringify(userObj)}`)

  const notValid = scimgateway.notValidAttributes(userObj, validScimAttr)
  if (notValid) {
    const err = new Error(`unsupported scim attributes: ${notValid} ` +
      `(supporting only these attributes: ${validScimAttr.toString()})`
    )
    throw err
  }

  if (!userObj.name) userObj.name = {}
  if (!userObj.emails) userObj.emails = { work: {} }
  if (!userObj.phoneNumbers) userObj.phoneNumbers = { work: {} }
  if (!userObj.entitlements) userObj.entitlements = { company: {} }

  const arrEmail = []
  const arrPhone = []
  const arrEntitlement = []
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
      formatted: userObj.name.formatted || null
    },
    title: userObj.title || '',
    emails: (arrEmail.length > 0) ? arrEmail : null,
    phoneNumbers: (arrPhone.length > 0) ? arrPhone : null,
    entitlements: (arrEntitlement.length > 0) ? arrEntitlement : null
  }

  try {
    const response = await doRequest(baseEntity, method, path, body)
    if (response.statusCode < 200 || response.statusCode > 299) {
      const err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
      throw err
    }
    return null
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id) => {
  const action = 'deleteUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)

  const method = 'DELETE'
  const path = `/Users/${id}`
  const body = null

  try {
    const response = await doRequest(baseEntity, method, path, body)
    if (response.statusCode < 200 || response.statusCode > 299) {
      const err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
      throw err
    }
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

  const notValid = scimgateway.notValidAttributes(attrObj, validScimAttr)
  if (notValid) {
    const err = new Error(`unsupported scim attributes: ${notValid} ` +
      `(supporting only these attributes: ${validScimAttr.toString()})`
    )
    throw err
  }

  if (!attrObj.name) attrObj.name = {}
  if (!attrObj.emails) attrObj.emails = {}
  if (!attrObj.phoneNumbers) attrObj.phoneNumbers = {}
  if (!attrObj.entitlements) attrObj.entitlements = {}

  const arrEmail = []
  const arrPhone = []
  const arrEntitlement = []
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
  let body = {} // { userName: id }
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
          value: body
        }
      ]
    }
  }

  try {
    const response = await doRequest(baseEntity, method, path, body)
    if (response.statusCode < 200 || response.statusCode > 299) {
      const err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
      throw err
    }
    return null
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

// =================================================
// getGroup
// =================================================
scimgateway.getGroup = async (baseEntity, getObj, attributes) => {
  // getObj = { filter: <filterAttribute>, identifier: <identifier> }
  // e.g: getObj = { filter: 'displayName', identifier: 'GroupA' }
  // filter: displayName and id must be supported
  // (they are most often considered as "the same" where identifier = GroupName)
  // Note, the value of id attribute returned will be used by deleteGroup, getGroupMembers and modifyGroup
  // attributes: if not blank, attributes listed should be returned
  // Should normally return all supported group attributes having id, displayName and members as mandatory
  // members may be skipped if attributes is not blank and do not contain members or members.value
  const action = 'getGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" ${getObj.filter}=${getObj.identifier} attributes=${attributes}`)

  const method = 'GET'
  const path = `/Groups?filter=${getObj.filter} eq "${getObj.identifier}"${(attributes) ? '&attributes=' + attributes : ''}` // GET = /Groups?filter=displayName eq "Admins"&attributes=externalId,id,members.value,displayName
  const body = null

  try {
    const response = await doRequest(baseEntity, method, path, body)
    if (!response.body.Resources) {
      const err = new Error(`${action}: Got empty response on REST request`)
      throw err
    }
    const retObj = {}
    if (response.body.Resources.length === 1) {
      const groupObj = response.body.Resources[0]
      if (!groupObj) return null // no group found
      // not parsing attributes in this example, returning what's mandatory for most IdP's
      retObj[getObj.filter] = groupObj[getObj.filter] // incase none of below (e.g. externalId)
      retObj.displayName = groupObj.displayName // mandatory
      retObj.id = groupObj.displayName // value same as displayName
      if (Array.isArray(groupObj.members)) { // comment out this line if using "users are member of group"
        retObj.members = []
        groupObj.members.forEach((el) => {
          if (el.value) retObj.members.push({ value: el.value })
        })
      }
    }
    return retObj
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

// =================================================
// getGroupMembers
// =================================================
scimgateway.getGroupMembers = async (baseEntity, id, attributes) => {
  // return all groups the user is member of having attributes included e.g: members.value,id,displayName
  // method used when "users member of group", if used - getUser must treat user attribute groups as virtual readOnly attribute
  // "users member of group" is SCIM default and this method should normally have some logic
  const action = 'getGroupMembers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" user id=${id} attributes=${attributes}`)
  const arrRet = []

  const method = 'GET'
  const path = `/Groups?filter=members.value eq "${id}"&attributes=${attributes}` // GET = /Groups?filter=members.value eq "bjensen"&attributes=members.value,displayName
  const body = null

  try {
    const response = await doRequest(baseEntity, method, path, body)
    if (!response.body.Resources) {
      const err = new Error(`${action}: Got empty response on REST request`)
      throw err
    }
    response.body.Resources.forEach(function (element) {
      if (Array.isArray(element.members)) {
        element.members.forEach(function (el) {
          if (el.value === id) { // user is member of group
            const userGroup = {
              id: element.id,
              displayName: element.displayName, // displayName is mandatory
              members: [{ value: el.value }] // only includes current user
            }
            arrRet.push(userGroup) // { id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }
          }
        })
      }
    })
    return arrRet
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

// =================================================
// getGroupUsers
// =================================================
scimgateway.getGroupUsers = async (baseEntity, id, attributes) => {
  // return array of all users that is member of this group id having attributes included e.g: groups.value,userName
  // method used when "group member of users", if used - getGroup must treat group attribute members as virtual readOnly attribute
  const action = 'getGroupUsers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attributes=${attributes}`)
  const arrRet = []
  return arrRet
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj) => {
  const action = 'createGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" groupObj=${JSON.stringify(groupObj)}`)

  const method = 'POST'
  const path = '/Groups'
  const body = { displayName: groupObj.displayName }

  try {
    const response = await doRequest(baseEntity, method, path, body)
    if (response.statusCode < 200 || response.statusCode > 299) {
      const err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
      throw err
    }
    return null
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id) => {
  const action = 'deleteGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)

  const method = 'DELETE'
  const path = `/Groups/${id}`
  const body = null

  try {
    const response = await doRequest(baseEntity, method, path, body)
    if (response.statusCode < 200 || response.statusCode > 299) {
      const err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
      throw err
    }
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

  if (!attrObj.members) {
    throw new Error(`plugin handling "${action}" only supports modification of members`)
  }
  if (!Array.isArray(attrObj.members)) {
    throw new Error(`plugin handling "${action}" error: ${JSON.stringify(attrObj)} - correct syntax is { "members": [...] }`)
  }

  let body = {}
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
    const addValues = []
    const removeValues = []
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
          value: addValues
        }
      )
    }
    if (removeValues.length > 0) {
      body.Operations.push(
        {
          op: 'remove',
          path: 'members',
          value: removeValues
        }
      )
    }
  }

  const method = 'PATCH'
  const path = `/Groups/${id}`

  try {
    const response = await doRequest(baseEntity, method, path, body)
    if (response.statusCode < 200 || response.statusCode > 299) {
      const err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
      throw err
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
// getServiceClient - returns options needed for connection parameters
//
//   path = e.g. "/xxx/yyy", then using host/port/protocol based on config baseUrls[0]
//          auth automatically added and failover according to baseUrls array
//
//   path = url e.g. "http(s)://<host>:<port>/xxx/yyy", then using the url host/port/protocol
//          opt (options) may be needed e.g {auth: {username: "username", password: "password"} }
//
const getServiceClient = async (baseEntity, method, path, opt) => {
  const action = 'getServiceClient'

  let urlObj
  if (!path) path = ''
  try {
    urlObj = new URL(path)
  } catch (err) {
    //
    // path (no url) - default approach and client will be cached based on config
    //
    if (_serviceClient[baseEntity]) { // serviceClient already exist
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: Using existing client`)
    } else {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: Client have to be created`)
      let client = null
      if (config.entity && config.entity[baseEntity]) client = config.entity[baseEntity]
      if (!client) {
        const err = new Error(`Base URL have baseEntity=${baseEntity}, and configuration file ${pluginName}.json is missing required baseEntity configuration for ${baseEntity}`)
        throw err
      }

      urlObj = new URL(config.entity[baseEntity].baseUrls[0])
      const param = {
        baseUrl: config.entity[baseEntity].baseUrls[0],
        options: {
          json: true, // json-object response instead of string
          headers: {
            'Content-Type': 'application/json',
            Authorization: 'Basic ' + Buffer.from(`${config.entity[baseEntity].username}:${scimgateway.getPassword(`endpoint.entity.${baseEntity}.password`, configFile)}`).toString('base64')
          },
          host: urlObj.hostname,
          port: urlObj.port, // null if https and 443 defined in url
          protocol: urlObj.protocol, // http: or https:
          rejectUnauthorized: false // accepts self-siged certificates
          // 'method' and 'path' added at the end
        }
      }

      // proxy
      if (config.entity[baseEntity].proxy && config.entity[baseEntity].proxy.host) {
        const agent = new HttpsProxyAgent(config.entity[baseEntity].proxy.host)
        param.options.agent = agent // proxy
        if (config.entity[baseEntity].proxy.username && config.entity[baseEntity].proxy.password) {
          param.options.headers['Proxy-Authorization'] = 'Basic ' + Buffer.from(`${config.entity[baseEntity].proxy.username}:${scimgateway.getPassword(`endpoint.entity.${baseEntity}.proxy.password`, configFile)}`).toString('base64') // using proxy with auth
        }
      }

      if (!_serviceClient[baseEntity]) _serviceClient[baseEntity] = {}
      _serviceClient[baseEntity] = param // serviceClient created
    }

    const cli = scimgateway.copyObj(_serviceClient[baseEntity]) // client ready

    // failover support
    path = _serviceClient[baseEntity].baseUrl + path
    urlObj = new URL(path)
    cli.options.host = urlObj.hostname
    cli.options.port = urlObj.port
    cli.options.protocol = urlObj.protocol

    // adding none static
    cli.options.method = method
    cli.options.path = `${urlObj.pathname}${urlObj.search}`
    if (opt) cli.options = scimgateway.extendObj(cli.options, opt) // merge with argument options

    return cli // final client
  }
  //
  // url path - none config based and used as is (no cache)
  //
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: Using none config based client`)
  let options = {
    json: true,
    headers: {
      'Content-Type': 'application/json'
    },
    host: urlObj.hostname,
    port: urlObj.port,
    protocol: urlObj.protocol,
    method: method,
    path: urlObj.pathname
  }

  // proxy
  if (config.entity[baseEntity].proxy && config.entity[baseEntity].proxy.host) {
    const agent = new HttpsProxyAgent(config.entity[baseEntity].proxy.host)
    options.agent = agent // proxy
    if (config.entity[baseEntity].proxy.username && config.entity[baseEntity].proxy.password) {
      options.headers['Proxy-Authorization'] = 'Basic ' + Buffer.from(`${config.entity[baseEntity].proxy.username}:${scimgateway.getPassword(`endpoint.entity.${baseEntity}.proxy.password`, configFile)}`).toString('base64') // using proxy with auth
    }
  }

  // merge any argument options - support basic auth using {auth: {username: "username", password: "password"} }
  if (opt) {
    const o = scimgateway.copyObj(opt)
    if (o.auth) {
      options.headers.Authorization = 'Basic ' + Buffer.from(`${o.auth.username}:${o.auth.password}`).toString('base64')
      delete o.auth
    }
    options = scimgateway.extendObj(options, o)
  }

  const cli = {}
  cli.options = options
  return cli // final client
}

const updateServiceClient = (baseEntity, obj) => {
  if (_serviceClient[baseEntity]) _serviceClient[baseEntity] = scimgateway.extendObj(_serviceClient[baseEntity], obj) // merge with argument options
}

//
// doRequest - execute REST service
//
const doRequest = async (baseEntity, method, path, body, opt, retryCount) => {
  try {
    const cli = await getServiceClient(baseEntity, method, path, opt)
    const options = cli.options
    const result = await new Promise((resolve, reject) => {
      let dataString = ''
      if (body) {
        if (options.headers['Content-Type'].toLowerCase() === 'application/x-www-form-urlencoded') {
          if (typeof data === 'string') dataString = body
          else dataString = querystring.stringify(body) // JSON to query string syntax + URL encoded
        } else dataString = JSON.stringify(body)
        options.headers['Content-Length'] = Buffer.byteLength(dataString, 'utf8')
      }

      const reqType = (options.protocol.toLowerCase() === 'https:') ? https.request : http.request
      const req = reqType(options, (res) => {
        const { statusCode, statusMessage } = res // solving parallel problem (const + don't use res.statusCode)

        let responseString = ''
        res.setEncoding('utf-8')

        res.on('data', (chunk) => {
          responseString += chunk
        })

        res.on('end', () => {
          const response = {
            statusCode: statusCode,
            statusMessage: statusMessage,
            body: null
          }
          try {
            if (responseString) response.body = JSON.parse(responseString)
          } catch (err) { response.body = responseString }
          if (statusCode < 200 || statusCode > 299) reject(new Error(JSON.stringify(response)))
          resolve(response)
        })
      }) // req

      req.on('socket', (socket) => {
        socket.setTimeout(60000) // connect and wait timeout => socket hang up
        socket.on('timeout', function () { req.abort() })
      })

      req.on('error', (error) => { // also catching req.abort
        req.end()
        reject(error)
      })

      if (dataString) req.write(dataString)
      req.end()
    }) // Promise

    scimgateway.logger.debug(`${pluginName}[${baseEntity}] doRequest ${method} ${options.protocol}//${options.host}${(options.port ? `:${options.port}` : '')}${path} Body = ${JSON.stringify(body)} Response = ${JSON.stringify(result)}`)
    return result
  } catch (err) { // includes failover/retry logic based on config baseUrls array
    scimgateway.logger.error(`${pluginName}[${baseEntity}] doRequest ${method} ${path} Body = ${JSON.stringify(body)} Error Response = ${err.message}`)
    if (!retryCount) retryCount = 0
    let urlObj
    try { urlObj = new URL(path) } catch (err) {}
    if (!urlObj && (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND')) {
      if (retryCount < config.entity[baseEntity].baseUrls.length) {
        retryCount++
        updateServiceClient(baseEntity, { baseUrl: config.entity[baseEntity].baseUrls[retryCount - 1] })
        scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${(config.entity[baseEntity].baseUrls.length > 1) ? 'failover ' : ''}retry[${retryCount}] using baseUrl = ${_serviceClient[baseEntity].baseUrl}`)
        const ret = await doRequest(baseEntity, method, path, body, opt, retryCount) // retry
        return ret // problem fixed
      } else {
        const newerr = new Error(err.message)
        newerr.message = newerr.message.replace('ECONNREFUSED', 'UnableConnectingService') // avoid returning ECONNREFUSED error
        newerr.message = newerr.message.replace('ENOTFOUND', 'UnableConnectingHost') // avoid returning ENOTFOUND error
        throw newerr
      }
    } else throw err // CA IM retries getUser failure once (retry 6 times on ECONNREFUSED)
  }
} // doRequest

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})
