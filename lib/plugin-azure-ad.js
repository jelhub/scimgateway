// =====================================================================================================================
// File:    plugin-azure-ad.js
//
// Author:  Jarle Elshaug
//
// Purpose: Azure AD provisioning including licenses e.g. O365
//
// Prereq:  Azure AD configuration:
//          Application key defined (clientsecret)
//          plugin-azure-ad.json configured with corresponding clientid and clientsecret
//          Application permission "Windows Azure Active Directory" - all "Application Permissions"
//          Application must be member of "User Account Administrator" (powershell import-Module MSOnline)
//
// Notes: For CA Provisioning - Use ConnectorXpress, import metafile
//        "node_modules\scimgateway\resources\Azure - ScimGateway.xml" for creating endpoint
//
//        Using "Custom SCIM" attributes defined in scimgateway.endpointMap
//        Some functionality will also work using standard SCIM
//        You could also use your own version of endpointMap
//
// /User                                      SCIM (custom)                       Endpoint (AAD)
// --------------------------------------------------------------------------------------------
// User Principal Name                        userName                            userPrincipalName
// Id                                         id                                  id
// Suspended                                  active                              accountEnabled
// Password                                   passwordProfile.password            passwordProfile.password
// First Name                                 name.givenName                      givenName
// Last Name                                  name.familyName                     surname
// Fullname                                   displayName                         displayName
// E-mail                                     mail                                mail
// Mobile Number                              mobilePhone                         mobilePhone
// Phone Number                               businessPhones                      businessPhones
// Manager Id                                 manager.managerId                   manager
// City                                       city                                city
// Country                                    country                             country
// Department                                 department                          department
// Job Title                                  jobTitle                            jobTitle
// Postal Code                                postalCode                          postalCode
// State or Locality                          state                               state
// Street Address                             streetAddress                       streetAddress
// Mail Nick Name                             mailNickname                        mailNickname
// Force Change Password Next Login           passwordProfile.forceChangePasswordNextSignIn  passwordProfile.forceChangePasswordNextSignIn
// onPremises Immutable ID                    onPremisesImmutableId               onPremisesImmutableId
// onPremises Synchronization Enabled         onPremisesSyncEnabled               onPremisesSyncEnabled
// User Type                                  userType                            userType
// Password Policies                          passwordPolicies                    passwordPolicies
// Preferred Language                         preferredLanguage                   preferredLanguage
// Usage Location                             usageLocation                       usageLocation
// Office Location                            officeLocation                      officeLocation
// Proxy Addresses                            proxyAddresses.value                proxyAddresses
// License                                    servicePlan.value                   servicePlan
// Groups                                     groups - virtual readOnly           N/A
//
// /Group                                     SCIM (custom)                       Endpoint (AAD)
// --------------------------------------------------------------------------------------------
// Name                                       displayName                         displayName
// Id                                         id                                  id
// Members                                    members                             members
//
// /servicePlan                               SCIM (custom)                       Endpoint (AAD)
// --------------------------------------------------------------------------------------------
// Service Plan Name                          servicePlanName                     servicePlanName
// SKU ID                                     skuId                               skuId
// SKU Part Number                            skuPartNumber                       skuPartNumber
//
// =====================================================================================================================

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
let config = require(configFile).endpoint
config = scimgateway.processExtConfig(pluginName, config) // add any external config process.env and process.file
scimgateway.authPassThroughAllowed = false // true enables auth passThrough (no scimgateway authentication). scimgateway instead includes ctx (ctx.request.header) in plugin methods. Note, requires plugin-logic for handling/passing ctx.request.header.authorization to be used in endpoint communication
// mandatory plugin initialization - end

if (config.map) { // having licensDetails map here instead of config file
  config.map.licenseDetails = {
    servicePlanId: {
      mapTo: 'id',
      type: 'string'
    },
    servicePlans: {
      mapTo: 'servicePlans',
      type: 'array'
    },
    skuId: {
      mapTo: 'skuId',
      type: 'string'
    },
    skuPartNumber: {
      mapTo: 'skuPartNumber',
      type: 'string'
    },
    servicePlanName: {
      mapTo: 'servicePlanName',
      type: 'string'
    },
    provisioningStatus: {
      mapTo: 'provisioningStatus',
      type: 'string'
    },
    appliesTo: {
      mapTo: 'appliesTo',
      type: 'string'
    }
  }
}

const userAttributes = []
for (const key in config.map.user) { // userAttributes = ['country', 'preferredLanguage', 'mail', 'city', 'displayName', 'postalCode', 'jobTitle', 'businessPhones', 'onPremisesSyncEnabled', 'officeLocation', 'name.givenName', 'passwordPolicies', 'id', 'state', 'department', 'mailNickname', 'manager.managerId', 'active', 'userName', 'name.familyName', 'proxyAddresses.value', 'servicePlan.value', 'mobilePhone', 'streetAddress', 'onPremisesImmutableId', 'userType', 'usageLocation']
  if (config.map.user[key].mapTo) userAttributes.push(config.map.user[key].mapTo)
}

const graphUrl = 'https://graph.microsoft.com/beta' // beta instead ov 'v1.0' gives all user attributes when no $select

const _serviceClient = {}
const lock = new scimgateway.Lock()

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

  const ret = {
    Resources: [],
    totalResults: null
  }

  if (_serviceClient[baseEntity]) {
    if (!_serviceClient[baseEntity].nextLink.users && getObj.startIndex && getObj.startIndex > 1) return (ret) // break endless fake-totalresult paging loop
    if (_serviceClient[baseEntity].nextLink.users && getObj.startIndex && getObj.startIndex < 2) _serviceClient[baseEntity].nextLink.users = null // should not occure
  }

  const method = 'GET'
  const body = null
  let path

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'userName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      path = 'getUser' // special handling
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
    if (getObj.startIndex && getObj.startIndex > 1) { // paging
      if (_serviceClient[baseEntity]) {
        if (_serviceClient[baseEntity].nextLink.users && _serviceClient[baseEntity].nextLink.users[getObj.startIndex]) {
          path = `/users?${_serviceClient[baseEntity].nextLink.users[getObj.startIndex]}`
          _serviceClient[baseEntity].nextLink.users = null
        } else {
          if (Object.keys(_serviceClient[baseEntity].nextLink.users).length > 0) {
            scimgateway.logger.error(`${pluginName}[${baseEntity}] invalid paging: got startIndex=${getObj.startIndex} - expected startIndex=${Object.keys(_serviceClient[baseEntity].nextLink.users)[0]} - returning empty response`)
          }
          _serviceClient[baseEntity].nextLink.users = null
          return ret
        }
      } else {
        scimgateway.logger.error(`${pluginName}[${baseEntity}] invalid paging: got startIndex=${getObj.startIndex} - expected startIndex=1 - returning empty response`)
        return ret
      }
    } else {
      path = `/users?$top=${(!getObj.count || getObj.count > 999) ? 999 : getObj.count}` // paging not supported using filter (Azure default page=100, max=999)
    }
  }
  // mandatory if-else logic - end

  if (!path) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  try {
    let response
    if (path === 'getUser') { // special
      response = { body: { value: [] } }
      const userObj = await getUser(baseEntity, getObj.value, attributes)
      if (userObj) response.body.value.push(userObj)
    } else response = await doRequest(baseEntity, method, path, body)
    if (!response.body.value) {
      throw new Error(`invalid response: ${JSON.stringify(response)}`)
    }
    for (let i = 0; i < response.body.value.length; ++i) { // map to corresponding inbound
      const [scimObj] = scimgateway.endpointMapper('inbound', response.body.value[i], config.map.user) // endpoint => SCIM/CustomSCIM attribute standard
      if (scimObj && typeof scimObj === 'object' && Object.keys(scimObj).length > 0) ret.Resources.push(scimObj)
    }
    if (getObj.startIndex && getObj.count) {
      if (response.body['@odata.nextLink']) {
        const key = getObj.startIndex + getObj.count // next valid startIndex request
        _serviceClient[baseEntity].nextLink.users = {}
        _serviceClient[baseEntity].nextLink.users[key] = response.body['@odata.nextLink'].split('?')[1] // paging keep search query
      } else _serviceClient[baseEntity].nextLink.users = null
    }
    if (!_serviceClient[baseEntity].nextLink.users) ret.totalResults = getObj.startIndex ? getObj.startIndex - 1 + response.body.value.length : response.body.value.length
    else ret.totalResults = 99999999 // to ensure we get a new paging request - don't know the total numbers of users - metadata directoryObject collections are not countable
    return (ret)
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

  const attrObj = {}
  if (userObj.servicePlan) {
    attrObj.servicePlan = userObj.servicePlan // will be included in a modifyuser
    delete userObj.servicePlan
  }

  const method = 'POST'
  const path = '/users'
  const [body] = scimgateway.endpointMapper('outbound', userObj, config.map.user)

  try {
    await doRequest(baseEntity, method, path, body)
    if (attrObj.servicePlan) {
      await scimgateway.modifyUser(baseEntity, userObj.userName, attrObj, ctx)
      return null
    } else return (null)
  } catch (err) {
    const newErr = new Error(`${action} error: ${err.message}`)
    if (err.message.includes('userPrincipalName already exists')) newErr.name = 'uniqueness' // maps to scimType error handling
    throw newErr
  }
}

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id, ctx) => {
  const action = 'deleteUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)
  const method = 'DELETE'
  const path = `/Users/${id}`
  const body = null

  try {
    await doRequest(baseEntity, method, path, body)
    return (null)
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
  const arrLicAdd = []
  const arrLicDel = []
  if (Array.isArray(attrObj.servicePlan)) {
    attrObj.servicePlan.forEach(function (el) {
      if (el.operation && el.operation === 'delete') { // delete license { servicePlan: [ { operation: 'delete', value: 'O365_BUSINESS::OFFICE_BUSINESS' } ] }
        arrLicDel.push(el.value)
      } else if (el.value) { // add license { servicePlan: [ { value: 'O365_BUSINESS::OFFICE_BUSINESS' } ] }
        arrLicAdd.push(el.value)
      }
    })
    delete attrObj.servicePlan
  }
  const [parsedAttrObj] = scimgateway.endpointMapper('outbound', attrObj, config.map.user) // SCIM/CustomSCIM => endpoint attribute standard
  if (parsedAttrObj instanceof Error) throw (parsedAttrObj) // error object

  const objManager = {}
  if (parsedAttrObj.manager) { // new manager
    objManager.manager = JSON.parse(JSON.stringify(parsedAttrObj.manager))
    delete parsedAttrObj.manager
  } else if (parsedAttrObj.manager === null) { // delete manager
    objManager.manager = null
    delete parsedAttrObj.manager
  }

  const profile = () => { // patch
    return new Promise((resolve, reject) => {
      (async () => {
        if (JSON.stringify(parsedAttrObj) === '{}') return resolve(null)
        for (const key in parsedAttrObj) { // if object the modified AAD object must contain all elements, if not they will be cleared e.g. employeeOrgData
          if (typeof parsedAttrObj[key] === 'object') { // get original object and merge
            const method = 'GET'
            const path = `/users/${id}?$select=${key}`
            try {
              const res = await doRequest(baseEntity, method, path, null)
              if (res && res.body && res.body[key]) {
                const fullKeyObj = Object.assign(res.body[key], parsedAttrObj[key]) // merge original with modified
                if (fullKeyObj && Object.keys(fullKeyObj).length > 0) {
                  parsedAttrObj[key] = fullKeyObj
                }
              }
            } catch (err) {
              return reject(err)
            }
          }
        }
        const method = 'PATCH'
        const path = `/users/${id}`
        try {
          await doRequest(baseEntity, method, path, parsedAttrObj)
          resolve(null)
        } catch (err) {
          return reject(err)
        }
      })()
    })
  }

  const manager = () => {
    return new Promise((resolve, reject) => {
      (async () => {
        let method = null
        let path = null
        let body = null
        if (objManager.manager) { // new manager
          method = 'PUT'
          path = `/users/${id}/manager/$ref`
          body = { '@odata.id': `${graphUrl}/users/${objManager.manager}` }
        } else if (objManager.manager === null) { // delete manager
          method = 'DELETE'
          path = `/users/${id}/manager/$ref`
          body = null
        } else return resolve(null)
        try {
          await doRequest(baseEntity, method, path, body)
          resolve(null)
        } catch (err) {
          return reject(err)
        }
      })()
    })
  }

  const license = () => {
    return new Promise((resolve, reject) => {
      (async () => {
        if (arrLicAdd.length < 1 && arrLicDel.length < 1) return resolve(null) // no licenses to update
        // currentLic
        let method = 'GET'
        let path = `/users/${querystring.escape(id)}/licenseDetails`
        const currentLic = {}

        try { // build currentLic
          let response
          try {
            response = await doRequest(baseEntity, method, path, null)
          } catch (err) {
            let statusCode
            try { statusCode = JSON.parse(err.message).statusCode } catch (e) {}
            if (statusCode === 404) return resolve(null) // no licenseDetails
            throw err
          }

          if (!response.body.value) {
            const err = new Error('No content for license information for user with id ' + id)
            return reject(err)
          }
          if (response.body.value.length > 0) {
            for (let i = 0; i < response.body.value.length; i++) { // currentLic = {skuId: [servicePlanId]}
              if (!currentLic[response.body.value[i].skuId]) currentLic[response.body.value[i].skuId] = []
              for (let index = 0; index < response.body.value[i].servicePlans.length; index++) {
                if (response.body.value[i].servicePlans[index].servicePlanName &&
                    (response.body.value[i].servicePlans[index].provisioningStatus === 'Success' ||
                    response.body.value[i].servicePlans[index].provisioningStatus === 'PendingInput')) {
                  currentLic[response.body.value[i].skuId].push(response.body.value[i].servicePlans[index].servicePlanId)
                }
              }
            }
          }

          // availableLic
          method = 'GET'
          path = '/subscribedSkus'
          const availableLic = {}
          const addLic = {}
          const removeLic = {}

          response = await doRequest(baseEntity, method, path, null)
          if (!response.body.value) {
            const err = new Error(`${action}: Got empty response on REST request`)
            return reject(err)
          }
          for (let i = 0; i < response.body.value.length; i++) { // availableLic = {skuId: [servicePlanId]}
            if (!availableLic[response.body.value[i].skuId]) availableLic[response.body.value[i].skuId] = []
            for (let index = 0; index < response.body.value[i].servicePlans.length; index++) {
              if (response.body.value[i].servicePlans[index].servicePlanName &&
                    (response.body.value[i].servicePlans[index].provisioningStatus === 'Success' ||
                    response.body.value[i].servicePlans[index].provisioningStatus === 'PendingInput')) {
                availableLic[response.body.value[i].skuId].push(response.body.value[i].servicePlans[index].servicePlanId)
              }
            }
            // addLic/removeLic based on arrAdd/arrRemove
            for (let j = 0; j < arrLicAdd.length; j++) { // add licenses
              const arrAdd = arrLicAdd[j].split('::')
              if (arrAdd.length !== 2) {
                const err = new Error(`${action}: License/ServicePart name must be on format skuPartNumber::servicePlanName `)
                return reject(err)
              }
              if (response.body.value[i].skuPartNumber === arrAdd[0]) { // addLic = {skuId: [servicePlanId]}
                const add = response.body.value[i].servicePlans.find(function (el) {
                  return (el.servicePlanName === arrAdd[1])
                })
                if (add) {
                  if (!addLic[response.body.value[i].skuId]) addLic[response.body.value[i].skuId] = []
                  addLic[response.body.value[i].skuId].push(add.servicePlanId)
                }
              }
            }
            for (let j = 0; j < arrLicDel.length; j++) { // delete licenses
              const arrDel = arrLicDel[j].split('::')
              if (arrDel.length !== 2) {
                const err = new Error(`${action}: License/ServicePart name must be on format skuPartNumber::servicePlanName `)
                return reject(err)
              }
              if (response.body.value[i].skuPartNumber === arrDel[0]) {
                const del = response.body.value[i].servicePlans.find(function (el) {
                  return (el.servicePlanName === arrDel[1])
                })
                if (del) {
                  if (!removeLic[response.body.value[i].skuId]) removeLic[response.body.value[i].skuId] = []
                  removeLic[response.body.value[i].skuId].push(del.servicePlanId)
                }
              }
            }
          }
          // disabledPlan = availableLic - currentLic
          const disabledPlans = {}
          for (const key in currentLic) {
            disabledPlans[key] = availableLic[key]
            for (let j = 0; j < currentLic[key].length; j++) {
              for (let k = 0; k < disabledPlans[key].length; k++) {
                if (disabledPlans[key][k] === currentLic[key][j]) disabledPlans[key].splice(k, 1) // delete
              }
            }
          }
          // merge disablePlan with addLic/removeLic
          for (const key in addLic) {
            if (!disabledPlans[key]) disabledPlans[key] = availableLic[key] // disable all
            for (let j = 0; j < addLic[key].length; j++) {
              for (let k = 0; k < disabledPlans[key].length; k++) {
                if (disabledPlans[key][k] === addLic[key][j]) disabledPlans[key].splice(k, 1) // delete
              }
            }
          }
          for (const key in removeLic) {
            for (let j = 0; j < removeLic[key].length; j++) {
              disabledPlans[key].push(removeLic[key][j])
            }
          }
          // prepare for update
          const lic = {
            addLicenses: [],
            removeLicenses: []
          }
          for (const key in disabledPlans) {
            if (addLic[key] || removeLic[key]) lic.addLicenses.push({ skuId: key, disabledPlans: disabledPlans[key] })
          }

          // Update with added/removed licenses
          method = 'POST'
          path = `/users/${id}/assignLicense`
          const body = lic
          await doRequest(baseEntity, method, path, body)

          resolve(null)
        } catch (err) {
          return reject(err)
        }
      })()
    })
  }

  return Promise.all([profile(), manager(), license()])
    .then((result) => { return (null) })
    .catch((err) => { throw new Error(`${action} error: ${err.message}`) })
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

  const ret = {
    Resources: [],
    totalResults: null
  }

  if (_serviceClient[baseEntity]) {
    if (!_serviceClient[baseEntity].nextLink.groups && getObj.startIndex && getObj.startIndex > 1) return (ret) // break endless fake-totalresult paging loop
    if (_serviceClient[baseEntity].nextLink.groups && getObj.startIndex && getObj.startIndex < 2) _serviceClient[baseEntity].nextLink.groups = null // should not occure
  }

  if (attributes.length < 1) attributes = ['id', 'displayName', 'members.value']
  if (!attributes.includes('id')) attributes.push('id')

  let includeMembers = false
  if (attributes.includes('members.value') || attributes.includes('members')) {
    includeMembers = true
  }

  const [attrs] = scimgateway.endpointMapper('outbound', attributes, config.map.group)
  const method = 'GET'
  const body = null
  let path

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'displayName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      if (getObj.attribute === 'id') {
        if (includeMembers) path = `/groups/${getObj.value}?$select=${attrs.join()}&$expand=members($select=id,displayName)`
        else path = `/groups/${getObj.value}?$select=${attrs.join()}`
      } else {
        if (includeMembers) path = `/groups?$filter=${getObj.attribute} eq '${getObj.value}'&$select=${attrs.join()}&$expand=members($select=id,displayName)`
        else path = `/groups?$filter=${getObj.attribute} eq '${getObj.value}'&$select=${attrs.join()}`
      }
    } else if (getObj.operator === 'eq' && getObj.attribute === 'members.value') {
      // mandatory - return all groups the user 'id' (getObj.value) is member of - correspond to getGroupMembers() in versions < 4.x.x
      // Resources = [{ id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }]
      path = `/users/${getObj.value}/memberOf/microsoft.graph.group?$select=id,displayName&$expand=members($select=id,displayName)`
    } else {
      // optional - simpel filtering
      throw new Error(`${action} error: not supporting simpel filtering: ${getObj.rawFilter}`)
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all groups to be returned - correspond to exploreGroups() in versions < 4.x.x
    if (getObj.startIndex && getObj.startIndex > 1) { // paging
      if (_serviceClient[baseEntity]) {
        if (_serviceClient[baseEntity].nextLink.groups && _serviceClient[baseEntity].nextLink.groups[getObj.startIndex]) {
          path = `/groups?${_serviceClient[baseEntity].nextLink.groups[getObj.startIndex]}`
          _serviceClient[baseEntity].nextLink.groups = null
        } else {
          if (Object.keys(_serviceClient[baseEntity].nextLink.groups).length > 0) {
            scimgateway.logger.error(`${pluginName}[${baseEntity}] invalid paging: got startIndex=${getObj.startIndex} - expected startIndex=${Object.keys(_serviceClient[baseEntity].nextLink.groups)[0]} - returning empty response`)
          }
          _serviceClient[baseEntity].nextLink.groups = null
          return ret
        }
      } else {
        scimgateway.logger.error(`${pluginName}[${baseEntity}] invalid paging: got startIndex=${getObj.startIndex} - expected startIndex=1 - returning empty response`)
        return ret
      }
    } else {
      if (includeMembers) path = `/groups?$top=${(!getObj.count || getObj.count > 999) ? 999 : getObj.count}&$select=${attrs.join()}&$expand=members($select=id,displayName)`
      else path = `/groups?$top=${(!getObj.count || getObj.count > 999) ? 999 : getObj.count}&$select=${attrs.join()}` // paging not supported using filter (Azure default page=100, max=999)
    }
  }
  // mandatory if-else logic - end

  if (!path) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  try {
    let response = await doRequest(baseEntity, method, path, body)
    if (!response.body) {
      throw new Error(`invalid response: ${JSON.stringify(response)}`)
    }
    if (!response.body.value) {
      if (typeof response.body === 'object' && !Array.isArray(response.body)) response = { body: { value: [response.body] } }
      else response.body.value = []
    }

    for (let i = 0; i < response.body.value.length; ++i) {
      let members
      if (response.body.value[i].members) {
        members = response.body.value[i].members.map(el => {
          return {
            value: el.id,
            display: el.displayName
          }
        })
        delete response.body.value[i].members
      }

      const [scimObj] = scimgateway.endpointMapper('inbound', response.body.value[i], config.map.group) // endpoint => SCIM/CustomSCIM attribute standard
      if (scimObj && typeof scimObj === 'object' && Object.keys(scimObj).length > 0) {
        if (members) scimObj.members = members
        ret.Resources.push(scimObj)
      }
    }

    if (getObj.startIndex && getObj.count) {
      if (response.body['@odata.nextLink']) {
        const key = getObj.startIndex + getObj.count // next valid startIndex request
        _serviceClient[baseEntity].nextLink.groups = {}
        _serviceClient[baseEntity].nextLink.groups[key] = response.body['@odata.nextLink'].split('?')[1] // paging keep search query
      } else _serviceClient[baseEntity].nextLink.groups = null
    }
    if (!_serviceClient[baseEntity].nextLink.groups) ret.totalResults = getObj.startIndex ? getObj.startIndex - 1 + response.body.value.length : response.body.value.length
    else ret.totalResults = 99999999 // to ensure we get a new paging request - don't know the total numbers of users - metadata directoryObject collections are not countable
    return (ret)
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
  const body = { displayName: groupObj.displayName }
  body.mailNickName = groupObj.displayName
  body.mailEnabled = false
  body.securityEnabled = true
  const method = 'POST'
  const path = '/Groups'

  try {
    const res = await scimgateway.getGroups(baseEntity, { attribute: 'displayName', operator: 'eq', value: groupObj.displayName }, ['id', 'displayName'], ctx)
    if (res && res.Resources && res.Resources.length > 0) {
      throw new Error(`group ${groupObj.displayName} already exist`)
    }
    await doRequest(baseEntity, method, path, body)
    return null
  } catch (err) {
    const newErr = new Error(`${action} error: ${err.message}`)
    if (err.message.includes('already exist')) newErr.name = 'uniqueness'
    throw newErr
  }
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

  if (!attrObj.members) {
    throw new Error(`${action} error: only supports modification of members`)
  }
  if (!Array.isArray(attrObj.members)) {
    throw new Error(`${action} error: ${JSON.stringify(attrObj)} - correct syntax is { "members": [...] }`)
  }

  const arrGrpAdd = []
  const arrGrpDel = []
  attrObj.members.forEach(function (el) {
    if (el.operation && el.operation === 'delete') { // delete member from group e.g {"members":[{"operation":"delete","value":"bjensen"}]}
      arrGrpDel.push(el.value)
    } else if (el.value) { // add member to group {"members":[{value":"bjensen"}]}
      arrGrpAdd.push(el.value)
    }
  })

  const addGrps = () => { // add groups
    return new Promise((resolve, reject) => {
      (async () => {
        if (arrGrpAdd.length < 1) return resolve(null)
        const method = 'POST'
        const path = `/groups/${id}/members/$ref`
        for (let i = 0, len = arrGrpAdd.length; i < len; i++) {
          const body = { '@odata.id': `${graphUrl}/directoryObjects/${arrGrpAdd[i]}` }
          try {
            await doRequest(baseEntity, method, path, body)
            if (i === len - 1) resolve(null) // loop completed
          } catch (err) {
            return reject(err)
          }
        }
      })()
    })
  }

  const removeGrps = () => { // remove groups
    return new Promise((resolve, reject) => {
      (async () => {
        if (arrGrpDel.length < 1) return resolve(null)
        const method = 'DELETE'
        const body = null
        for (let i = 0, len = arrGrpDel.length; i < len; i++) {
          const path = `/groups/${id}/members/${arrGrpDel[i]}/$ref`
          try {
            await doRequest(baseEntity, method, path, body)
            if (i === len - 1) resolve(null) // loop completed
          } catch (err) {
            return reject(err)
          }
        }
      })()
    })
  }

  return Promise.all([addGrps(), removeGrps()])
    .then((res) => { return res })
    .catch((err) => { throw new Error(`${action} error: ${err.message}`) })
}

// =================================================
// getServicePlans
// =================================================
scimgateway.getServicePlans = async (baseEntity, getObj, attributes, ctx) => {
  //
  // "getObj" = { attribute: <>, operator: <>, value: <>, rawFilter: <>, startIndex: <>, count: <> }
  // rawFilter is always included when filtering - attribute, operator and value are included when requesting unique object or simpel filtering
  // See comments in the "mandatory if-else logic - start"
  //
  // "attributes" contains a list of attributes to be returned - if blank, all supported attributes should be returned
  // Should normally return all supported user attributes having id and servicePlanName as mandatory
  // id and servicePlanName are most often considered as "the same" having value = <servicePlanName>
  // Note, the value of returned 'id' will be used as 'id' in modifyServicePlan and deleteServicePlan
  // scimgateway will automatically filter response according to the attributes list
  //
  const action = 'getServicePlans'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes}`)

  const ret = {
    Resources: [],
    totalResults: null
  }

  if (_serviceClient[baseEntity]) {
    if (!_serviceClient[baseEntity].nextLink.users && getObj.startIndex && getObj.startIndex > 1) return (ret) // break endless fake-totalresult paging loop
    if (_serviceClient[baseEntity].nextLink.users && getObj.startIndex && getObj.startIndex < 2) _serviceClient[baseEntity].nextLink.users = null // should not occure
  }

  const method = 'GET'
  const body = null
  let path

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'servicePlanName'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      if (attributes.length === 1 && attributes[0] === 'servicePlanName') {
        ret.Resources = [{ servicePlanName: getObj.value }]
        return ret
      }
      path = 'getServicePlan' // special handling
    } else if (getObj.operator === 'eq' && getObj.attribute === 'servicePlan.value') {
      // optional - only used when servicePlans are member of users, not default behavior - correspond to getGroupUsers() in versions < 4.x.x
      throw new Error(`${action} error: servicePlans member of user filtering not supported: ${getObj.rawFilter}`)
    } else {
      // optional - simpel filtering
      throw new Error(`${action} error: simpel filtering not supported: ${getObj.rawFilter}`)
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: advanced filtering not supported: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all serviePlans to be returned - correspond to exploreServicePlans() in versions < 4.x.x
    path = '/subscribedSkus' // paging not supported
  }

  if (!path) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  try {
    let response
    if (path === 'getServicePlan') { // special
      response = { body: { value: [] } }
      path = '/subscribedSkus'

      const res = await doRequest(baseEntity, method, path, body)
      if (!res.body.value) {
        throw new Error('got empty response on REST request')
      }

      const [arrOutbound] = (scimgateway.endpointMapper('outbound', attributes, config.map.licenseDetails))
      const [arrInbound] = (scimgateway.endpointMapper('inbound', attributes, config.map.licenseDetails))

      const arr = getObj.value.split('::') // servicePlaneName
      const skuPartNumber = arr[0]
      const plan = arr[1]
      const planObj = {}

      for (let i = 0; i < res.body.value.length; i++) {
        if (res.body.value[i].skuPartNumber !== skuPartNumber) continue
        for (let index = 0; index < res.body.value[i].servicePlans.length; index++) {
          if (res.body.value[i].servicePlans[index].servicePlanName === plan) {
            planObj.servicePlanName = `${skuPartNumber}::${res.body.value[i].servicePlans[index].servicePlanName}`
            planObj.id = res.body.value[i].servicePlans[index].servicePlanId
            for (let j = 0; j < arrInbound.length; j++) { // skuPartNumber, skuId, servicePlanName, servicePlanId
              if (arrInbound[j] !== 'servicePlanName' && arrInbound[j] !== 'id') planObj[arrInbound[j]] = res.body.value[i][arrOutbound[j]]
            }
            i = res.body.value.length
            break
          }
        }
      }
      if (planObj) ret.Resources.push(planObj)
    } else {
      response = await doRequest(baseEntity, method, path, body)

      if (!response.body.value) {
        throw new Error('got empty response on REST request')
      }

      for (let i = 0; i < response.body.value.length; i++) {
        const skuPartNumber = response.body.value[i].skuPartNumber
        for (let index = 0; index < response.body.value[i].servicePlans.length; index++) {
          if (response.body.value[i].servicePlans[index].servicePlanName && response.body.value[i].servicePlans[index].provisioningStatus === 'Success') {
            const scimPlan = {
              servicePlanName: `${skuPartNumber}::${response.body.value[i].servicePlans[index].servicePlanName}`,
              id: response.body.value[i].servicePlans[index].servicePlanId
            }
            ret.Resources.push(scimPlan)
          }
        }
      }
    }

    ret.totalResults = ret.Resources.length // no paging
    return ret
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// createServicePlan
// =================================================
scimgateway.createServicePlan = async (baseEntity, id, ctx) => {
  const action = 'createServicePlan'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)
  throw new Error(`${action} error: ${action} is not supported`)
}

// =================================================
// deleteServicePlan
// =================================================
scimgateway.deleteServicePlan = async (baseEntity, id, ctx) => {
  const action = 'deleteServicePlan'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)
  throw new Error(`${action} error: ${action} is not supported`)
}

// =================================================
// modifyServicePlan
// =================================================
scimgateway.modifyServicePlan = async (baseEntity, id, ctx) => {
  const action = 'modifyServicePlan'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)
  throw new Error(`${action} error: ${action} is not supported`)
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
    if (_serviceClient[baseEntity] && _serviceClient[baseEntity].accessToken) { // serviceClient already exist - Azure plugin specific
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: Using existing client`)
      // check if token refresh is needed
      const d = new Date() / 1000 // seconds (unix time)
      if (_serviceClient[baseEntity].accessToken.validTo < d + 30) { // less than 30 sec before token expiration
        scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: Accesstoken about to expire in ${_serviceClient[baseEntity].accessToken.validTo - d} seconds`)
        try {
          const accessToken = await getAccessToken(baseEntity)
          _serviceClient[baseEntity].accessToken = accessToken
          _serviceClient[baseEntity].options.headers.Authorization = ` Bearer ${accessToken.access_token}`
        } catch (err) {
          const newErr = err
          throw newErr
        }
      }
    } else {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: Client have to be created`)
      let client = null
      if (config.entity && config.entity[baseEntity]) client = config.entity[baseEntity]
      if (!client) {
        const err = new Error(`Base URL have baseEntity=${baseEntity}, and configuration file ${pluginName}.json is missing required baseEntity configuration for ${baseEntity}`)
        throw err
      }

      // Azure plugin specific
      const accessToken = await getAccessToken(baseEntity)
      if (!config.entity[baseEntity].baseUrls) config.entity[baseEntity].baseUrls = [graphUrl] // Azure plugin avoid config file and keep baseUrls logic

      urlObj = new URL(config.entity[baseEntity].baseUrls[0])
      const param = {
        baseUrl: config.entity[baseEntity].baseUrls[0],
        accessToken: accessToken, // Azure plugin specific
        options: {
          json: true, // json-object response instead of string
          headers: {
            'Content-Type': 'application/json',
            Authorization: ` Bearer ${accessToken.access_token}`
          },
          host: urlObj.hostname,
          port: urlObj.port, // null if https and 443 defined in url
          protocol: urlObj.protocol // http: or https:
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

      // Azure plugin specific
      _serviceClient[baseEntity].nextLink = {}
      _serviceClient[baseEntity].nextLink.users = null // Azure users pagination
      _serviceClient[baseEntity].nextLink.groups = null // Azure groups pagination
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

    scimgateway.logger.debug(`${pluginName}[${baseEntity}] doRequest ${method} ${options.protocol}//${options.host}${(options.port ? `:${options.port}` : '')}${options.path} Body = ${JSON.stringify(body)} Response = ${JSON.stringify(result)}`)
    return result
  } catch (err) { // includes failover/retry logic based on config baseUrls array
    let statusCode
    try { statusCode = JSON.parse(err.message).statusCode } catch (e) {}
    if (statusCode === 404) { // not logged as error, let caller decide e.g. getUser-manager
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] doRequest ${method} ${path} Body = ${JSON.stringify(body)} Error Response = ${err.message}`)
    } else scimgateway.logger.error(`${pluginName}[${baseEntity}] doRequest ${method} ${path} Body = ${JSON.stringify(body)} Error Response = ${err.message}`)
    if (!retryCount) retryCount = 0
    let urlObj
    try { urlObj = new URL(path) } catch (err) {}
    if (!urlObj && (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || err.code === 'ETIMEDOUT')) {
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
// getAccessToken - returns oauth jwt accesstoken
//
const getAccessToken = async (baseEntity) => {
  await lock.acquire()
  const d = new Date() / 1000 // seconds (unix time)
  if (_serviceClient[baseEntity] && _serviceClient[baseEntity].accessToken &&
   (_serviceClient[baseEntity].accessToken.validTo >= d + 30)) { // avoid simultaneously token requests
    lock.release()
    return _serviceClient[baseEntity].accessToken
  }

  const action = 'getAccessToken'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: Retrieving accesstoken`)

  const req = `https://login.microsoftonline.com/${config.entity[baseEntity].tenantIdGUID}/oauth2/token`
  const method = 'POST'

  const form = { // to be query string formatted
    grant_type: 'client_credentials',
    client_id: config.entity[baseEntity].clientId,
    client_secret: scimgateway.getPassword(`endpoint.entity.${baseEntity}.clientSecret`, configFile),
    resource: 'https://graph.microsoft.com'
  }

  const options = {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded' // body must be query string formatted (no JSON)
    }
  }

  try {
    const response = await doRequest(baseEntity, method, req, form, options)
    if (!response.body) {
      const err = new Error(`[${action}] No data retrieved from: ${method} ${req}`)
      throw (err)
    }
    const jbody = response.body
    if (jbody.error) {
      const err = new Error(`[${action}] Error message: ${jbody.error_description}`)
      throw (err)
    } else if (!jbody.access_token || !jbody.expires_in) {
      const err = new Error(`[${action}] Error message: Retrieved invalid token response`)
      throw (err)
    }

    const d = new Date() / 1000 // seconds (unix time)
    jbody.validTo = d + parseInt(jbody.expires_in) // instead of using expires_on (clock may not be in sync with NTP, AAD default expires_in = 3600 seconds)
    scimgateway.logger.silly(`${pluginName}[${baseEntity}] ${action}: AccessToken =  ${jbody.access_token}`)

    lock.release()
    return jbody
  } catch (err) {
    lock.release()
    throw (err)
  }
}

const getUser = async (baseEntity, uid, attributes) => { // uid = id, userName (upn) or externalId (upn)
  if (attributes.length < 1) {
    attributes = userAttributes
  }

  const user = () => {
    return new Promise((resolve, reject) => {
      (async () => {
        // const [attrs] = scimgateway.endpointMapper('outbound', attributes, config.map.user) // SCIM/CustomSCIM => endpoint attribute standard
        const method = 'GET'
        const path = `/users/${querystring.escape(uid)}?$expand=manager($select=userPrincipalName)` // beta returns all attributes or use: ?$select=${attrs.join()}
        const body = null
        try {
          const response = await doRequest(baseEntity, method, path, body)
          const userObj = response.body
          if (!userObj) {
            const err = new Error('Got empty response when retrieving data for ' + uid)
            return reject(err)
          }

          let managerId
          if (userObj.manager && userObj.manager.userPrincipalName) managerId = userObj.manager.userPrincipalName
          delete userObj.manager
          if (managerId) userObj.manager = managerId

          resolve(userObj)
        } catch (err) {
          return reject(err)
        }
      })()
    })
  }

  const license = () => {
    return new Promise((resolve, reject) => {
      (async () => {
        if (!attributes.includes('servicePlan.value')) return resolve(null) // licenses not requested
        const method = 'GET'
        const path = `/users/${querystring.escape(uid)}/licenseDetails`
        const body = null
        const retObj = { servicePlan: [] }

        try {
          const response = await doRequest(baseEntity, method, path, body)
          if (!response.body.value) {
            const err = new Error('No content for license information ' + uid)
            return reject(err)
          } else {
            if (response.body.value.length < 1) return resolve(null) // User with no licenses
            for (let i = 0; i < response.body.value.length; i++) {
              const skuPartNumber = response.body.value[i].skuPartNumber
              for (let index = 0; index < response.body.value[i].servicePlans.length; index++) {
                if (response.body.value[i].servicePlans[index].provisioningStatus === 'Success' ||
                response.body.value[i].servicePlans[index].provisioningStatus === 'PendingInput') {
                  const servicePlan = { value: `${skuPartNumber}::${response.body.value[i].servicePlans[index].servicePlanName}` }
                  retObj.servicePlan.push(servicePlan)
                }
              }
            }
          }
          resolve(retObj)
        } catch (err) {
          let statusCode
          try { statusCode = JSON.parse(err.message).statusCode } catch (e) {}
          if (statusCode === 404) return resolve(null) // user have no plans
          return reject(err)
        }
      })()
    })
  }

  // return Promise.all([user(), manager(), license()])
  return Promise.all([user(), license()])
    .then((results) => {
      let retObj = {}
      for (const i in results) { // merge async.parallell results to one
        retObj = Object.assign(retObj, results[i])
      }
      return retObj
    })
    .catch((err) => {
      if (err.message.includes('empty response')) return null // no user found
      else throw (err)
    })
}

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})
