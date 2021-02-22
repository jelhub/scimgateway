// =================================================================================
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
let config = require(configFile).endpoint
config = scimgateway.processExtConfig(pluginName, config) // add any external config process.env and process.file
// mandatory plugin initialization - end

const graphv1 = 'https://graph.microsoft.com/v1.0'
const _serviceClient = {}
const lock = new scimgateway.Lock()

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

  await getServiceClient(baseEntity) // because need to make sure having _serviceClient with Azure paging - @odata.nextLink
  if (!_serviceClient[baseEntity].nextLink.users.skiptoken && startIndex && startIndex > 1) return (ret) // break endless fake-totalresult paging loop
  if (_serviceClient[baseEntity].nextLink.users.skiptoken && startIndex && startIndex < 2) _serviceClient[baseEntity].nextLink.users.skiptoken = null // should not occure
  const method = 'GET'
  let path = null
  if (_serviceClient[baseEntity].nextLink.users.skiptoken) { // paging
    path = `/users?${_serviceClient[baseEntity].nextLink.users.skiptoken}`
  } else {
    path = `/users?$top=${(!count || count > 999) ? 999 : count}` // paging not supported using filter (Azure default page=100, max=999)
  }
  const body = null

  try {
    const response = await doRequest(baseEntity, method, path, body)
    if (!response.body.value) {
      const err = new Error(`${action}: Got empty response on request`)
      throw (err)
    }
    for (let i = 0; i < response.body.value.length; ++i) {
      if (response.body.value[i].id && response.body.value[i].userPrincipalName) {
        const upn = response.body.value[i].userPrincipalName // upn external users: myaccount_outlook.com#EXT#@mycompany.onmicrosoft.com
        const scimUser = { // returning userName and id
          userName: upn || response.body.value[i].userPrincipalName,
          id: response.body.value[i].id
        }
        ret.Resources.push(scimUser)
      }
    }
    if (response.body['@odata.nextLink']) _serviceClient[baseEntity].nextLink.users.skiptoken = response.body['@odata.nextLink'].split('?')[1] // paging keep search query
    else _serviceClient[baseEntity].nextLink.users.skiptoken = null
    if (!startIndex && !count) ret.totalResults = response.body.value.length // client request without paging
    else ret.totalResults = 99999999 // faking to ensure we get a new paging request - don't know the total numbers of users - metadata directoryObject collections are not countable
    return (ret)
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
  const ret = { // itemsPerPage will be set by scimgateway
    Resources: [],
    totalResults: null
  }

  await getServiceClient(baseEntity) // because need to make sure having _serviceClient with Azure paging - @odata.nextLink
  if (!_serviceClient[baseEntity].nextLink.groups.skiptoken && startIndex && startIndex > 1) return (ret) // break endless fake-totalresult paging loop
  if (_serviceClient[baseEntity].nextLink.groups.skiptoken && startIndex && startIndex < 2) _serviceClient[baseEntity].nextLink.groups.skiptoken = null // should not occure
  const method = 'GET'
  let path = null
  if (_serviceClient[baseEntity].nextLink.groups.skiptoken) { // paging
    path = `/groups?${_serviceClient[baseEntity].nextLink.groups.skiptoken}`
  } else {
    path = `/groups?$top=${(!count || count > 999) ? 999 : count}` // paging not supported using filter (Azure default page=100, max=999)
  }
  const body = null

  try {
    const response = await doRequest(baseEntity, method, path, body)
    if (!response.body.value) {
      const err = new Error(`${action}: Got empty response on request`)
      throw (err)
    }
    for (let i = 0; i < response.body.value.length; ++i) {
      if (response.body.value[i].id && response.body.value[i].displayName) {
        const scimGroup = { // displayName and id is mandatory, note: we set id=displayName
          displayName: response.body.value[i].displayName,
          id: response.body.value[i].id
        }
        ret.Resources.push(scimGroup)
      }
    }
    if (response.body['@odata.nextLink']) _serviceClient[baseEntity].nextLink.groups.skiptoken = response.body['@odata.nextLink'].split('?')[1] // paging keep search query
    else _serviceClient[baseEntity].nextLink.groups.skiptoken = null
    if (!startIndex && !count) ret.totalResults = response.body.value.length // client request without paging
    else ret.totalResults = 99999999 // faking to ensure we get a new paging request - don't know the total numbers of groups - metadata directoryObject collections are not countable
    return (ret) // all explored groups in page of result
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
  // (they are most often considered as "the same type of attribute" where identifier = UserID )
  // Note, the value of id attribute returned will be used by modifyUser and deleteUser
  const action = 'getUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" ${getObj.filter}=${getObj.identifier} attributes=${attributes}`)

  if (getObj.filter === 'manager.managerId') {
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] ignoring returning all users having ${getObj.filter}=${getObj.identifier} - AAD will do manager attribute cleanup on deletion of manager`)
    const arr = []
    return arr
  }
  if (getObj.filter !== 'userName' && getObj.filter !== 'externalId' && getObj.filter !== 'id') {
    throw new Error(`plugin do not support handling "${action}" ${getObj.filter}`)
  }

  const user = () => {
    return new Promise(async (resolve, reject) => {
      // attributes=country,preferredLanguage,mail,city,displayName,postalCode,jobTitle,businessPhones,onPremisesSyncEnabled,officeLocation,name.givenName,passwordPolicies,id,state,department,mailNickname,manager.managerId,active,userName,name.familyName,proxyAddresses.value,servicePlan.value,mobilePhone,streetAddress,onPremisesImmutableId,userType,usageLocation
      const [parsedAttr] = scimgateway.endpointMapper('outbound', attributes, scimgateway.endpointMap.microsoftGraphUser) // SCIM/CustomSCIM => endpoint attribute standard
      const method = 'GET'
      const path = `/users/${querystring.escape(getObj.identifier)}?$select=${parsedAttr}` // #EXT# need url encoding e.g myaccount_outlook.com#EXT#@mycompany.onmicrosoft.com
      const body = null
      try {
        const response = await doRequest(baseEntity, method, path, body)
        const userObj = response.body
        if (!userObj) {
          const err = new Error('Got empty response when retrieving data for ' + getObj.identifier)
          return reject(err)
        }
        resolve(userObj)
      } catch (err) {
        return reject(err)
      }
    })
  }

  const manager = () => {
    return new Promise(async (resolve, reject) => {
      if (attributes.indexOf('manager.managerId') < 0) return resolve(null) // request without manager
      const method = 'GET'
      const path = `/users/${querystring.escape(getObj.identifier)}/manager?$select=id`
      const body = null
      try {
        const response = await doRequest(baseEntity, method, path, body)
        if (!response.body.id) {
          const err = new Error('Manager id not found when retrieving manager for ' + getObj.identifier)
          return reject(err)
        } else resolve({ manager: response.body.id })
      } catch (err) {
        let statusCode
        try { statusCode = JSON.parse(err.message).statusCode } catch (e) {}
        if (statusCode === 404) return resolve(null) // no manager attribute set on Azure user object (doReqest not logging 404 as error)
        return reject(err)
      }
    })
  }

  const license = () => {
    return new Promise(async (resolve, reject) => {
      if (attributes.indexOf('servicePlan.value') < 0) return resolve(null) // licenses not requested
      const method = 'GET'
      const path = `/users/${querystring.escape(getObj.identifier)}/licenseDetails`
      const body = null
      const retObj = { servicePlan: [] }

      try {
        const response = await doRequest(baseEntity, method, path, body)
        if (!response.body.value) {
          const err = new Error('No content for license information ' + getObj.identifier)
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
    })
  }

  return Promise.all([user(), manager(), license()])
    .then((results) => {
      let retObj = {}
      for (const i in results) { // merge async.parallell results to one
        retObj = Object.assign(retObj, results[i])
      }

      const [obj] = scimgateway.endpointMapper('inbound', retObj, scimgateway.endpointMap.microsoftGraphUser) // endpoint => SCIM/CustomSCIM attribute standard
      return obj
    })
    .catch((err) => {
      if (err.message.includes('empty response')) return (null) // no user found
      else throw (err)
    })
}

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj) => {
  const action = 'createUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" userObj=${JSON.stringify(userObj)}`)

  const attrObj = {}
  if (userObj.servicePlan) {
    attrObj.servicePlan = userObj.servicePlan // will be included in a modifyuser
    delete userObj.servicePlan
  }

  const method = 'POST'
  const path = '/users'
  const [body] = scimgateway.endpointMapper('outbound', userObj, scimgateway.endpointMap.microsoftGraphUser)

  try {
    await doRequest(baseEntity, method, path, body)
    if (attrObj.servicePlan) {
      await scimgateway.modifyUser(baseEntity, userObj.userName, attrObj)
      return null
    } else return (null)
  } catch (err) {
    const newErr = new Error(err.message)
    if (newErr.message.includes('userPrincipalName already exists')) newErr.name = 'DuplicateKeyError' // gives scimgateway statuscode 409 instead of default 500
    throw (newErr)
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
    await doRequest(baseEntity, method, path, body)
    return (null)
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
  const [parsedAttrObj] = scimgateway.endpointMapper('outbound', attrObj, scimgateway.endpointMap.microsoftGraphUser) // SCIM/CustomSCIM => endpoint attribute standard
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
    return new Promise(async (resolve, reject) => {
      if (JSON.stringify(parsedAttrObj) === '{}') return resolve(null)
      const method = 'PATCH'
      const path = `/users/${id}`
      try {
        await doRequest(baseEntity, method, path, parsedAttrObj)
        resolve(null)
      } catch (err) {
        return reject(err)
      }
    })
  }

  const manager = () => {
    return new Promise(async (resolve, reject) => {
      let method = null
      let path = null
      let body = null
      if (objManager.manager) { // new manager
        method = 'PUT'
        path = `/users/${id}/manager/$ref`
        body = { '@odata.id': `${graphv1}/users/${objManager.manager}` }
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
    })
  }

  const license = () => {
    return new Promise(async (resolve, reject) => {
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
    })
  }

  return Promise.all([profile(), manager(), license()])
    .then((result) => { return (null) })
    .catch((err) => { throw (err) })
}

// =================================================
// getGroup
// =================================================
scimgateway.getGroup = async (baseEntity, getObj, attributes) => {
  // getObj = { filter: <filterAttribute>, identifier: <identifier> }
  // e.g: getObj = { filter: 'displayName', identifier: 'GroupA' }
  // filter: displayName and id must be supported
  // (they are most often considered as "the same type of attribute" where identifier = GroupName)
  // Note, the value of id attribute returned will be used by deleteGroup, getGroupMembers and modifyGroup
  const action = 'getGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" ${getObj.filter}=${getObj.identifier} attributes=${attributes}`)

  if (getObj.filter !== 'displayName' && getObj.filter !== 'id') {
    throw new Error(`plugin do not support handling "${action}" ${getObj.filter}`)
  }

  try {
    let includeMembers = false
    if (attributes.indexOf('members.value') >= 0) includeMembers = true
    const [parsedAttr] = scimgateway.endpointMapper('outbound', attributes, scimgateway.endpointMap.microsoftGraphGroup) // SCIM/CustomSCIM => endpoint attribute standard

    const retObj = await new Promise(async (resolve, reject) => {
      let path
      if (getObj.filter === 'id') path = `/groups/${getObj.identifier}?$select=${parsedAttr}`
      else path = `/groups?$filter=${getObj.filter} eq '${getObj.identifier}'&$select=${parsedAttr}${includeMembers ? ',id' : ''}` // displayName or externalId => group id needed for includeMembers (retObj.id)
      const method = 'GET'
      const body = null
      const response = await doRequest(baseEntity, method, path, body)
      if (!response.body.value || !Array.isArray(response.body.value) || !(response.body.value.length === 1)) {
        const err = new Error(`${action}: Got empty or invalid response on REST request`)
        return reject(err)
      } else {
        const obj = response.body.value[0]
        const [retObj] = scimgateway.endpointMapper('inbound', obj, scimgateway.endpointMap.microsoftGraphGroup) // endpoint => SCIM/CustomSCIM attribute standard
        return resolve(retObj)
      }
    })

    if (!includeMembers) return retObj
    const method = 'GET'
    const path = `/groups/${retObj.id}/members?$select=id,userPrincipalName`
    const body = null

    const response = await doRequest(baseEntity, method, path, body)
    if (!response.body.value && !Array.isArray(response.body.value)) {
      const err = new Error(`${action}: Got empty response on REST request`)
      throw (err)
    } else { // add all group members to retObj
      retObj.members = []
      response.body.value.forEach(function (el) {
        retObj.members.push({ value: el.id })
      })
      return retObj // not parsing attributes
    }
  } catch (err) {
    if (err.message.includes('empty or invalid response')) return (null) // no group found
    else throw err
  }
}

// =================================================
// getGroupMembers
// =================================================
scimgateway.getGroupMembers = async (baseEntity, id, attributes) => {
  const action = 'getGroupMembers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" user id=${id} attributes=${attributes}`)
  const arrRet = []
  const method = 'GET'
  const path = `/users/${id}/memberOf?$select=displayName`
  const body = null

  try {
    const response = await doRequest(baseEntity, method, path, body)
    if (!response.body.value) {
      const err = new Error(`${action}: Got empty response on REST request`)
      throw (err)
    }
    response.body.value.forEach(function (el) {
      const userGroup = {
        displayName: el.displayName, // displayName is mandatory
        members: [{ value: id }] // only includes current user
      }
      arrRet.push(userGroup)
    })
    return arrRet
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

// =================================================
// getServicePlanMembers
// =================================================
scimgateway.getServicePlanMembers = async (baseEntity, id, attributes) => { // not in used
  const action = 'getServicePlanMembers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" user id=${id} attributes=${attributes}`)
  const arrRet = []
  return arrRet
}

// =================================================
// getGroupUsers
// =================================================
scimgateway.getGroupUsers = async (baseEntity, groupName, attributes) => { // not in used
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
  const body = { displayName: groupObj.displayName }
  body.mailNickName = groupObj.displayName
  body.mailEnabled = false
  body.securityEnabled = true
  const method = 'POST'
  const path = '/Groups'

  try {
    await doRequest(baseEntity, method, path, body)
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
  // if supporting delete group we need some endpoint logic here
  const err = new Error(`Delete group is not supported by ${pluginName}`)
  throw (err)
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
    return new Promise(async (resolve, reject) => {
      if (arrGrpAdd.length < 1) return resolve(null)
      const method = 'POST'
      const path = `/groups/${id}/members/$ref`
      for (let i = 0, len = arrGrpAdd.length; i < len; i++) {
        const body = { '@odata.id': `${graphv1}/directoryObjects/${arrGrpAdd[i]}` }
        try {
          await doRequest(baseEntity, method, path, body)
          if (i === len - 1) resolve(null) // loop completed
        } catch (err) {
          return reject(err)
        }
      }
    })
  }

  const removeGrps = () => { // remove groups
    return new Promise(async (resolve, reject) => {
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
    })
  }

  return Promise.all([addGrps(), removeGrps()])
    .then((res) => { return res })
    .catch((err) => { throw (err) })
}

// =================================================
// exploreServicePlans
// =================================================
scimgateway.exploreServicePlans = async (baseEntity, attributes, startIndex, count) => {
  const action = 'exploreServicePlans'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`)
  const ret = { // itemsPerPage will be set by scimgateway
    Resources: [],
    totalResults: null
  }
  const method = 'GET'
  const path = '/subscribedSkus' // paging not supported
  const body = null

  try {
    const response = await doRequest(baseEntity, method, path, body)
    if (!response.body.value) {
      const err = new Error(`${action}: Got empty response on REST request`)
      throw (err)
    }
    for (let i = 0; i < response.body.value.length; i++) {
      const skuPartNumber = response.body.value[i].skuPartNumber
      for (let index = 0; index < response.body.value[i].servicePlans.length; index++) {
        if (response.body.value[i].servicePlans[index].servicePlanName && response.body.value[i].servicePlans[index].provisioningStatus === 'Success') {
          const scimPlan = {
            servicePlanName: `${skuPartNumber}::${response.body.value[i].servicePlans[index].servicePlanName}`
          }
          ret.Resources.push(scimPlan)
        }
      }
    }
    ret.totalResults = response.body.value.length
    return ret // all explored plans
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

// =================================================
// getServicePlan
// =================================================
scimgateway.getServicePlan = async (baseEntity, getObj, attributes) => {
  const action = 'geServicePlan'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" ${getObj.filter}=${getObj.identifier} attributes=${attributes}`)

  if (getObj.filter !== 'servicePlanName' && getObj.filter !== 'id') {
    throw new Error(`plugin do not support handling "${action}" ${getObj.filter}`)
  }

  if (attributes === 'servicePlanName') return { servicePlanName: getObj.identifier }
  const arrOutbound = (scimgateway.endpointMapper('outbound', attributes, scimgateway.endpointMap.microsoftGraphLicenseDetails)[0]).split(',')
  const arrInbound = (scimgateway.endpointMapper('inbound', attributes, scimgateway.endpointMap.microsoftGraphLicenseDetails)[0]).split(',')
  const method = 'GET'
  const path = '/subscribedSkus'
  const body = null

  try {
    const response = await doRequest(baseEntity, method, path, body)
    if (!response.body.value) {
      const err = new Error(`${action}: Got empty response on REST request`)
      throw (err)
    }
    const arr = getObj.identifier.split('::') // servicePlaneName
    const skuPartNumber = arr[0]
    const plan = arr[1]
    const ret = {}

    for (let i = 0; i < response.body.value.length; i++) {
      if (response.body.value[i].skuPartNumber !== skuPartNumber) continue
      for (let index = 0; index < response.body.value[i].servicePlans.length; index++) {
        if (response.body.value[i].servicePlans[index].servicePlanName === plan) {
          ret.servicePlanName = `${skuPartNumber}::${response.body.value[i].servicePlans[index].servicePlanName}`
          ret.id = response.body.value[i].servicePlans[index].servicePlanId
          for (let j = 0; j < arrInbound.length; j++) { // skuPartNumber, skuId, servicePlanName, servicePlanId
            if (arrInbound[j] !== 'servicePlanName' && arrInbound[j] !== 'id') ret[arrInbound[j]] = response.body.value[i][arrOutbound[j]]
          }
          i = response.body.value.length
          break
        }
      }
    }
    return ret
  } catch (err) {
    const newErr = err
    throw newErr
  }
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
      if (!config.entity[baseEntity].baseUrls) config.entity[baseEntity].baseUrls = [graphv1] // Azure plugin avoid config file and keep baseUrls logic

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
      _serviceClient[baseEntity].nextLink.users = { skiptoken: null } // Azure users pagination
      _serviceClient[baseEntity].nextLink.groups = { skiptoken: null } // Azure groups pagination
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
    let statusCode
    try { statusCode = JSON.parse(err.message).statusCode } catch (e) {}
    if (statusCode === 404) { // not logged as error, let caller decide e.g. getUser-manager
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] doRequest ${method} ${path} Body = ${JSON.stringify(body)} Error Response = ${err.message}`)
    } else scimgateway.logger.error(`${pluginName}[${baseEntity}] doRequest ${method} ${path} Body = ${JSON.stringify(body)} Error Response = ${err.message}`)
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

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})
