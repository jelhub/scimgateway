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
const url = require('url')
const querystring = require('querystring')

// mandatory plugin initialization - start
const path = require('path')
let ScimGateway = null
try {
  ScimGateway = require('scimgateway')
} catch (err) {
  ScimGateway = require('./scimgateway')
}
let scimgateway = new ScimGateway()
let pluginName = path.basename(__filename, '.js')
let configDir = path.join(__dirname, '..', 'config')
let configFile = path.join(`${configDir}`, `${pluginName}.json`)
let config = require(configFile).endpoint
config = scimgateway.processExtConfig(pluginName, config) // add any external config process.env and process.file
// mandatory plugin initialization - end

let graphv1 = 'https://graph.microsoft.com/v1.0'
let _serviceClient = {}
const lock = new scimgateway.Lock()

// =================================================
// exploreUsers
// =================================================
scimgateway.exploreUsers = async (baseEntity, attributes, startIndex, count) => {
  let action = 'exploreUsers'
  scimgateway.logger.debug(`${pluginName} handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`)
  let ret = { // itemsPerPage will be set by scimgateway
    'Resources': [],
    'totalResults': null
  }

  await getServiceClient(baseEntity) // because need to make sure having _serviceClient with Azure paging - @odata.nextLink
  if (!_serviceClient[baseEntity].nextLink.users.skiptoken && startIndex && startIndex > 1) return (ret) // break endless fake-totalresult paging loop
  if (_serviceClient[baseEntity].nextLink.users.skiptoken && startIndex && startIndex < 2) _serviceClient[baseEntity].nextLink.users.skiptoken = null // should not occure
  let method = 'GET'
  let path = null
  if (_serviceClient[baseEntity].nextLink.users.skiptoken) { // paging
    path = `/users?${_serviceClient[baseEntity].nextLink.users.skiptoken}`
  } else {
    path = `/users?$top=${(!count || count > 999) ? 999 : count}` // paging not supported using filter (Azure default page=100, max=999)
  }
  let body = null

  try {
    let response = await doRequest(baseEntity, method, path, body)
    if (!response.body.value) {
      let err = new Error(`${action}: Got empty response on request`)
      throw (err)
    }
    for (let i = 0; i < response.body.value.length; ++i) {
      if (response.body.value[i].id && response.body.value[i].userPrincipalName) {
        let upn = response.body.value[i].userPrincipalName // upn external users: myaccount_outlook.com#EXT#@mycompany.onmicrosoft.com
        let scimUser = { // userName and id is mandatory
          'userName': upn || response.body.value[i].userPrincipalName,
          'id': response.body.value[i].id,
          'externalId': upn || response.body.value[i].userPrincipalName
        }
        ret.Resources.push(scimUser)
      }
    }
    if (response.body['@odata.nextLink']) _serviceClient[baseEntity].nextLink.users.skiptoken = response.body['@odata.nextLink'].split('?')[1] // paging keep search query
    else _serviceClient[baseEntity].nextLink.users.skiptoken = null
    if (!startIndex && !count) ret.totalResults = response.body.value.length // client request without paging
    else ret.totalResults = 99999999 // faking to ensure we get a new paging request - don't know the total numbers of users - metadata directoryObject collections are not countable
    return (ret)
  } catch (err) { throw (err) }
}

// =================================================
// exploreGroups
// =================================================
scimgateway.exploreGroups = async (baseEntity, attributes, startIndex, count) => {
  let action = 'exploreGroups'
  scimgateway.logger.debug(`${pluginName} handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`)
  let ret = { // itemsPerPage will be set by scimgateway
    'Resources': [],
    'totalResults': null
  }

  await getServiceClient(baseEntity) // because need to make sure having _serviceClient with Azure paging - @odata.nextLink
  if (!_serviceClient[baseEntity].nextLink.groups.skiptoken && startIndex && startIndex > 1) return (ret) // break endless fake-totalresult paging loop
  if (_serviceClient[baseEntity].nextLink.groups.skiptoken && startIndex && startIndex < 2) _serviceClient[baseEntity].nextLink.groups.skiptoken = null // should not occure
  let method = 'GET'
  let path = null
  if (_serviceClient[baseEntity].nextLink.groups.skiptoken) { // paging
    path = `/groups?${_serviceClient[baseEntity].nextLink.groups.skiptoken}`
  } else {
    path = `/groups?$top=${(!count || count > 999) ? 999 : count}` // paging not supported using filter (Azure default page=100, max=999)
  }
  let body = null

  try {
    let response = await doRequest(baseEntity, method, path, body)
    if (!response.body.value) {
      let err = new Error(`${action}: Got empty response on request`)
      throw (err)
    }
    for (let i = 0; i < response.body.value.length; ++i) {
      if (response.body.value[i].id && response.body.value[i].displayName) {
        let scimGroup = { // displayName and id is mandatory, note: we set id=displayName
          'displayName': response.body.value[i].displayName,
          'id': response.body.value[i].id,
          'externalId': response.body.value[i].displayName
        }
        ret.Resources.push(scimGroup)
      }
    }
    if (response.body['@odata.nextLink']) _serviceClient[baseEntity].nextLink.groups.skiptoken = response.body['@odata.nextLink'].split('?')[1] // paging keep search query
    else _serviceClient[baseEntity].nextLink.groups.skiptoken = null
    if (!startIndex && !count) ret.totalResults = response.body.value.length // client request without paging
    else ret.totalResults = 99999999 // faking to ensure we get a new paging request - don't know the total numbers of groups - metadata directoryObject collections are not countable
    return (ret) // all explored groups in page of result
  } catch (err) { throw (err) }
}

// =================================================
// getUser
// =================================================
scimgateway.getUser = async (baseEntity, userName, attributes) => {
  let action = 'getUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" userName=${userName} attributes=${attributes}`)

  let user = () => {
    return new Promise(async (resolve, reject) => {
        // attributes=country,preferredLanguage,mail,city,displayName,postalCode,jobTitle,businessPhones,onPremisesSyncEnabled,officeLocation,name.givenName,passwordPolicies,id,state,department,mailNickname,manager.managerId,active,userName,name.familyName,proxyAddresses.value,servicePlan.value,mobilePhone,streetAddress,onPremisesImmutableId,userType,usageLocation
      let parsedAttr = scimgateway.endpointMapper('outbound', attributes, scimgateway.endpointMap.microsoftGraphUser) // SCIM/CustomSCIM => endpoint attribute standard
      let method = 'GET'
      let path = `/users/${querystring.escape(userName)}?$select=${parsedAttr}` // #EXT# need url encoding e.g myaccount_outlook.com#EXT#@mycompany.onmicrosoft.com
      let body = null
      try {
        let response = await doRequest(baseEntity, method, path, body)
        let userObj = response.body
        if (!userObj) {
          let err = new Error('Got empty response when retrieving data for ' + userName)
          return reject(err)
        }
        resolve(userObj)
      } catch (err) {
        return reject(err)
      }
    })
  }

  let manager = () => {
    return new Promise(async (resolve, reject) => {
      if (attributes.indexOf('manager.managerId') < 0) return resolve(null) // request without manager
      let method = 'GET'
      let path = `/users/${querystring.escape(userName)}/manager?$select=id`
      let body = null
      try {
        let response = await doRequest(baseEntity, method, path, body)
        if (!response.body.id) {
          let err = new Error('Manager id not found when retrieving manager for ' + userName)
          return reject(err)
        } else resolve({ 'manager': { 'managerId': response.body.id } })
      } catch (err) {
        let statusCode
        try { statusCode = JSON.parse(err.message).statusCode } catch (e) {}
        if (statusCode === 404) return resolve(null) // user have no manager
        return reject(err)
      }
    })
  }

  let license = () => {
    return new Promise(async (resolve, reject) => {
      if (attributes.indexOf('servicePlan.value') < 0) return resolve(null) // licenses not requested
      let method = 'GET'
      let path = `/users/${querystring.escape(userName)}/licenseDetails`
      let body = null
      let retObj = {'servicePlan': []}

      try {
        let response = await doRequest(baseEntity, method, path, body)
        if (!response.body.value) {
          let err = new Error('No content for license information ' + userName)
          return reject(err)
        } else {
          if (response.body.value.length < 1) return resolve(null) // User with no licenses
          for (let i = 0; i < response.body.value.length; i++) {
            let skuPartNumber = response.body.value[i].skuPartNumber
            for (let index = 0; index < response.body.value[i].servicePlans.length; index++) {
              if (response.body.value[i].servicePlans[index].provisioningStatus === 'Success' || response.body.value[i].servicePlans[index].provisioningStatus === 'PendingInput') {
                let servicePlan = { 'value': `${skuPartNumber}::${response.body.value[i].servicePlans[index].servicePlanName}` }
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
      for (let i in results) { // merge async.parallell results to one
        retObj = Object.assign(retObj, results[i])
      }
      retObj = scimgateway.endpointMapper('inbound', retObj, scimgateway.endpointMap.microsoftGraphUser) // endpoint => SCIM/CustomSCIM attribute standard
      return (retObj) // return user
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
  let action = 'createUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" userObj=${JSON.stringify(userObj)}`)

  let attrObj = {}
  if (userObj.servicePlan) {
    attrObj.servicePlan = userObj.servicePlan // will be included in a modifyuser
    delete userObj.servicePlan
  }

  let method = 'POST'
  let path = '/users'
  let body = scimgateway.endpointMapper('outbound', userObj, scimgateway.endpointMap.microsoftGraphUser)

  try {
    await doRequest(baseEntity, method, path, body)
    if (attrObj.servicePlan) {
      await scimgateway.modifyUser(baseEntity, userObj.userName, attrObj)
      return null
    } else return (null)
  } catch (err) {
    if (err.message.includes('userPrincipalName already exists')) err.name = 'DuplicateKeyError' // gives scimgateway statuscode 409 instead of default 500
    throw (err)
  }
}

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id) => {
  let action = 'deleteUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)
  let method = 'DELETE'
  let path = `/Users/${id}`
  let body = null

  try {
    await doRequest(baseEntity, method, path, body)
    return (null)
  } catch (err) { throw (err) }
}

// =================================================
// modifyUser
// =================================================
scimgateway.modifyUser = async (baseEntity, id, attrObj) => {
  let action = 'modifyUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)
  let arrLicAdd = []
  let arrLicDel = []
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
  let parsedAttrObj = scimgateway.endpointMapper('outbound', attrObj, scimgateway.endpointMap.microsoftGraphUser) // SCIM/CustomSCIM => endpoint attribute standard
  if (parsedAttrObj instanceof Error) throw (parsedAttrObj) // error object

  let objManager = {}
  if (parsedAttrObj.manager) { // new manager
    objManager.manager = JSON.parse(JSON.stringify(parsedAttrObj.manager))
    delete parsedAttrObj.manager
  } else if (parsedAttrObj.manager === null) { // delete manager
    objManager.manager = null
    delete parsedAttrObj.manager
  }

  let profile = () => { // patch
    return new Promise(async (resolve, reject) => {
      if (JSON.stringify(parsedAttrObj) === '{}') return resolve(null)
      let method = 'PATCH'
      let path = `/users/${id}`
      try {
        await doRequest(baseEntity, method, path, parsedAttrObj)
        resolve(null)
      } catch (err) {
        return reject(err)
      }
    })
  }

  let manager = () => {
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

  let license = () => {
    return new Promise(async (resolve, reject) => {
      if (arrLicAdd.length < 1 && arrLicDel.length < 1) return resolve(null) // no licenses to update
      // currentLic
      let method = 'GET'
      let path = `/users/${querystring.escape(id)}/licenseDetails`
      let currentLic = {}

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
          let err = new Error('No content for license information for user with id ' + id)
          return reject(err)
        }
        if (response.body.value.length > 0) {
          for (let i = 0; i < response.body.value.length; i++) { // currentLic = {skuId: [servicePlanId]}
            if (!currentLic[response.body.value[i].skuId]) currentLic[response.body.value[i].skuId] = []
            for (let index = 0; index < response.body.value[i].servicePlans.length; index++) {
              if (response.body.value[i].servicePlans[index].servicePlanName &&
                    (response.body.value[i].servicePlans[index].provisioningStatus === 'Success' || response.body.value[i].servicePlans[index].provisioningStatus === 'PendingInput')) {
                currentLic[response.body.value[i].skuId].push(response.body.value[i].servicePlans[index].servicePlanId)
              }
            }
          }
        }

        // availableLic
        method = 'GET'
        path = '/subscribedSkus'
        let availableLic = {}
        let addLic = {}
        let removeLic = {}

        response = await doRequest(baseEntity, method, path, null)
        if (!response.body.value) {
          let err = new Error(`${action}: Got empty response on REST request`)
          return reject(err)
        }
        for (let i = 0; i < response.body.value.length; i++) { // availableLic = {skuId: [servicePlanId]}
          if (!availableLic[response.body.value[i].skuId]) availableLic[response.body.value[i].skuId] = []
          for (let index = 0; index < response.body.value[i].servicePlans.length; index++) {
            if (response.body.value[i].servicePlans[index].servicePlanName &&
                    (response.body.value[i].servicePlans[index].provisioningStatus === 'Success' || response.body.value[i].servicePlans[index].provisioningStatus === 'PendingInput')) {
              availableLic[response.body.value[i].skuId].push(response.body.value[i].servicePlans[index].servicePlanId)
            }
          }
          // addLic/removeLic based on arrAdd/arrRemove
          for (let j = 0; j < arrLicAdd.length; j++) { // add licenses
            let arrAdd = arrLicAdd[j].split('::')
            if (arrAdd.length !== 2) {
              let err = new Error(`${action}: License/ServicePart name must be on format skuPartNumber::servicePlanName `)
              return reject(err)
            }
            if (response.body.value[i].skuPartNumber === arrAdd[0]) { // addLic = {skuId: [servicePlanId]}
              let add = response.body.value[i].servicePlans.find(function (el) {
                return (el.servicePlanName === arrAdd[1])
              })
              if (add) {
                if (!addLic[response.body.value[i].skuId]) addLic[response.body.value[i].skuId] = []
                addLic[response.body.value[i].skuId].push(add.servicePlanId)
              }
            }
          }
          for (let j = 0; j < arrLicDel.length; j++) { // delete licenses
            let arrDel = arrLicDel[j].split('::')
            if (arrDel.length !== 2) {
              let err = new Error(`${action}: License/ServicePart name must be on format skuPartNumber::servicePlanName `)
              return reject(err)
            }
            if (response.body.value[i].skuPartNumber === arrDel[0]) {
              let del = response.body.value[i].servicePlans.find(function (el) {
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
        let disabledPlans = {}
        for (let key in currentLic) {
          disabledPlans[key] = availableLic[key]
          for (let j = 0; j < currentLic[key].length; j++) {
            for (let k = 0; k < disabledPlans[key].length; k++) {
              if (disabledPlans[key][k] === currentLic[key][j]) disabledPlans[key].splice(k, 1) // delete
            }
          }
        }
        // merge disablePlan with addLic/removeLic
        for (let key in addLic) {
          if (!disabledPlans[key]) disabledPlans[key] = availableLic[key] // disable all
          for (let j = 0; j < addLic[key].length; j++) {
            for (let k = 0; k < disabledPlans[key].length; k++) {
              if (disabledPlans[key][k] === addLic[key][j]) disabledPlans[key].splice(k, 1) // delete
            }
          }
        }
        for (let key in removeLic) {
          for (let j = 0; j < removeLic[key].length; j++) {
            disabledPlans[key].push(removeLic[key][j])
          }
        }
        // prepare for update
        let lic = {
          'addLicenses': [],
          'removeLicenses': []
        }
        for (let key in disabledPlans) {
          if (addLic[key] || removeLic[key]) lic.addLicenses.push({ 'skuId': key, 'disabledPlans': disabledPlans[key] })
        }

        // Update with added/removed licenses
        method = 'POST'
        path = `/users/${id}/assignLicense`
        let body = lic

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
scimgateway.getGroup = async (baseEntity, displayName, attributes) => {
  try {
    let action = 'getGroup'
    scimgateway.logger.debug(`${pluginName} handling "${action}" displayName=${displayName} attributes=${attributes}`)

    let includeMembers = false
    if (attributes.indexOf('members.value') >= 0) includeMembers = true
    let parsedAttr = scimgateway.endpointMapper('outbound', attributes, scimgateway.endpointMap.microsoftGraphGroup) // SCIM/CustomSCIM => endpoint attribute standard

    let retObj = await new Promise(async (resolve, reject) => { // new Promise(async (resolve, reject) => {
      let rePattern = new RegExp(/.*-.*-.*-.*-.*/)
      if (rePattern.test(displayName)) { // using id and not displayName
        let id = displayName
        let method = 'GET'
        let path = `/groups/${id}?$select=${parsedAttr}`
        let body = null

        let response = await doRequest(baseEntity, method, path, body)
        if (!response.body && !response.body.displayName) {
          let err = new Error(`${action}: Got empty or invalid response on REST request`)
          return reject(err)
        } else {
          let retObj = scimgateway.endpointMapper('inbound', response.body, scimgateway.endpointMap.microsoftGraphGroup) // endpoint => SCIM/CustomSCIM attribute standard
          return resolve(retObj)
        }
      } else { // using displayName and not id
        let method = 'GET'
        let path = `/groups?$filter=displayName eq '${displayName}'&$select=${parsedAttr}${includeMembers ? ',id' : ''}` // group id needed for includeMembers (retObj.id)
        let body = null

        let response = await doRequest(baseEntity, method, path, body)
        if (!response.body.value && !Array.isArray(response.body.value) && !response.body.value.length === 1) {
          let err = new Error(`${action}: Got empty or invalid response on REST request`)
          return reject(err)
        } else {
          let retObj = response.body.value[0]
          retObj = scimgateway.endpointMapper('inbound', retObj, scimgateway.endpointMap.microsoftGraphGroup) // endpoint => SCIM/CustomSCIM attribute standard
          return resolve(retObj)
        }
      }
    })

    if (!includeMembers) return retObj
    let method = 'GET'
    let path = `/groups/${retObj.id}/members?$select=id,userPrincipalName`
    let body = null

    let response = await doRequest(baseEntity, method, path, body)
    if (!response.body.value && !Array.isArray(response.body.value)) {
      let err = new Error(`${action}: Got empty response on REST request`)
      throw (err)
    } else { // add all group members to retObj
      retObj.members = []
      response.body.value.forEach(function (el) {
        retObj.members.push({ 'value': el.id })
      })
      return retObj
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
  let action = 'getGroupMembers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" user id=${id} attributes=${attributes}`)
  let arrRet = []
  let method = 'GET'
  let path = `/users/${id}/memberOf?$select=displayName`
  let body = null

  try {
    let response = await doRequest(baseEntity, method, path, body)
    if (!response.body.value) {
      let err = new Error(`${action}: Got empty response on REST request`)
      throw (err)
    }
    response.body.value.forEach(function (el) {
      let userGroup = {
        'displayName': el.displayName,   // displayName is mandatory
        'members': [{ 'value': id }]     // only includes current user
      }
      arrRet.push(userGroup)
    })
    return arrRet
  } catch (err) {
    throw (err)
  }
}

// =================================================
// getServicePlanMembers
// =================================================
scimgateway.getServicePlanMembers = async (baseEntity, id, attributes) => { // not in used
  let action = 'getServicePlanMembers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" user id=${id} attributes=${attributes}`)
  let arrRet = []
  return arrRet
}

// =================================================
// getGroupUsers
// =================================================
scimgateway.getGroupUsers = async (baseEntity, groupName, attributes) => { // not in used
  let action = 'getGroupUsers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" groupName=${groupName} attributes=${attributes}`)
  let arrRet = []
  return arrRet
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj) => {
  let action = 'createGroup'
  scimgateway.logger.debug(`${pluginName} handling "${action}" groupObj=${JSON.stringify(groupObj)}`)
  let body = { 'displayName': groupObj.displayName }
  body.mailNickName = groupObj.displayName
  body.mailEnabled = false
  body.securityEnabled = true
  let method = 'POST'
  let path = '/Groups'

  try {
    await doRequest(baseEntity, method, path, body)
    return null
  } catch (err) { throw (err) }
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id) => {
  let action = 'deleteGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)
    // if supporting delete group we need some endpoint logic here
  let err = new Error(`Delete group is not supported by ${pluginName}`)
  throw (err)
}

// =================================================
// modifyGroupMembers
// =================================================
scimgateway.modifyGroupMembers = async (baseEntity, id, members) => {
  let action = 'modifyGroupMembers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} members=${JSON.stringify(members)}`)
  let arrGrpAdd = []
  let arrGrpDel = []
  if (Array.isArray(members)) {
    members.forEach(function (el) {
      if (el.operation && el.operation === 'delete') { // delete member from group e.g {"members":[{"operation":"delete","value":"bjensen"}]}
        arrGrpDel.push(el.value)
      } else if (el.value) { // add member to group {"members":[{value":"bjensen"}]}
        arrGrpAdd.push(el.value)
      }
    })
  }

  let addGrps = () => { // add groups
    return new Promise(async (resolve, reject) => {
      if (arrGrpAdd.length < 1) return resolve(null)
      let method = 'POST'
      let path = `/groups/${id}/members/$ref`
      for (let i = 0, len = arrGrpAdd.length; i < len; i++) {
        let body = { '@odata.id': `${graphv1}/directoryObjects/${arrGrpAdd[i]}` }
        try {
          await doRequest(baseEntity, method, path, body)
          if (i === len - 1) resolve(null) // loop completed
        } catch (err) {
          return reject(err)
        }
      }
    })
  }

  let removeGrps = () => { // remove groups
    return new Promise(async (resolve, reject) => {
      if (arrGrpDel.length < 1) return resolve(null)
      let method = 'DELETE'
      let body = null
      for (let i = 0, len = arrGrpDel.length; i < len; i++) {
        let path = `/groups/${id}/members/${arrGrpDel[i]}/$ref`
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
  let action = 'exploreServicePlans'
  scimgateway.logger.debug(`${pluginName} handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`)
  let ret = { // itemsPerPage will be set by scimgateway
    'Resources': [],
    'totalResults': null
  }
  let method = 'GET'
  let path = '/subscribedSkus' // paging not supported
  let body = null

  try {
    let response = await doRequest(baseEntity, method, path, body)
    if (!response.body.value) {
      let err = new Error(`${action}: Got empty response on REST request`)
      throw (err)
    }
    for (let i = 0; i < response.body.value.length; i++) {
      let skuPartNumber = response.body.value[i].skuPartNumber
      for (let index = 0; index < response.body.value[i].servicePlans.length; index++) {
        if (response.body.value[i].servicePlans[index].servicePlanName && response.body.value[i].servicePlans[index].provisioningStatus === 'Success') {
          let scimPlan = {
            'servicePlanName': `${skuPartNumber}::${response.body.value[i].servicePlans[index].servicePlanName}`
          }
          ret.Resources.push(scimPlan)
        }
      }
    }
    ret.totalResults = response.body.value.length
    return ret // all explored plans
  } catch (err) {
    throw (err)
  }
}

// =================================================
// getServicePlan
// =================================================
scimgateway.getServicePlan = async (baseEntity, servicePlanName, attributes) => {
  let action = 'geServicePlan'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}"`)
  if (attributes === 'servicePlanName') return { 'servicePlanName': servicePlanName }
  let arrOutbound = (scimgateway.endpointMapper('outbound', attributes, scimgateway.endpointMap.microsoftGraphLicenseDetails)).split(',')
  let arrInbound = (scimgateway.endpointMapper('inbound', attributes, scimgateway.endpointMap.microsoftGraphLicenseDetails)).split(',')
  let method = 'GET'
  let path = '/subscribedSkus'
  let body = null

  try {
    let response = await doRequest(baseEntity, method, path, body)
    if (!response.body.value) {
      let err = new Error(`${action}: Got empty response on REST request`)
      throw (err)
    }
    let arr = servicePlanName.split('::')
    let skuPartNumber = arr[0]
    let plan = arr[1]
    let ret = {}

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
    throw (err)
  }
}

//
// getServiceClient - returns options needed for connection parameters
//
//   path = e.g. "/xxx/yyy", then using host/port/protocol based on config baseUrls[0]
//          auth automatically added and failover according to baseUrls array
//
//   path = url e.g. "http(s)://<host>:<port>/xxx/yyy", then using the url host/port/protocol
//          opt (options) may be needed e.g {auth: {username: "username", password: "password"} }
//
let getServiceClient = async (baseEntity, method, path, opt) => {
  let action = 'getServiceClient'

  let host = null
  if (!path) path = ''
  if (path) host = url.parse(path).hostname

  if (!host) {
    //
    // path (no url) - default approach and client will be cached based on config
    //
    if (_serviceClient[baseEntity] && _serviceClient[baseEntity]['accessToken']) { // serviceClient already exist - Azure plugin specific
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: Using existing client`)
      // check if token refresh is needed
      let d = new Date() / 1000 // seconds (unix time)
      if (_serviceClient[baseEntity].accessToken.validTo < d + 30) { // less than 30 sec before token expiration
        scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: Accesstoken about to expire in ${_serviceClient[baseEntity].accessToken.validTo - d} seconds`)
        try {
          let accessToken = await getAccessToken(baseEntity)
          _serviceClient[baseEntity].accessToken = accessToken
          _serviceClient[baseEntity].options.headers.Authorization = ` Bearer ${accessToken.access_token}`
        } catch (err) { throw (err) }
      }
    } else {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: Client have to be created`)
      let client = null
      if (config.entity && config.entity[baseEntity]) client = config.entity[baseEntity]
      if (!client) {
        let err = new Error(`Base URL have baseEntity=${baseEntity}, and configuration file ${pluginName}.json is missing required baseEntity configuration for ${baseEntity}`)
        throw err
      }

      // Azure plugin specific
      let accessToken = await getAccessToken(baseEntity)
      if (!config.entity[baseEntity].baseUrls) config.entity[baseEntity].baseUrls = [graphv1] // Azure plugin avoid config file and keep baseUrls logic

      let param = {
        'baseUrl': config.entity[baseEntity].baseUrls[0],
        'accessToken': accessToken, // Azure plugin specific
        'options': {
          'json': true, // json-object response instead of string
          'headers': {
            'Content-Type': 'application/json',
            'Authorization': ` Bearer ${accessToken.access_token}`
          },
          'host': url.parse(config.entity[baseEntity].baseUrls[0]).hostname,
          'port': url.parse(config.entity[baseEntity].baseUrls[0]).port,
          'protocol': url.parse(config.entity[baseEntity].baseUrls[0]).protocol // http: or https:
          // 'method' and 'path' added at the end
        }
      }

      // proxy
      if (config.entity[baseEntity].proxy && config.entity[baseEntity].proxy.host) {
        let agent = new HttpsProxyAgent(config.entity[baseEntity].proxy.host)
        param.options.agent = agent // proxy
        if (config.entity[baseEntity].proxy.username && config.entity[baseEntity].proxy.password) {
          param.options.headers['Proxy-Authorization'] = 'Basic ' + Buffer.from(`${config.entity[baseEntity].proxy.username}:${scimgateway.getPassword(`endpoint.entity.${baseEntity}.proxy.password`, configFile)}`).toString('base64') // using proxy with auth
        }
      }

      if (!_serviceClient[baseEntity]) _serviceClient[baseEntity] = {}
      _serviceClient[baseEntity] = param // serviceClient created
      // Azure plugin specific
      _serviceClient[baseEntity].nextLink = {}
      _serviceClient[baseEntity].nextLink.users = { 'skiptoken': null } // Azure users pagination
      _serviceClient[baseEntity].nextLink.groups = { 'skiptoken': null } // Azure groups pagination
    }

    let options = scimgateway.copyObj(_serviceClient[baseEntity].options) // client ready

    // failover support
    path = _serviceClient[baseEntity].baseUrl + path
    options.host = url.parse(path).hostname
    options.port = url.parse(path).port
    options.protocol = url.parse(path).protocol

    // adding none static
    options.method = method
    options.path = url.parse(path).path
    if (opt) options = scimgateway.extendObj(options, opt) // merge with argument options

    return options // final client
  } else {
    //
    // url path - none config based and used as is (no cache)
    //
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: Using none config based client`)
    let options = {
      'json': true,
      'headers': {
        'Content-Type': 'application/json'
      },
      'host': url.parse(path).hostname,
      'port': url.parse(path).port,
      'protocol': url.parse(path).protocol,
      'method': method,
      'path': url.parse(path).path
    }

    // proxy
    if (config.entity[baseEntity].proxy && config.entity[baseEntity].proxy.host) {
      let agent = new HttpsProxyAgent(config.entity[baseEntity].proxy.host)
      options.agent = agent // proxy
      if (config.entity[baseEntity].proxy.username && config.entity[baseEntity].proxy.password) {
        options.headers['Proxy-Authorization'] = 'Basic ' + Buffer.from(`${config.entity[baseEntity].proxy.username}:${scimgateway.getPassword(`endpoint.entity.${baseEntity}.proxy.password`, configFile)}`).toString('base64') // using proxy with auth
      }
    }

    // merge any argument options - support basic auth using {auth: {username: "username", password: "password"} }
    if (opt) {
      let o = scimgateway.copyObj(opt)
      if (o.auth) {
        options.headers.Authorization = 'Basic ' + Buffer.from(`${o.auth.username}:${o.auth.password}`).toString('base64')
        delete o.auth
      }
      options = scimgateway.extendObj(options, o)
    }

    return options // final client
  }
}

//
// doRequest - execute REST service
//
let doRequest = async (baseEntity, method, path, body, opt, retryCount) => {
  try {
    let options = await getServiceClient(baseEntity, method, path, opt)
    let result = await new Promise((resolve, reject) => {
      let dataString = ''
      if (body) {
        if (options.headers['Content-Type'].toLowerCase() === 'application/x-www-form-urlencoded') {
          if (typeof data === 'string') dataString = body
          else dataString = querystring.stringify(body) // JSON to query string syntax + URL encoded
        } else dataString = JSON.stringify(body)
        options.headers['Content-Length'] = Buffer.byteLength(dataString, 'utf8')
      }
      let reqType = (options.protocol.toLowerCase() === 'https:') ? https.request : http.request

      let req = reqType(options, (res) => {
        const { statusCode, statusMessage } = res // solving parallel problem (const + don't use res.statusCode)

        let responseString = ''
        res.setEncoding('utf-8')

        res.on('data', (chunk) => {
          responseString += chunk
        })

        res.on('end', () => {
          let response = {
            'statusCode': statusCode,
            'statusMessage': statusMessage,
            'body': null
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

    scimgateway.logger.debug(`${pluginName}[${baseEntity}] doRequest ${method} ${options.protocol}//${options.host}${(options.port ? `:${options.port}` : '')}${path} Response = ${JSON.stringify(result)}`)
    return result
  } catch (err) { // includes failover/retry logic based on config baseUrls array
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] dopath ${method} ${path} Error response = ${err.message}`)
    if (!retryCount) retryCount = 0
    if (!url.parse(path).hostname && (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND')) {
      if (retryCount < config.entity[baseEntity].baseUrls.length) {
        retryCount++
        _serviceClient[baseEntity].baseUrl = config.entity[baseEntity].baseUrls[retryCount - 1] // baseUrl changed
        scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${(config.entity[baseEntity].baseUrls.length > 1) ? 'failover ' : ''}retry[${retryCount}] using baseUrl = ${_serviceClient[baseEntity].baseUrl}`)
        let ret = await doRequest(baseEntity, method, path, body, opt, retryCount) // retry
        return ret // problem fixed
      } else {
        let newerr = new Error(err.message)
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
let getAccessToken = async (baseEntity) => {
  await lock.acquire()
  let d = new Date() / 1000 // seconds (unix time)
  if (_serviceClient[baseEntity] && _serviceClient[baseEntity].accessToken &&
   (_serviceClient[baseEntity].accessToken.validTo >= d + 30)) { // avoid simultaneously token requests
    lock.release()
    return _serviceClient[baseEntity].accessToken
  }

  let action = 'getAccessToken'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: Retrieving accesstoken`)

  let req = `https://login.microsoftonline.com/${config.entity[baseEntity].tenantIdGUID}/oauth2/token`
  let method = 'POST'

  let form = { // to be query string formatted
    'grant_type': 'client_credentials',
    'client_id': config.entity[baseEntity].clientId,
    'client_secret': scimgateway.getPassword(`endpoint.entity.${baseEntity}.clientSecret`, configFile),
    'resource': 'https://graph.microsoft.com'
  }

  let options = {
    'headers': {
      'Content-Type': 'application/x-www-form-urlencoded' // body must be query string formatted (no JSON)
    }
  }

  try {
    let response = await doRequest(baseEntity, method, req, form, options)
    if (!response.body) {
      let err = new Error(`[${action}] No data retrieved from: ${method} ${req}`)
      throw (err)
    }
    let jbody = response.body
    if (jbody.error) {
      let err = new Error(`[${action}] Error message: ${jbody.error_description}`)
      throw (err)
    } else if (!jbody.access_token || !jbody.expires_in) {
      let err = new Error(`[${action}] Error message: Retrieved invalid token response`)
      throw (err)
    }

    let d = new Date() / 1000 // seconds (unix time)
    jbody['validTo'] = d + parseInt(jbody.expires_in) // instead of using expires_on (clock may not be in sync with NTP, AAD default expires_in = 3600 seconds)
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
process.on('SIGINT', () => {   // Ctrl+C
})
