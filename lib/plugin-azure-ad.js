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

const request = require('request')
const querystring = require('querystring')
const async = require('async')

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
// mandatory plugin initialization - end

let graphv1 = 'https://graph.microsoft.com/v1.0'
let _serviceClient = {}

scimgateway.on('exploreUsers', function (baseEntity, startIndex, count, callback) {
  let action = 'exploreUsers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}"`)
  let ret = { // itemsPerPage will be set by scimgateway
    'Resources': [],
    'totalResults': null
  }

  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    if (!serviceClient.nextLink.users.skiptoken && startIndex && startIndex > 1) return callback(null, ret) // break endless fake-totalresult paging loop
    if (serviceClient.nextLink.users.skiptoken && startIndex && startIndex < 2) serviceClient.nextLink.users.skiptoken = null // should not occure
    let method = 'get'
    let req = null
    if (serviceClient.nextLink.users.skiptoken) { // paging
      req = `/users?${serviceClient.nextLink.users.skiptoken}`
    } else {
      req = `/users?$top=${(!count || count > 999) ? 999 : count}` // paging not supported using filter (Azure default page=100, max=999)
    }
    request[method](graphv1 + req, serviceClient.options, function (err, response, body) {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} = ${graphv1}${req} Response = ${JSON.stringify(body)}`)
      if (err) return callback(err)
      else if (response.statusCode < 200 || response.statusCode > 299) {
        let err = new Error(`Error message: ${response.statusMessage} - ${(body.error && body.error.message) ? body.error.message : null}`)
        return callback(err)
      } else if (!body.value) {
        let err = new Error(`${action}: Got empty response on REST request`)
        return callback(err)
      }
      for (let i = 0; i < body.value.length; ++i) {
        if (body.value[i].id && body.value[i].userPrincipalName) {
          let upn = body.value[i].userPrincipalName // upn external users: myaccount_outlook.com#EXT#@mycompany.onmicrosoft.com
          let scimUser = { // userName and id is mandatory
            'userName': upn || body.value[i].userPrincipalName,
            'id': body.value[i].id,
            'externalId': upn || body.value[i].userPrincipalName
          }
          ret.Resources.push(scimUser)
        }
      }
      if (body['@odata.nextLink']) serviceClient.nextLink.users.skiptoken = body['@odata.nextLink'].split('?')[1] // paging keep search query
      else serviceClient.nextLink.users.skiptoken = null
      if (!startIndex && !count) ret.totalResults = body.value.length // client request without paging
      else ret.totalResults = 99999999 // faking to ensure we get a new paging request - don't know the total numbers of users - metadata directoryObject collections are not countable
      callback(null, ret) // all explored users in page of result
    })
  })
})

scimgateway.on('exploreGroups', function (baseEntity, startIndex, count, callback) {
  let action = 'exploreGroups'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}"`)
  let ret = { // itemsPerPage will be set by scimgateway
    'Resources': [],
    'totalResults': null
  }
  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    if (!serviceClient.nextLink.groups.skiptoken && startIndex && startIndex > 1) return callback(null, ret) // break endless fake-totalresult paging loop
    if (serviceClient.nextLink.groups.skiptoken && startIndex && startIndex < 2) serviceClient.nextLink.groups.skiptoken = null // should not occure
    let method = 'get'
    let req = null
    if (serviceClient.nextLink.groups.skiptoken) { // paging
      req = `/groups?${serviceClient.nextLink.groups.skiptoken}`
    } else {
      req = `/groups?$top=${(!count || count > 999) ? 999 : count}` // paging not supported using filter (Azure default page=100, max=999)
    }
    request[method](graphv1 + req, serviceClient.options, function (err, response, body) {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} =  ${graphv1}${req} Response = ${JSON.stringify(body)}`)
      if (err) return callback(err)
      else if (response.statusCode < 200 || response.statusCode > 299) {
        let err = new Error(`Error message: ${response.statusMessage} - ${(body.error && body.error.message) ? body.error.message : null}`)
        return callback(err)
      } else if (!body.value) {
        let err = new Error(`${action}: Got empty response on REST request`)
        return callback(err)
      }
      for (let i = 0; i < body.value.length; ++i) {
        if (body.value[i].id && body.value[i].displayName) {
          let scimGroup = { // displayName and id is mandatory, note: we set id=displayName
            'displayName': body.value[i].displayName,
            'id': body.value[i].id,
            'externalId': body.value[i].displayName
          }
          ret.Resources.push(scimGroup)
        }
      }
      if (body['@odata.nextLink']) serviceClient.nextLink.groups.skiptoken = body['@odata.nextLink'].split('?')[1] // paging keep search query
      else serviceClient.nextLink.groups.skiptoken = null
      if (!startIndex && !count) ret.totalResults = body.value.length // client request without paging
      else ret.totalResults = 99999999 // faking to ensure we get a new paging request - don't know the total numbers of groups - metadata directoryObject collections are not countable
      callback(null, ret) // all explored groups in page of result
    })
  })
})

scimgateway.on('getUser', function (baseEntity, userName, attributes, callback) {
  let action = 'getUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}" userName=${userName} attributes=${attributes}`)
  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    // attributes=country,preferredLanguage,mail,city,displayName,postalCode,jobTitle,businessPhones,onPremisesSyncEnabled,officeLocation,name.givenName,passwordPolicies,id,state,department,mailNickname,manager.managerId,active,userName,name.familyName,proxyAddresses.value,servicePlan.value,mobilePhone,streetAddress,onPremisesImmutableId,userType,usageLocation
    let parsedAttr = scimgateway.endpointMapper('outbound', attributes, scimgateway.endpointMap.microsoftGraphUser) // SCIM/CustomSCIM => endpoint attribute standard
    async.parallel(
      [
        function (callback) { // return userObj
          let method = 'get'
          let req = `/users/${querystring.escape(userName)}?$select=${parsedAttr}` // #EXT# need url encoding e.g myaccount_outlook.com#EXT#@mycompany.onmicrosoft.com
          request[method](graphv1 + req, serviceClient.options, function (err, response, body) {
            scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} = ${graphv1}${req} Response = ${JSON.stringify(body)}`)
            if (err) return callback(err)
            else if (response.statusCode < 200 || response.statusCode > 299) {
              let err = new Error(`Error message: ${response.statusMessage} - ${(body.error && body.error.message) ? body.error.message : null}`)
              return callback(err)
            }
            let userObj = body
            if (!userObj) {
              let err = new Error('Got empty response when retrieving data for ' + userName)
              return callback(err)
            }
            callback(null, userObj)
          })
        },
        function (callback) { // return manager
          if (attributes.indexOf('manager.managerId') < 0) return callback(null) // request without manager
          let method = 'get'
          let req = `/users/${querystring.escape(userName)}/manager?$select=id`
          request[method](graphv1 + req, serviceClient.options, function (err, response, body) {
            scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} = ${graphv1}${req} Response = ${JSON.stringify(body)}`)
            if (err) return callback(err)
            else if (response.statusCode < 200 || response.statusCode > 299) {
              return callback(null) // user have no manager defined
            }
            if (!body.id) {
              let err = new Error('Manager id not found when retrieving manager for ' + userName)
              return callback(err)
            } else callback(null, { 'manager': { 'managerId': body.id } })
          })
        },
        function (callback) { // return licenses
          if (attributes.indexOf('servicePlan.value') < 0) return callback(null) // licenses not requested
          let method = 'get'
          let req = `/users/${querystring.escape(userName)}/licenseDetails`
          let retObj = {}
          retObj.servicePlan = []
          request[method](graphv1 + req, serviceClient.options, function (err, response, body) {
            scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} = ${graphv1}${req} Response = ${JSON.stringify(body)}`)
            if (err) return callback(err)
            else if (response.statusCode < 200 || response.statusCode > 299) {
              return callback(null)
            }
            if (!body.value) {
              let err = new Error('No content for license information ' + userName)
              return callback(err)
            } else {
              if (body.value.length < 1) return callback(null, null) // User with no licenses
              for (let i = 0; i < body.value.length; i++) {
                let skuPartNumber = body.value[i].skuPartNumber
                for (let index = 0; index < body.value[i].servicePlans.length; index++) {
                  if (body.value[i].servicePlans[index].provisioningStatus === 'Success' || body.value[i].servicePlans[index].provisioningStatus === 'PendingInput') {
                    let servicePlan = { 'value': `${skuPartNumber}::${body.value[i].servicePlans[index].servicePlanName}` }
                    retObj.servicePlan.push(servicePlan)
                  }
                }
              }
            }
            callback(null, retObj)
          })
        }
      ],

      function (err, results) { // final callback return completed userObj
        if (err) return callback(err)
        let retObj = {}
        for (let i in results) { // merge async.parallell results to one
          retObj = Object.assign(retObj, results[i])
        }
        retObj = scimgateway.endpointMapper('inbound', retObj, scimgateway.endpointMap.microsoftGraphUser) // endpoint => SCIM/CustomSCIM attribute standard
        callback(null, retObj) // return user
      }
    ) // async
  })
})

scimgateway.on('createUser', function (baseEntity, userObj, callback) {
  let action = 'createUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}" userObj=${JSON.stringify(userObj)}`)
  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    let method = 'post'
    let req = '/users'
    let options = JSON.parse(JSON.stringify(serviceClient.options)) // use a copy and not reference
    options.body = scimgateway.endpointMapper('outbound', userObj, scimgateway.endpointMap.microsoftGraphUser)
    request[method](graphv1 + req, options, function (err, response, body) {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} = ${graphv1}${req} Response = ${JSON.stringify(body)}`)
      if (err) return callback(err)
      else if (response.statusCode < 200 || response.statusCode > 299) {
        let err = new Error(`Error message: ${response.statusMessage} - ${(body.error && body.error.message) ? body.error.message : null}`)
        return callback(err)
      }
      callback(null)
    })
  })
})

scimgateway.on('deleteUser', function (baseEntity, id, callback) {
  let action = 'deleteUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}" id=${id}`)
  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    let method = 'delete'
    let req = `/Users/${id}`
    request[method](graphv1 + req, serviceClient.options, function (err, response, body) {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} = ${graphv1}${req} Response = ${JSON.stringify(body)}`)
      if (err) return callback(err)
      else if (response.statusCode < 200 || response.statusCode > 299) {
        let err = new Error(`Error message: ${response.statusMessage} - ${(body.error && body.error.message) ? body.error.message : null}`)
        return callback(err)
      }
      callback(null)
    })
  })
})

scimgateway.on('modifyUser', function (baseEntity, id, attrObj, callback) {
  let action = 'modifyUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)
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
  if (parsedAttrObj instanceof Error) return callback(parsedAttrObj) // error object

  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    let objManager = {}
    if (parsedAttrObj.manager) { // new manager
      objManager.manager = JSON.parse(JSON.stringify(parsedAttrObj.manager))
      delete parsedAttrObj.manager
    } else if (parsedAttrObj.manager === null) { // delete manager
      objManager.manager = null
      delete parsedAttrObj.manager
    }

    async.parallel(
      [
        function (callback) { // patch
          if (JSON.stringify(parsedAttrObj) === '{}') return callback(null)
          let method = 'patch'
          let req = `/users/${id}`
          let options = JSON.parse(JSON.stringify(serviceClient.options)) // use a copy and not reference
          options.body = parsedAttrObj
          request[method](graphv1 + req, options, function (err, response, body) {
            scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} = ${graphv1}${req} Body = ${JSON.stringify(options.body)} Response = ${JSON.stringify(body)}`)
            if (err) return callback(err)
            else if (response.statusCode < 200 || response.statusCode > 299) {
              let err = new Error(`Error message: ${response.statusMessage} - ${(body.error && body.error.message) ? body.error.message : null}`)
              return callback(err)
            }
            callback(null)
          })
        },
        function (callback) { // manager
          let method = null
          let req = null
          let options = null
          if (objManager.manager) { // new manager
            method = 'put'
            req = `/users/${id}/manager/$ref`
            options = JSON.parse(JSON.stringify(serviceClient.options))
            options.body = { '@odata.id': `${graphv1}/users/${objManager.manager}` }
          } else if (objManager.manager === null) { // delete manager
            method = 'delete'
            req = `/users/${id}/manager/$ref`
            options = JSON.parse(JSON.stringify(serviceClient.options)) // use a copy and not reference
            options.body = null
          } else return callback(null)
          request[method](graphv1 + req, options, function (err, response, body) {
            scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} = ${graphv1}${req} Body = ${JSON.stringify(options.body)} Response = ${JSON.stringify(body)}`)
            if (err) return callback(err)
            else if (response.statusCode < 200 || response.statusCode > 299) {
              let err = new Error(`Error message: ${response.statusMessage} - ${(body.error && body.error.message) ? body.error.message : null}`)
              return callback(err)
            }
            callback(null)
          })
        },
        function (callback) { // licenses
          if (arrLicAdd.length < 1 && arrLicDel.length < 1) return callback(null) // no licenses to update
          // currentLic
          let method = 'get'
          let req = `/users/${querystring.escape(id)}/licenseDetails`
          let currentLic = {}
          request[method](graphv1 + req, serviceClient.options, function (err, response, body) { // build curretLic
            scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} = ${graphv1}${req} Response = ${JSON.stringify(body)}`)
            if (err) return callback(err)
            else if (response.statusCode < 200 || response.statusCode > 299) {
              return callback(null)
            }
            if (!body.value) {
              let err = new Error('No content for license information for user with id ' + id)
              return callback(err)
            }
            if (body.value.length > 0) {
              for (let i = 0; i < body.value.length; i++) { // currentLic = {skuId: [servicePlanId]}
                if (!currentLic[body.value[i].skuId]) currentLic[body.value[i].skuId] = []
                for (let index = 0; index < body.value[i].servicePlans.length; index++) {
                  if (body.value[i].servicePlans[index].servicePlanName && body.value[i].servicePlans[index].provisioningStatus === 'Success') {
                    currentLic[body.value[i].skuId].push(body.value[i].servicePlans[index].servicePlanId)
                  }
                }
              }
            }
            // availableLic
            method = 'get'
            req = '/subscribedSkus'
            let availableLic = {}
            let addLic = {}
            let removeLic = {}
            request[method](graphv1 + req, serviceClient.options, function (err, response, body) { // build availableLic
              scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} =  ${graphv1}${req} Response = ${JSON.stringify(body)}`)
              if (err) return callback(err)
              else if (response.statusCode < 200 || response.statusCode > 299) {
                let err = new Error(`Error message: ${response.statusMessage} - ${(body.error && body.error.message) ? body.error.message : null}`)
                return callback(err)
              } else if (!body.value) {
                let err = new Error(`${action}: Got empty response on REST request`)
                return callback(err)
              }
              for (let i = 0; i < body.value.length; i++) { // availableLic = {skuId: [servicePlanId]}
                if (!availableLic[body.value[i].skuId]) availableLic[body.value[i].skuId] = []
                for (let index = 0; index < body.value[i].servicePlans.length; index++) {
                  if (body.value[i].servicePlans[index].servicePlanName && body.value[i].servicePlans[index].provisioningStatus === 'Success') {
                    availableLic[body.value[i].skuId].push(body.value[i].servicePlans[index].servicePlanId)
                  }
                }
                // addLic/removeLic based on arrAdd/arrRemove
                for (let j = 0; j < arrLicAdd.length; j++) { // add licenses
                  let arrAdd = arrLicAdd[j].split('::')
                  if (arrAdd.length !== 2) {
                    let err = new Error(`${action}: License/ServicePart name must be on format skuPartNumber::servicePlanName `)
                    return callback(err)
                  }
                  if (body.value[i].skuPartNumber === arrAdd[0]) { // addLic = {skuId: [servicePlanId]}
                    let add = body.value[i].servicePlans.find(function (el) {
                      return (el.servicePlanName === arrAdd[1])
                    })
                    if (add) {
                      if (!addLic[body.value[i].skuId]) addLic[body.value[i].skuId] = []
                      addLic[body.value[i].skuId].push(add.servicePlanId)
                    }
                  }
                }
                for (let j = 0; j < arrLicDel.length; j++) { // delete licenses
                  let arrDel = arrLicDel[j].split('::')
                  if (arrDel.length !== 2) {
                    let err = new Error(`${action}: License/ServicePart name must be on format skuPartNumber::servicePlanName `)
                    return callback(err)
                  }
                  if (body.value[i].skuPartNumber === arrDel[0]) {
                    let del = body.value[i].servicePlans.find(function (el) {
                      return (el.servicePlanName === arrDel[1])
                    })
                    if (del) {
                      if (!removeLic[body.value[i].skuId]) removeLic[body.value[i].skuId] = []
                      removeLic[body.value[i].skuId].push(del.servicePlanId)
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
              method = 'post'
              req = `/users/${id}/assignLicense`
              let options = JSON.parse(JSON.stringify(serviceClient.options))
              options.body = lic

              request[method](graphv1 + req, options, function (err, response, body) {
                scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} =  ${graphv1}${req} Response = ${JSON.stringify(body)}`)
                if (err) return callback(err)
                else if (response.statusCode < 200 || response.statusCode > 299) {
                  let err = new Error(`Error message: ${response.statusMessage} - ${(body.error && body.error.message) ? body.error.message : null}`)
                  return callback(err)
                }
                callback(null)
              })
            }) // build availableLic
          }) // build currentLic
        }

      ],

      function (err, results) { // final callback
        if (err) return callback(err)
        else callback(null)
      }
    ) // async
  })
})

scimgateway.on('getGroup', function (baseEntity, displayName, attributes, callback) {
  let action = 'getGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "getGroup" group displayName=${displayName} attributes=${attributes}`)
  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    let includeMembers = false
    if (attributes.indexOf('members.value') >= 0) includeMembers = true
    let parsedAttr = scimgateway.endpointMapper('outbound', attributes, scimgateway.endpointMap.microsoftGraphGroup) // SCIM/CustomSCIM => endpoint attribute standard
    async.waterfall(
      [
        function (callback) { // return retObj with id and displayName
          let rePattern = new RegExp(/.*-.*-.*-.*-.*/)
          if (rePattern.test(displayName)) { // using id and not displayName
            let id = displayName
            let method = 'get'
            let req = `/groups/${id}?$select=${parsedAttr}`
            request[method](graphv1 + req, serviceClient.options, function (err, response, body) { // need displayName
              scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} = ${graphv1}${req} Response = ${JSON.stringify(body)}`)
              if (err) return callback(err)
              else if (!body && !body.displayName) {
                let err = new Error(`${action}: Got empty or invalid response on REST request`)
                return callback(err)
              } else {
                let retObj = scimgateway.endpointMapper('inbound', body, scimgateway.endpointMap.microsoftGraphGroup) // endpoint => SCIM/CustomSCIM attribute standard

                callback(null, retObj)
              }
            })
          } else { // using displayName and not id
            let method = 'get'
            let req = `/groups?$filter=displayName eq '${displayName}'&$select=${parsedAttr}${includeMembers ? ',id' : ''}` // group id needed for includeMembers (retObj.id)
            request[method](graphv1 + req, serviceClient.options, function (err, response, body) {
              scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} = ${graphv1}${req} Response = ${JSON.stringify(body)}`)
              if (err) return callback(err)
              else if (!body.value && !Array.isArray(body.value) && !body.value.length === 1) {
                let err = new Error(`${action}: Got empty or invalid response on REST request`)
                return callback(err)
              } else {
                let retObj = body.value[0]
                retObj = scimgateway.endpointMapper('inbound', retObj, scimgateway.endpointMap.microsoftGraphGroup) // endpoint => SCIM/CustomSCIM attribute standard
                callback(null, retObj)
              }
            })
          }
        },
        function (retObj, callback) { // return retObj with group members
          if (!includeMembers) return callback(null, retObj)
          let method = 'get'
          let req = `/groups/${retObj.id}/members?$select=id,userPrincipalName`
          request[method](graphv1 + req, serviceClient.options, function (err, response, body) { // need members of group
            scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} = ${graphv1}${req} Response = ${JSON.stringify(body)}`)
            if (err) return callback(err)
            else if (!body.value && !Array.isArray(body.value)) {
              let err = new Error(`${action}: Got empty response on REST request`)
              return callback(err)
            } else { // add all group members to retObj
              retObj.members = []
              body.value.forEach(function (el) {
                retObj.members.push({ 'value': el.id })
              })
              callback(null, retObj)
            }
          })
        }
      ],
      function (err, retObj) { // final callback function
        if (err) return callback(err)
        callback(null, retObj)
      }
    ) // async
  })
})

scimgateway.on('getGroupMembers', function (baseEntity, id, attributes, callback) {
  let action = 'getGroupMembers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}" user id=${id} attributes=${attributes}`)
  let arrRet = []
  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    let method = 'get'
    let req = `/users/${id}/memberOf?$select=displayName`
    request[method](graphv1 + req, serviceClient.options, function (err, response, body) {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} = ${graphv1}${req} Response = ${JSON.stringify(body)}`)
      if (err) return callback(err)
      else if (!body.value) {
        let err = new Error(`${action}: Got empty response on REST request`)
        return callback(err)
      }
      body.value.forEach(function (el) {
        let userGroup = {
          'displayName': el.displayName,   // displayName is mandatory
          'members': [{ 'value': id }]     // only includes current user
        }
        arrRet.push(userGroup)
      })
      callback(null, arrRet)
    })
  })
})

scimgateway.on('getServicePlanMembers', function (baseEntity, id, attributes, callback) { // not in used
  let action = 'getServicePlanMembers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}" user id=${id} attributes=${attributes}`)
  let arrRet = []
  callback(null, arrRet)
})

scimgateway.on('getGroupUsers', function (baseEntity, groupName, attributes, callback) { // not in used
  let action = 'getGroupUsers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}" groupName=${groupName} attributes=${attributes}`)
  let arrRet = []
  callback(null, arrRet)
})

scimgateway.on('createGroup', function (baseEntity, groupObj, callback) {
  let action = 'createGroup'
  scimgateway.logger.debug(`${pluginName} handling event "${action}" groupObj=${JSON.stringify(groupObj)}`)
  let body = { 'displayName': groupObj.displayName }
  body.mailNickName = groupObj.displayName
  body.mailEnabled = false
  body.securityEnabled = true
  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    let method = 'post'
    let req = '/Groups'
    let options = JSON.parse(JSON.stringify(serviceClient.options)) // use a copy and not reference
    options['body'] = body
    request[method](graphv1 + req, options, function (err, response, body) {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} = ${graphv1}${req} Body = ${JSON.stringify(options.body)} Response = ${JSON.stringify(body)}`)
      if (err) return callback(err)
      else if (response.statusCode < 200 || response.statusCode > 299) {
        let err = new Error(`Error message: ${response.statusMessage} - ${(body.error && body.error.message) ? body.error.message : null}`)
        return callback(err)
      }
      callback(null)
    })
  })
})

scimgateway.on('deleteGroup', function (baseEntity, id, callback) {
  let action = 'deleteGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}" id=${id}`)
  // if supporting delete group we need some endpoint logic here
  let err = new Error(`Delete group is not supported by ${pluginName}`)
  return callback(err)
})

scimgateway.on('modifyGroupMembers', function (baseEntity, id, members, callback) {
  let action = 'modifyGroupMembers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}" id=${id} members=${JSON.stringify(members)}`)
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
  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    async.parallel(
      [
        function (callback) { // add groups
          if (arrGrpAdd.length < 1) return callback(null)
          let method = 'post'
          let req = `/groups/${id}/members/$ref`
          for (let i = 0, len = arrGrpAdd.length; i < len; i++) {
            let options = JSON.parse(JSON.stringify(serviceClient.options))
            options['body'] = { '@odata.id': `${graphv1}/directoryObjects/${arrGrpAdd[i]}` }
            request[method](graphv1 + req, options, function (err, response, body) {
              scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} = ${graphv1}${req} Body = ${JSON.stringify(options.body)} Response = ${JSON.stringify(body)}`)
              if (err) return callback(err)
              else if (response.statusCode < 200 || response.statusCode > 299) {
                let err = new Error(`Error message: ${response.statusMessage} - ${(body.error && body.error.message) ? body.error.message : null}`)
                return callback(err)
              }
              if (i === len - 1) callback(null) // loop completed
            })
          }
        },
        function (callback) { // remove groups
          if (arrGrpDel.length < 1) return callback(null)
          let method = 'delete'
          let options = JSON.parse(JSON.stringify(serviceClient.options))
          for (let i = 0, len = arrGrpDel.length; i < len; i++) {
            let req = `/groups/${id}/members/${arrGrpDel[i]}/$ref`
            request[method](graphv1 + req, options, function (err, response, body) {
              scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} = ${graphv1}${req} Body = ${JSON.stringify(options.body)} Response = ${JSON.stringify(body)}`)
              if (err) return callback(err)
              else if (response.statusCode < 200 || response.statusCode > 299) {
                let err = new Error(`Error message: ${response.statusMessage} - ${(body.error && body.error.message) ? body.error.message : null}`)
                return callback(err)
              }
              if (i === len - 1) callback(null) // loop completed
            })
          }
        }
      ],

      function (err) { // final callback
        if (err) return callback(err)
        callback(null)
      }
    ) // async
  })
})

scimgateway.on('exploreServicePlans', function (baseEntity, startIndex, count, callback) {
  let action = 'exploreServicePlans'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}"`)
  let ret = { // itemsPerPage will be set by scimgateway
    'Resources': [],
    'totalResults': null
  }
  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    let method = 'get'
    let req = '/subscribedSkus' // paging not supported
    request[method](graphv1 + req, serviceClient.options, function (err, response, body) {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} =  ${graphv1}${req} Response = ${JSON.stringify(body)}`)
      if (err) return callback(err)
      else if (response.statusCode < 200 || response.statusCode > 299) {
        let err = new Error(`Error message: ${response.statusMessage} - ${(body.error && body.error.message) ? body.error.message : null}`)
        return callback(err)
      } else if (!body.value) {
        let err = new Error(`${action}: Got empty response on REST request`)
        return callback(err)
      }
      for (let i = 0; i < body.value.length; i++) {
        let skuPartNumber = body.value[i].skuPartNumber
        for (let index = 0; index < body.value[i].servicePlans.length; index++) {
          if (body.value[i].servicePlans[index].servicePlanName && body.value[i].servicePlans[index].provisioningStatus === 'Success') {
            let scimPlan = {
              'servicePlanName': `${skuPartNumber}::${body.value[i].servicePlans[index].servicePlanName}`
            }
            ret.Resources.push(scimPlan)
          }
        }
      }
      ret.totalResults = body.value.length
      callback(null, ret) // all explored plans
    })
  })
})

scimgateway.on('getServicePlan', function (baseEntity, servicePlanName, attributes, callback) {
  let action = 'geServicePlan'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}"`)
  if (attributes === 'servicePlanName') return callback(null, { 'servicePlanName': servicePlanName })
  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    let arrOutbound = (scimgateway.endpointMapper('outbound', attributes, scimgateway.endpointMap.microsoftGraphLicenseDetails)).split(',')
    let arrInbound = (scimgateway.endpointMapper('inbound', attributes, scimgateway.endpointMap.microsoftGraphLicenseDetails)).split(',')
    let method = 'get'
    let req = '/subscribedSkus'
    request[method](graphv1 + req, serviceClient.options, function (err, response, body) {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} ${method.toUpperCase()} =  ${graphv1}${req} Response = ${JSON.stringify(body)}`)
      if (err) return callback(err)
      else if (response.statusCode < 200 || response.statusCode > 299) {
        let err = new Error(`Error message: ${response.statusMessage} - ${(body.error && body.error.message) ? body.error.message : null}`)
        return callback(err)
      } else if (!body.value) {
        let err = new Error(`${action}: Got empty response on REST request`)
        return callback(err)
      }
      let arr = servicePlanName.split('::')
      let skuPartNumber = arr[0]
      let plan = arr[1]
      let ret = {}

      for (let i = 0; i < body.value.length; i++) {
        if (body.value[i].skuPartNumber !== skuPartNumber) continue
        for (let index = 0; index < body.value[i].servicePlans.length; index++) {
          if (body.value[i].servicePlans[index].servicePlanName === plan) {
            ret.servicePlanName = `${skuPartNumber}::${body.value[i].servicePlans[index].servicePlanName}`
            ret.id = body.value[i].servicePlans[index].servicePlanId
            for (let j = 0; j < arrInbound.length; j++) { // skuPartNumber, skuId, servicePlanName, servicePlanId
              if (arrInbound[j] !== 'servicePlanName' && arrInbound[j] !== 'id') ret[arrInbound[j]] = body.value[i][arrOutbound[j]]
            }
            i = body.value.length
            break
          }
        }
      }
      callback(null, ret)
    })
  })
})

//
// getServiceClient - returns connection parameters needed
//
let getServiceClient = function (baseEntity, callback) {
  let action = 'getServiceClient'
  if (_serviceClient[baseEntity] && _serviceClient[baseEntity]['accessToken']) { // serviceClient already exist
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: Using existing client`)
    // check if token refresh is needed
    let d = new Date() / 1000 // seconds (unix time)
    if (_serviceClient[baseEntity].accessToken.validTo < d + 30) { // less than 30 sec before token expiration
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: Accesstoken about to expire in ${_serviceClient[baseEntity].accessToken.validTo - d} seconds => renewing token`)
      getAccessToken(baseEntity, function (err, accessToken) {
        if (err) return callback(err)
        _serviceClient[baseEntity].accessToken = accessToken
        _serviceClient[baseEntity].options.auth.bearer = accessToken.access_token
        callback(null, _serviceClient[baseEntity])
      })
    } else callback(null, _serviceClient[baseEntity])
  } else { // serviceClient doesn't exist - create a new one
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: Client have to be created`)
    getAccessToken(baseEntity, function (err, accessToken) {
      if (err) return callback(err)
      let client = null
      if (config.entity && config.entity[baseEntity]) client = config.entity[baseEntity]
      if (!client) {
        let err = new Error(`Base URL have baseEntity=${baseEntity}, and configuration file ${pluginName}.json is missing required baseEntity configuration for ${baseEntity}`)
        return callback(err)
      }

      let param = {
        'accessToken': accessToken,
        'baseUrl': config.entity[baseEntity].baseUrl,
        'options': {
          'json': true, // json-object response instead of string
          'auth': {
            'bearer': accessToken.access_token
          },
          'headers': {
            'Content-Type': 'application/json'
          }
        }
      }

      if (!_serviceClient[baseEntity]) _serviceClient[baseEntity] = {}
      _serviceClient[baseEntity] = param // serviceClient created
      _serviceClient[baseEntity].nextLink = {}
      _serviceClient[baseEntity].nextLink.users = { 'skiptoken': null } // users pagination
      _serviceClient[baseEntity].nextLink.groups = { 'skiptoken': null } // groups pagination
      callback(null, _serviceClient[baseEntity])
    })
  }
}

//
// getAccessToken - returns oauth jwt accesstoken
//
let getAccessToken = function (baseEntity, callback) {
  let action = 'getAccessToken'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: Retrieving accesstoken`)

  let options = {
    'headers': {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    'proxy': config.entity[baseEntity].proxy,
    'form': { // form instead of body
      'grant_type': 'client_credentials',
      'client_id': config.entity[baseEntity].clientId,
      'client_secret': scimgateway.getPassword(`endpoint.entity.${baseEntity}.clientSecret`, configFile), // config.entity[baseEntity].clientSecret,
      'resource': 'https://graph.microsoft.com'
    }
  }

  let method = 'get'
  let req = `https://login.microsoftonline.com/${config.entity[baseEntity].tenantIdGUID}/oauth2/token`
  request[method](req, options, function (err, response, body) {
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: ${method.toUpperCase()} =  ${req} Response = ${body}`)

    if (err) return callback(err)
    else if (response.statusCode < 200 || response.statusCode > 299) {
      let err = new Error(`Error message: ${response.statusMessage} - ${(body.error && body.error.message) ? body.error.message : null}`)
      return callback(err)
    } else if (!body) {
      let err = new Error(`[${action}] No data retrieved from ${req}`)
      return callback(err)
    }

    let jbody = null
    try {
      jbody = JSON.parse(body)
    } catch (error) {
      let err = new Error(`[${action}] Error message: JSON formatting of body content failed - body: ${body}`)
      return callback(err)
    }
    if (jbody.error) {
      let err = new Error(`[${action}] Error message: ${jbody.error_description}`)
      return callback(err)
    } else if (!jbody.access_token || !jbody.expires_in) {
      let err = new Error(`[${action}] Error message: Retrieved invalid token response`)
      return callback(err)
    }

    let d = new Date() / 1000 // seconds (unix time)
    jbody['validTo'] = d + parseInt(jbody.expires_in) // instead of using expires_on (clock may not be in sync with NTP, AAD default expires_in = 3600 seconds)
    scimgateway.logger.silly(`${pluginName}[${baseEntity}] ${action}: AccessToken =  ${jbody.access_token}`)

    callback(null, jbody)
  })
}
