// =================================================================================
// File:    plugin-forwardinc.js
//
// Author:  Jarle Elshaug
//
// Purpose: SOAP Webservice user-provisioning for endpoint "Forwardinc"
//
// Prereq:  Forwardinc webservice is up and running
//          Forwardinc comes with CA IM SDK (SDKWS)
//          For details please see:
//          https://docops.ca.com/ca-identity-manager/12-6-8/EN/programming/connector-programming-reference/sdk-sample-connectors/sdkws-sdk-web-services-connector/sdkws-sample-connector-build-requirements
//
// Supported attributes:
//
// GlobalUser   Template                                Scim                            Endpoint
// -----------------------------------------------------------------------------------------------
// User name    %AC%                                    userName                        userID
// Password     %P%                                     password                        password
// First Name   %UF%                                    name.givenName                  firstName
// Last Name    %UL%                                    name.familyName                 lastName
// Full Name    %UN%                                    name.formatted                  displayName
// Job title    %UT%                                    title                           title
// Email        %UE% (Emails, type=Work)                emails.work                     emailAddress
// Phone        %UP% (Phone Numbers, type=Work)         phoneNumbers.work               phoneNumber
// Company      %UCOMP% (Entitlements, type=Company)    entitlements.company            company
//
// =================================================================================

'use strict'

const soap = require('soap')

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
  'userName', // userName is mandatory
  'active', // active is mandatory
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

const wsdlDir = path.join(`${configDir}`, 'wsdls')
const endpointUsername = config.username
const endpointPassword = scimgateway.getPassword('endpoint.password', configFile)
const _serviceClient = {}

// =================================================
// exploreUsers
// =================================================
scimgateway.exploreUsers = async (baseEntity, attributes, startIndex, count) => {
  const action = 'exploreUsers'
  scimgateway.logger.debug(`${pluginName} handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`)
  try {
    const ret = { // itemsPerPage will be set by scimgateway
      Resources: [],
      totalResults: null
    }

    let soapRequest = { sql: 'SELECT * FROM Users' }
    let result = await doRequest(baseEntity, action, soapRequest)

    if (!result.return) {
      const err = new Error(`${action} ${config[action].method} : Got empty response on soap request: ${soapRequest}`)
      err.name = 'NoResult'
      throw err
    }
    const hdl = result.return.handleId
    if (result.return.size < 1) {
      soapRequest = { handleId: hdl }
      try { doRequest(baseEntity, action + '#releaseHandle', soapRequest) } catch (err) {}
      return ret // no users found
    }

    soapRequest = {
      handleId: hdl,
      startIndex: 0,
      endIndex: result.return.size - 1
    }
    result = await doRequest(baseEntity, action + '#searchPagedUser', soapRequest) // using action client but method searchPagedUser

    if (!result.return) {
      const err = new Error(`exploreUsers searchPagedUsers: Got empty response on soap request: ${soapRequest}`)
      err.name = 'NoResult'
      throw err
    }

    result.return.forEach(function (element) {
      const scimUser = { // userName and id is mandatory, note: we set id=userName (because update user sends scim id and not userName)
        userName: element.userID,
        id: element.userID,
        externalId: element.userID
      }
      ret.Resources.push(scimUser)
    })
    soapRequest = { handleId: hdl }
    try { doRequest(baseEntity, action + '#releaseHandle', soapRequest) } catch (err) {}

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
  scimgateway.logger.debug(`${pluginName} handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`)
  try {
    const ret = { // itemsPerPage will be set by scimgateway
      Resources: [],
      totalResults: null
    }

    const soapRequest = { sql: 'SELECT * FROM Groups' }
    const result = await doRequest(baseEntity, action, soapRequest)

    if (!result) return ret // no groups
    else if (!result.return) {
      const err = new Error(`${action} ${config[action].method} : Got empty response on soap request: ${soapRequest}`)
      err.name = 'NoResult'
      throw err
    }

    result.return.forEach(function (element) {
      const scimGroup = { // displayName and id is mandatory, note: we set id=displayName
        displayName: element.groupID,
        id: element.groupID,
        externalId: element.groupID
      }
      ret.Resources.push(scimGroup)
    })

    return ret // all explored groups
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

// =================================================
// getUser
// =================================================
scimgateway.getUser = async (baseEntity, userName, attributes) => {
  const action = 'getUser'
  scimgateway.logger.debug(`${pluginName} handling "${action}" userName=${userName} attributes=${attributes}`)
  try {
    let arrAttr = []
    if (attributes) arrAttr = attributes.split(',')

    if (attributes && arrAttr.length < 3) { // userName and/or id - check if user exist
      // Could use pingUser, but instead using lookupUser that is assigned to getUser in the configuration file
      // let soapRequest = { "name": userName };
      // serviceClient.pingUser()
      const soapRequest = { userID: userName }
      const result = await doRequest(baseEntity, action, soapRequest)

      if (!result.return) return null // no user found
      const userObj = {
        userName: userName,
        id: userName,
        externalId: userName
      }
      return userObj
    } else { // all endpoint supported attributes
      const soapRequest = { userID: userName }
      const result = await doRequest(baseEntity, action, soapRequest)

      if (!result.return) return null // no user found
      const userObj = {
        userName: userName,
        id: userName,
        externalId: userName,
        password: result.return.password,
        name: {
          givenName: result.return.firstName,
          familyName: result.return.lastName,
          formatted: result.return.displayName
        },
        title: result.return.title,
        emails: (result.return.emailAddress) ? [{
          value: result.return.emailAddress,
          type: 'work'
        }] : null,
        phoneNumbers: (result.return.phoneNumber) ? [{
          value: result.return.phoneNumber,
          type: 'work'
        }] : null,
        entitlements: (result.return.company) ? [{
          value: result.return.company,
          type: 'Company'
        }] : null
      }
      return userObj
    } // else
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
  scimgateway.logger.debug(`${pluginName} handling "${action}" userObj=${JSON.stringify(userObj)}`)
  try {
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

    const soapRequest = {
      user: {
        userID: userObj.userName,
        password: userObj.password || null,
        firstName: userObj.name.givenName || null,
        lastName: userObj.name.familyName || null,
        displayName: userObj.name.formatted || null,
        title: userObj.title || null,
        emailAddress: userObj.emails.work.value || null,
        phoneNumber: userObj.phoneNumbers.work.value || null,
        company: userObj.entitlements.company.value || null
      }
    }

    const result = await doRequest(baseEntity, action, soapRequest)

    if (!result.return) {
      const err = new Error(`${action} ${config[action].method} : Got empty response on soap request: ${soapRequest}`)
      err.name = 'NoResult'
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
  scimgateway.logger.debug(`${pluginName} handling "${action}" id=${id}`)
  try {
    const soapRequest = { userID: id }
    const result = await doRequest(baseEntity, action, soapRequest)

    if (!result.return) {
      const err = new Error(`${action} ${config[action].method} : Got empty response on soap request: ${soapRequest}`)
      err.name = 'NoResult'
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
  scimgateway.logger.debug(`${pluginName} handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)
  try {
    // forwardinc modify user will blank all attributes not included in soap request...
    // We therefore need to to retrieve all user attributes from forwardinc and merge with updated attributes.
    // Modify user will then include all user attributes.

    let userObj = await scimgateway.getUser(baseEntity, id, 'userName,id,and,all,the,rest')

    const notValid = scimgateway.notValidAttributes(attrObj, validScimAttr)
    if (notValid) {
      const err = new Error(`unsupported scim attributes: ${notValid} ` +
                `(supporting only these attributes: ${validScimAttr.toString()})`
      )
      throw err
    }

    userObj = scimgateway.convertedScim(userObj) // multivalue array to none-array based on type
    for (const key1 in attrObj) {
      if (typeof attrObj[key1] === 'object') { // name.familyName
        for (const key2 in attrObj[key1]) {
          if (!userObj[key1]) userObj[key1] = {}
          userObj[key1][key2] = attrObj[key1][key2]
        }
      } else userObj[key1] = attrObj[key1] // merge modified attr into userObj
    }

    if (!userObj.name) userObj.name = {}
    if (!userObj.emails) userObj.emails = { work: {} }
    if (!userObj.phoneNumbers) userObj.phoneNumbers = { work: {} }
    if (!userObj.entitlements) userObj.entitlements = { company: {} }

    const soapRequest = {
      user: {
        userID: id,
        password: userObj.password,
        firstName: userObj.name.givenName,
        lastName: userObj.name.familyName,
        displayName: userObj.name.formatted,
        emailAddress: userObj.emails.work.value,
        phoneNumber: userObj.phoneNumbers.work.value,
        company: userObj.entitlements.company.value,
        title: userObj.title
      }
    }

    await doRequest(baseEntity, action, soapRequest)

    return null
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

// =================================================
// getGroup
// =================================================
scimgateway.getGroup = async (baseEntity, displayName, attributes) => {
  const action = 'getGroup'
  scimgateway.logger.debug(`${pluginName} handling "${action}" displayName=${displayName} attributes=${attributes}`)
  try {
    const soapRequest = { groupID: displayName }
    const result = await doRequest(baseEntity, action, soapRequest)

    if (!result.return) return null // no group found
    const retObj = {}
    retObj.displayName = result.return.groupID // displayName is mandatory
    retObj.id = result.return.groupID
    retObj.externalId = result.return.groupID // mandatory for Azure AD
    if (Array.isArray(result.return.members)) {
      retObj.members = []
      result.return.members.forEach(function (element) {
        retObj.members.push({ value: element })
      })
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
  const action = 'getGroupMembers'
  scimgateway.logger.debug(`${pluginName} handling "${action}" user id=${id} attributes=${attributes}`)
  try {
    const arrRet = []

    const soapRequest = { sql: 'SELECT * FROM Groups' }
    const result = await doRequest(baseEntity, action, soapRequest)

    if (!result) return arrRet // no groups
    else if (!result.return) {
      const err = new Error(`${action} ${config[action].method} : Got empty response on soap request: ${soapRequest}`)
      err.name = 'NoResult'
      throw err
    }

    result.return.forEach(function (element) {
      if (Array.isArray(element.members)) {
        element.members.forEach(function (el) {
          if (el === id) { // user is member of group
            const userGroup = {
              displayName: element.groupID, // displayName is mandatory
              members: [{ value: el }] // only includes current user (not all members)
            }
            arrRet.push(userGroup)
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
scimgateway.getGroupUsers = async (baseEntity, groupName, attributes) => {
  const action = 'getGroupUsers'
  scimgateway.logger.debug(`${pluginName} handling "${action}" groupName=${groupName} attributes=${attributes}`)
  const arrRet = []
  return arrRet
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj) => {
  const action = 'createGroup'
  scimgateway.logger.debug(`${pluginName} handling "${action}" groupObj=${JSON.stringify(groupObj)}`)
  // groupObj.displayName contains the group to be created
  // if supporting create group we need some endpoint logic here
  const err = new Error(`Create group is not supported by ${pluginName}`)
  throw err
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id) => {
  const action = 'deleteGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)
  // if supporting delete group we need some endpoint logic here
  const err = new Error(`Delete group is not supported by ${pluginName}`)
  throw err
}

// =================================================
// modifyGroupMembers
// =================================================
scimgateway.modifyGroupMembers = async (baseEntity, id, members) => {
  const action = 'modifyGroupMembers'
  scimgateway.logger.debug(`${pluginName} handling "${action}" id=${id} members=${JSON.stringify(members)}`)
  try {
    if (Array.isArray(members)) {
      members.forEach(async function (el) {
        if (el.operation && el.operation === 'delete') { // delete member from group
          const soapRequest = {
            groupID: id,
            userID: el.value
          }
          const result = await doRequest(baseEntity, action + '#removeUserFromGroup', soapRequest)

          if (!result.return) {
            const err = new Error(`${action} removeUserFromGroup : Got empty response on soap request: ${soapRequest}`)
            err.name = 'NoResult'
            throw err
          }
          return null
        } else { // add member to group
          const soapRequest = {
            groupID: id,
            userID: el.value
          }
          const result = await doRequest(baseEntity, action + '#assignUserToGroup', soapRequest)

          if (!result.return) {
            const err = new Error(`${action} assignUserToGroup : Got empty response on soap request: ${soapRequest}`)
            throw err
          }
          return null
        }
      })
    } else return null
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

const getServiceClient = async (baseEntity, action) => {
  const entityService = config[action].service

  if (_serviceClient[baseEntity] && _serviceClient[baseEntity][entityService]) { // serviceClient already exist
    scimgateway.logger.debug(`${pluginName} getServiceClient[${baseEntity}][${entityService}]: Using existing client`)
    return _serviceClient[baseEntity][entityService]
  }

  scimgateway.logger.debug(`${pluginName} getServiceClient[${baseEntity}][${entityService}]: Client have to be created`)

  let urlToWsdl = null // may be file system URL or http URL
  let serviceEndpoint = null

  /* uncomment if using baseEntity for client spesific configuration - endpoint.entity.<client>
    if (config.entity && !config.entity[baseEntity]) {
        let err = new Error(`Base URL have baseEntity=${baseEntity}, and configuration file ${pluginName}.json is missing required baseEntity configuration for ${baseEntity}`);
        throw err
    }
    */

  if (!config[action]) {
    const err = new Error(`getServiceClient function called with invalid action definition: ${action}`)
    throw err
  }

  urlToWsdl = require('path').resolve(`${wsdlDir}/${entityService}.wsdl`) // file system URL
  if (!config.baseServiceEndpoint) config.baseServiceEndpoint = config.baseServiceEndpoints[0] // failover logic may set baseServiceEndpoint
  serviceEndpoint = config.baseServiceEndpoint + '/' + entityService

  const wsdlOptions = {}

  try {
    const serviceClient = await soap.createClientAsync(urlToWsdl, wsdlOptions)
    serviceClient.setSecurity(new soap.WSSecurity(endpointUsername, endpointPassword, { passwordType: 'PasswordText', hasTimeStamp: false }))
    serviceClient.setEndpoint(serviceEndpoint) // https://FQDN/path/to/service (not needed if urToWsdl is url not file)

    /* Custom soap header example (not used in plugin-forwardinc)
    let customHeader = {
        "AutHeader": {
            "Source": "Example",
            "Context": {
                "company": baseEntity,
                "userid": config.entity[baseEntity].userId,
                "credentials": new Buffer(signedAssertion).toString('base64') // base64 encoded signed assertion
            }
        }
    };
    serviceClient.addSoapHeader(customHeader);
    */

    if (!_serviceClient[baseEntity]) _serviceClient[baseEntity] = {}
    _serviceClient[baseEntity][entityService] = serviceClient // serviceClient created

    serviceClient.on('response', function (body, response, eid) {
      if (response) scimgateway.logger.debug(`${pluginName} soapListener Request = ${response.request.body} Response = ${(response.body) ? response.body.replace(/[\n\r]/g, '').replace(new RegExp('> +<', 'g'), '><') : ''}`)
    })

    return _serviceClient[baseEntity][entityService]
  } catch (err) {
    let newErr
    if (err.message) newErr = new Error(`createClient ${urlToWsdl} errorMessage: ${err.message}`)
    else newErr = new Error(`createClient ${urlToWsdl} errorMessage: invalid service definition - wsdl maybe not found?`)
    throw newErr
  }
}

//
// doRequest - execute SOAP service
//
const doRequest = async (baseEntity, actionMethod, soapRequest, retryCount) => {
  try {
    const [action, method] = actionMethod.split('#') // if method then owerride config file action/method definition
    const serviceClient = await getServiceClient(baseEntity, action)
    let arrResult
    let result
    if (method) {
      arrResult = await serviceClient[method + 'Async'](soapRequest)
      result = arrResult[0]
      scimgateway.logger.debug(`${pluginName} ${action} ${method} Request = ${JSON.stringify(soapRequest)} Response = ${JSON.stringify(result)}`)
    } else {
      arrResult = await serviceClient[config[action].method + 'Async'](soapRequest)
      result = arrResult[0]
      scimgateway.logger.debug(`${pluginName} ${action} ${config[action].method} Request = ${JSON.stringify(soapRequest)} Response = ${JSON.stringify(result)}`)
    }
    return result
  } catch (err) { // ECONNREFUSED or ENOTFOUND => retry/failover all baseServiceEndpoints starting with primary
    scimgateway.logger.error(`${pluginName}[${baseEntity}] doRequest ${actionMethod} Request = ${JSON.stringify(soapRequest)} Error Response = ${err.message}`)
    if (!retryCount) retryCount = 0
    if (err.cause && err.cause.code && (err.cause.code === 'ECONNREFUSED' || err.cause.code === 'ENOTFOUND')) {
      if (retryCount < config.baseServiceEndpoints.length) {
        retryCount++
        delete _serviceClient[baseEntity]
        config.baseServiceEndpoint = config.baseServiceEndpoints[retryCount - 1]
        scimgateway.logger.debug(`${pluginName} ${actionMethod} ${(config.baseServiceEndpoints.length > 1) ? 'failover ' : ''}retry[${retryCount}] using baseServiceEndpoint = ${config.baseServiceEndpoint}`)
        const ret = await doRequest(baseEntity, actionMethod, soapRequest, retryCount) // retry
        return ret // problem fixed
      } else {
        const newerr = new Error(err.message)
        newerr.message = newerr.message.replace('ECONNREFUSED', 'UnableConnectingService') // avoid returning ECONNREFUSED error
        newerr.message = newerr.message.replace('ENOTFOUND', 'UnableConnectingHost') // avoid returning ENOTFOUND error
        throw newerr
      }
    } else throw err // CA IM retries getUser failure once (retry 6 times on ECONNREFUSED)
  }
}

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})
