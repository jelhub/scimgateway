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
// getUsers
// =================================================
scimgateway.getUsers = async (baseEntity, getObj, attributes) => {
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

  let soapRequest
  let soapAction
  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'userName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      soapRequest = { userID: getObj.value }
      soapAction = 'getUser'
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
    soapRequest = { sql: 'SELECT * FROM Users' }
    soapAction = 'exploreUsers'
  }
  // mandatory if-else logic - end

  if (!soapRequest) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  try {
    const ret = {
      Resources: [],
      totalResults: null // not used - paging not supported
    }

    const serviceClient = await getServiceClient(baseEntity, soapAction)

    let result = await serviceClient[config[soapAction].method + 'Async'](soapRequest)
    if (!Array.isArray(result) || result.length < 4) {
      throw new Error(`${config[soapAction].service}-${config[soapAction].method} : Invalid SOAP result: ${JSON.stringify(result)}`)
    }
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${config[soapAction].service}-${config[soapAction].method} endpoint: ${serviceClient.endpoint} rawRequest: ${result[3]} rawResponse: ${result[1].replace(/\n/g, '')}`)
    result = result[0]

    if (!result.return) {
      throw new Error(`${action} ${config[soapAction].method} : Got empty response on soap request: ${JSON.stringify(soapRequest)}`)
    }

    const hdl = result.return.handleId
    if (hdl) {
      if (result.return.size < 1) {
        soapRequest = { handleId: hdl }
        try { serviceClient['releaseHandle' + 'Async'](soapRequest) } catch (err) {}
        return ret // no users found
      }

      soapRequest = {
        handleId: hdl,
        startIndex: 0,
        endIndex: result.return.size - 1
      }

      result = await serviceClient['searchPagedUser' + 'Async'](soapRequest)
      if (!Array.isArray(result) || result.length < 4) {
        throw new Error(`${soapAction} searchPagedUser : Invalid SOAP result: ${JSON.stringify(result)}`)
      }
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${config[soapAction].service}-searchPagedUser endpoint: ${serviceClient.endpoint} rawRequest: ${result[3]} rawResponse: ${result[1].replace(/\n/g, '')}`)
      result = result[0]

      if (!result.return) {
        throw new Error(`exploreUsers searchPagedUsers: Got empty response on soap request: ${soapRequest}`)
      }
    }

    if (!Array.isArray(result.return)) result.return = [result.return]

    result.return.forEach(function (el) {
      const userObj = {
        userName: el.userID,
        id: el.userID,
        externalId: el.userID,
        password: el.password,
        name: {
          givenName: el.firstName,
          familyName: el.lastName,
          formatted: el.displayName
        },
        title: el.title,
        emails: (el.emailAddress) ? [{ value: el.emailAddress, type: 'work' }] : null,
        phoneNumbers: (el.phoneNumber) ? [{ value: el.phoneNumber, type: 'work' }] : null,
        entitlements: (el.company) ? [{ value: el.company, type: 'company' }] : null
      }
      ret.Resources.push(userObj)
    })

    if (hdl) {
      soapRequest = { handleId: hdl }
      try { serviceClient['releaseHandle' + 'Async'](soapRequest) } catch (err) {}
    }

    return ret
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj) => {
  const action = 'createUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" userObj=${JSON.stringify(userObj)}`)
  try {
    const notValid = scimgateway.notValidAttributes(userObj, validScimAttr)
    if (notValid) {
      throw new Error(`unsupported scim attributes: ${notValid} (supporting only these attributes: ${validScimAttr.toString()})`)
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

    const serviceClient = await getServiceClient(baseEntity, action)

    let result = await serviceClient[config[action].method + 'Async'](soapRequest)
    if (!Array.isArray(result) || result.length < 4) {
      throw new Error(`${config[action].service}-${config[action].method} : Invalid SOAP result: ${JSON.stringify(result)}`)
    }
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${config[action].service}-${config[action].method} endpoint: ${serviceClient.endpoint} rawRequest: ${result[3]} rawResponse: ${result[1].replace(/\n/g, '')}`)
    result = result[0]

    if (!result.return) {
      throw new Error(`${action} ${config[action].method} : Got empty response on soap request: ${soapRequest}`)
    }
    return null
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id) => {
  const action = 'deleteUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)
  try {
    const serviceClient = await getServiceClient(baseEntity, action)

    const soapRequest = { userID: id }

    let result = await serviceClient[config[action].method + 'Async'](soapRequest)
    if (!Array.isArray(result) || result.length < 4) {
      throw new Error(`${config[action].service}-${config[action].method} : Invalid SOAP result: ${JSON.stringify(result)}`)
    }
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${config[action].service}-${config[action].method} endpoint: ${serviceClient.endpoint} rawRequest: ${result[3]} rawResponse: ${result[1].replace(/\n/g, '')}`)
    result = result[0]

    if (!result.return) {
      throw new Error(`${config[action].method} : Got empty response on soap request: ${soapRequest}`)
    }
    return null
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// modifyUser
// =================================================
scimgateway.modifyUser = async (baseEntity, id, attrObj) => {
  const action = 'modifyUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)
  try {
    // forwardinc modify user will blank all attributes not included in soap request...
    // We therefore need to to retrieve all user attributes from forwardinc and merge with updated attributes.
    // Modify user will then include all user attributes.
    const getObj = {
      attribute: 'id',
      operator: 'eq',
      value: id
    }

    const res = await scimgateway.getUsers(baseEntity, getObj, '')

    let userObj
    if (res && Array.isArray(res.Resources) && res.Resources.length === 1) userObj = res.Resources[0]
    if (!userObj) throw new Error(`user ${id} not found`)

    const notValid = scimgateway.notValidAttributes(attrObj, validScimAttr)
    if (notValid) {
      throw new Error(`unsupported scim attributes: ${notValid} (supporting only these attributes: ${validScimAttr.toString()})`)
    }

    if (!userObj.name) userObj.name = {}
    if (!userObj.emails) userObj.emails = { work: {} }
    else if (Array.isArray(userObj.emails)) userObj.emails = { work: { value: userObj.emails[0].value } }
    if (!userObj.phoneNumbers) userObj.phoneNumbers = { work: {} }
    else if (Array.isArray(userObj.phoneNumbers)) userObj.phoneNumbers = { work: { value: userObj.phoneNumbers[0].value } }
    if (!userObj.entitlements) userObj.entitlements = { company: {} }
    else if (Array.isArray(userObj.entitlements)) userObj.entitlements = { company: { value: userObj.entitlements[0].value } }

    // merge userObj with modified attrObj
    for (const key1 in attrObj) {
      if (typeof attrObj[key1] === 'object') { // name.familyName
        for (const key2 in attrObj[key1]) {
          if (!userObj[key1]) userObj[key1] = {}
          userObj[key1][key2] = attrObj[key1][key2]
        }
      } else userObj[key1] = attrObj[key1] // merge modified attr into userObj
    }

    const serviceClient = await getServiceClient(baseEntity, action)

    const soapRequest = {
      user: {
        userID: id,
        password: userObj.password,
        firstName: userObj.name.givenName,
        lastName: userObj.name.familyName,
        displayName: userObj.name.formatted,
        emailAddress: userObj.emails.work.value, // note, using default configuration setting  scim.skipTypeConvert = false
        phoneNumber: userObj.phoneNumbers.work.value,
        company: userObj.entitlements.company.value,
        title: userObj.title
      }
    }

    let result = await serviceClient[config[action].method + 'Async'](soapRequest)
    if (!Array.isArray(result) || result.length < 4) {
      throw new Error(`${config[action].service}-${config[action].method} : Invalid SOAP result: ${JSON.stringify(result)}`)
    }
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${config[action].service}-${config[action].method} endpoint: ${serviceClient.endpoint} rawRequest: ${result[3]} rawResponse: ${result[1].replace(/\n/g, '')}`)
    result = result[0]

    return null
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// getGroups
// =================================================
scimgateway.getGroups = async (baseEntity, getObj, attributes) => {
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

  let soapRequest
  let soapAction
  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'displayName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      soapRequest = { groupID: getObj.value }
      soapAction = 'getGroup'
    } else if (getObj.operator === 'eq' && getObj.attribute === 'members.value') {
      // mandatory - return all groups the user 'id' (getObj.value) is member of - correspond to getGroupMembers() in versions < 4.x.x
      // Resources = [{ id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }]
      soapRequest = { sql: 'SELECT * FROM Groups' }
      soapAction = 'exploreGroups'
    } else {
      // optional - simpel filtering
      throw new Error(`${action} error: not supporting simpel filtering: ${getObj.rawFilter}`)
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all groups to be returned - correspond to exploreGroups() in versions < 4.x.x
    soapRequest = { sql: 'SELECT * FROM Groups' }
    soapAction = 'exploreGroups'
  }
  // mandatory if-else logic - end

  if (!soapRequest) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  const ret = { // itemsPerPage will be set by scimgateway
    Resources: [],
    totalResults: null
  }

  try {
    const serviceClient = await getServiceClient(baseEntity, soapAction)

    let result = await serviceClient[config[soapAction].method + 'Async'](soapRequest)
    if (!Array.isArray(result) || result.length < 4) {
      throw new Error(`${config[soapAction].service}-${config[soapAction].method} : Invalid SOAP result: ${JSON.stringify(result)}`)
    }
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${config[soapAction].service}-${config[soapAction].method} endpoint: ${serviceClient.endpoint} rawRequest: ${result[3]} rawResponse: ${result[1].replace(/\n/g, '')}`)
    result = result[0]

    if (!result) return ret // no groups
    else if (!result.return) {
      throw new Error(`${config[soapAction].method} : Got empty response on soap request: ${soapRequest}`)
    }

    if (!Array.isArray(result.return)) result.return = [result.return]

    if (getObj.attribute === 'members.value' && getObj.operator === 'eq') {
      result.return.forEach(function (el) {
        const scimGroup = {
          displayName: el.groupID,
          id: el.groupID,
          externalId: el.groupID
        }
        scimGroup.members = []
        if (Array.isArray(el.members)) {
          const found = el.members.find(el => el === getObj.value)
          if (found) scimGroup.members.push({ value: getObj.value }) // only include members.value
        }
        if (scimGroup.members.length === 1) ret.Resources.push(scimGroup)
      })
    } else {
      result.return.forEach(function (el) {
        const scimGroup = {
          displayName: el.groupID,
          id: el.groupID,
          externalId: el.groupID
        }
        scimGroup.members = []
        if (Array.isArray(el.members)) {
          el.members.forEach(function (userid) {
            scimGroup.members.push({ value: userid })
          })
        }
        ret.Resources.push(scimGroup)
      })
    }
    return ret
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj) => {
  const action = 'createGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" groupObj=${JSON.stringify(groupObj)}`)
  // groupObj.displayName contains the group to be created
  // if supporting create group, we need some endpoint logic here
  throw new Error(`${action} error: ${action} is not supported`)
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id) => {
  const action = 'deleteGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)
  // if supporting delete group, we need some endpoint logic here
  throw new Error(`${action} error: ${action} is not supported`)
}

// =================================================
// modifyGroup
// =================================================
scimgateway.modifyGroup = async (baseEntity, id, attrObj) => {
  const action = 'modifyGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)

  if (!attrObj.members) {
    throw new Error(`${action} error: only supports modification of members`)
  }
  if (!Array.isArray(attrObj.members)) {
    throw new Error(`${action} error: ${JSON.stringify(attrObj)} - correct syntax is { "members": [...] }`)
  }

  try {
    const serviceClient = await getServiceClient(baseEntity, action)

    attrObj.members.forEach(async function (el) {
      if (el.operation && el.operation === 'delete') { // delete member from group
        const soapRequest = {
          groupID: id,
          userID: el.value
        }
        let result = await serviceClient['removeUserFromGroup' + 'Async'](soapRequest)
        if (!Array.isArray(result) || result.length < 4) {
          throw new Error(`${config[action].service}-removeUserFromGroup : Invalid SOAP result: ${JSON.stringify(result)}`)
        }
        result = result[0]

        if (!result.return) {
          throw new Error(`${config[action].service}-removeUserFromGroup : Got empty response on soap request: ${soapRequest}`)
        }
        return null
      } else { // add member to group
        const soapRequest = {
          groupID: id,
          userID: el.value
        }
        let result = await serviceClient['assignUserToGroup' + 'Async'](soapRequest)
        if (!Array.isArray(result) || result.length < 4) {
          throw new Error(`${config[action].service}-assignUserToGroup : Invalid SOAP result: ${JSON.stringify(result)}`)
        }
        result = result[0]

        if (!result.return) {
          throw new Error(`assignUserToGroup : Got empty response on soap request: ${soapRequest}`)
        }
        return null
      }
    })
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// helpers
// =================================================

const getServiceClient = async (baseEntity, action) => {
  try {
    const entityService = config[action].service

    if (_serviceClient[baseEntity] && _serviceClient[baseEntity][entityService]) { // serviceClient already exist
      // here we may also check for expired auth and update _serviceClient if needed
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] getServiceClient[${baseEntity}][${entityService}]: Using existing client`)
      return _serviceClient[baseEntity][entityService]
    }

    scimgateway.logger.debug(`${pluginName}[${baseEntity}] getServiceClient[${baseEntity}][${entityService}]: Client have to be created`)

    let urlToWsdl = null // may be file system URL or http URL
    let serviceEndpoint = null
    let client = null

    if (config.entity && config.entity[baseEntity]) client = config.entity[baseEntity]
    if (!client) {
      const err = new Error(`Base URL have baseEntity=${baseEntity}, and configuration file ${pluginName}.json is missing required baseEntity configuration for ${baseEntity}`)
      throw err
    }

    if (!config[action]) {
      throw new Error(`getServiceClient function called with invalid action definition: ${action}`)
    }
    urlToWsdl = require('path').resolve(`${wsdlDir}/${entityService}.wsdl`)// file system wsdl/URL
    // urlToWsdl = `${config.baseServiceEndpoint}/${entityService}?wsdl` // http URL
    serviceEndpoint = config.baseServiceEndpoint + '/' + entityService

    const wsdlOptions = {
      handleNilAsNull: false
    }

    const customHeader = {}
    /*
    const customHeader = {
      AutHeader: {
        Source: 'Example',
        Context: {
          company: baseEntity,
          userid: config.entity[baseEntity].userId,
          credentials: Buffer.from(signedAssertion).toString('base64') // base64 encoded signed assertion
        }
      }
    }
    */

    try {
      const serviceClient = await soap.createClientAsync(urlToWsdl, wsdlOptions)
      serviceClient.setSecurity(new soap.WSSecurity(endpointUsername, endpointPassword, { passwordType: 'PasswordText', hasTimeStamp: false })) // ForwardInc using WSSecurity
      serviceClient.addSoapHeader(customHeader)
      serviceClient.setEndpoint(serviceEndpoint) // https://FQDN/path/to/service (wsdl name without ?wsdl extension)

      if (!_serviceClient[baseEntity]) _serviceClient[baseEntity] = {}
      _serviceClient[baseEntity][entityService] = serviceClient // serviceClient created
      return _serviceClient[baseEntity][entityService]
    } catch (err) {
      if (err.message) throw new Error(`createClient ${urlToWsdl} errorMessage: ${err.message}`)
      else throw new Error(`createClient ${urlToWsdl} errorMessage: invalid service definition - wsdl maybe not found?`)
    }
  } catch (err) {
    const newErr = err
    throw newErr
  }
} // getServiceClient

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})
