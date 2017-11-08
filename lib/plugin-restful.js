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

const request = require('request')
const dot = require('dot-object')

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
let validScimAttr = [ // array containing scim attributes supported by our plugin code. Empty array - all attrbutes are supported by endpoint
  'userName',         // userName is mandatory
  'active',           // active is mandatory
  'password',
  'name.givenName',
  'name.familyName',
  'name.formatted',
  'title',
  // "emails",         // accepts all multivalues for this key
  'emails.work',       // accepts multivalues if type value equal work (lowercase)
  // "phoneNumbers",
  'phoneNumbers.work',
  // "entitlements"
  'entitlements.company'
]
// mandatory plugin initialization - end

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
    let req = '/Users?attributes=userName'
    request.get(serviceClient.baseUrl + req, serviceClient.options, function (err, response, body) {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} GET = ${serviceClient.baseUrl}${req} Response = ${JSON.stringify(body)}`)
      if (err) return callback(err)
      else if (response.statusCode < 200 || response.statusCode > 299) {
        let err = new Error(`Error message: ${response.statusMessage} - ${body}`)
        return callback(err)
      } else if (!body.Resources) {
        let err = new Error(`${action}: Got empty response on REST request`)
        return callback(err)
      }
      if (!startIndex && !count) { // client request without paging
        startIndex = 1
        count = body.Resources.length
      }
      for (let index = startIndex - 1; index < body.Resources.length && (index + 1 - startIndex) < count; ++index) {
        if (body.Resources[index].id && body.Resources[index].userName) {
          let scimUser = { // userName and id is mandatory, note: we set id=userName
            'userName': body.Resources[index].userName,
            'id': body.Resources[index].id,
            'externalId': body.Resources[index].userName
          }
          ret.Resources.push(scimUser)
        }
      }
      // not needed if client or endpoint do not support paging
      ret.totalResults = body.Resources.length
      ret.startIndex = startIndex
      callback(null, ret) // all explored users
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
    let req = '/Groups?attributes=displayName'
    request.get(serviceClient.baseUrl + req, serviceClient.options, function (err, response, body) {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} GET =  ${serviceClient.baseUrl}${req} Response = ${JSON.stringify(body)}`)
      if (err) return callback(err)
      else if (response.statusCode < 200 || response.statusCode > 299) {
        let err = new Error(`Error message: ${response.statusMessage} - ${body}`)
        return callback(err)
      } else if (!body.Resources) {
        let err = new Error(`${action}: Got empty response on REST request`)
        return callback(err)
      }
      if (!startIndex && !count) { // client request without paging
        startIndex = 1
        count = body.Resources.length
      }
      for (let index = startIndex - 1; index < body.Resources.length && (index + 1 - startIndex) < count; ++index) {
        if (body.Resources[index].id && body.Resources[index].displayName) {
          let scimGroup = { // displayName and id is mandatory, note: we set id=displayName
            'displayName': body.Resources[index].displayName,
            'id': body.Resources[index].id,
            'externalId': body.Resources[index].displayName
          }
          ret.Resources.push(scimGroup)
        }
      }
      // not needed if client or endpoint do not support paging
      ret.totalResults = body.Resources.length
      ret.startIndex = startIndex
      callback(null, ret) // all explored users
    })
  })
})

scimgateway.on('getUser', function (baseEntity, userName, attributes, callback) {
  let action = 'getUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}" userName=${userName} attributes=${attributes}`)

  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    let arrAttr = []
    if (attributes) arrAttr = attributes.split(',')
    if (attributes && arrAttr.length < 3) { // userName and/or id - check if user exist
      let req = `/Users?filter=userName eq "${userName}"&attributes=userName`
      request.get(serviceClient.baseUrl + req, serviceClient.options, function (err, response, body) {
        scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} GET = ${serviceClient.baseUrl}${req} Response = ${JSON.stringify(body)}`)
        if (err) return callback(err)
        else if (response.statusCode < 200 || response.statusCode > 299) {
          let err = new Error(`Error message: ${response.statusMessage} - ${body}`)
          return callback(err)
        } else if (!body.Resources) {
          let err = new Error(`${action}: Got empty response on REST request`)
          return callback(err)
        }
        let userObj = body.Resources.find(function (element) { // Verify user exist
          return element.userName === userName
        })
        if (!userObj) {
          let err = new Error('Could not find user with userName ' + userName)
          return callback(err)
        }
        let retObj = {
          'id': userName,
          'userName': userName,
          'externalId': userName
        }
        callback(null, retObj) // return user found
      })
    } else { // all endpoint supported attributes
      let req = `/Users?filter=userName eq "${userName}"&
      attributes=userName,active,name.givenName,name.familyName,name.formatted,title,emails,phoneNumbers,entitlements`

      request.get(serviceClient.baseUrl + req, serviceClient.options, function (err, response, body) {
        scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} GET = ${serviceClient.baseUrl}${req} Response = ${JSON.stringify(body)}`)
        if (err) return callback(err)
        else if (response.statusCode < 200 || response.statusCode > 299) {
          let err = new Error(`Error message: ${response.statusMessage} - ${body}`)
          return callback(err)
        } else if (!body.Resources) {
          let err = new Error(`${action}: Got empty response on REST request`)
          return callback(err)
        }
        let userObj = body.Resources.find(function (element) { // Verify user exist
          return element.userName === userName
        })
        if (!userObj) {
          let err = new Error('Could not find user with userName ' + userName)
          return callback(err)
        }

        if (!userObj.name) userObj.name = {}
        if (!userObj.emails) userObj.emails = [{}]
        if (!userObj.phoneNumbers) userObj.phoneNumbers = [{}]
        if (!userObj.entitlements) userObj.entitlements = [{}]

        let objWorkEmail = scimgateway.getArrayObject(userObj, 'emails', 'work')
        let objWorkPhone = scimgateway.getArrayObject(userObj, 'phoneNumbers', 'work')
        let objCompanyEntitlement = scimgateway.getArrayObject(userObj, 'entitlements', 'company')

        let arrEmail = []
        let arrPhone = []
        let arrEntitlement = []
        if (objWorkEmail) arrEmail.push(objWorkEmail)
        else arrEmail = null
        if (objWorkPhone) arrPhone.push(objWorkPhone)
        else arrPhone = null
        if (objCompanyEntitlement) arrEntitlement.push(objCompanyEntitlement)
        else arrEntitlement = null

        let retObj = {
          'userName': userObj.userName,
          'id': userObj.userName,
          'externalId': userObj.userName,
          'active': userObj.active,
          'name': {
            'givenName': userObj.name.givenName || '',
            'familyName': userObj.name.familyName || '',
            'formatted': userObj.name.formatted || ''
          },
          'title': userObj.title,
          'emails': arrEmail,
          'phoneNumbers': arrPhone,
          'entitlements': arrEntitlement
        }

        callback(null, retObj) // return user found
      })
    } // else
  })
})

scimgateway.on('createUser', function (baseEntity, userObj, callback) {
  let action = 'createUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}" userObj=${JSON.stringify(userObj)}`)

  let notValid = scimgateway.notValidAttributes(userObj, validScimAttr)
  if (notValid) {
    let err = new Error(`unsupported scim attributes: ${notValid} ` +
      `(supporting only these attributes: ${validScimAttr.toString()})`
    )
    return callback(err)
  }

  if (!userObj.name) userObj.name = {}
  if (!userObj.emails) userObj.emails = { 'work': {} }
  if (!userObj.phoneNumbers) userObj.phoneNumbers = { 'work': {} }
  if (!userObj.entitlements) userObj.entitlements = { 'company': {} }

  let arrEmail = []
  let arrPhone = []
  let arrEntitlement = []
  if (userObj.emails.work.value) arrEmail.push(userObj.emails.work)
  if (userObj.phoneNumbers.work.value) arrPhone.push(userObj.phoneNumbers.work)
  if (userObj.entitlements.company.value) arrEntitlement.push(userObj.entitlements.company)

  let body = {
    'userName': userObj.userName,
    'active': userObj.active || true,
    'password': userObj.password || null,
    'name': {
      'givenName': userObj.name.givenName || null,
      'familyName': userObj.name.familyName || null,
      'formatted': userObj.name.formatted || null
    },
    'title': userObj.title || '',
    'emails': (arrEmail.length > 0) ? arrEmail : null,
    'phoneNumbers': (arrPhone.length > 0) ? arrPhone : null,
    'entitlements': (arrEntitlement.length > 0) ? arrEntitlement : null
  }

  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    let req = '/Users'
    let cli = {}
    dot.copy('options', 'options', serviceClient, cli) // because serviceClient object should not be changed (e.g adding body)
    cli.options['body'] = body
    request.post(serviceClient.baseUrl + req, cli.options, function (err, response, body) {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} POST = ${serviceClient.baseUrl}${req} Body = ${JSON.stringify(cli.options.body)} Response = ${JSON.stringify(body)}`)
      if (err) return callback(err)
      else if (response.statusCode < 200 || response.statusCode > 299) {
        let err = new Error(`Error message: ${response.statusMessage} - ${body}`)
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
    let req = `/Users/${id}`
    request.delete(serviceClient.baseUrl + req, serviceClient.options, function (err, response, body) {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} DELETE = ${serviceClient.baseUrl}${req} Response = ${JSON.stringify(body)}`)
      if (err) return callback(err)
      else if (response.statusCode < 200 || response.statusCode > 299) {
        let err = new Error(`Error message: ${response.statusMessage} - ${body}`)
        return callback(err)
      }
      callback(null)
    })
  })
})

scimgateway.on('modifyUser', function (baseEntity, id, attrObj, callback) {
  let action = 'modifyUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)

  let notValid = scimgateway.notValidAttributes(attrObj, validScimAttr)
  if (notValid) {
    let err = new Error(`unsupported scim attributes: ${notValid} ` +
      `(supporting only these attributes: ${validScimAttr.toString()})`
    )
    return callback(err)
  }

  if (!attrObj.name) attrObj.name = {}
  if (!attrObj.emails) attrObj.emails = {}
  if (!attrObj.phoneNumbers) attrObj.phoneNumbers = {}
  if (!attrObj.entitlements) attrObj.entitlements = {}

  let arrEmail = []
  let arrPhone = []
  let arrEntitlement = []
  if (attrObj.emails.work) arrEmail.push(attrObj.emails.work)
  if (attrObj.phoneNumbers.work) arrPhone.push(attrObj.phoneNumbers.work)
  if (attrObj.entitlements.company) arrEntitlement.push(attrObj.entitlements.company)

  let body = { 'userName': id }
  if (attrObj.active == true) body.active = true
  else if (attrObj.active == false) body.active = false

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

  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    let req = `/Users/${id}`
    let cli = {}
    dot.copy('options', 'options', serviceClient, cli) // because serviceClient object should not be changed (e.g adding body)
    cli.options['body'] = body
    request.patch(serviceClient.baseUrl + req, cli.options, function (err, response, body) {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} PATCH = ${serviceClient.baseUrl}${req} Body = ${JSON.stringify(cli.options.body)} Response = ${JSON.stringify(body)}`)
      if (err) return callback(err)
      else if (response.statusCode < 200 || response.statusCode > 299) {
        let err = new Error(`Error message: ${response.statusMessage} - ${body}`)
        return callback(err)
      }
      callback(null)
    })
  })
})

scimgateway.on('getGroup', function (baseEntity, displayName, attributes, callback) {
  let action = 'getGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "getGroup" group displayName=${displayName} attributes=${attributes}`)

  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    // GET = /Groups?filter=displayName eq "Admins"&attributes=externalId,id,members.value,displayName
    let req = `/Groups?filter=displayName eq "${displayName}"&attributes=${attributes}`
    request.get(serviceClient.baseUrl + req, serviceClient.options, function (err, response, body) {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} GET = ${serviceClient.baseUrl}${req} Response = ${JSON.stringify(body)}`)
      if (err) return callback(err)
      else if (!body.Resources) {
        let err = new Error(`${action}: Got empty response on REST request`)
        return callback(err)
      }

      let retObj = {}

      if (body.Resources.length === 1) {
        let grp = body.Resources[0]
        retObj.displayName = grp.displayName // displayName is mandatory
        retObj.id = grp.id
        retObj.externalId = grp.displayName // mandatory for Azure AD
        if (Array.isArray(grp.members)) {
          retObj.members = []
          grp.members.forEach(function (el) {
            retObj.members.push({ 'value': el.value })
          })
        }
      }
      callback(null, retObj)
    })
  })
})

scimgateway.on('getGroupMembers', function (baseEntity, id, attributes, startIndex, count, callback) {
  let action = 'getGroupMembers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}" user id=${id} attributes=${attributes}`)
  let ret = {
    'Resources': [],
    'totalResults': null
  }

  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    // GET = /Groups?filter=members.value eq "bjensen"&attributes=members.value,displayName
    let req = `/Groups?filter=members.value eq "${id}"&attributes=${attributes}`
    request.get(serviceClient.baseUrl + req, serviceClient.options, function (err, response, body) {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} GET = ${serviceClient.baseUrl}${req} Response = ${JSON.stringify(body)}`)

      if (err) return callback(err)
      else if (!body.Resources) {
        let err = new Error(`${action}: Got empty response on REST request`)
        return callback(err)
      }

      body.Resources.forEach(function (element) {
        if (Array.isArray(element.members)) {
          element.members.forEach(function (el) {
            if (el.value === id) { // user is member of group
              let userGroup = {
                'displayName': element.displayName,   // displayName is mandatory
                'members': [{ 'value': el.value }]    // only includes current user
              }
              ret.Resources.push(userGroup)
            }
          })
        }
      })
      callback(null, ret)
    })
  })
})

scimgateway.on('getGroupUsers', function (baseEntity, groupName, attributes, callback) {
  let action = 'getGroupUsers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}" groupName=${groupName} attributes=${attributes}`)
  let arrRet = []
  callback(null, arrRet)
})

scimgateway.on('createGroup', function (baseEntity, groupObj, callback) {
  let action = 'createGroup'
  scimgateway.logger.debug(`${pluginName} handling event "${action}" groupObj=${JSON.stringify(groupObj)}`)
  let body = { 'displayName': groupObj.displayName }

  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    let req = '/Groups'
    let cli = {}
    dot.copy('options', 'options', serviceClient, cli) // because serviceClient object should not be changed (e.g adding body)
    cli.options['body'] = body
    request.post(serviceClient.baseUrl + req, cli.options, function (err, response, body) {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} POST = ${serviceClient.baseUrl}${req} Body = ${JSON.stringify(cli.options.body)} Response = ${JSON.stringify(body)}`)
      if (err) return callback(err)
      else if (response.statusCode < 200 || response.statusCode > 299) {
        let err = new Error(`Error message: ${response.statusMessage} - ${body}`)
        return callback(err)
      }
      callback(null)
    })
  })
})

scimgateway.on('modifyGroupMembers', function (baseEntity, id, members, callback) {
  let action = 'modifyGroupMembers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling event "${action}" id=${id} members=${JSON.stringify(members)}`)
  let body = { 'members': [] }
  if (Array.isArray(members)) {
    members.forEach(function (el) {
      if (el.operation && el.operation === 'delete') { // delete member from group
        // PATCH = /Groups/Admins Body = {"members":[{"operation":"delete","value":"bjensen"}]}
        body.members.push({ 'operation': 'delete', 'value': el.value })
      } else { // add member to group/
        // PATCH = /Groups/Admins Body = {"members":[{"value":"bjensen"}]
        body.members.push({ 'value': el.value })
      }
    })
  } // if Array

  getServiceClient(baseEntity, function (err, serviceClient) {
    if (err) return callback(err)
    let req = `/Groups/${id}`
    let cli = {}
    dot.copy('options', 'options', serviceClient, cli) // because serviceClient object should not be changed (e.g adding body)
    cli.options['body'] = body
    request.patch(serviceClient.baseUrl + req, cli.options, function (err, response, body) {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action} PATCH = ${serviceClient.baseUrl}${req} Body = ${JSON.stringify(cli.options.body)} Response = ${JSON.stringify(body)}`)
      if (err) return callback(err)
      else if (response.statusCode < 200 || response.statusCode > 299) {
        let err = new Error(`Error message: ${response.statusMessage} - ${body}`)
        return callback(err)
      }
      callback(null)
    })
  })
})

//
// getServiceClient - returns connection parameters needed
//
let getServiceClient = function (baseEntity, callback) {
  if (_serviceClient[baseEntity]) { // serviceClient already exist
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] getServiceClient: Using existing client`)
    return callback(null, _serviceClient[baseEntity])
  }
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] getServiceClient: Client have to be created`)
  let client = null
  if (config.entity && config.entity[baseEntity]) client = config.entity[baseEntity]
  if (!client) {
    let err = new Error(`Base URL have baseEntity=${baseEntity}, and configuration file ${pluginName}.json is missing required baseEntity configuration for ${baseEntity}`)
    return callback(err)
  }

  let param = {
    'baseUrl': config.entity[baseEntity].baseUrl,
    'options': {
      'json': true, // json-object response instead of string
      'headers': {
        'Authorization': 'Basic ' + Buffer.from(`${config.entity[baseEntity].username}:${scimgateway.getPassword(`endpoint.entity.${baseEntity}.password`, configFile)}`).toString('base64'),
        'Content-Type': 'application/json'
        // "Proxy-Authorization": auth  // using proxy
      }
    }
  }

  if (!_serviceClient[baseEntity]) _serviceClient[baseEntity] = {}
  _serviceClient[baseEntity] = param // serviceClient created
  callback(null, _serviceClient[baseEntity])
}
