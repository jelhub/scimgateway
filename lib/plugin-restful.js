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
config = scimgateway.processExtConfig(pluginName, config) // add any external config process.env and process.file
// mandatory plugin initialization - end

let _serviceClient = {}

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

  let method = 'GET'
  let path = '/Users?attributes=userName'
  let body = null

  try {
    let response = await doRequest(baseEntity, method, path, body)
    if (response.statusCode < 200 || response.statusCode > 299) {
      let err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
      throw (err)
    } else if (!response.body.Resources) {
      let err = new Error(`${action}: Got empty response on REST request`)
      throw (err)
    }
    if (!startIndex && !count) { // client request without paging
      startIndex = 1
      count = response.body.Resources.length
    }
    for (let index = startIndex - 1; index < response.body.Resources.length && (index + 1 - startIndex) < count; ++index) {
      if (response.body.Resources[index].id && response.body.Resources[index].userName) {
        let scimUser = { // userName and id is mandatory, note: we set id=userName
          'userName': response.body.Resources[index].userName,
          'id': response.body.Resources[index].id,
          'externalId': response.body.Resources[index].userName
        }
        ret.Resources.push(scimUser)
      }
    }
      // not needed if client or endpoint do not support paging
    ret.totalResults = response.body.Resources.length
    ret.startIndex = startIndex
    return ret // all explored users
  } catch (err) {
    throw err
  }
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

  let method = 'GET'
  let path = '/Groups?attributes=displayName'
  let body = null

  try {
    let response = await doRequest(baseEntity, method, path, body)
    if (response.statusCode < 200 || response.statusCode > 299) {
      let err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
      throw err
    } else if (!response.body.Resources) {
      let err = new Error(`${action}: Got empty response on REST request`)
      throw err
    }
    if (!startIndex && !count) { // client request without paging
      startIndex = 1
      count = response.body.Resources.length
    }
    for (let index = startIndex - 1; index < response.body.Resources.length && (index + 1 - startIndex) < count; ++index) {
      if (response.body.Resources[index].id && response.body.Resources[index].displayName) {
        let scimGroup = { // displayName and id is mandatory, note: we set id=displayName
          'displayName': response.body.Resources[index].displayName,
          'id': response.body.Resources[index].id,
          'externalId': response.body.Resources[index].displayName
        }
        ret.Resources.push(scimGroup)
      }
    }
    // not needed if client or endpoint do not support paging
    ret.totalResults = response.body.Resources.length
    ret.startIndex = startIndex
    return ret // all explored users
  } catch (err) {
    throw err
  }
}

// =================================================
// getUser
// =================================================
scimgateway.getUser = async (baseEntity, userName, attributes) => {
  let action = 'getUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" userName=${userName} attributes=${attributes}`)
  let arrAttr = []
  if (attributes) arrAttr = attributes.split(',')
  if (attributes && arrAttr.length < 3) { // userName and/or id - check if user exist
    let method = 'GET'
    let path = `/Users?filter=userName eq "${userName}"&attributes=userName`
    let body = null

    try {
      let response = await doRequest(baseEntity, method, path, body)
      if (response.statusCode < 200 || response.statusCode > 299) {
        let err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
        throw err
      } else if (!response.body.Resources) {
        let err = new Error(`${action}: Got empty response on REST request`)
        throw err
      }
      let userObj = response.body.Resources.find(function (element) { // Verify user exist
        return element.userName === userName
      })
      if (!userObj) return null // no user found

      let retObj = {
        'id': userName,
        'userName': userName,
        'externalId': userName
      }
      return retObj // return user found
    } catch (err) {
      throw err
    }
  } else { // all endpoint supported attributes
    let method = 'GET'
    let path = `/Users?filter=userName eq "${userName}"&
      attributes=userName,active,name.givenName,name.familyName,name.formatted,title,emails,phoneNumbers,entitlements`
    let body = null
    try {
      let response = await doRequest(baseEntity, method, path, body)
      if (response.statusCode < 200 || response.statusCode > 299) {
        let err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
        throw err
      } else if (!response.body.Resources) {
        let err = new Error(`${action}: Got empty response on REST request`)
        throw err
      }
      let userObj = response.body.Resources.find(function (element) { // Verify user exist
        return element.userName === userName
      })
      if (!userObj) return null // no user found

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
      return retObj // return user found
    } catch (err) {
      throw err
    }
  } // else
}

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj) => {
  let action = 'createUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" userObj=${JSON.stringify(userObj)}`)

  let notValid = scimgateway.notValidAttributes(userObj, validScimAttr)
  if (notValid) {
    let err = new Error(`unsupported scim attributes: ${notValid} ` +
      `(supporting only these attributes: ${validScimAttr.toString()})`
    )
    throw err
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

  let method = 'POST'
  let path = '/Users'
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

  try {
    let response = await doRequest(baseEntity, method, path, body)
    if (response.statusCode < 200 || response.statusCode > 299) {
      let err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
      throw err
    }
    return null
  } catch (err) {
    throw err
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
    let response = await doRequest(baseEntity, method, path, body)
    if (response.statusCode < 200 || response.statusCode > 299) {
      let err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
      throw err
    }
    return null
  } catch (err) {
    throw err
  }
}

// =================================================
// modifyUser
// =================================================
scimgateway.modifyUser = async (baseEntity, id, attrObj) => {
  let action = 'modifyUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`)

  let notValid = scimgateway.notValidAttributes(attrObj, validScimAttr)
  if (notValid) {
    let err = new Error(`unsupported scim attributes: ${notValid} ` +
      `(supporting only these attributes: ${validScimAttr.toString()})`
    )
    throw err
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

  let method = 'PATCH'
  let path = `/Users/${id}`
  let body = { 'userName': id }
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

  try {
    let response = await doRequest(baseEntity, method, path, body)
    if (response.statusCode < 200 || response.statusCode > 299) {
      let err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
      throw err
    }
    return null
  } catch (err) {
    throw err
  }
}

// =================================================
// getGroup
// =================================================
scimgateway.getGroup = async (baseEntity, displayName, attributes) => {
  let action = 'getGroup'
  scimgateway.logger.debug(`${pluginName} handling "${action}" displayName=${displayName} attributes=${attributes}`)

  let method = 'GET'
  let path = `/Groups?filter=displayName eq "${displayName}"&attributes=${attributes}` // GET = /Groups?filter=displayName eq "Admins"&attributes=externalId,id,members.value,displayName
  let body = null

  try {
    let response = await doRequest(baseEntity, method, path, body)
    if (!response.body.Resources) {
      let err = new Error(`${action}: Got empty response on REST request`)
      throw err
    }
    let retObj = {}
    if (response.body.Resources.length === 1) {
      let grp = response.body.Resources[0]
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
    return retObj
  } catch (err) {
    throw err
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
  let path = `/Groups?filter=members.value eq "${id}"&attributes=${attributes}` // GET = /Groups?filter=members.value eq "bjensen"&attributes=members.value,displayName
  let body = null

  try {
    let response = await doRequest(baseEntity, method, path, body)
    if (!response.body.Resources) {
      let err = new Error(`${action}: Got empty response on REST request`)
      throw err
    }
    response.body.Resources.forEach(function (element) {
      if (Array.isArray(element.members)) {
        element.members.forEach(function (el) {
          if (el.value === id) { // user is member of group
            let userGroup = {
              'displayName': element.displayName,   // displayName is mandatory
              'members': [{ 'value': el.value }]    // only includes current user
            }
            arrRet.push(userGroup)
          }
        })
      }
    })
    return arrRet
  } catch (err) {
    throw err
  }
}

// =================================================
// getGroupUsers
// =================================================
scimgateway.getGroupUsers = async (baseEntity, groupName, attributes) => {
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

  let method = 'POST'
  let path = '/Groups'
  let body = { 'displayName': groupObj.displayName }

  try {
    let response = await doRequest(baseEntity, method, path, body)
    if (response.statusCode < 200 || response.statusCode > 299) {
      let err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
      throw err
    }
    return null
  } catch (err) {
    throw err
  }
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id) => {
  let action = 'deleteGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)

  let method = 'DELETE'
  let path = `/Groups/${id}`
  let body = null

  try {
    let response = await doRequest(baseEntity, method, path, body)
    if (response.statusCode < 200 || response.statusCode > 299) {
      let err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
      throw err
    }
    return null
  } catch (err) {
    throw err
  }
}

// =================================================
// modifyGroupMembers
// =================================================
scimgateway.modifyGroupMembers = async (baseEntity, id, members) => {
  let action = 'modifyGroupMembers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} members=${JSON.stringify(members)}`)
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

  let method = 'PATCH'
  let path = `/Groups/${id}`

  try {
    let response = await doRequest(baseEntity, method, path, body)
    if (response.statusCode < 200 || response.statusCode > 299) {
      let err = new Error(`Error message: ${response.statusMessage} - ${JSON.stringify(response.body)}`)
      throw err
    }
    return null
  } catch (err) {
    throw err
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
    if (_serviceClient[baseEntity]) { // serviceClient already exist
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: Using existing client`)
    } else {
      scimgateway.logger.debug(`${pluginName}[${baseEntity}] ${action}: Client have to be created`)
      let client = null
      if (config.entity && config.entity[baseEntity]) client = config.entity[baseEntity]
      if (!client) {
        let err = new Error(`Base URL have baseEntity=${baseEntity}, and configuration file ${pluginName}.json is missing required baseEntity configuration for ${baseEntity}`)
        throw err
      }

      let param = {
        'baseUrl': config.entity[baseEntity].baseUrls[0],
        'options': {
          'json': true, // json-object response instead of string
          'headers': {
            'Content-Type': 'application/json',
            'Authorization': 'Basic ' + Buffer.from(`${config.entity[baseEntity].username}:${scimgateway.getPassword(`endpoint.entity.${baseEntity}.password`, configFile)}`).toString('base64')
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
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] doRequest ${method} ${path} Error response = ${err.message}`)
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
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => {   // Ctrl+C
})
