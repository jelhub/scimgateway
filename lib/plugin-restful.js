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

const _serviceClient = {}

// =================================================
// exploreUsers
// =================================================
scimgateway.exploreUsers = async (baseEntity, attributes, startIndex, count) => {
  const action = 'exploreUsers'
  scimgateway.logger.debug(`${pluginName} handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`)
  const ret = { // itemsPerPage will be set by scimgateway
    Resources: [],
    totalResults: null
  }

  const method = 'GET'
  const path = '/Users?attributes=userName'
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
    for (let index = startIndex - 1; index < response.body.Resources.length && (index + 1 - startIndex) < count; ++index) {
      if (response.body.Resources[index].id && response.body.Resources[index].userName) {
        const scimUser = { // userName and id is mandatory, note: we set id=userName
          userName: response.body.Resources[index].userName,
          id: response.body.Resources[index].id,
          externalId: response.body.Resources[index].userName
        }
        ret.Resources.push(scimUser)
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
  scimgateway.logger.debug(`${pluginName} handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`)
  const ret = { // itemsPerPage will be set by scimgateway
    Resources: [],
    totalResults: null
  }

  const method = 'GET'
  const path = '/Groups?attributes=displayName'
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
scimgateway.getUser = async (baseEntity, userName, attributes) => {
  const action = 'getUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" userName=${userName} attributes=${attributes}`)
  let arrAttr = []
  if (attributes) arrAttr = attributes.split(',')
  if (attributes && arrAttr.length < 3) { // userName and/or id - check if user exist
    const method = 'GET'
    const path = `/Users?filter=userName eq "${userName}"&attributes=userName`
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
      const userObj = response.body.Resources.find(function (element) { // Verify user exist
        return element.userName === userName
      })
      if (!userObj) return null // no user found

      const retObj = {
        id: userName,
        userName: userName,
        externalId: userName
      }
      return retObj // return user found
    } catch (err) {
      const newErr = err
      throw newErr
    }
  } else { // all endpoint supported attributes
    const method = 'GET'
    const path = `/Users?filter=userName eq "${userName}"&
      attributes=userName,active,name.givenName,name.familyName,name.formatted,title,emails,phoneNumbers,entitlements`
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
      const userObj = response.body.Resources.find(function (element) { // Verify user exist
        return element.userName === userName
      })
      if (!userObj) return null // no user found

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
        id: userObj.userName,
        externalId: userObj.userName,
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
      return retObj // return user found
    } catch (err) {
      const newErr = err
      throw newErr
    }
  } // else
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
  if (attrObj.emails.work) arrEmail.push(attrObj.emails.work)
  if (attrObj.phoneNumbers.work) arrPhone.push(attrObj.phoneNumbers.work)
  if (attrObj.entitlements.company) arrEntitlement.push(attrObj.entitlements.company)

  const method = 'PATCH'
  const path = `/Users/${id}`
  const body = { userName: id }
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
scimgateway.getGroup = async (baseEntity, displayName, attributes) => {
  const action = 'getGroup'
  scimgateway.logger.debug(`${pluginName} handling "${action}" displayName=${displayName} attributes=${attributes}`)

  const method = 'GET'
  const path = `/Groups?filter=displayName eq "${displayName}"&attributes=${attributes}` // GET = /Groups?filter=displayName eq "Admins"&attributes=externalId,id,members.value,displayName
  const body = null

  try {
    const response = await doRequest(baseEntity, method, path, body)
    if (!response.body.Resources) {
      const err = new Error(`${action}: Got empty response on REST request`)
      throw err
    }
    const retObj = {}
    if (response.body.Resources.length === 1) {
      const grp = response.body.Resources[0]
      retObj.displayName = grp.displayName // displayName is mandatory
      retObj.id = grp.id
      retObj.externalId = grp.displayName // mandatory for Azure AD
      if (Array.isArray(grp.members)) {
        retObj.members = []
        grp.members.forEach(function (el) {
          retObj.members.push({ value: el.value })
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
              displayName: element.displayName, // displayName is mandatory
              members: [{ value: el.value }] // only includes current user
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
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" groupName=${groupName} attributes=${attributes}`)
  const arrRet = []
  return arrRet
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj) => {
  const action = 'createGroup'
  scimgateway.logger.debug(`${pluginName} handling "${action}" groupObj=${JSON.stringify(groupObj)}`)

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
// modifyGroupMembers
// =================================================
scimgateway.modifyGroupMembers = async (baseEntity, id, members) => {
  const action = 'modifyGroupMembers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} members=${JSON.stringify(members)}`)
  const body = { members: [] }
  if (Array.isArray(members)) {
    members.forEach(function (el) {
      if (el.operation && el.operation === 'delete') { // delete member from group
        // PATCH = /Groups/Admins Body = {"members":[{"operation":"delete","value":"bjensen"}]}
        body.members.push({ operation: 'delete', value: el.value })
      } else { // add member to group/
        // PATCH = /Groups/Admins Body = {"members":[{"value":"bjensen"}]
        body.members.push({ value: el.value })
      }
    })
  } // if Array

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
