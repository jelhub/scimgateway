// =================================================================================
// File:    plugin-api.js
//
// Author:  Jarle Elshaug
//
// Purpose: Demonstrate scimgateway api functionality by using a REST based plugin
//          Using /api ScimGateway transfer "as is" to plugin and returns plugin result by adding
//          {"meta": {"result": "success"}}
//          or
//          {"meta": {"result": "error"}}
//
//          This plugin becomes what you it to be
//
// Test prereq: Internet connection towards baseUrl defined for testing purpose (http://fakerestapi.azurewebsites.net)
//
// Supported by scimgateway:
//  GET /api
//  GET /api?queries
//  GET /api/{id}
//  POST /api + body
//  PUT /api/{id} + body
//  PATCH /api/{id} + body
//  DELETE /api/{id}
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
config = scimgateway.processExtConfig(pluginName, config) // add any external config process.env and process.file
// mandatory plugin initialization - end

let _serviceClient = {}

// =================================================
// postApi
// =================================================
//
// example:
// post http://localhost:8890/api
// body = {"eventName":"AssignAccessRoleEvent","subjectName":"RACF_System-B","userID":"peter01"}
//
scimgateway.postApi = async (baseEntity, apiObj) => {
  let action = 'postApi'
  scimgateway.logger.debug(`${pluginName} handling "${action}" apiObj=${JSON.stringify(apiObj)}`)

  if (!apiObj.eventName || !apiObj.subjectName || !apiObj.userID) {
    let err = new Error('Unsupported POST content')
    throw err
  }

  let method = 'POST'
  let path = '/api/Books'
  let body = {
    'ID': 1,
    'Title': apiObj.eventName,
    'Description': apiObj.subjectName,
    'Excerpt': apiObj.userID
  }
  try {
    let response = await doRequest(baseEntity, method, path, body)
    return response.body
  } catch (err) {
    throw err
  }
}

// =================================================
// putApi
// =================================================
//
// example:
// put http://localhost:8890/api/1
// body = {"eventName":"AssignAccessRoleEvent","subjectName":"RACF_System-B","userID":"peter01"}
//
scimgateway.putApi = async (baseEntity, id, apiObj) => {
  let action = 'putApi'
  scimgateway.logger.debug(`${pluginName} handling "${action}" id=${id} apiObj=${JSON.stringify(apiObj)}`)

  if (!apiObj.eventName || !apiObj.subjectName || !apiObj.userID) {
    let err = new Error('Unsupported PUT content')
    throw err
  }

  let method = 'PUT'
  let path = `/api/Books/${id}`
  let body = {
    'ID': id,
    'Title': apiObj.eventName,
    'Description': apiObj.subjectName,
    'Excerpt': apiObj.userID
  }
  try {
    let response = await doRequest(baseEntity, method, path, body)
    return response.body
  } catch (err) {
    throw err
  }
}

// =================================================
// patchApi
// =================================================
//
// example:
// patch http://localhost:8890/api/1
// body = {"eventName":"AssignAccessRoleEvent","subjectName":"RACF_System-B","userID":"peter01"}
//
scimgateway.patchApi = async (baseEntity, id, apiObj) => {
  let action = 'patchApi'
  scimgateway.logger.debug(`${pluginName} handling "${action}" id=${id} apiObj=${JSON.stringify(apiObj)}`)

  if (!apiObj.eventName && !apiObj.subjectName && !apiObj.userID) {
    let err = new Error('Unsupported PATCH content')
    throw err
  }

  let method = 'PATCH'
  let path = `/api/Books/${id}`
  let body = { 'ID': id }
  if (apiObj.eventName) body.Title = apiObj.eventName
  if (apiObj.subjectName) body.Description = apiObj.subjectName
  if (apiObj.userID) body.Excerpt = apiObj.userID

  try { // note, Books example do not support patch
    let response = await doRequest(baseEntity, method, path, body)
    return response.body
  } catch (err) {
    throw err
  }
}

// =================================================
// getApi
// =================================================
//
// examples:
// get http://localhost:8890/api
// get http://localhost:8890/api/1
// get http://localhost:8890/api?queries
//
scimgateway.getApi = async (baseEntity, id, apiQuery) => {
  let action = 'getApi'
  scimgateway.logger.debug(`${pluginName} handling "${action}" id=${id} apiQuery=${JSON.stringify(apiQuery)}`)

  try {
    let method = 'GET'
    if (id) {
      let path = `/api/Books/${id}`
      let body = null
      let response = await doRequest(baseEntity, method, path, body)
      return response.body
    } else {
      let path = '/api/Books'
      let body = null
      if (apiQuery) {} // some logic here
      let response = await doRequest(baseEntity, method, path, body)
      return response.body
    }
  } catch (err) {
    throw err
  }
}

// =================================================
// deleteApi
// =================================================
//
// example:
// delete http://localhost:8890/api/1
//
scimgateway.deleteApi = async (baseEntity, id) => {
  let action = 'deleteApi'
  scimgateway.logger.debug(`${pluginName} handling "${action}" id=${id}`)

  let method = 'DELETE'
  let path = `/api/Books/${id}`
  let body = null

  try {
    let response = await doRequest(baseEntity, method, path, body)
    return response.body
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
          'protocol': url.parse(config.entity[baseEntity].baseUrls[0]).protocol, // http: or https:
          'rejectUnauthorized': false // accepts self-siged certificates
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

    scimgateway.logger.debug(`${pluginName}[${baseEntity}] doRequest ${method} ${options.protocol}//${options.host}${(options.port ? `:${options.port}` : '')}${path} Body = ${JSON.stringify(body)} Response = ${JSON.stringify(result)}`)
    return result
  } catch (err) { // includes failover/retry logic based on config baseUrls array
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] doRequest ${method} ${path} Body = ${JSON.stringify(body)} Error Response = ${err.message}`)
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
