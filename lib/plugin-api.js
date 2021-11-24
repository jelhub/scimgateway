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

const _serviceClient = {}

// =================================================
// postApi
// =================================================
//
// example:
// post http://localhost:8890/api
// body = {"eventName":"AssignAccessRoleEvent","subjectName":"RACF_System-B","userID":"peter01"}
//
scimgateway.postApi = async (baseEntity, apiObj) => {
  const action = 'postApi'
  scimgateway.logger.debug(`${pluginName} handling "${action}" apiObj=${JSON.stringify(apiObj)}`)

  if (!apiObj.eventName || !apiObj.subjectName || !apiObj.userID) {
    const err = new Error('Unsupported POST content')
    throw err
  }

  const method = 'POST'
  const path = '/api/v1/Books'
  const body = {
    ID: 1,
    Title: apiObj.eventName,
    Description: apiObj.subjectName,
    Excerpt: apiObj.userID
  }
  try {
    const response = await doRequest(baseEntity, method, path, body)
    return response.body
  } catch (err) {
    const newErr = err
    throw newErr
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
  const action = 'putApi'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} apiObj=${JSON.stringify(apiObj)}`)

  if (!apiObj.eventName || !apiObj.subjectName || !apiObj.userID) {
    const err = new Error('Unsupported PUT content')
    throw err
  }

  const method = 'PUT'
  const path = `/api/v1/Books/${id}`
  const body = {
    ID: id,
    Title: apiObj.eventName,
    Description: apiObj.subjectName,
    Excerpt: apiObj.userID
  }
  try {
    const response = await doRequest(baseEntity, method, path, body)
    return response.body
  } catch (err) {
    const newErr = err
    throw newErr
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
  const action = 'patchApi'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} apiObj=${JSON.stringify(apiObj)}`)

  if (!apiObj.eventName && !apiObj.subjectName && !apiObj.userID) {
    const err = new Error('Unsupported PATCH content')
    throw err
  }

  const method = 'PATCH'
  const path = `/api/v1/Books/${id}`
  const body = { ID: id }
  if (apiObj.eventName) body.Title = apiObj.eventName
  if (apiObj.subjectName) body.Description = apiObj.subjectName
  if (apiObj.userID) body.Excerpt = apiObj.userID

  try { // note, Books example do not support patch
    const response = await doRequest(baseEntity, method, path, body)
    return response.body
  } catch (err) {
    const newErr = err
    throw newErr
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
scimgateway.getApi = async (baseEntity, id, apiQuery, apiObj) => {
  const action = 'getApi'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} apiQuery=${JSON.stringify(apiQuery)} apiObj=${JSON.stringify(apiObj)}`)

  try {
    const method = 'GET'
    if (id) {
      const path = `/api/v1/Books/${id}`
      const body = null
      const response = await doRequest(baseEntity, method, path, body)
      return response.body
    } else {
      const path = '/api/Books'
      const body = null
      if (apiQuery) { /* some logic here */ }
      const response = await doRequest(baseEntity, method, path, body)
      return response.body
    }
  } catch (err) {
    const newErr = err
    throw newErr
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
  const action = 'deleteApi'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)

  const method = 'DELETE'
  const path = `/api/v1/Books/${id}`
  const body = null

  try {
    const response = await doRequest(baseEntity, method, path, body)
    return response.body
  } catch (err) {
    const newErr = err
    throw newErr
  }
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
