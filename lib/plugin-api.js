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
try {
  config = ScimGateway.prototype.processExtConfig(config) // external config support process.env and process.file
} catch (err) {
  scimgateway.logger.error(`${pluginName} ${err.message}`)
  scimgateway.logger.error(`${pluginName} stopping...`)
  console.log()
  process.exit(1)
}
// mandatory plugin initialization - end

let _serviceClient = {}

// POST api example
// post http://localhost:8890/api
// body = {"eventName":"AsignAccessRoleEvent","subjectName":"RACF_System-B","userID":"peter01"}
scimgateway.on('postApi', function (baseEntity, apiObj, callback) {
  let action = 'postApi'
  scimgateway.logger.debug(`${pluginName} handling event "${action}" apiObj=${JSON.stringify(apiObj)}`)

  if (!apiObj.eventName || !apiObj.subjectName || !apiObj.userID) {
    let err = new Error('Unsupported api POST content')
    return callback(err, null)
  }

  let body = {
    'ID': 1,
    'Title': apiObj.eventName,
    'Description': apiObj.subjectName,
    'Excerpt': apiObj.userID
  }

  doRequest(baseEntity, '/api/Books', 'POST', body, function (err, result) {
    scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] Response = ${JSON.stringify(result)}`)
    if (err) return callback(err, result)
    callback(null, result)
  }) // doRequest
})

// PUT api example
// put http://localhost:8890/api/1
// body = {"eventName":"AsignAccessRoleEvent","subjectName":"RACF_System-B","userID":"peter01"}
scimgateway.on('putApi', function (baseEntity, id, apiObj, callback) {
  let action = 'putApi'
  scimgateway.logger.debug(`${pluginName} handling event "${action}" id=${id} apiObj=${JSON.stringify(apiObj)}`)

  if (!apiObj.eventName || !apiObj.subjectName || !apiObj.userID) {
    let err = new Error('Unsupported api PUT content')
    return callback(err, null)
  }

  let body = {
    'ID': id,
    'Title': apiObj.eventName,
    'Description': apiObj.subjectName,
    'Excerpt': apiObj.userID
  }

  doRequest(baseEntity, `/api/Books/${id}`, 'PUT', body, function (err, result) {
    scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] Response = ${JSON.stringify(result)}`)
    if (err) return callback(err, result)
    callback(null, result)
  })
})

// PATCH api example
// patch http://localhost:8890/api/1
// body = {"eventName":"AsignAccessRoleEvent","subjectName":"RACF_System-B","userID":"peter01"}
scimgateway.on('patchApi', function (baseEntity, id, apiObj, callback) {
  let action = 'patchApi'
  scimgateway.logger.debug(`${pluginName} handling event "${action}" id=${id} apiObj=${JSON.stringify(apiObj)}`)

  if (!apiObj.eventName && !apiObj.subjectName && !apiObj.userID) {
    let err = new Error('Unsupported api PATCH content')
    return callback(err, null)
  }

  let body = { 'ID': id }
  if (apiObj.eventName) body.Title = apiObj.eventName
  if (apiObj.subjectName) body.Description = apiObj.subjectName
  if (apiObj.userID) body.Excerpt = apiObj.userID

  // note, Books example do not support patch...
  doRequest(baseEntity, `/api/Books/${id}`, 'PATCH', body, function (err, result) {
    scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] Response = ${JSON.stringify(result)}`)
    if (err) return callback(err, result)
    callback(null, result)
  })
})

// GET api example
// get http://localhost:8890/api
// get http://localhost:8890/api/1
// get http://localhost:8890/api?queries
scimgateway.on('getApi', function (baseEntity, id, apiQuery, callback) {
  let action = 'getApi'
  scimgateway.logger.debug(`${pluginName} handling event "${action}" id=${id} apiQuery=${JSON.stringify(apiQuery)}`)
  if (id) {
    doRequest(baseEntity, `/api/Books/${id}`, 'GET', null, function (err, result) {
      scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] Response = ${JSON.stringify(result)}`)
      if (err) return callback(err, result)
      callback(null, result)
    })
  } else {
    let query = null
    if (apiQuery) { // some logic to set the query
    }
    doRequest(baseEntity, `/api/Books`, 'GET', query, function (err, result) {
      scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] Response = ${JSON.stringify(result)}`)
      if (err) return callback(err, result)
      callback(null, result)
    })
  }
})

// DELETE api example
// delete http://localhost:8890/api/1
scimgateway.on('deleteApi', function (baseEntity, id, callback) {
  let action = 'deleteApi'
  scimgateway.logger.debug(`${pluginName} handling event "${action}" id=${id}`)

  doRequest(baseEntity, `/api/Books/${id}`, 'DELETE', null, function (err, result) {
    scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] Response = ${JSON.stringify(result)}`)
    if (err) return callback(err, result)
    callback(null, result)
  })
})

//
// getServiceClient - returns connection parameters needed
//
let getServiceClient = function (baseEntity, callback) {
  if (_serviceClient[baseEntity]) { // serviceClient already exist
    scimgateway.logger.debug(`${pluginName} getServiceClient[${baseEntity}]: Using existing client`)
    return callback(null, _serviceClient[baseEntity])
  }
  scimgateway.logger.debug(`${pluginName} getServiceClient[${baseEntity}]: Client have to be created`)
  let client = null
  if (config.entity && config.entity[baseEntity]) client = config.entity[baseEntity]
  if (!client) {
    let err = new Error(`Base URL have baseEntity=${baseEntity}, and configuration file ${pluginName}.json is missing required baseEntity configuration for ${baseEntity}`)
    return callback(err)
  }

  let param = {
    'host': url.parse(config.entity[baseEntity].baseUrl).hostname,
    'port': url.parse(config.entity[baseEntity].baseUrl).port,
    'protocol': url.parse(config.entity[baseEntity].baseUrl).protocol.slice(0, -1), // remove trailing ":"
    'auth': 'Basic ' + Buffer.from(`${config.entity[baseEntity].username}:${scimgateway.getPassword(`endpoint.entity.${baseEntity}.password`, configFile)}`).toString('base64')
  }

  if (!_serviceClient[baseEntity]) _serviceClient[baseEntity] = {}
  _serviceClient[baseEntity] = param // serviceClient created
  callback(null, _serviceClient[baseEntity])
}

//
// doRequest - execute REST service
//
let doRequest = function (baseEntity, endpoint, method, data, callback) {
  getServiceClient(baseEntity, function (err, serviceClient) { // e.g serviceClient = {host: "localhost, port: "8880", auth: 'Basic' + new Buffer("gwadmin:password").toString('base64')}
    if (err) return callback(err)
    let dataString = ''
    let headers = {}

    if (method === 'GET') {
      if (typeof (data) === 'string') dataString = data
      else dataString = querystring.stringify(data) // JSON to query string syntax + URL encoded - preferred method
      if (dataString) endpoint += '?' + dataString
      headers = {
        'Authorization': serviceClient.auth     // not using proxy
        // "Proxy-Authorization": auth          // using proxy
      }
    } else {
      dataString = JSON.stringify(data)
      headers = {
        'Authorization': serviceClient.auth,    // not using proxy
        // "Proxy-Authorization": auth          // using proxy
        'Content-Type': 'application/json',
        'Content-Length': dataString.length
      }
    }

    let options = {
      'host': serviceClient.host,
      'port': serviceClient.port,
      'path': endpoint,
      'method': method,
      'headers': headers
    }

    let reqType = (serviceClient.protocol === 'https') ? https.request : http.request
    let req = reqType(options, function (res) {
      let responseString = ''
      res.setEncoding('utf-8')

      req.on('error', function (error) {
        callback(error)
      })

      res.on('data', function (data) {
        responseString += data
      })

      res.on('end', function () {
        if (res.statusCode < 200 || res.statusCode > 299) {
          let err = new Error(`Error message: ${res.statusMessage} - ${responseString}`)
          return callback(err)
        }
        if (responseString.length < 1) callback(null, null)
        else callback(null, JSON.parse(responseString))
      })
    })

    req.write(dataString)
    req.end()
    scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] Request = ${req.agent.protocol}//${req._headers.host} ${req.method} ${req.path}`)
  }) // getServiceClient
}
