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

// for supporting nodejs running scimgateway package directly, using dynamic import instead of: import { ScimGateway } from 'scimgateway'
// scimgateway also inclues HelperRest: import { ScimGateway, HelperRest } from 'scimgateway'

// start - mandatory plugin initialization
const ScimGateway: typeof import('scimgateway').ScimGateway = await (async () => {
  try {
    return (await import('scimgateway')).ScimGateway
  } catch (err) {
    const source = './scimgateway.ts'
    return (await import(source)).ScimGateway
  }
})()
const HelperRest: typeof import('scimgateway').HelperRest = await (async () => {
  try {
    return (await import('scimgateway')).HelperRest
  } catch (err) {
    const source = './scimgateway.ts'
    return (await import(source)).HelperRest
  }
})()
const scimgateway = new ScimGateway()
scimgateway.authPassThroughAllowed = false
// end - mandatory plugin initialization

const helper = new HelperRest(scimgateway)

// =================================================
// postApi
// =================================================
//
// example:
// post http://localhost:8890/api
// body = {"title":"BMW X5","price":58}
//
scimgateway.postApi = async (baseEntity, apiObj, ctx) => {
  const action = 'postApi'
  scimgateway.logDebug(baseEntity, `handling ${action} apiObj=${JSON.stringify(apiObj)}`)

  if ((typeof (apiObj) !== 'object') || (Object.keys(apiObj).length === 0)) {
    throw new Error('unsupported POST syntax')
  }

  const method = 'POST'
  const path = '/products/add'
  const body = apiObj
  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
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
// put http://localhost:8890/api/100
// body = {"title":"BMW X1","price":21}
//
scimgateway.putApi = async (baseEntity, id, apiObj, ctx) => {
  const action = 'putApi'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} apiObj=${JSON.stringify(apiObj)}`)

  if ((typeof (apiObj) !== 'object') || (Object.keys(apiObj).length === 0)) {
    throw new Error('unsupported PUT syntax')
  }

  const method = 'PUT'
  const path = `/products/${id}`
  const body = apiObj
  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
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
// patch http://localhost:8890/api/100
// body = {"title":"BMW X3"}
//
scimgateway.patchApi = async (baseEntity, id, apiObj, ctx) => {
  const action = 'patchApi'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} apiObj=${JSON.stringify(apiObj)}`)

  if ((typeof (apiObj) !== 'object') || (Object.keys(apiObj).length === 0)) {
    throw new Error('unsupported PATCH syntax')
  }

  const method = 'PATCH'
  const path = `/products/${id}`
  const body = apiObj

  try { // note, Books example do not support patch
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
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
// get http://localhost:8890/api/100
//
scimgateway.getApi = async (baseEntity, id, apiQuery, apiObj, ctx) => {
  const action = 'getApi'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} apiQuery=${JSON.stringify(apiQuery)} apiObj=${JSON.stringify(apiObj)}`)

  const method = 'GET'
  let path = '/products'
  const body = null

  if (id) {
    path += `/${id}`
  }

  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    return response.body
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
// delete http://localhost:8890/api/100
//
scimgateway.deleteApi = async (baseEntity, id, ctx) => {
  const action = 'deleteApi'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id}`)

  const method = 'DELETE'
  const path = `/products/${id}`
  const body = null

  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    return response.body
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})
