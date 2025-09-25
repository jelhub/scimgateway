// =================================================================================
// File:    plugin-api.ts
//
// Author:  Jarle Elshaug
//
// Purpose: Demonstrate scimgateway api functionality by using a REST based plugin
//          Using /api scimgateway transfer "as is" to plugin and returns plugin result
//          This plugin becomes what you it to be
//
// Supported methods:
//  GET /api
//  GET /api?queries
//  GET /api/{id}
//  POST /api + body
//  PUT /api/{id} + body
//  PATCH /api/{id} + body
//  DELETE /api/{id}
//  <method> /pub/api - '/pub/api' is the publicApi path having no authentication - all methods supported - using scimgateway.publicApi()
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
scimgateway.postApi = async (baseEntity, body, ctx) => {
  const action = 'postApi'
  scimgateway.logDebug(baseEntity, `handling ${action} body=${JSON.stringify(body)} passThrough=${ctx ? 'true' : 'false'}`)

  if ((typeof (body) !== 'object') || (Object.keys(body).length === 0)) {
    throw new Error('unsupported POST syntax')
  }

  const method = 'POST'
  const path = '/products/add'
  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
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
// put http://localhost:8890/api/100
// body = {"title":"BMW X1","price":21}
//
scimgateway.putApi = async (baseEntity, id, body, ctx) => {
  const action = 'putApi'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} body=${JSON.stringify(body)} passThrough=${ctx ? 'true' : 'false'}`)

  if ((typeof (body) !== 'object') || (Object.keys(body).length === 0)) {
    throw new Error('unsupported PUT syntax')
  }

  const method = 'PUT'
  const path = `/products/${id}`
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
scimgateway.patchApi = async (baseEntity, id, body, ctx) => {
  const action = 'patchApi'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} body=${JSON.stringify(body)} passThrough=${ctx ? 'true' : 'false'}`)

  if ((typeof (body) !== 'object') || (Object.keys(body).length === 0)) {
    throw new Error('unsupported PATCH syntax')
  }

  const method = 'PATCH'
  const path = `/products/${id}`

  try { // note, Books example do not support patch
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
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
// get http://localhost:8890/api/100
//
scimgateway.getApi = async (baseEntity, id, query, ctx) => {
  const action = 'getApi'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} apiQuery=${JSON.stringify(query)}} passThrough=${ctx ? 'true' : 'false'}`)

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
    throw err
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
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} passThrough=${ctx ? 'true' : 'false'}`)

  const method = 'DELETE'
  const path = `/products/${id}`
  const body = null

  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    return response.body
  } catch (err) {
    throw err
  }
}

// =================================================
// publicApi
// public available - no authentication
// =================================================
//
// example:
// GET http://localhost:8890/pub/api/bmw?model=BMW X3
// POST http://localhost:8890/pub/api - body={"model":"BMW X3"}
// PATCH http://localhost:8890/pub/api/bmw - body={"model":"BMW X5"}
// PUT http://localhost:8890/pub/api/bmw - body={"model":"BMW X3"}
// DELETE http://localhost:8890/pub/api/bmw
//
const getPublicApi = async (baseEntity: string, id: string | undefined, query: Record<string, any> | undefined) => {
  return { get: { baseEntity, id, query } }
}

const postPublicApi = async (baseEntity: string, body: any) => {
  if (!body) throw new Error('POST is missing mandatory body')
  return { post: { body } }
}

const patchPublicApi = async (baseEntity: string, id: string | undefined, body: any) => {
  if (!id || !body) throw new Error('PATCH is missing mandatory id/body')
  return { patch: { id, body } }
}

const putPublicApi = async (baseEntity: string, id: string | undefined, body: any) => {
  if (!id || !body) throw new Error('PUT is missing mandatory id/body')
  return { put: { id, body } }
}

const deletePublicApi = async (baseEntity: string, id: string | undefined, body: any) => {
  if (!id) throw new Error('DELETE is missing mandatory id')
  return { delete: { id, body } }
}

scimgateway.publicApi = async (baseEntity, method, id, query, body, ctx) => {
  const action = 'publicApi'
  scimgateway.logDebug(baseEntity, `handling ${action} method=${method} id=${id} query=${query ? JSON.stringify(query) : query} body=${JSON.stringify(body)} passThrough=${ctx ? 'true' : 'false'}`)

  switch (method) {
    case 'GET':
      return await getPublicApi(baseEntity, id, query)
    case 'POST':
      return await postPublicApi(baseEntity, body)
    case 'PATCH':
      return await patchPublicApi(baseEntity, id, body)
    case 'PUT':
      return await putPublicApi(baseEntity, id, body)
    case 'DELETE':
      return await deletePublicApi(baseEntity, id, body)
    default:
      throw new Error(`${action} method ${method} is not supported`)
  }
}

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})
