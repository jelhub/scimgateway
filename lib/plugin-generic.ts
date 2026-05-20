// =================================================================================
// File:    plugin-generic.ts
//
// Author:  Jarle Elshaug
//
// Purpose: Generic REST Webservice user-provisioning according to the configuration file setup
// 
// Notes:
//   - Uses endpointMapper for flexible attribute mapping. Configuration includes endpoint.map.user/group settings.
//   - The default configuration uses one-to-one SCIM mapping, with plugin-loki as the target SCIM endpoint.
//       * This means plugin-loki must be up and running (enabled in index.ts).
//       * Can be used as a SCIM v1.1 <=> v2.0 gateway.
//   - getUsers() and getGroups() are generic:
//       * Include logic for target endpoints with or without pagination support.
//       * Support OData endpoints.
//       * Support allowListing to filter out objects that should not be included.
//   - modifyGroup() is currently hardcoded for the SCIM endpoint and must be updated to reflect the configured endpoint.
//
//   endpointMapper supports 'valueMap'. Example configuration:
//
//    "map": {
//      "group": {
//        ...
//        "displayName": {
//          "mapTo": "displayName",
//          "type": "string",
//          "valueMap": {
//            "outboundEndpointGrp1": "inboundScimGrp1",
//            "Employees": "Admins"
//          }
//        },
//        ...
//      }
//      ...
//    }
//
//   Using the above settings restricts the client using SCIM Gateway with regard to group management.
//   The client will only see and be able to manage groups with SCIM names "inboundScimGrp1" and "Admins",
//   if their mapped counterparts exist at the target endpoint as "outboundEndpointGrp1" and "Employees".
//
//   Use case:
//     - Allowlisting specific groups
//     - Supporting different inbound/outbound names (e.g., Entra ID group provisioning to SCIM Gateway)
//
// =================================================================================

// start - mandatory plugin initialization
import { ScimGateway, HelperRest } from 'scimgateway'
const scimgateway = new ScimGateway()
const helper = new HelperRest(scimgateway)
const config = scimgateway.getConfig()
scimgateway.authPassThroughAllowed = false
scimgateway.pluginAndOrFilter = false
// end - mandatory plugin initialization

const isAllowlistingUser = config.map?.user
  ? Object.values(config.map.user).some((item: any) => typeof item?.valueMap === 'object' && Object.keys(item.valueMap).length > 0)
  : false

const isAllowlistingGroup = config.map?.group
  ? Object.values(config.map.group).some((item: any) => typeof item.valueMap === 'object' && Object.keys(item.valueMap).length > 0)
  : false

// =================================================
// getUsers
// =================================================
scimgateway.getUsers = async (baseEntity, getObj, attributes, ctx) => {
  const action = 'getUsers'
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes} passThrough=${ctx ? 'true' : 'false'}`)

  const [attrs] = scimgateway.endpointMapper('outbound', attributes, config.map.user)
  const method = 'GET'
  const body = null
  let path
  let options: Record<string, any> = {}

  // start mandatory if-else logic
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'userName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      if (getObj.attribute === 'id') path = `/Users/${getObj.value}?attributes=${attrs.join()}` // GET /Users/bjensen?attributes=
      else path = `/Users?filter=${getObj.attribute} eq "${getObj.value}"${(attrs.length > 0) ? '&attributes=' + attrs.join() : ''}` // GET /Users?filter=userName eq "bjensen"&attributes=userName,active,name.givenName,name.familyName,name.formatted,title,emails,phoneNumbers,entitlements
    } else if (getObj.operator === 'eq' && getObj.attribute === 'group.value') {
      // optional - only used when groups are member of users, not default behavior - correspond to getGroupUsers() in versions < 4.x.x
      path = `/Users?filter=${getObj.attribute} eq "${getObj.value}"${(attrs.length > 0) ? '&attributes=' + attrs.join() : ''}`
    } else {
      // optional - simpel filtering
      path = `/Users?filter=${getObj.attribute} ${getObj.operator} "${getObj.value}"${(attrs.length > 0) ? '&attributes=' + attrs.join() : ''}`
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all users to be returned - correspond to exploreUsers() in versions < 4.x.x
    path = `/Users${(attrs.length > 0 ? '?attributes=' + attrs.join() : '')}`
  }
  if (getObj.and || getObj.or) {
    // plugin have enabled 'scimgateway.pluginAndOrFilter' and the query includes an additonal and/or getObj that must to be handled and combined with the initial getObj
    // we could have this logic above, if not it must be defined here
    throw new Error(`${action} error: logic for handling and/or filter is not implemented by plugin, not supporting: ${getObj.rawFilter}`)
  }
  // end mandatory if-else logic

  if (!path) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  const targetStartIndex = getObj.startIndex || 1
  const targetCount = getObj.count || 200

  // Notes for OData (nextLink) paging support:
  //  - request parameters should include "$count=true" when valid
  //  - see plugin-entra-id.ts which use OData
  //  - uncomment below
  /*
  // enable doRequest() OData paging support 
  let paging = { startIndex: getObj.startIndex || 1 }
  if (!ctx) ctx = { paging }
  else ctx.paging = paging

  if (path.includes('$count=true')) { // $count=true requires ConsistencyLevel
    // note: when using $expand, the $count=true might be ignored by target endpoint and the ctx.paging.totalResults updated by doReqest() will be incremental
    if (!options.headers) options.headers = {}
    options.headers.ConsistencyLevel = 'eventual'
  }
  */

  const ret: any = { // itemsPerPage will be set by scimgateway
    Resources: [],
    totalResults: null,
  }

  let currentStartIndex = isAllowlistingUser ? 1 : targetStartIndex
  let allValidResources: any[] = []
  let totalSkipped = 0
  let targetTotalResults: number | null = null
  let iteration = 0
  const maxIterations = 5 // Safety limit for look-ahead fetching
  const resourcesNeeded = isAllowlistingUser ? targetStartIndex + targetCount - 1 : targetCount

  try {
    while (allValidResources.length < resourcesNeeded && iteration < maxIterations) {
      let currentPath = path
      // may skip adding SCIM pagination parameters startIndex/count if not supported by target endpoint
      if (currentPath.includes('?')) currentPath += `&startIndex=${currentStartIndex}&count=${targetCount}`
      else currentPath += `?startIndex=${currentStartIndex}&count=${targetCount}`

      // In this use case the target response body is SCIM and includes the Resources array - response.body.Resources
      // Replace the "response.body.Resources" according to target endpoint response syntax 
      // OData response is supported by the response.body.value check
      const response = await helper.doRequest(baseEntity, method, currentPath, body, ctx, options)
      if (response.statusCode > 399) {
        throw new Error(`${response.statusMessage} - ${JSON.stringify(response.body)}`)
      } else if (!response.body) {
        throw new Error(`invalid response: ${JSON.stringify(response)}`)
      } else if (!response.body.Resources && !Array.isArray(response.body.value)) {
        const userObj = response.body
        const [scimObj, err] = scimgateway.endpointMapper('inbound', userObj, config.map.user)
        if (err && err.message.includes('valueMap')) return null // allowListing when valueMap is configured, skipping objects not being "valueMapped"
        return scimObj
      }

      const resources = response.body.Resources || response.body.value || []
      targetTotalResults = (response.body.totalResults !== undefined && response.body.totalResults !== null) ? response.body.totalResults : null
      if (ctx?.paging && Object.hasOwn(ctx.paging, 'totalResults')) targetTotalResults = ctx.paging.totalResults

      const pageValidResources: any[] = []
      for (const res of resources) {
        if (!res || Object.keys(res).length < 1) continue
        const [scimObj, err] = scimgateway.endpointMapper('inbound', res, config.map.user)
        if (err && err.message.includes('valueMap')) continue // allowListing when valueMap is configured, skipping objects not being "valueMapped"
        if (scimObj && typeof scimObj === 'object' && Object.keys(scimObj).length > 0) {
          pageValidResources.push(scimObj)
        }
      }

      totalSkipped += (resources.length - pageValidResources.length)
      allValidResources.push(...pageValidResources)

      if (targetTotalResults === null) {
        // Target endpoint returned full list
        ret.totalResults = isAllowlistingUser ? allValidResources.length : targetStartIndex - 1 + allValidResources.length
        ret.Resources = isAllowlistingUser ? allValidResources.slice(targetStartIndex - 1, targetStartIndex - 1 + targetCount) : allValidResources.slice(0, targetCount)
        return ret
      }

      // If we reached the end of target's list
      if ((currentStartIndex - 1 + resources.length) >= targetTotalResults) break

      // Look-ahead: fetch next page because some results were filtered out
      currentStartIndex += resources.length
      if (ctx?.paging) ctx.paging.startIndex = currentStartIndex
      iteration++
    }

    if (ctx?.paging && getObj.startIndex !== ctx.paging.startIndex) { // changed by doRequest()
      ret.startIndex = ctx.paging.startIndex
    }
    if (ctx?.paging && Object.hasOwn(ctx.paging, 'totalResults')) targetTotalResults = ctx.paging.totalResults

    ret.totalResults = (targetTotalResults !== null && targetTotalResults > totalSkipped) ? targetTotalResults - totalSkipped : (isAllowlistingUser ? allValidResources.length : targetStartIndex - 1 + allValidResources.length)
    ret.Resources = isAllowlistingUser ? allValidResources.slice(targetStartIndex - 1, targetStartIndex - 1 + targetCount) : allValidResources.slice(0, targetCount)
    if (!ret.startIndex) ret.startIndex = targetStartIndex

    return ret
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj, ctx) => {
  const action = 'createUser'
  scimgateway.logDebug(baseEntity, `handling ${action} userObj=${JSON.stringify(userObj)} passThrough=${ctx ? 'true' : 'false'}`)

  const [targetObj] = scimgateway.endpointMapper('outbound', userObj, config.map.user)

  const method = 'POST'
  const path = '/Users'
  const body = targetObj

  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (response.statusCode > 399) {
      throw new Error(`${response.statusMessage} - ${JSON.stringify(response.body)}`)
    }
    return null
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id, ctx) => {
  const action = 'deleteUser'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} passThrough=${ctx ? 'true' : 'false'}`)

  const method = 'DELETE'
  const path = `/Users/${id}`
  const body = null

  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (response.statusCode > 399) {
      throw new Error(`${response.statusMessage} - ${JSON.stringify(response.body)}`)
    }
    return null
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// modifyUser
// =================================================
scimgateway.modifyUser = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyUser'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} attrObj=${JSON.stringify(attrObj)} passThrough=${ctx ? 'true' : 'false'}`)

  const [targetObj] = scimgateway.endpointMapper('outbound', attrObj, config.map.user)

  const method = 'PATCH'
  const path = `/Users/${id}`
  let body = targetObj

  if (config.entity[baseEntity].scimVersion && config.entity[baseEntity].scimVersion !== '1.1') { // scim 2.0 endpoint
    body = {
      Operations: [
        {
          op: 'replace',
          value: body,
        },
      ],
    }
  }

  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (response.statusCode > 399) {
      throw new Error(`${response.statusMessage} - ${JSON.stringify(response.body)}`)
    }
    return null
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// getGroups
// =================================================
scimgateway.getGroups = async (baseEntity, getObj, attributes, ctx) => {
  const action = 'getGroups'
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes} passThrough=${ctx ? 'true' : 'false'}`)

  const ret: any = { // itemsPerPage will be set by scimgateway
    Resources: [],
    totalResults: null,
  }

  const [attrs] = scimgateway.endpointMapper('outbound', attributes, config.map.group)

  const method = 'GET'
  const body = null
  let path
  let options: Record<string, any> = {}

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'displayName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned
      if (getObj.attribute === 'displayName') {
        const [obj, err] = scimgateway.endpointMapper('outbound', { displayName: getObj.value }, config.map.group)
        if (err && err.message.includes('displayName.valueMap')) return ret // valueMap configured for object having mapTo=displayName and value not allowlisted
        getObj.value = obj.displayName
      }
      if (getObj.attribute === 'id') path = `/Groups/${getObj.value}?attributes=${attrs.join()}` // GET /Users/bjensen?attributes=
      else path = `/Groups?filter=${getObj.attribute} eq "${getObj.value}"${(attrs.length > 0) ? '&attributes=' + attrs.join() : ''}` // GET /Users?filter=userName eq "bjensen"&attributes=userName,active,name.givenName,name.familyName,name.formatted,title,emails,phoneNumbers,entitlements
    } else if (getObj.operator === 'eq' && getObj.attribute === 'members.value') {
      // mandatory - return all groups the user 'id' (getObj.value) is member of - correspond to getGroupMembers() in versions < 4.x.x
      // Resources = [{ id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }]
      path = `/Groups?filter=${getObj.attribute} eq "${getObj.value}"${(attrs.length > 0) ? '&attributes=' + attrs.join() : ''}`
    } else {
      // optional - simpel filtering
      path = `/Groups?filter=${getObj.attribute} eq "${getObj.value}"${(attrs.length > 0) ? '&attributes=' + attrs.join() : ''}`
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all groups to be returned - correspond to exploreGroups() in versions < 4.x.x
    path = `/Groups${(attrs.length > 0 ? '?attributes=' + attrs.join() : '')}`
  }
  if (getObj.and || getObj.or) {
    // plugin have enabled 'scimgateway.pluginAndOrFilter' and the query includes an additonal and/or getObj that must to be handled and combined with the initial getObj
    // we could have this logic above, if not it must be defined here
    throw new Error(`${action} error: logic for handling and/or filter is not implemented by plugin, not supporting: ${getObj.rawFilter}`)
  }
  // mandatory if-else logic - end

  if (!path) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  const targetStartIndex = getObj.startIndex || 1
  const targetCount = getObj.count || 200

  // Notes for OData (nextLink) paging support:
  //  - request parameters should include "$count=true" when valid
  //  - see plugin-entra-id.ts which use OData
  //  - uncomment below
  /*
  // enable doRequest() OData paging support 
  let paging = { startIndex: getObj.startIndex || 1 }
  if (!ctx) ctx = { paging }
  else ctx.paging = paging

  if (path.includes('$count=true')) { // $count=true requires ConsistencyLevel
    // note: when using $expand, the $count=true might be ignored by target endpoint and the ctx.paging.totalResults updated by doReqest() will be incremental
    if (!options.headers) options.headers = {}
    options.headers.ConsistencyLevel = 'eventual'
  }
  */

  let currentStartIndex = isAllowlistingGroup ? 1 : targetStartIndex
  let allValidResources: any[] = []
  let totalSkipped = 0
  let targetTotalResults: number | null = null
  let iteration = 0
  const maxIterations = 5 // Safety limit for look-ahead fetching
  const resourcesNeeded = isAllowlistingGroup ? targetStartIndex + targetCount - 1 : targetCount

  try {
    while (allValidResources.length < resourcesNeeded && iteration < maxIterations) {
      let currentPath = path
      // may skip adding SCIM pagination parameters startIndex/count if not supported by target endpoint
      if (!currentPath.includes('$count')) { // check for OData $count
        if (currentPath.includes('?')) currentPath += `&startIndex=${currentStartIndex}&count=${targetCount}`
        else currentPath += `?startIndex=${currentStartIndex}&count=${targetCount}`
      }

      // In this use case the target response body is SCIM and includes the Resources array - response.body.Resources
      // Replace the "response.body.Resources" according to target endpoint response syntax 
      // OData response is supported by the response.body.value check
      const response = await helper.doRequest(baseEntity, method, currentPath, body, ctx, options)
      if (response.statusCode > 399) {
        throw new Error(`${response.statusMessage} - ${JSON.stringify(response.body)}`)
      } else if (!response.body) {
        throw new Error(`invalid response: ${JSON.stringify(response)}`)
      } else if (!response.body.Resources && !Array.isArray(response.body.value)) {
        const groupObj = response.body
        const [scimObj, err] = scimgateway.endpointMapper('inbound', groupObj, config.map.group)
        if (err && err.message.includes('valueMap')) return null // allowListing when valueMap is configured, skipping objects not being "valueMapped"
        return scimObj
      }

      const resources = response.body.Resources || response.body.value || []
      targetTotalResults = (response.body.totalResults !== undefined && response.body.totalResults !== null) ? response.body.totalResults : null
      if (ctx?.paging && Object.hasOwn(ctx.paging, 'totalResults')) targetTotalResults = ctx.paging.totalResults

      const pageValidResources: any[] = []
      for (const res of resources) {
        if (!res || Object.keys(res).length < 1) continue
        const [scimObj, err] = scimgateway.endpointMapper('inbound', res, config.map.group)
        if (err && err.message.includes('valueMap')) continue // allowListing when valueMap is configured, skipping objects not being "valueMapped". Example: map.group.displayName.valueMap={"outboundEndpointGrp1":"inboundScimGrp1","Employees":"Admins"}
        if (scimObj && typeof scimObj === 'object' && Object.keys(scimObj).length > 0) {
          pageValidResources.push(scimObj)
        }
      }

      totalSkipped += (resources.length - pageValidResources.length)
      allValidResources.push(...pageValidResources)

      if (targetTotalResults === null) {
        // Target endpoint returned full list
        ret.totalResults = isAllowlistingGroup ? allValidResources.length : targetStartIndex - 1 + allValidResources.length
        ret.Resources = isAllowlistingGroup ? allValidResources.slice(targetStartIndex - 1, targetStartIndex - 1 + targetCount) : allValidResources.slice(0, targetCount)
        return ret
      }

      // If we reached the end of target's list
      if ((currentStartIndex - 1 + resources.length) >= targetTotalResults) break

      // Look-ahead: fetch next page because some results were filtered out
      currentStartIndex += resources.length
      if (ctx?.paging) ctx.paging.startIndex = currentStartIndex
      iteration++
    }

    if (ctx?.paging && getObj.startIndex !== ctx.paging.startIndex) { // changed by doRequest()
      ret.startIndex = ctx.paging.startIndex
    }
    if (ctx?.paging && Object.hasOwn(ctx.paging, 'totalResults')) targetTotalResults = ctx.paging.totalResults

    ret.totalResults = (targetTotalResults !== null && targetTotalResults > totalSkipped) ? targetTotalResults - totalSkipped : (isAllowlistingGroup ? allValidResources.length : targetStartIndex - 1 + allValidResources.length)
    ret.Resources = isAllowlistingGroup ? allValidResources.slice(targetStartIndex - 1, targetStartIndex - 1 + targetCount) : allValidResources.slice(0, targetCount)
    if (!ret.startIndex) ret.startIndex = targetStartIndex

    return ret
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj, ctx) => {
  const action = 'createGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} groupObj=${JSON.stringify(groupObj)} passThrough=${ctx ? 'true' : 'false'}`)

  const [targetObj, err] = scimgateway.endpointMapper('outbound', groupObj, config.map.group)
  if (err && err.message.includes('displayName.valueMap')) {
    // valueMap configured for object having mapTo=displayName and value not allowlisted
    err.message = new Error(`${action} error: ${err.message}`)
    throw err
  }

  const method = 'POST'
  const path = '/Groups'
  const body = targetObj

  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (response.statusCode > 399) {
      throw new Error(`${response.statusMessage} - ${JSON.stringify(response.body)}`)
    }
    return null
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id, ctx) => {
  const action = 'deleteGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} passThrough=${ctx ? 'true' : 'false'}`)

  const method = 'DELETE'
  const path = `/Groups/${id}`
  const body = null

  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (response.statusCode > 399) {
      throw new Error(`${response.statusMessage} - ${JSON.stringify(response.body)}`)
    }
    return null
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// modifyGroup
// =================================================
scimgateway.modifyGroup = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} attrObj=${JSON.stringify(attrObj)} passThrough=${ctx ? 'true' : 'false'}`)

  if (!attrObj.members && !attrObj.description) {
    throw new Error(`${action} error: only supports modification of members and description`)
  }
  if (!Array.isArray(attrObj.members)) {
    throw new Error(`${action} error: ${JSON.stringify(attrObj)} - correct syntax is { "members": [...] }`)
  }

  const membersToAdd = attrObj.members.filter(m => m.value && m.operation !== 'delete').map((m) => { return { value: m.value } })
  const membersToRemove = attrObj.members.filter(m => m.value && m.operation === 'delete').map((m) => { return { value: m.value } })

  // Note, below logic is hardcoded for the SCIM endpoint and must be updated to reflect the configured endpoint.
  // Please see other plugins for how it can be implemented
  let body: any = {}
  if (config.entity[baseEntity].scimVersion && config.entity[baseEntity].scimVersion === '1.1') { // scim v1.1 endpoint
    if (attrObj.members.length < 1) return null
    body = { members: attrObj.members }
  } else { // scim 2.0 endpoint
    if (membersToAdd.length < 1 && membersToRemove.length < 1) return null
    body = { Operations: [] }
    if (membersToAdd.length > 0) {
      body.Operations.push(
        {
          op: 'add',
          path: 'members',
          value: membersToAdd,
        },
      )
    }
    if (membersToRemove.length > 0) {
      body.Operations.push(
        {
          op: 'remove',
          path: 'members',
          value: membersToRemove,
        },
      )
    }
  }

  const method = 'PATCH'
  const path = `/Groups/${id}`

  try {
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (response.statusCode > 399) {
      throw new Error(`${response.statusMessage} - ${JSON.stringify(response.body)}`)
    }
    return null
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// helpers
// =================================================

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})
