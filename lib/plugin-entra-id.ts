// =====================================================================================================================
// File:    plugin-entra-id.js
//
// Author:  Jarle Elshaug
//
// Purpose: Entra ID provisioning including licenses e.g. O365
//
// Prereq:  Entra ID configuration:
//          Application key defined (clientsecret)
//          plugin-entra-ad.json configured with corresponding clientid and clientsecret
//          Application permission: Directory.ReadWriteAll and Organization.ReadWrite.All
//          Application must be member of "User Account Administrator" or "Global administrator"
//
// Notes: For Symantec/Broadcom/CA Provisioning - Use ConnectorXpress, import metafile
//        "node_modules\scimgateway\config\resources\Azure - ScimGateway.xml" for creating endpoint
//
//        Using "Custom SCIM" attributes defined in scimgateway.endpointMap
//        Some functionality will also work using standard SCIM
//        You could also use your own version of endpointMap
//
// /User                                      SCIM (custom)                       Endpoint (AAD)
// --------------------------------------------------------------------------------------------
// User Principal Name                        userName                            userPrincipalName
// Id                                         id                                  id
// Suspended                                  active                              accountEnabled
// Password                                   passwordProfile.password            passwordProfile.password
// First Name                                 name.givenName                      givenName
// Last Name                                  name.familyName                     surname
// Fullname                                   displayName                         displayName
// E-mail                                     mail                                mail
// Mobile Number                              mobilePhone                         mobilePhone
// Phone Number                               businessPhones                      businessPhones
// Manager Id                                 manager.managerId                   manager
// City                                       city                                city
// Country                                    country                             country
// Department                                 department                          department
// Job Title                                  jobTitle                            jobTitle
// Postal Code                                postalCode                          postalCode
// State or Locality                          state                               state
// Street Address                             streetAddress                       streetAddress
// Mail Nick Name                             mailNickname                        mailNickname
// Force Change Password Next Login           passwordProfile.forceChangePasswordNextSignIn  passwordProfile.forceChangePasswordNextSignIn
// onPremises Immutable ID                    onPremisesImmutableId               onPremisesImmutableId
// onPremises Synchronization Enabled         onPremisesSyncEnabled               onPremisesSyncEnabled
// User Type                                  userType                            userType
// Password Policies                          passwordPolicies                    passwordPolicies
// Preferred Language                         preferredLanguage                   preferredLanguage
// Usage Location                             usageLocation                       usageLocation
// Office Location                            officeLocation                      officeLocation
// Proxy Addresses                            proxyAddresses.value                proxyAddresses
// Groups                                     groups - virtual readOnly           N/A
//
// /Group                                     SCIM (custom)                       Endpoint (AAD)
// --------------------------------------------------------------------------------------------
// Name                                       displayName                         displayName
// Id                                         id                                  id
// Members                                    members                             members
// =====================================================================================================================

// start - mandatory plugin initialization
import { ScimGateway, HelperRest } from 'scimgateway'
const scimgateway = new ScimGateway()
const helper = new HelperRest(scimgateway)
const config = scimgateway.getConfig()
scimgateway.authPassThroughAllowed = false
// end - mandatory plugin initialization

const newHelper = new HelperRest(scimgateway)

if (config.map) { // having licensDetails map here instead of config file
  config.map.licenseDetails = {
    servicePlanId: {
      mapTo: 'id',
      type: 'string',
    },
    servicePlans: {
      mapTo: 'servicePlans',
      type: 'array',
    },
    skuId: {
      mapTo: 'skuId',
      type: 'string',
    },
    skuPartNumber: {
      mapTo: 'skuPartNumber',
      type: 'string',
    },
    servicePlanName: {
      mapTo: 'servicePlanName',
      type: 'string',
    },
    provisioningStatus: {
      mapTo: 'provisioningStatus',
      type: 'string',
    },
    appliesTo: {
      mapTo: 'appliesTo',
      type: 'string',
    },
  }
}

const userAttributes: string[] = []
for (const key in config.map.user) { // userAttributes = ['id', 'country', 'preferredLanguage', 'mail', 'city', 'displayName', 'postalCode', 'jobTitle', 'businessPhones', 'onPremisesSyncEnabled', 'officeLocation', 'name.givenName', 'passwordPolicies', 'id', 'state', 'department', 'mailNickname', 'manager.managerId', 'active', 'userName', 'name.familyName', 'proxyAddresses.value', 'servicePlan.value', 'mobilePhone', 'streetAddress', 'onPremisesImmutableId', 'userType', 'usageLocation']
  if (config.map.user[key].mapTo) userAttributes.push(config.map.user[key].mapTo)
}
if (!userAttributes.includes('id')) userAttributes.push('id')

const groupAttributes: string[] = []
for (const key in config.map.group) { // groupAttributes = ['id', 'displayName', 'securityEnabled', 'mailEnabled']
  if (config.map.group[key].mapTo) groupAttributes.push(config.map.group[key].mapTo)
}
if (!groupAttributes.includes('id')) groupAttributes.push('id')
if (!groupAttributes.includes('members.value')) groupAttributes.push('members.value')

// =================================================
// getUsers
// =================================================
scimgateway.getUsers = async (baseEntity, getObj, attributes, ctx) => {
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
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes} passThrough=${ctx ? 'true' : 'false'}`)

  const ret: any = {
    Resources: [],
    totalResults: null,
  }

  const method = 'GET'
  const body = null
  let path
  let options: Record<string, any> = {}
  let isExpandManager = true

  if (Object.hasOwn(getObj, 'value')) getObj.value = encodeURIComponent(getObj.value)
  if (!Object.hasOwn(getObj, 'count')) getObj.count = 200
  if (getObj.count > 500) getObj.count = 500 // Entra ID max 999

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'userName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      path = 'getUser' // special handling
    } else if (getObj.operator === 'eq' && getObj.attribute === 'group.value') {
      // optional - only used when groups are member of users, not default behavior - correspond to getGroupUsers() in versions < 4.x.x
      throw new Error(`${action} error: not supporting groups member of user filtering: ${getObj.rawFilter}`)
    } else {
      // optional - simpel filtering
      if (getObj.attribute) {
        const [endpointAttr] = scimgateway.endpointMapper('outbound', getObj.attribute, config.map.user)
        if (!endpointAttr) throw new Error(`${action} filter error: not supporting ${getObj.rawFilter} because there are no map.user configuration of SCIM attribute '${getObj.attribute}'`)
        if (!operatorMap[getObj.operator]) throw new Error(`${action} error: operator '${getObj.operator}' is not supported in filter: ${getObj.rawFilter}`)

        const odataFilter = operatorMap[getObj.operator](endpointAttr, getObj.value)
        // advanced queries like 'contains', '$search', and '$count' require the ConsistencyLevel header.
        if (!options.headers) options.headers = {}
        options.headers.ConsistencyLevel = 'eventual'

        if (odataFilter.startsWith('$search=')) {
          path = `/users?$top=${getObj.count}&$count=true&${odataFilter}`
          isExpandManager = false // using $search we cannot include $expand=manager
        } else { // eq, sw, co, etc.
          path = `/users?$top=${getObj.count}&$count=true&$filter=${odataFilter}`
        }
      }
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    // note, advanced filtering "light" using and/or (not combined) is handled by scimgateway through plugin simpel filtering above
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all users to be returned - correspond to exploreUsers() in versions < 4.x.x
    path = `/users?$top=${getObj.count}&$count=true` // $count=true requires ConsistencyLevel
    if (!options.headers) options.headers = {}
    options.headers.ConsistencyLevel = 'eventual'
  }
  // mandatory if-else logic - end

  if (!path) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  // enable doRequest() OData paging support 
  let paging = { startIndex: getObj.startIndex }
  if (!ctx) ctx = { paging }
  else ctx.paging = paging

  try {
    let response: any
    if (path === 'getUser') { // special
      response = { body: { value: [] } }
      const userObj: any = await getUser(baseEntity, getObj.value, attributes, ctx, options)
      if (userObj) response.body.value.push(userObj)
    } else {
      if (isExpandManager) path += '&$expand=manager($select=userPrincipalName)'
      response = await helper.doRequest(baseEntity, method, path, body, ctx, options)
    }
    if (!response.body.value) {
      throw new Error(`invalid response: ${JSON.stringify(response)}`)
    }
    for (let i = 0; i < response.body.value.length; ++i) {
      if (response.body.value[i].manager?.userPrincipalName) {
        let managerId = response.body.value[i].manager.userPrincipalName
        if (managerId) response.body.value[i].manager = managerId
        else delete response.body.value[i].manager
      } else if (!isExpandManager && response.body.value[i].id) {
        const userObj: any = await getUser(baseEntity, response.body.value[i].id, [], ctx, options)
        if (userObj && userObj.manager) {
          response.body.value[i] = userObj
        }
      }
      // map to inbound
      const [scimObj] = scimgateway.endpointMapper('inbound', response.body.value[i], config.map.user) // endpoint => SCIM/CustomSCIM attribute standard
      if (scimObj && typeof scimObj === 'object' && Object.keys(scimObj).length > 0) ret.Resources.push(scimObj)
    }

    if (getObj.startIndex !== ctx.paging.startIndex) { // changed by doRequest()
      ret.startIndex = ctx.paging.startIndex
    }
    if (ctx.paging.totalResults) ret.totalResults = ctx.paging.totalResults // set by doRequest()
    else ret.totalResults = getObj.startIndex ? getObj.startIndex - 1 + response.body.value.length : response.body.value.length

    return (ret)
  } catch (err: any) {
    if (err.message.includes('Request_ResourceNotFound')) return { Resources: [] }
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj, ctx) => {
  const action = 'createUser'
  scimgateway.logDebug(baseEntity, `handling ${action} userObj=${JSON.stringify(userObj)} passThrough=${ctx ? 'true' : 'false'}`)

  const addonObj: Record<string, any> = {}
  if (userObj.servicePlan) {
    addonObj.servicePlan = userObj.servicePlan
    delete userObj.servicePlan
  }
  if (userObj.manager) {
    addonObj.manager = userObj.manager
    delete userObj.manager
  }
  if (userObj.proxyAddresses) {
    addonObj.proxyAddresses = userObj.proxyAddresses
    delete userObj.proxyAddresses
  }

  const method = 'POST'
  const path = '/users'
  const [body] = scimgateway.endpointMapper('outbound', userObj, config.map.user)

  try {
    const res = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (Object.keys(addonObj).length > 0) {
      const id = res?.body?.id || userObj.userName
      await scimgateway.modifyUser(baseEntity, id, addonObj, ctx) // manager, proxyAddresses, servicePlan
    }
    return res?.body
  } catch (err: any) {
    const newErr = new Error(`${action} error: ${err.message}`)
    if (err.message.includes('userPrincipalName already exists')) newErr.name += '#409' // customErrCode
    else if (err.message.includes('Property netId is invalid')) {
      newErr.name += '#409'
      let addMsg = ''
      if (userObj.mail) addMsg = ' e.g., mail'
      newErr.message = 'userPrincipalName already exists and/or other unique attribute conflicts' + addMsg
    }
    throw newErr
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
    await helper.doRequest(baseEntity, method, path, body, ctx)
    return (null)
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

  if (attrObj.servicePlan) delete attrObj.servicePlan // use license management through groups
  const [parsedAttrObj] = scimgateway.endpointMapper('outbound', attrObj, config.map.user) // SCIM/CustomSCIM => endpoint attribute standard
  if (parsedAttrObj instanceof Error) throw (parsedAttrObj) // error object

  const objManager: Record<string, any> = {}
  if (Object.prototype.hasOwnProperty.call(parsedAttrObj, 'manager')) {
    objManager.manager = parsedAttrObj.manager
    if (objManager.manager === '') objManager.manager = null
    delete parsedAttrObj.manager
  }

  const profile = () => { // patch
    return new Promise((resolve, reject) => {
      (async () => {
        if (JSON.stringify(parsedAttrObj) === '{}') return resolve(null)
        let res: any
        for (const key in parsedAttrObj) { // if object the modified AAD object must contain all elements, if not they will be cleared e.g. employeeOrgData
          if (typeof parsedAttrObj[key] === 'object') { // get original object and merge
            const method = 'GET'
            const path = `/users/${id}`
            try {
              if (!res) {
                res = await helper.doRequest(baseEntity, method, path, null, ctx)
              }
              if (res?.body && res.body[key]) {
                const fullKeyObj = Object.assign(res.body[key], parsedAttrObj[key]) // merge original with modified
                if (fullKeyObj && Object.keys(fullKeyObj).length > 0) {
                  for (const k in fullKeyObj) {
                    if (fullKeyObj[k] === '') {
                      fullKeyObj[k] = null
                    }
                  }
                  parsedAttrObj[key] = fullKeyObj
                }
              }
            } catch (err) {
              return reject(err)
            }
          } else if (parsedAttrObj[key] === '') {
            parsedAttrObj[key] = null
          }
        }
        const method = 'PATCH'
        const path = `/users/${id}`
        try {
          await helper.doRequest(baseEntity, method, path, parsedAttrObj, ctx)
          resolve(null)
        } catch (err) {
          return reject(err)
        }
      })()
    })
  }

  const manager = () => {
    return new Promise((resolve, reject) => {
      (async () => {
        if (!Object.prototype.hasOwnProperty.call(objManager, 'manager')) return resolve(null)
        let method: string | null = null
        let path: string | null = null
        let body: Record<string, any> | null = null
        if (objManager.manager) { // new manager
          const graphUrl = helper.getGraphUrl()
          method = 'PUT'
          path = `/users/${id}/manager/$ref`
          body = { '@odata.id': `${graphUrl}/users/${objManager.manager}` }
        } else { // delete manager (null/undefined/'')
          method = 'DELETE'
          path = `/users/${id}/manager/$ref`
          body = null
        }
        try {
          await helper.doRequest(baseEntity, method, path, body, ctx)
          resolve(null)
        } catch (err) {
          return reject(err)
        }
      })()
    })
  }

  return Promise.all([profile(), manager()]) // license() deprecated - use license management through groups
    .then((_) => { return (null) })
    .catch((err) => { throw new Error(`${action} error: ${err.message}`) })
}

// =================================================
// getGroups
// =================================================
scimgateway.getGroups = async (baseEntity, getObj, attributes, ctx) => {
  const action = 'getGroups'
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes} passThrough=${ctx ? 'true' : 'false'}`)

  const ret: any = {
    Resources: [],
    totalResults: null,
  }

  if (Object.hasOwn(getObj, 'value')) getObj.value = encodeURIComponent(getObj.value)
  if (attributes.length === 0) attributes = groupAttributes
  let includeMembers = false
  if (attributes.includes('members.value') || attributes.includes('members')) {
    includeMembers = true
  }

  const [attrs] = scimgateway.endpointMapper('outbound', attributes, config.map.group)
  const method = 'GET'
  const body = null
  let path
  let options: Record<string, any> = {}
  let isUserMemberOf = getObj?.operator === 'eq' && getObj?.attribute === 'members.value'

  if (!Object.hasOwn(getObj, 'count')) getObj.count = 500
  if (getObj.count > 500) getObj.count = 500 // Entra ID max 999

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'displayName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      if (getObj.attribute === 'id') {
        if (includeMembers) path = `/groups/${getObj.value}?$select=${attrs.join()}&$expand=members($select=id,displayName)`
        else path = `/groups/${getObj.value}?$select=${attrs.join()}`
      } else {
        if (includeMembers) path = `/groups?$filter=${getObj.attribute} eq '${getObj.value}'&$select=${attrs.join()}&$expand=members($select=id,displayName)`
        else path = `/groups?$filter=${getObj.attribute} eq '${getObj.value}'&$select=${attrs.join()}`
      }
    } else if (isUserMemberOf) {
      // mandatory - return all groups the user 'id' (getObj.value) is member of - correspond to getGroupMembers() in versions < 4.x.x
      // Resources = [{ id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }]
      path = `/users/${getObj.value}/transitiveMemberOf/microsoft.graph.group?$top=${getObj.count}&$count=true&select=id,displayName`
    } else {
      // optional - simpel filtering
      if (getObj.attribute) {
        const [endpointAttr] = scimgateway.endpointMapper('outbound', getObj.attribute, config.map.group)
        if (!endpointAttr) throw new Error(`${action} filter error: not supporting ${getObj.rawFilter} because there are no map.group configuration of SCIM attribute '${getObj.attribute}'`)
        if (!operatorMap[getObj.operator]) throw new Error(`${action} error: operator '${getObj.operator}' is not supported in filter: ${getObj.rawFilter}`)

        const odataFilter = operatorMap[getObj.operator](endpointAttr, getObj.value)
        // advanced queries like 'contains', '$search', and '$count' require the ConsistencyLevel header.
        if (!options.headers) options.headers = {}
        options.headers.ConsistencyLevel = 'eventual'

        if (odataFilter.startsWith('$search=')) {
          path = `/groups?$top=${getObj.count}&$count=true&${odataFilter}`
        } else {
          path = `/groups?$top=${getObj.count}&$count=true&$filter=${odataFilter}`
        } // all attributes, not using: path += `&$select=${attrs}`
      }
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    // note, advanced filtering "light" using and/or (not combined) is handled by scimgateway through plugin simpel filtering above
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all groups to be returned - correspond to exploreGroups() in versions < 4.x.x
    if (includeMembers) path = `/groups?$top=${getObj.count}&$count=true&$select=${attrs.join()}&$expand=members($select=id,displayName)`
    else path = `/groups?$top=${getObj.count}&$count=true&$select=${attrs.join()}` // $count=true requires ConsistencyLevel
    if (!options.headers) options.headers = {}
    options.headers.ConsistencyLevel = 'eventual'
  }
  // mandatory if-else logic - end

  if (!path) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  // enable doRequest() OData paging support 
  let paging = { startIndex: getObj.startIndex }
  if (!ctx) ctx = { paging }
  else ctx.paging = paging

  const newCtx = { ...ctx }
  newCtx.paging = { startIndex: 1 }

  try {
    let response: any
    let responseMemberOf: any
    if (!isUserMemberOf) response = await helper.doRequest(baseEntity, method, path, body, ctx, options)
    else {
      // request both the default transitiveMemberOf (includes nested groups) and memberOf because we want to distinguish SCIM type=direct/indirect
      const pathMemberOf = `/users/${getObj.value}/memberOf/microsoft.graph.group?$top=${getObj.count}&$count=true&select=id,displayName`
      const allErrors: string[] = []
      const results = await Promise.allSettled([
        helper.doRequest(baseEntity, method, path, body, ctx, options),
        newHelper.doRequest(baseEntity, method, pathMemberOf, body, newCtx, options), // using newHelper to avoid shared internal helperRest paging 
      ])
      const errors = results
        .filter(r => r.status === 'rejected')
        .map(r => (r as PromiseRejectedResult).reason.message)
        .filter(msg => !msg.includes('already exist'))
      allErrors.push(...errors)

      if (allErrors.length > 0) {
        throw new Error(allErrors.join(', '))
      }

      response = (results[0] as PromiseFulfilledResult<any>).value // includes all groups (also nested)
      responseMemberOf = (results[1] as PromiseFulfilledResult<any>).value // do not include nested groups

      let nextStartIndex = scimgateway.getNextStartIndex(responseMemberOf.body.value.length * 2, newCtx.paging.startIndex, responseMemberOf.body.value.length)
      if (nextStartIndex > newCtx.paging.startIndex && responseMemberOf && responseMemberOf.body.value && Array.isArray(responseMemberOf.body.value)) {
        // use paging to ensure responseMemberOf is complete 
        let totalResults = responseMemberOf.body.value.length
        let startIndex = 1
        let res: any
        do {
          try {
            startIndex = nextStartIndex
            newCtx.paging.startIndex = startIndex
            res = await newHelper.doRequest(baseEntity, method, pathMemberOf, body, newCtx, options)
          } catch (err) { void 0 }
          if (res?.body && res.body.value && Array.isArray(res.body.value) && res.body.value.length > 0) {
            const count = res.body.value.length
            totalResults += count
            nextStartIndex = scimgateway.getNextStartIndex(totalResults + count, startIndex, count)
            for (let i = 0; i < res.body.value.length; i++) {
              if (!res.body.value[i].id) continue
              responseMemberOf.body.value.push(res.body.value[i])
            }
          }
        } while (nextStartIndex > startIndex)
      }

      if (response.body && response.body.value && Array.isArray(response.body.value)) {
        const directIds = new Set()
        if (responseMemberOf.body && responseMemberOf.body.value && Array.isArray(responseMemberOf.body.value)) {
          responseMemberOf.body.value.forEach((el: any) => directIds.add(el.id))
        }
        response.body.value.forEach((el: any) => {
          if (directIds.has(el.id)) el.type = 'direct'
          else el.type = 'indirect'
        })
      }
    }
    if (!response.body) {
      throw new Error(`invalid response: ${JSON.stringify(response)}`)
    }
    if (!response.body.value) {
      if (typeof response.body === 'object' && !Array.isArray(response.body)) response = { body: { value: [response.body] } }
      else response.body.value = []
    }

    for (let i = 0; i < response.body.value.length; ++i) {
      let members: any
      if (response.body.value[i].members) {
        members = response.body.value[i].members.map((el: Record<string, any>) => {
          return {
            value: el.id,
            display: el.displayName,
          }
        })
        delete response.body.value[i].members
      } else if (getObj.operator === 'eq' && getObj.attribute === 'members.value') { // Not using expand-members. Only includes current user as member, but should have requested all...
        members = [{
          value: getObj.value,
          type: response.body.value[i].type || 'direct',
        }]
      }

      const [scimObj] = scimgateway.endpointMapper('inbound', response.body.value[i], config.map.group) // endpoint => SCIM/CustomSCIM attribute standard
      if (scimObj && typeof scimObj === 'object' && Object.keys(scimObj).length > 0) {
        if (members) scimObj.members = members
        ret.Resources.push(scimObj)
      }
    }

    if (getObj.startIndex !== ctx.paging.startIndex) { // changed by doRequest()
      ret.startIndex = ctx.paging.startIndex
    }
    if (ctx.paging.totalResults) ret.totalResults = ctx.paging.totalResults // set by doRequest()
    else ret.totalResults = getObj.startIndex ? getObj.startIndex - 1 + response.body.value.length : response.body.value.length

    return (ret)
  } catch (err: any) {
    if (err.message.includes('Request_ResourceNotFound')) return { Resources: [] }
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj, ctx) => {
  const action = 'createGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} groupObj=${JSON.stringify(groupObj)} passThrough=${ctx ? 'true' : 'false'}`)

  const body: any = { displayName: groupObj.displayName }
  body.mailNickName = groupObj.displayName?.replace(/[^a-zA-Z0-9]/g, '')
  body.mailEnabled = false
  body.securityEnabled = true
  const method = 'POST'
  const path = '/Groups'

  try {
    const res = await scimgateway.getGroups(baseEntity, { attribute: 'displayName', operator: 'eq', value: groupObj.displayName }, ['id', 'displayName'], ctx)
    if (res && res.Resources && res.Resources.length > 0) {
      throw new Error(`group ${groupObj.displayName} already exist`)
    }
    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    return response?.body
  } catch (err: any) {
    const newErr = new Error(`${action} error: ${err.message}`)
    if (err.message.includes('already exist')) newErr.name += '#409' // customErrCode
    throw newErr
  }
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id, ctx) => {
  const action = 'deleteGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} passThrough=${ctx ? 'true' : 'false'}`)

  const method = 'DELETE'
  const path = `/groups/${id}`
  const body = null

  await helper.doRequest(baseEntity, method, path, body, ctx)
}

// =================================================
// modifyGroup
// =================================================
scimgateway.modifyGroup = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} attrObj=${JSON.stringify(attrObj)} passThrough=${ctx ? 'true' : 'false'}`)

  if (!attrObj.members) {
    throw new Error(`${action} error: only supports modification of members`)
  }
  if (!Array.isArray(attrObj.members)) {
    throw new Error(`${action} error: ${JSON.stringify(attrObj)} - correct syntax is { "members": [...] }`)
  }

  const membersToAdd = attrObj.members.filter(m => m.value && m.operation !== 'delete').map(m => m.value)
  const membersToRemove = attrObj.members.filter(m => m.value && m.operation === 'delete').map(m => m.value)
  const promises: Promise<any>[] = []

  if (membersToAdd.length > 0) {
    const graphUrl = helper.getGraphUrl()
    const method = 'POST'
    const path = `/groups/${id}/members/$ref`
    membersToAdd.forEach((memberId) => {
      const body = { '@odata.id': `${graphUrl}/directoryObjects/${memberId}` }
      promises.push(helper.doRequest(baseEntity, method, path, body, ctx))
    })
  }

  if (membersToRemove.length > 0) {
    const method = 'DELETE'
    const body = null
    membersToRemove.forEach((memberId) => {
      const path = `/groups/${id}/members/${memberId}/$ref`
      promises.push(helper.doRequest(baseEntity, method, path, body, ctx))
    })
  }

  try {
    const allErrors: string[] = []
    for (let i = 0; i < promises.length; i += 5) {
      const chunk = promises.slice(i, i + 5)
      const results = await Promise.allSettled(chunk)
      const errors = results
        .filter(r => r.status === 'rejected')
        .map(r => (r as PromiseRejectedResult).reason.message)
        .filter(msg => !msg.includes('already exist'))
      allErrors.push(...errors)
    }
    if (allErrors.length > 0) {
      throw new Error(allErrors.join(', '))
    }
    return null
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// getServicePlans
// =================================================
scimgateway.getServicePlans = async (baseEntity, getObj, attributes, ctx) => {
  //
  // "getObj" = { attribute: <>, operator: <>, value: <>, rawFilter: <>, startIndex: <>, count: <> }
  // rawFilter is always included when filtering - attribute, operator and value are included when requesting unique object or simpel filtering
  // See comments in the "mandatory if-else logic - start"
  //
  // "attributes" contains a list of attributes to be returned - if blank, all supported attributes should be returned
  // Should normally return all supported user attributes having id and servicePlanName as mandatory
  // id and servicePlanName are most often considered as "the same" having value = <servicePlanName>
  // Note, the value of returned 'id' will be used as 'id' in modifyServicePlan and deleteServicePlan
  // scimgateway will automatically filter response according to the attributes list
  //
  const action = 'getServicePlans'
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes} passThrough=${ctx ? 'true' : 'false'}`)

  const ret: any = {
    Resources: [],
    totalResults: null,
  }

  const method = 'GET'
  const body = null
  let path

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'servicePlanName'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      if (attributes.length === 1 && attributes[0] === 'servicePlanName') {
        ret.Resources = [{ servicePlanName: getObj.value }]
        return ret
      }
      path = 'getServicePlan' // special handling
    } else if (getObj.operator === 'eq' && getObj.attribute === 'servicePlan.value') {
      // optional - only used when servicePlans are member of users, not default behavior - correspond to getGroupUsers() in versions < 4.x.x
      throw new Error(`${action} error: servicePlans member of user filtering not supported: ${getObj.rawFilter}`)
    } else {
      // optional - simpel filtering
      throw new Error(`${action} error: simpel filtering not supported: ${getObj.rawFilter}`)
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: advanced filtering not supported: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all serviePlans to be returned - correspond to exploreServicePlans() in versions < 4.x.x
    path = '/subscribedSkus' // paging not supported
  }

  if (!path) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  try {
    let response
    if (path === 'getServicePlan') { // special
      response = { body: { value: [] } }
      path = '/subscribedSkus'

      const res = await helper.doRequest(baseEntity, method, path, body, ctx)
      if (!res.body.value) {
        throw new Error('got empty response on REST request')
      }

      const [arrOutbound] = (scimgateway.endpointMapper('outbound', attributes, config.map.licenseDetails))
      const [arrInbound] = (scimgateway.endpointMapper('inbound', attributes, config.map.licenseDetails))

      const arr = getObj.value.split('::') // servicePlaneName
      const skuPartNumber = arr[0]
      const plan = arr[1]
      const planObj: Record<string, any> = {}

      for (let i = 0; i < res.body.value.length; i++) {
        if (res.body.value[i].skuPartNumber !== skuPartNumber) continue
        for (let index = 0; index < res.body.value[i].servicePlans.length; index++) {
          if (res.body.value[i].servicePlans[index].servicePlanName === plan) {
            planObj.servicePlanName = `${skuPartNumber}::${res.body.value[i].servicePlans[index].servicePlanName}`
            planObj.id = res.body.value[i].servicePlans[index].servicePlanId
            for (let j = 0; j < arrInbound.length; j++) { // skuPartNumber, skuId, servicePlanName, servicePlanId
              if (arrInbound[j] !== 'servicePlanName' && arrInbound[j] !== 'id') planObj[arrInbound[j]] = res.body.value[i][arrOutbound[j]]
            }
            i = res.body.value.length
            break
          }
        }
      }
      if (planObj) ret.Resources.push(planObj)
    } else {
      response = await helper.doRequest(baseEntity, method, path, body, ctx)

      if (!response.body.value) {
        throw new Error('got empty response on REST request')
      }

      for (let i = 0; i < response.body.value.length; i++) {
        const skuPartNumber = response.body.value[i].skuPartNumber
        for (let index = 0; index < response.body.value[i].servicePlans.length; index++) {
          if (response.body.value[i].servicePlans[index].servicePlanName && response.body.value[i].servicePlans[index].provisioningStatus === 'Success') {
            const scimPlan = {
              servicePlanName: `${skuPartNumber}::${response.body.value[i].servicePlans[index].servicePlanName}`,
              id: response.body.value[i].servicePlans[index].servicePlanId,
            }
            ret.Resources.push(scimPlan)
          }
        }
      }
    }

    ret.totalResults = ret.Resources.length // no paging
    return ret
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// getUser
// addOn helper for plugin-azure-ad
// =================================================
const getUser = async (baseEntity: string, uid: string, attributes: string[], ctx?: undefined | Record<string, any>, options?: undefined | Record<string, any>) => { // uid = id, userName (upn) or externalId (upn)
  try {
    if (attributes.length < 1) {
      attributes = userAttributes
    }

    const userPromise = (async () => {
      const method = 'GET'
      const path = `/users/${uid}?$expand=manager($select=userPrincipalName)`
      const body = null
      const response = await helper.doRequest(baseEntity, method, path, body, ctx)
      const userObj = response.body
      if (!userObj) {
        throw new Error('Got empty response when retrieving data for ' + uid)
      }
      if (userObj.manager?.userPrincipalName) {
        userObj.manager = userObj.manager.userPrincipalName
      } else {
        delete userObj.manager
      }
      return userObj
    })()

    const licensePromise = (async () => {
      if (!attributes.includes('servicePlans.value')) return null // licenses not requested
      const method = 'GET'
      const path = `/users/${uid}/licenseDetails`
      const body = null
      const retObj: Record<string, any> = { servicePlan: [] }
      try {
        const response = await helper.doRequest(baseEntity, method, path, body, ctx, options)
        if (response.body?.value?.length > 0) {
          for (const licenseDetail of response.body.value) {
            const skuPartNumber = licenseDetail.skuPartNumber
            for (const servicePlan of licenseDetail.servicePlans) {
              if (['Success', 'PendingInput'].includes(servicePlan.provisioningStatus)) {
                retObj.servicePlan.push({ value: `${skuPartNumber}::${servicePlan.servicePlanName}` })
              }
            }
          }
        }
        return retObj
      } catch (err: any) {
        let statusCode
        try { statusCode = JSON.parse(err.message).statusCode } catch (e) { }
        if (statusCode === 404) return null // user has no plans
        throw err // re-throw other errors
      }
    })()

    const [userResult, licenseResult] = await Promise.all([
      userPromise,
      licensePromise,
    ])

    let retObj = {}
    if (userResult) retObj = Object.assign(retObj, userResult)
    if (licenseResult) retObj = Object.assign(retObj, licenseResult)
    return retObj
  } catch (err: any) {
    if (err.message.includes('Request_ResourceNotFound') || err.message.includes('empty response')) return null // no user found
    throw err
  }
}

//
// SCIM to OData filter operator map
//
type ScimOpFn = (attribute: string, value?: string) => string
const operatorMap: Record<string, ScimOpFn> = {
  eq: (a, v) => `${a} eq ${['true', 'false'].includes(v as string) ? v : `'${v}'`}`,
  ne: (a, v) => `${a} ne ${['true', 'false'].includes(v as string) ? v : `'${v}'`}`,
  // co: (a, v) => `contains(${a}, '${v}')`, // not supported by Entra ID
  // co: (a, v) => `$search="${a}:${v}"`, // comment out - Entra ID do not support true “contains”
  sw: (a, v) => `startswith(${a}, '${v}')`,
  // ew: (a, v) => `endswith(${a}, '${v}')`, // not supported by Entra ID
  pr: a => `${a} ne null`,
  gt: (a, v) => `${a} gt ${v}`,
  ge: (a, v) => `${a} ge ${v}`,
  lt: (a, v) => `${a} lt ${v}`,
  le: (a, v) => `${a} le ${v}`,
}

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})
