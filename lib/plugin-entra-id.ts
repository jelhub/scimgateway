// =====================================================================================================================
// File:    plugin-entra-id.js
//
// Author:  Jarle Elshaug
//
// Purpose: Entra ID provisioning including licenses e.g. O365
//
// Prereq:  Entra ID configuration:
//          Entra Application key defined (clientsecret). Other options are upload a certificate or configure "Federated Identity Credentials"
//          plugin-entra-ad.json configured with corresponding clientid and clientsecret (or certificate/federated identity credentials)
//          Application permission: Directory.ReadWriteAll and Organization.ReadWrite.All
//          Application must be member of "User Account Administrator" or "Global administrator"
//
// Notes: For Symantec/Broadcom/CA Provisioning - Use ConnectorXpress, import metafile
//        "node_modules\scimgateway\config\resources\Azure - ScimGateway.xml" for creating endpoint
//
//        'GET /Entitlements' retrieves a list of all available entitlements (licences) and corresponds with users entitlements
//
//        Using "Custom SCIM" attributes defined in configuration endpoint.entity.map
//        Schema generated according to this configuration
//        Note, the 'map.user.signInActivity' requires Entra ID Premium license and API permissions: 'AuditLog.Read.All'. Remove this mapping if conditions not met".
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
// Phone Number                               businessPhone                       businessPhones
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
// Entitlements                               entitlements                        entitlements (assignedLicenses) - value=skuId, type=skuPartNumber and display=<user-friendly license name>
// SignInActivity                             signInActivity                      signInActivity (lastSignInDateTime, lastSuccessfulSignInDateTime and lastNonInteractiveSignInDateTime), Note: Requires Entra ID Premium license and API permissions: 'AuditLog.Read.All'. Remove this mapping if conditions not met".
//
// /Group                                     SCIM (custom)                       Endpoint (AAD)
// --------------------------------------------------------------------------------------------
// Name                                       displayName                         displayName
// Id                                         id                                  id
// Description                                description                         description
// Members                                    members                             members
// =====================================================================================================================

import path from 'node:path'

// start - mandatory plugin initialization
import { ScimGateway, HelperRest } from 'scimgateway'
const scimgateway = new ScimGateway()
const helper = new HelperRest(scimgateway)
const config = scimgateway.getConfig()
scimgateway.authPassThroughAllowed = false
// end - mandatory plugin initialization

const newHelper = new HelperRest(scimgateway)
const entitlementsByValues: Record<string, any> = {} // {skuId: {...}}
const lock = new scimgateway.Lock()

// load Azure license mapping JSON-file having skuPartNumber and corresponding user-friendly name
let fs: typeof import('fs')
let licenseMapping: Record<string, any> = {}
async function loadLicenseMapping() {
  try {
    if (!fs) fs = (await import('fs'))
    let mappingPath = path.join(scimgateway.pluginDir, 'azure-license-mapping.json')
    if (fs.existsSync(mappingPath)) {
      licenseMapping = JSON.parse(fs.readFileSync(mappingPath, 'utf8'))
    } else {
      mappingPath = path.join(scimgateway.gwDir, 'azure-license-mapping.json')
      if (fs.existsSync(mappingPath)) {
        licenseMapping = JSON.parse(fs.readFileSync(mappingPath, 'utf8'))
      }
    }
  } catch (err) {
    scimgateway.logDebug('plugin-entra-id', `Error loading license mapping: ${err}`)
  }
}
loadLicenseMapping()

const mapAttributes: string[] = []
const mapAttributesTo: string[] = []
let userSelectAttributes: string[] = []
const [entitlementsAttr] = scimgateway.endpointMapper('inbound', 'entitlements', config.map.user)

for (const key in config.map.user) { // mapAttributesTo = ['id', 'country', 'preferredLanguage', 'mail', 'city', 'displayName', 'postalCode', 'jobTitle', 'businessPhone', 'onPremisesSyncEnabled', 'officeLocation', 'name.givenName', 'passwordPolicies', 'id', 'state', 'department', 'mailNickname', 'manager.managerId', 'active', 'userName', 'name.familyName', 'proxyAddresses.value', 'servicePlan.value', 'mobilePhone', 'streetAddress', 'onPremisesImmutableId', 'userType', 'usageLocation']
  if (config.map.user[key].mapTo) {
    mapAttributes.push(key)
    mapAttributesTo.push(config.map.user[key].mapTo)
    let attr = key.split('.')[0]
    if (entitlementsAttr && attr === entitlementsAttr) attr = 'assignedLicenses'
    if (!userSelectAttributes.includes(attr)) userSelectAttributes.push(attr)
  }
}
if (!mapAttributes.includes('id')) {
  mapAttributes.push('id')
  if (!userSelectAttributes.includes('id')) userSelectAttributes.push('id')
}
if (!mapAttributesTo.includes('id')) mapAttributesTo.push('id')

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

  let selectAttributes: string[] = []
  if (attributes.length > 0) {
    for (const attribute of attributes) {
      const [endpointAttr] = scimgateway.endpointMapper('outbound', attribute, config.map.user)
      let attr = endpointAttr.split('.')[0]
      if (!attr) continue
      if (attribute.startsWith('entitlements')) attr = 'assignedLicenses'
      if (!selectAttributes.includes(attr)) selectAttributes.push(attr)
    }
  } else selectAttributes = userSelectAttributes

  const method = 'GET'
  const body = null
  let path
  let options: Record<string, any> = {}
  let isExpandManager = true

  if (Object.hasOwn(getObj, 'value')) getObj.value = encodeURIComponent(getObj.value)
  if (!Object.hasOwn(getObj, 'count')) getObj.count = 100
  if (getObj.count > 100) getObj.count = 100 // Entra ID max 100 (historically max was 999)

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id', 'userName', 'externalId'].includes(getObj.attribute)) {
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      path = `/users/${getObj.value}?$select=${selectAttributes.join(',')}`
    } else if (getObj.operator === 'eq' && getObj.attribute === 'group.value') {
      // optional - only used when groups are member of users, not default behavior - correspond to getGroupUsers() in versions < 4.x.x
      throw new Error(`${action} error: not supporting groups member of user filtering: ${getObj.rawFilter}`)
    } else if (getObj.operator === 'pr' && getObj.attribute === 'entitlements') { // pr - presence of (only return objects having getObj.attribute)
      path = `/users?$top=${getObj.count}&$count=true&filter=assignedLicenses/$count ne 0& &$select=${selectAttributes.join(',')}`
    } else {
      // optional - simpel filtering
      if (getObj.attribute) {
        let [endpointAttr] = scimgateway.endpointMapper('outbound', getObj.attribute, config.map.user)
        if (!endpointAttr) throw new Error(`${action} filter error: not supporting ${getObj.rawFilter} because there are no map.user configuration of SCIM attribute '${getObj.attribute}'`)
        if (!operatorMap[getObj.operator]) throw new Error(`${action} error: operator '${getObj.operator}' is not supported in filter: ${getObj.rawFilter}`)
        const eArr = endpointAttr.split('.')
        if (eArr[0] == 'signInActivity' && eArr.length === 2) {
          endpointAttr = eArr.join('/') // signInActivity/lastSuccessfulSignInDateTime - filter=signInActivity.lastSuccessfulSignInDateTime lt "2025-12-04T00:00:00Z"
        }
        let odataFilter = operatorMap[getObj.operator](endpointAttr, getObj.value)
        if (!odataFilter) {
          const [supported] = scimgateway.endpointMapper('inbound', 'displayName,userPrincipalName,mail,proxyAddresses', config.map.user)
          throw new Error(`${action} error: Entra ID only supports operator '${getObj.operator}' for a limited set of attributes (e.g., SCIM attributes: ${supported}) and therefore not supporting filter: ${getObj.rawFilter}`)
        }

        const arr = getObj.attribute.split('.')
        if (arr.length === 2) {
          if (config.map.user[arr[0]] && ['complexArray', 'complexObject'].includes(config.map.user[arr[0]]?.type)) {
            if (arr[0] === 'entitlements') { // using entitlements for license
              const skuIdDefs = await getSkuIdDefs(baseEntity, {}, [], ctx)
              const skuIdArr = searchSkuIdDefs(skuIdDefs, getObj)
              if (skuIdArr.length === 0) return ret
              else if (skuIdArr.length > 1) throw new Error(`filter error: not supporting ${getObj.rawFilter} - entitlements filter supports only 'value', 'type' and 'display' with opearator 'eq'. Example1: filter=entitlements.value eq "84a661c4-e949-4bd2-a560-ed7766fcaf2b" Example2: filter=entitlements.type eq "AAD_PREMIUM_P2"`)
              odataFilter = `assignedLicenses/any(x:x/skuId eq ${skuIdArr[0]})`
            }
          }
        }

        // advanced queries like 'contains', '$search', and '$count' require the ConsistencyLevel header.
        if (!options.headers) options.headers = {}
        options.headers.ConsistencyLevel = 'eventual'

        if (odataFilter.startsWith('$search=')) {
          path = `/users?$top=${getObj.count}&$count=true&${odataFilter}&$select=${selectAttributes.join(',')}`
          isExpandManager = false // using $search we cannot include $expand=manager
        } else { // eq, sw, co, etc.
          path = `/users?$top=${getObj.count}&$count=true&$filter=${odataFilter}&$select=${selectAttributes.join(',')}`
        }
      }
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    // note, advanced filtering "light" using and/or (not combined) is handled by scimgateway through plugin simpel filtering above
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all users to be returned - correspond to exploreUsers() in versions < 4.x.x
    path = `/users?$top=${getObj.count}&$count=true&$select=${selectAttributes.join(',')}`
  }
  // mandatory if-else logic - end

  if (!path) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  if (path.includes('$count=true')) { // $count=true requires ConsistencyLevel
    if (!options.headers) options.headers = {}
    options.headers.ConsistencyLevel = 'eventual'
  }

  // enable doRequest() OData paging support 
  let paging = { startIndex: getObj.startIndex }
  if (!ctx) ctx = { paging }
  else ctx.paging = paging

  try {
    let response: any
    if (isExpandManager && selectAttributes.includes('manager')) {
      path += '&$expand=manager($select=userPrincipalName)'
    }

    response = await helper.doRequest(baseEntity, method, path, body, ctx, options)

    if (!response.body?.value) {
      const singleUser = response.body
      response.body = { value: [singleUser] }
    }
    if (!response.body.value) {
      throw new Error(`invalid response: ${JSON.stringify(response)}`)
    }

    const skuIdDefs = await getSkuIdDefs(baseEntity, {}, [], ctx)
    for (let i = 0; i < response.body.value.length; ++i) {
      if (!isExpandManager && selectAttributes.includes('manager') && response.body.value[i].id) {
        const singleUserPath = `/users/${response.body.value[i].id}?$select=${attributes.join()}&$expand=manager($select=userPrincipalName)`
        const singleUserRes = await helper.doRequest(baseEntity, 'GET', singleUserPath, null, ctx, options)
        if (singleUserRes.body) response.body.value[i] = singleUserRes.body
      }
      if (response.body.value[i].manager?.userPrincipalName) {
        let managerId = response.body.value[i].manager.userPrincipalName
        if (managerId) response.body.value[i].manager = managerId
        else delete response.body.value[i].manager
      }

      if (response.body.value[i].signInActivity) {
        delete response.body.value[i].signInActivity.lastSignInRequestId
        delete response.body.value[i].signInActivity.lastNonInteractiveSignInRequestId
        delete response.body.value[i].signInActivity.lastSuccessfulSignInRequestId
      }

      if (mapAttributesTo.includes('entitlements')) { // assignedLicenses map to entitlements
        const [entitlementsAttr] = scimgateway.endpointMapper('inbound', 'entitlements', config.map.user)
        if (entitlementsAttr) {
          if (response.body.value[i].assignedLicenses && Array.isArray(response.body.value[i].assignedLicenses)) {
            if (!response.body.value[i][entitlementsAttr]) response.body.value[i][entitlementsAttr] = []
            for (const lic of response.body.value[i].assignedLicenses) {
              const entitlement = skuIdDefs[lic.skuId]
              delete entitlement.licenseInfo
              if (lic.skuId && skuIdDefs[lic.skuId]) response.body.value[i][entitlementsAttr].push(skuIdDefs[lic.skuId])
            }
          }
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
  if (userObj.manager) {
    addonObj.manager = userObj.manager
    delete userObj.manager
  }
  if (userObj.proxyAddresses) {
    addonObj.proxyAddresses = userObj.proxyAddresses
    delete userObj.proxyAddresses
  }
  if (userObj.entitlements) {
    delete userObj.entitlements // entitlements (licenses) not supported for create/modify - use groups for license management
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

  if (attrObj.entitlements) delete attrObj.entitlements // entitlements (licenses) not supported for create/modify - use groups for license management
  const [parsedAttrObj] = scimgateway.endpointMapper('outbound', attrObj, config.map.user) // SCIM/CustomSCIM => endpoint attribute standard
  if (parsedAttrObj instanceof Error) throw (parsedAttrObj) // error object

  const objManager: Record<string, any> = {}
  if (Object.hasOwn(parsedAttrObj, 'manager')) {
    objManager.manager = parsedAttrObj.manager
    if (objManager.manager === '') objManager.manager = null
    delete parsedAttrObj.manager
  }

  const profile = () => { // patch
    return new Promise((resolve, reject) => {
      (async () => {
        if (JSON.stringify(parsedAttrObj) === '{}') return resolve(null)
        let res: any
        for (const key in parsedAttrObj) { // if object, the modified Entra ID object must contain all elements, if not they will be cleared e.g. employeeOrgData
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
        if (!Object.hasOwn(objManager, 'manager')) return resolve(null)
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

  if (!Object.hasOwn(getObj, 'count')) getObj.count = 100
  if (getObj.count > 100) getObj.count = 100 // Entra ID max 100 (historically max was 999)

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
    else path = `/groups?$top=${getObj.count}&$count=true&$select=${attrs.join()}`
  }
  // mandatory if-else logic - end

  if (!path) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  if (path.includes('$count=true')) { // $count=true requires ConsistencyLevel
    if (!options.headers) options.headers = {}
    options.headers.ConsistencyLevel = 'eventual'
  }

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
        members = response.body.value[i].members.reduce((acc: any[], el: Record<string, any>) => {
          const odataType = el['@odata.type']
          let type: string | undefined

          if (odataType?.endsWith('.user')) type = 'User'
          else if (odataType?.endsWith('.group')) type = 'Group'
          /*
          else if (odataType?.endsWith('.servicePrincipal')) type = 'ServicePrincipal'
          else if (odataType?.endsWith('.application')) type = 'Application'
          else if (odataType?.endsWith('.device')) type = 'Device'
          */

          if (type) { // only include valid type (User/Group)
            acc.push({
              value: el.id,
              display: el.displayName,
              type: type,
            })
          }
          return acc
        }, [])
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

  if (!attrObj.members && !attrObj.description) {
    throw new Error(`${action} error: only supports modification of members and description`)
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
// getEntitlements
// =================================================
scimgateway.getEntitlements = async (baseEntity, getObj, attributes, ctx) => {
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
  const action = 'getEntitlements'
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes} passThrough=${ctx ? 'true' : 'false'}`)

  const ret: any = {
    Resources: [],
    totalResults: null,
  }

  const method = 'GET'
  const body = null
  let path
  let searchAttr

  if (!Object.hasOwn(getObj, 'count')) getObj.count = 100
  if (getObj.count > 100) getObj.count = 100

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.attribute === 'value') {
      path = '/subscribedSkus'
      searchAttr = 'value' // skuId
    } else if (getObj.attribute === 'type') {
      path = '/subscribedSkus'
      searchAttr = 'type' // skuPartNumber
    } else if (getObj.attribute === 'display') {
      path = '/subscribedSkus'
      searchAttr = 'display'
    } else {
      // optional - simpel filtering
      throw new Error(`${action} error: simpel filtering only supports: 'value', 'type' and 'display' - not supporting: ${getObj.rawFilter}`)
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: advanced filtering not supported: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering
    path = `/subscribedSkus`
  }

  if (!path) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)
  path += '?$select=skuId,skuPartNumber,consumedUnits,prepaidUnits'

  try {
    let response
    response = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (!response.body.value) {
      throw new Error('got empty response on REST request')
    }
    for (let i = 0; i < response.body.value.length; i++) {
      const skuPartNumber = response.body.value[i].skuPartNumber
      const displayName = licenseMapping[skuPartNumber] ? licenseMapping[skuPartNumber].displayName : skuPartNumber
      const used = response.body.value[i].consumedUnits
      const available = response.body.value[i].prepaidUnits?.enabled

      const licenseInfo: Record<string, any> = {}
      licenseInfo.usage = { used, available }
      if (licenseMapping[skuPartNumber]) {
        licenseInfo.licenseCategory = licenseMapping[skuPartNumber].licenseCategory
        licenseInfo.isBillable = licenseMapping[skuPartNumber].isBillable
        licenseInfo.priceUSD = licenseMapping[skuPartNumber].priceUSD
        licenseInfo.includes = licenseMapping[skuPartNumber].includes
      }
      ret.Resources.push({
        type: skuPartNumber, value: response.body.value[i].skuId, display: displayName, licenseInfo })
    }

    if (searchAttr && ret.Resources.length > 0) {
      ret.Resources = ret.Resources.filter((el: any) => {
        switch (getObj.operator) {
          case 'eq': return el[searchAttr]?.toLowerCase() === getObj.value?.toLowerCase()
          case 'co': return el[searchAttr]?.toLowerCase().includes(getObj.value?.toLowerCase())
          case 'sw': return el[searchAttr]?.toLowerCase().startsWith(getObj.value?.toLowerCase())
          default: return false
        }
      })
    }

    ret.totalResults = response.body.value.length // '/subscribedSkus' does not support paging
    return ret
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
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
  co: (a, v) => { // Entra ID supports "contains" only for a limted set of indexed attributes
    if (['displayName', 'userPrincipalName', 'mail', 'proxyAddresses'].includes(a)) {
      return `$search="${a}:${v}"`
    }
    return ''
  },
  sw: (a, v) => `startswith(${a}, '${v}')`,
  // ew: (a, v) => `endswith(${a}, '${v}')`, // not supported by Entra ID
  pr: a => `${a} ne null`,
  gt: (a, v) => `${a} gt ${v}`,
  ge: (a, v) => `${a} ge ${v}`,
  lt: (a, v) => `${a} lt ${v}`,
  le: (a, v) => `${a} le ${v}`,
}

//
// getSkuIdDefs returns Entitlements array as object having entitlement.value as key {<skuId-1>: <entitlement-1>, <skuId-2>: <entitlement-2>}
// Keep an updated entitlementsByValues in memory
// We can then use users/assignedLicenses instead of costly users/licenseDetails
//
const getSkuIdDefs = async (baseEntity: string, getObj: Record<string, any>, attributes: string[], ctx?: undefined | Record<string, any>): Promise<Record<string, any>> => {
  if (!entitlementsByValues.validTo || Date.now() > entitlementsByValues.validTo) {
    await lock.acquire()
    const entitlements = await scimgateway.getEntitlements(baseEntity, getObj, attributes, ctx)
    Object.keys(entitlementsByValues).forEach(key => delete entitlementsByValues[key])
    for (const resource of entitlements.Resources) {
      delete resource.usage
      if (resource.value) entitlementsByValues[resource.value] = resource
    }
    entitlementsByValues.validTo = Date.now() + 24 * 60 * 60 * 1000 // 24 hours
    lock.release()
  }
  return entitlementsByValues
}

//
// searchSkuIdDefs returns array of skuIds matching getObj filter
//
const searchSkuIdDefs = (skuIdDefs: Record<string, any>, getObj: Record<string, any>): string[] => {
  if (typeof skuIdDefs !== 'object' || !getObj?.attribute || !getObj?.operator || !getObj?.value) return []
  const arr = getObj.attribute.split('.')
  if (arr.length !== 2 || arr[0] !== 'entitlements') return []
  const attribute = arr[1]
  const skuIds: string[] = []
  const getObjValue = decodeURIComponent(getObj.value)

  for (const key in skuIdDefs) {
    if (typeof skuIdDefs[key] !== 'object') continue
    switch (getObj.operator) {
      case 'eq':
        if (attribute === 'value' && skuIdDefs[key]?.value === getObjValue) skuIds.push(key)
        else if (attribute === 'type' && skuIdDefs[key]?.type === getObjValue) skuIds.push(key)
        else if (attribute === 'display' && skuIdDefs[key]?.display === getObjValue) skuIds.push(key)
        break
      case 'co':
        if (attribute === 'value' && skuIdDefs[key]?.value?.toLowerCase().includes(getObjValue?.toLowerCase())) skuIds.push(key)
        else if (attribute === 'type' && skuIdDefs[key]?.type?.toLowerCase().includes(getObjValue?.toLowerCase())) skuIds.push(key)
        else if (attribute === 'display' && skuIdDefs[key]?.display?.toLowerCase().includes(getObj.value?.toLowerCase())) skuIds.push(key)
        break
      case 'sw':
        if (attribute === 'value' && skuIdDefs[key]?.value?.toLowerCase().startsWith(getObjValue.toLowerCase())) skuIds.push(key)
        else if (attribute === 'type' && skuIdDefs[key]?.type?.toLowerCase().startsWith(getObjValue?.toLowerCase())) skuIds.push(key)
        else if (attribute === 'display' && skuIdDefs[key]?.display?.toLowerCase().startsWith(getObjValue?.toLowerCase())) skuIds.push(key)
        break
      default: break
    }
  }
  return skuIds
}

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})
