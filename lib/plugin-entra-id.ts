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

import querystring from 'querystring'
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
const config = scimgateway.getConfig()
scimgateway.authPassThroughAllowed = false
// end - mandatory plugin initialization

const helper = new HelperRest(scimgateway)

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
for (const key in config.map.user) { // userAttributes = ['country', 'preferredLanguage', 'mail', 'city', 'displayName', 'postalCode', 'jobTitle', 'businessPhones', 'onPremisesSyncEnabled', 'officeLocation', 'name.givenName', 'passwordPolicies', 'id', 'state', 'department', 'mailNickname', 'manager.managerId', 'active', 'userName', 'name.familyName', 'proxyAddresses.value', 'servicePlan.value', 'mobilePhone', 'streetAddress', 'onPremisesImmutableId', 'userType', 'usageLocation']
  if (config.map.user[key].mapTo) userAttributes.push(config.map.user[key].mapTo)
}

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
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes}`)

  const ret: any = {
    Resources: [],
    totalResults: null,
  }

  const method = 'GET'
  const body = null
  let path

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
      throw new Error(`${action} error: not supporting simpel filtering: ${getObj.rawFilter}`)
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all users to be returned - correspond to exploreUsers() in versions < 4.x.x
    if (getObj.startIndex && getObj.startIndex > 1) { // paging
      path = helper.nextLinkPaging(baseEntity, 'users', getObj.startIndex)
      if (!path) return ret
    } else {
      getObj.count = (!getObj.count || getObj.count > 999) ? 999 : getObj.count
      path = `/users?$top=${getObj.count}` // paging not supported using filter (Entra ID default page=100, max=999)
    }
  }
  // mandatory if-else logic - end

  if (!path) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  try {
    let response: any
    if (path === 'getUser') { // special
      response = { body: { value: [] } }
      const userObj: any = await getUser(baseEntity, getObj.value, attributes, ctx)
      if (userObj) response.body.value.push(userObj)
    } else response = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (!response.body.value) {
      throw new Error(`invalid response: ${JSON.stringify(response)}`)
    }
    for (let i = 0; i < response.body.value.length; ++i) { // map to corresponding inbound
      const [scimObj] = scimgateway.endpointMapper('inbound', response.body.value[i], config.map.user) // endpoint => SCIM/CustomSCIM attribute standard
      if (scimObj && typeof scimObj === 'object' && Object.keys(scimObj).length > 0) ret.Resources.push(scimObj)
    }
    if (getObj.count === response.body.value.length) ret.totalResults = 99999999 // to ensure we get a new paging request - don't know the total numbers of users - metadata directoryObject collections are not countable
    else ret.totalResults = getObj.startIndex ? getObj.startIndex - 1 + response.body.value.length : response.body.value.length
    return (ret)
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj, ctx) => {
  const action = 'createUser'
  scimgateway.logDebug(baseEntity, `handling ${action} userObj=${JSON.stringify(userObj)}`)

  const addonObj: Record<string, any> = {}
  if (userObj.servicePlan) {
    addonObj.servicePlan = userObj.servicePlan
    delete userObj.servicePlan
  }
  if (userObj.manager) {
    addonObj.manager = userObj.manager
    delete userObj.manager
  }

  const method = 'POST'
  const path = '/users'
  const [body] = scimgateway.endpointMapper('outbound', userObj, config.map.user)

  try {
    await helper.doRequest(baseEntity, method, path, body, ctx)
    if (Object.keys(addonObj).length > 0) {
      await scimgateway.modifyUser(baseEntity, userObj.userName, addonObj, ctx) // manager, servicePlan
      return null
    } else return (null)
  } catch (err: any) {
    const newErr = new Error(`${action} error: ${err.message}`)
    if (err.message.includes('userPrincipalName already exists')) newErr.name += '#409' // customErrCode
    throw newErr
  }
}

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id, ctx) => {
  const action = 'deleteUser'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id}`)
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
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} attrObj=${JSON.stringify(attrObj)}`)

  if (attrObj.servicePlan) delete attrObj.servicePlan // use license management through groups
  const [parsedAttrObj] = scimgateway.endpointMapper('outbound', attrObj, config.map.user) // SCIM/CustomSCIM => endpoint attribute standard
  if (parsedAttrObj instanceof Error) throw (parsedAttrObj) // error object

  const objManager: Record<string, any> = {}
  if (Object.prototype.hasOwnProperty.call(parsedAttrObj, 'manager')) {
    objManager.manager = parsedAttrObj.manager
    delete parsedAttrObj.manager
  }

  const profile = () => { // patch
    return new Promise((resolve, reject) => {
      (async () => {
        if (JSON.stringify(parsedAttrObj) === '{}') return resolve(null)
        for (const key in parsedAttrObj) { // if object the modified AAD object must contain all elements, if not they will be cleared e.g. employeeOrgData
          if (typeof parsedAttrObj[key] === 'object') { // get original object and merge
            const method = 'GET'
            const path = `/users/${id}?$select=${key}`
            try {
              const res = await helper.doRequest(baseEntity, method, path, null, ctx)
              if (res && res.body && res.body[key]) {
                const fullKeyObj = Object.assign(res.body[key], parsedAttrObj[key]) // merge original with modified
                if (fullKeyObj && Object.keys(fullKeyObj).length > 0) {
                  parsedAttrObj[key] = fullKeyObj
                }
              }
            } catch (err) {
              return reject(err)
            }
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
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes}`)

  const ret: any = {
    Resources: [],
    totalResults: null,
  }

  if (attributes.length < 1) attributes = ['id', 'displayName', 'members.value']
  if (!attributes.includes('id')) attributes.push('id')

  let includeMembers = false
  if (attributes.includes('members.value') || attributes.includes('members')) {
    includeMembers = true
  }

  const [attrs] = scimgateway.endpointMapper('outbound', attributes, config.map.group)
  const method = 'GET'
  const body = null
  let path

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
    } else if (getObj.operator === 'eq' && getObj.attribute === 'members.value') {
      // mandatory - return all groups the user 'id' (getObj.value) is member of - correspond to getGroupMembers() in versions < 4.x.x
      // Resources = [{ id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }]
      // not using below expand because Entra ID returns only a maximum of 20 items for the expanded relationship
      // path = `/users/${getObj.value}/memberOf/microsoft.graph.group?$select=id,displayName&$expand=members($select=id,displayName)`
      path = `/users/${getObj.value}/memberOf/microsoft.graph.group?$select=id,displayName`
    } else {
      // optional - simpel filtering
      throw new Error(`${action} error: not supporting simpel filtering: ${getObj.rawFilter}`)
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all groups to be returned - correspond to exploreGroups() in versions < 4.x.x
    // Entra paging not supported because of select filter (Entra default page=100, max=999)
    // TODO: use a query that supports paging to fix current 999 limit of groups
    getObj.count = 999
    if (includeMembers) path = `/groups?$top=${getObj.count}&$select=${attrs.join()}&$expand=members($select=id,displayName)`
    else path = `/groups?$top=${getObj.count}&$select=${attrs.join()}`
  }
  // mandatory if-else logic - end

  if (!path) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  try {
    let response = await helper.doRequest(baseEntity, method, path, body, ctx)
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
        }]
      }

      const [scimObj] = scimgateway.endpointMapper('inbound', response.body.value[i], config.map.group) // endpoint => SCIM/CustomSCIM attribute standard
      if (scimObj && typeof scimObj === 'object' && Object.keys(scimObj).length > 0) {
        if (members) scimObj.members = members
        ret.Resources.push(scimObj)
      }
    }

    // Entra paging not supported because of select filter
    getObj.startIndex = 1
    ret.totalResults = getObj.startIndex ? getObj.startIndex - 1 + response.body.value.length : response.body.value.length

    return (ret)
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj, ctx) => {
  const action = 'createGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} groupObj=${JSON.stringify(groupObj)}`)
  const body: any = { displayName: groupObj.displayName }
  body.mailNickName = groupObj.displayName
  body.mailEnabled = false
  body.securityEnabled = true
  const method = 'POST'
  const path = '/Groups'

  try {
    const res = await scimgateway.getGroups(baseEntity, { attribute: 'displayName', operator: 'eq', value: groupObj.displayName }, ['id', 'displayName'], ctx)
    if (res && res.Resources && res.Resources.length > 0) {
      throw new Error(`group ${groupObj.displayName} already exist`)
    }
    await helper.doRequest(baseEntity, method, path, body, ctx)
    return null
  } catch (err: any) {
    const newErr = new Error(`${action} error: ${err.message}`)
    if (err.message.includes('already exist')) newErr.name += '#409' // customErrCode
    throw newErr
  }
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id) => {
  const action = 'deleteGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id}`)
  throw new Error(`${action} error: ${action} is not supported`)
}

// =================================================
// modifyGroup
// =================================================
scimgateway.modifyGroup = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyGroup'
  scimgateway.logDebug(baseEntity, `handling ${action} id=${id} attrObj=${JSON.stringify(attrObj)}`)

  if (!attrObj.members) {
    throw new Error(`${action} error: only supports modification of members`)
  }
  if (!Array.isArray(attrObj.members)) {
    throw new Error(`${action} error: ${JSON.stringify(attrObj)} - correct syntax is { "members": [...] }`)
  }

  const arrGrpAdd: Record<string, any>[] = []
  const arrGrpDel: Record<string, any>[] = []
  attrObj.members.forEach(function (el) {
    if (el.operation && el.operation === 'delete') { // delete member from group e.g {"members":[{"operation":"delete","value":"bjensen"}]}
      arrGrpDel.push(el.value)
    } else if (el.value) { // add member to group {"members":[{value":"bjensen"}]}
      arrGrpAdd.push(el.value)
    }
  })

  const addGrps = () => { // add groups
    return new Promise((resolve, reject) => {
      (async () => {
        if (arrGrpAdd.length < 1) return resolve(null)
        const method = 'POST'
        const path = `/groups/${id}/members/$ref`
        const graphUrl = helper.getGraphUrl()
        for (let i = 0, len = arrGrpAdd.length; i < len; i++) {
          const body = { '@odata.id': `${graphUrl}/directoryObjects/${arrGrpAdd[i]}` }
          try {
            await helper.doRequest(baseEntity, method, path, body, ctx)
            if (i === len - 1) resolve(null) // loop completed
          } catch (err) {
            return reject(err)
          }
        }
      })()
    })
  }

  const removeGrps = () => { // remove groups
    return new Promise((resolve, reject) => {
      (async () => {
        if (arrGrpDel.length < 1) return resolve(null)
        const method = 'DELETE'
        const body = null
        for (let i = 0, len = arrGrpDel.length; i < len; i++) {
          const path = `/groups/${id}/members/${arrGrpDel[i]}/$ref`
          try {
            await helper.doRequest(baseEntity, method, path, body, ctx)
            if (i === len - 1) resolve(null) // loop completed
          } catch (err) {
            return reject(err)
          }
        }
      })()
    })
  }

  return Promise.all([addGrps(), removeGrps()])
    .then((res) => { return res })
    .catch((err) => { throw new Error(`${action} error: ${err.message}`) })
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
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes}`)

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
const getUser = async (baseEntity: string, uid: string, attributes: string[], ctx?: undefined | Record<string, any>) => { // uid = id, userName (upn) or externalId (upn)
  if (attributes.length < 1) {
    attributes = userAttributes
  }

  const user = () => {
    return new Promise((resolve, reject) => {
      (async () => {
        const method = 'GET'
        const path = `/users/${querystring.escape(uid)}?$expand=manager($select=userPrincipalName)` // beta returns all attributes or use: ?$select=${attrs.join()}
        const body = null
        try {
          const response = await helper.doRequest(baseEntity, method, path, body, ctx)
          const userObj = response.body
          if (!userObj) {
            const err = new Error('Got empty response when retrieving data for ' + uid)
            return reject(err)
          }
          let managerId
          if (userObj.manager && userObj.manager.userPrincipalName) managerId = userObj.manager.userPrincipalName
          delete userObj.manager
          if (managerId) userObj.manager = managerId
          resolve(userObj)
        } catch (err) {
          return reject(err)
        }
      })()
    })
  }

  const license = () => {
    return new Promise((resolve, reject) => {
      (async () => {
        if (!attributes.includes('servicePlan.value')) return resolve(null) // licenses not requested
        const method = 'GET'
        const path = `/users/${querystring.escape(uid)}/licenseDetails`
        const body = null
        const retObj: Record<string, any> = {}
        retObj.servicePlan = []
        try {
          const response = await helper.doRequest(baseEntity, method, path, body, ctx)
          if (!response.body.value) {
            const err = new Error('No content for license information ' + uid)
            return reject(err)
          } else {
            if (response.body.value.length < 1) return resolve(null) // User with no licenses
            for (let i = 0; i < response.body.value.length; i++) {
              const skuPartNumber = response.body.value[i].skuPartNumber
              for (let index = 0; index < response.body.value[i].servicePlans.length; index++) {
                if (response.body.value[i].servicePlans[index].provisioningStatus === 'Success'
                  || response.body.value[i].servicePlans[index].provisioningStatus === 'PendingInput') {
                  const servicePlan = { value: `${skuPartNumber}::${response.body.value[i].servicePlans[index].servicePlanName}` }
                  retObj.servicePlan.push(servicePlan)
                }
              }
            }
          }
          resolve(retObj)
        } catch (err: any) {
          let statusCode
          try { statusCode = JSON.parse(err.message).statusCode } catch (e) {}
          if (statusCode === 404) return resolve(null) // user have no plans
          return reject(err)
        }
      })()
    })
  }

  return Promise.all([user(), license()])
    .then((results) => {
      let retObj = {}
      for (const i in results) { // merge async.parallell results to one
        retObj = Object.assign(retObj, results[i])
      }
      return retObj
    })
    .catch((err) => {
      if (err.message.includes('empty response')) return null // no user found
      else throw (err)
    })
}

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})
