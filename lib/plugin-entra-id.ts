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
//        'GET /Roles' retrieves a list of all available roles specified by type (e.g. Permanent or Eligible) and corresponds with the users attribute roles.
//        'GET /Entitlements' retrieves a list of all available entitlements specified by type (e.g. License) and corresponds with the users attribute entitlements.
//
//        Using "Custom SCIM" attributes defined in configuration endpoint.entity.map
//        Schema generated according mapping configuration.
//        Note:
//          - 'map.user.signInActivity' requires Entra ID Premium license and API permissions 'AuditLog.Read.All'. Remove 'signInActivity' mapping if conditions not met".
//          - 'map.user.roles relates to both Permanent roles and PIM Eligible roles.
//            PIM is included on tenant having P2 or Governance License and requires following API permissions:
//            - PIM Eligible roles requires API permissions 'RoleEligiblitySchedule.ReadWrite.All'
//            - PIM Permanent roles requires API permissions 'RoleManagement.ReadWrite.Directory'
//            - Remove 'roles' mapping if conditions not met
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
// Roles                                      roles                               roles (roleAssignments/roleEligibilitySchedules) - type=Permanent/Eligiable, value=id, display=role display name
// Entitlements                               entitlements                        entitlements (assignedLicenses) - type=License, value=skuId and display=user-friendly-license-name / type=AccessPackage, value=AP-id and display=AP-displayName
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
scimgateway.pluginAndOrFilter = true
// end - mandatory plugin initialization

const newHelper = new HelperRest(scimgateway)
const entitlementsByValues: Record<string, any> = {} // {skuId: {...}}
const rolesByValues: Record<string, any> = {} // {skuId: {...}}
const rolesAssignments: Record<string, any> = {}
const lockEntitlement = new scimgateway.Lock()
const lockRole = new scimgateway.Lock()
const permission: Record<string, any> = {}

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

for (const key in config.map.user) { // mapAttributesTo = ['id', 'country', 'preferredLanguage', 'mail', 'city', 'displayName', 'postalCode', 'jobTitle', 'businessPhone', 'onPremisesSyncEnabled', 'officeLocation', 'name.givenName', 'passwordPolicies', 'id', 'state', 'department', 'mailNickname', 'manager.managerId', 'active', 'userName', 'name.familyName', 'proxyAddresses.value', 'servicePlan.value', 'mobilePhone', 'streetAddress', 'onPremisesImmutableId', 'userType', 'usageLocation']
  if (config.map.user[key].mapTo) {
    mapAttributes.push(key)
    mapAttributesTo.push(config.map.user[key].mapTo)
    let attr = key.split('.')[0]
    // complexArray/complexObject are special
    if (config.map.user[key].mapTo === 'entitlements') attr = 'assignedLicenses'
    if (config.map.user[key].mapTo === 'roles') continue

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

// check if signinActivity and PIM eligible roles can be used and update permission accordingly
// signInActivity requires Entra ID Premium license and API permissions: 'AuditLog.Read.All'.
// PIM eligible roles requires either Entra ID P2 or Governance License and API permissions: 'RoleEligiblitySchedule.ReadWrite.All'
;(async () => {
  for (const baseEntity in config.entity) {
    try {
      permission[baseEntity] = {}
      const [signInResult, eligibleResult, accessPackageResult] = await Promise.allSettled([
        (async () => {
          if (!mapAttributesTo.includes('signInActivity')) throw new Error('skipping signInActivity check')
          await helper.doRequest(baseEntity, 'GET', '/users?$top=1&$select=id,signInActivity', null, null)
        })(),
        (async () => {
          if (!mapAttributesTo.includes('roles')) throw new Error('skipping eligible check')
          await helper.doRequest(baseEntity, 'GET', '/roleManagement/directory/roleEligibilityScheduleInstances?$top=1', null, null)
        })(),
        (async () => {
          if (!mapAttributesTo.includes('entitlements')) throw new Error('skipping access package check')
          await helper.doRequest(baseEntity, 'GET', '/identityGovernance/entitlementManagement/accessPackages?$top=1&$select=id', null, null)
        })(),
      ])
      if (signInResult.status === 'fulfilled') {
        permission[baseEntity].signInActivity = true
      } else {
        permission[baseEntity].signInActivity = false
        if (mapAttributesTo.includes('signInActivity')) scimgateway.logError(baseEntity, `signInActivity functionality has been deactivatede because it requires Entra ID Premium license, as well as the API permissions 'AuditLog.Read.All'`)
      }
      if (eligibleResult.status === 'fulfilled') {
        permission[baseEntity].eligible = true
      } else {
        permission[baseEntity].eligible = false
        if (mapAttributesTo.includes('roles')) scimgateway.logError(baseEntity, `PIM eligible role functionality has been deactivated because it requires either a P2 or Governance license, as well as the API permission 'RoleEligibilitySchedule.ReadWrite.All'`)
      }
      if (accessPackageResult.status === 'fulfilled') {
        permission[baseEntity].accessPackage = true
      } else {
        permission[baseEntity].accessPackage = false
        if (mapAttributesTo.includes('roles')) scimgateway.logError(baseEntity, `IGA Access Packages functionality has been deactivated because it requires API permission 'EntitlementManagement.Read.All'`)
      }
    } catch (err) {}
  }
})()

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
  let response: any
  let selectAttributes: string[] = []

  if (attributes.length > 0) {
    for (const attribute of attributes) {
      const [endpointAttr] = scimgateway.endpointMapper('outbound', attribute, config.map.user)
      let attr = endpointAttr.split('.')[0]
      if (!attr) continue
      // complexArray/complexObject are special
      if (attribute.startsWith('entitlements')) attr = 'assignedLicenses'
      if (attribute.startsWith('roles')) continue
      if (!selectAttributes.includes(attr)) selectAttributes.push(attr)
    }
  } else selectAttributes = userSelectAttributes

  if (!permission[baseEntity]?.signInActivity) { // remove signInActivity
    const index = selectAttributes.indexOf('signInActivity')
    if (index > -1) {
      selectAttributes.splice(index, 1)
    }
  }

  const method = 'GET'
  const body = null
  let path: string = ''
  let options: Record<string, any> = {}
  let isExpandManager = true

  if (Object.hasOwn(getObj, 'value')) getObj.value = encodeURIComponent(getObj.value)
  if (!Object.hasOwn(getObj, 'count')) getObj.count = 100
  if (getObj.count > 100) getObj.count = 100 // Entra ID max 100 (historically max was 999)

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id'].includes(getObj.attribute)) { // userName/externalId using simpel filtering because direct lookup by upn do not allow select attribute signInActivity
      // mandatory - unique filtering - single unique user to be returned - correspond to getUser() in versions < 4.x.x
      path = `/users/${getObj.value}?$select=${selectAttributes.join(',')}`
    } else if (getObj.operator === 'eq' && getObj.attribute === 'group.value') {
      // optional - only used when groups are member of users, not default behavior - correspond to getGroupUsers() in versions < 4.x.x
      throw new Error(`${action} error: not supporting groups member of user filtering: ${getObj.rawFilter}`)
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

        let odataFilter: string | undefined = operatorMap[getObj.operator](endpointAttr, getObj.value)

        // role and entitlements filtering
        const arr = getObj.attribute.split('.')
        if (['roles', 'entitlements'].includes(arr[0])) {
          odataFilter = undefined

          let type
          let obj // set to the filter object based on the "type-object" and the use of and-object
          if (getObj.attribute === `${arr[0]}.type`) {
            type = getObj.value
            if (getObj.and) obj = getObj.and
            else obj = getObj
          } else if (getObj.and?.attribute === `${arr[0]}.type`) {
            type = getObj.and.value
            obj = getObj
          } else obj = getObj // no type defined

          if (config.map.user[arr[0]] && ['complexArray', 'complexObject'].includes(config.map.user[arr[0]]?.type)) {
            if (arr[0] === 'roles') {
              if (type && type !== 'Permanent' && type !== 'Eligible') throw new Error(`${action} filter error: when using roles.type, the type must be either 'Permanent' or 'Eligible`)
              const o = await getUsersByRole(baseEntity, obj, (type) ? decodeURIComponent(type) as 'Permanent' | 'Eligible' : undefined, ctx)

              if (!Array.isArray(o) || o.length === 0) return ret
              const fnArr: { fn: () => Promise<any> }[] = []
              for (const id of o) {
                const userPath = `/users/${id}?$select=${selectAttributes.join(',')}`
                const fn = () => helper.doRequest(baseEntity, 'GET', userPath, null, ctx?.headers ? { headers: ctx?.headers } : undefined)
                fnArr.push({ fn })
              }
              response = { body: { value: [] } }
              await fnCunckExecute(fnArr, response.body.value) // fnCunckExecute results in response.body.value and evaluated later
              if (response.body.value.length === 0) return ret
            } else if (arr[0] === 'entitlements') { // using entitlements for licenses and access packages
              if (getObj.attribute !== 'entitlements.type' && getObj.and?.attribute !== 'entitlements.type') throw new Error(`${action} filter error: mandatory entitlements.type is missing, examples: entitlements[type eq "xxx"], entitlements[type eq "xxx" and value eq "xxx"], entitlements[type eq "xxx" and display <eq/co/sw> "xxx"]`)
              if (type === 'License') {
                if (obj.operator === 'eq' && obj.attribute === 'entitlements.type') { // entitlements[type eq "License"]
                  path = `/users?$top=${getObj.count}&$count=true&$filter=assignedLicenses/$count ne 0&$select=${selectAttributes.join(',')}`
                  isExpandManager = false
                } else { // entitlements[type eq "License" and value eq "xxx"], entitlements[type eq "License" and display <eq/co/sw> "xxx"]
                  const skuIdDefs = await getSkuIdDefs(baseEntity, {}, [], ctx)
                  const skuIdArr = searchSkuIdDefs(skuIdDefs, obj)
                  if (skuIdArr.length === 0) return ret
                  if (skuIdArr.length === 1) odataFilter = `assignedLicenses/any(x:x/skuId eq ${skuIdArr[0]})`
                  else throw new Error(`${action} filter error: not supporting ${getObj.rawFilter} - entitlements filter resulted in more than one skuId which is not supported. For guaranteed uniqueness use: filter=entitlements[type eq "License" and value eq "<skuId>"]`)
                }
              } else if (type === 'AccessPackage') {
                let o: Record<string, any> | undefined
                if (obj.operator === 'eq' && obj.attribute === 'entitlements.type') { // entitlements[type eq "AccessPackage"]
                  o = await getUsersByAccessPackage(baseEntity, obj, ctx?.headers ? { headers: ctx?.headers } : undefined)
                } else { // entitlements[type eq "AccessPackage" and value eq "xxx"], entitlements[type eq "AccessPackage" and display <eq/co/sw> "xxx"]
                  if (obj.operator !== 'eq') throw new Error(`${action} error: for entitlements.type="AccessPackage" only operator 'eq' is supported for the entitlements.value`)
                  o = await getUsersByAccessPackage(baseEntity, obj, ctx?.headers ? { headers: ctx?.headers } : undefined)
                }
                if (typeof o !== 'object' || o === null || Object.keys(o).length === 0) return ret
                const isAttrsOk = attributes.length > 0 && attributes.length < 3 && (attributes.includes('id') || attributes.includes('displayName'))
                const fnArr: { fn: () => Promise<any> }[] = []
                for (const key in o) {
                  if (isAttrsOk) ret.Resources.push(o[key])
                  else {
                    const userPath = `/users/${key}?$select=${selectAttributes.join(',')}`
                    const fn = () => helper.doRequest(baseEntity, 'GET', userPath, null, ctx?.headers ? { headers: ctx?.headers } : undefined)
                    fnArr.push({ fn })
                  }
                }
                if (isAttrsOk) return ret
                else {
                  response = { body: { value: [] } }
                  await fnCunckExecute(fnArr, response.body.value) // fnCunckExecute results in response.body.value and evaluated later
                  if (response.body.value.length === 0) return ret
                }
              } else throw new Error(`${action} error: entitlements.type must be either "License" or "AccessPackage"`)
            } else throw new Error(`${action} error: not supporting filtering: ${getObj.rawFilter}`)
            if (getObj.and) delete getObj.and // delete to flag done and final check will succeed
          } else throw new Error(`${action} error: not supporting filtering: ${getObj.rawFilter}`)
        }

        if (odataFilter !== undefined) {
          if (odataFilter === '') {
            const [supported] = scimgateway.endpointMapper('inbound', 'displayName,userPrincipalName,mail,proxyAddresses', config.map.user)
            throw new Error(`${action} error: Entra ID only supports operator '${getObj.operator}' for a limited set of attributes (e.g., SCIM attributes: ${supported}) and therefore not supporting filter: ${getObj.rawFilter}`)
          }

          if (odataFilter.startsWith('$search=')) {
            path = `/users?$top=${getObj.count}&$count=true&${odataFilter}&$select=${selectAttributes.join(',')}`
            isExpandManager = false // using $search we cannot include $expand=manager
          } else { // eq, sw, co, etc.
            path = `/users?$top=${getObj.count}&$count=true&$filter=${odataFilter}&$select=${selectAttributes.join(',')}`
          }

          // advanced queries like 'contains', '$search', and '$count' require the ConsistencyLevel header.
          if (!options.headers) options.headers = {}
          options.headers.ConsistencyLevel = 'eventual'
        }
      }

      if (getObj.operator === 'pr' || getObj.operator === 'not pr') isExpandManager = false
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    // note, advanced filtering "light" using and/or (not combined) is handled by scimgateway through plugin simpel filtering above
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all users to be returned - correspond to exploreUsers() in versions < 4.x.x
    path = `/users?$top=${getObj.count}&$count=true&$select=${selectAttributes.join(',')}`
  }

  if (getObj.and || getObj.or) {
    // plugin have enabled 'scimgateway.pluginAndOrFilter' and the query includes an additonal and/or getObj that must to be handled and combined with the initial getObj
    // we could have this logic above, if not it must be defined here
    throw new Error(`${action} error: logic for handling and/or filter is not implemented by plugin, not supporting: ${getObj.rawFilter}`)
  }
  // mandatory if-else logic - end

  if (!path && !response?.body?.value) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  if (path.includes('$count=true')) { // $count=true requires ConsistencyLevel
    // note: when using $expand, the $count=true might be ignored by target endpoint and the ctx.paging.totalResults updated by doReqest() will be incremental
    if (!options.headers) options.headers = {}
    options.headers.ConsistencyLevel = 'eventual'
  }

  // enable doRequest() OData paging support 
  let paging = { startIndex: getObj.startIndex }
  if (!ctx) ctx = { paging }
  else ctx.paging = paging

  try {
    if (isExpandManager && selectAttributes.includes('manager')) {
      path += '&$expand=manager($select=userPrincipalName)'
    }

    if (!response?.body?.value) {
      response = await helper.doRequest(baseEntity, method, path, body, ctx, options)
    }

    if (!response.body?.value) {
      const singleUser = response.body
      response.body = { value: [singleUser] }
    }
    if (!response.body.value) {
      throw new Error(`invalid response: ${JSON.stringify(response)}`)
    }
    const fnArr: { index: number, fn: () => Promise<any> }[] = []
    const skuIdDefs = await getSkuIdDefs(baseEntity, {}, [], ctx)

    // include manager
    if (!isExpandManager && selectAttributes.includes('manager')) {
      for (let i = 0; i < response.body.value.length; ++i) {
        if (!response.body.value[i].id) break
        const singleUserPath = `/users/${response.body.value[i].id}/manager?$select=userPrincipalName`
        const fn = () => helper.doRequest(baseEntity, 'GET', singleUserPath, null, ctx?.headers ? { headers: ctx?.headers } : undefined, options)
        fnArr.push({ index: i, fn })
      }
      await fnCunckExecute(fnArr, response.body.value, 'manager')
    }

    // include groups (before roles)
    if (attributes.length === 0 || attributes.includes('groups')) {
      for (let i = 0; i < response.body.value.length; ++i) {
        if (!response.body.value[i].id) break
        const fn = () => scimgateway.getUserGroups(baseEntity, response.body.value[i].id, ctx?.headers ? { headers: ctx?.headers } : undefined)
        fnArr.push({ index: i, fn })
      }
      await fnCunckExecute(fnArr, response.body.value, 'groups')
    }

    // attribute cleanup and mapping
    for (let i = 0; i < response.body.value.length; ++i) {
      const obj = response.body.value[i]
      if (obj.manager?.userPrincipalName) {
        let managerId = obj.manager.userPrincipalName
        if (managerId) obj.manager = managerId
        else delete obj.manager
      }

      if (obj.signInActivity) {
        delete obj.signInActivity.lastSignInRequestId
        delete obj.signInActivity.lastNonInteractiveSignInRequestId
        delete obj.signInActivity.lastSuccessfulSignInRequestId
      }

      // include roles and entitlements
      if (obj.id) {
        const roles = async (obj: Record<string, any>): Promise<Record<string, any>[]> => {
          // roles type=Permanent/Eligible
          if ((attributes.includes('roles') || attributes.length === 0) && mapAttributesTo.includes('roles')) {
            return await getUserRoles(baseEntity, obj.id, obj.groups, ctx?.headers ? { headers: ctx?.headers } : undefined)
          } else return []
        }
        const entitlements = async (obj: Record<string, any>): Promise<Record<string, any>[]> => {
          const result: Record<string, any>[] = []
          if ((attributes.includes('entitlements') || attributes.length === 0) && mapAttributesTo.includes('entitlements')) {
            // entitlements type=License => assignedLicenses
            if (obj.assignedLicenses && Array.isArray(obj.assignedLicenses)) {
              for (const lic of response.body.value[i].assignedLicenses) {
                if (lic.skuId && skuIdDefs[lic.skuId]) result.push(skuIdDefs[lic.skuId])
              }
            }
            // entitlements type=AccessPackage
            if (permission[baseEntity]?.accessPackage) {
              const method = 'GET'
              const body = null
              const path = `/identityGovernance/entitlementManagement/assignments?$filter=target/objectId eq '${obj.id}'&$expand=accessPackage($select=id,displayName)`
              const r = await helper.doRequest(baseEntity, method, path, body, ctx?.headers ? { headers: ctx?.headers } : undefined)
              if (!r.body?.value) {
                if (r.body?.id) r.body.value = [r.body]
                else throw new Error(`invalid response: ${JSON.stringify(response)}`)
              }
              const now = new Date()
              for (let j = 0; j < r.body.value.length; j++) {
                if (!isAccessPackageScheduleValid(now, r.body.value[j].expiredDateTime, r.body.value[j].schedule)) continue
                const ap: Record<string, any> = r.body.value[j].accessPackage
                if (!ap || !ap.id || !ap.displayName) continue
                result.push({
                  type: 'AccessPackage', value: ap.id, display: ap.displayName,
                })
              }
            }
          }
          return result
        }
        const arrResolve = await Promise.all([
          roles(obj),
          entitlements(obj),
        ])
        obj.roles = arrResolve[0]
        obj.entitlements = arrResolve[1]
      }

      // map to inbound
      const [scimObj] = scimgateway.endpointMapper('inbound', obj, config.map.user) // endpoint => SCIM/CustomSCIM attribute standard
      if (scimObj && typeof scimObj === 'object' && Object.keys(scimObj).length > 0) {
        if (obj.groups && !scimObj.groups) scimObj.groups = obj.groups // not included in mapper
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
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj, ctx) => {
  const action = 'createUser'
  scimgateway.logDebug(baseEntity, `handling ${action} userObj=${JSON.stringify(userObj)} passThrough=${ctx ? 'true' : 'false'}`)

  // roles and entitlements only supported for getUsers - readOnly 
  if (userObj.roles) delete userObj.roles
  if (userObj.entitlements) delete userObj.entitlements

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

  // roles and entitlements only supported for getUsers - readOnly 
  // if (attrObj.roles) delete attrObj.roles
  if (attrObj.entitlements) delete attrObj.entitlements

  const [parsedAttrObj]: Record<string, any>[] = scimgateway.endpointMapper('outbound', attrObj, config.map.user) // SCIM/CustomSCIM => endpoint attribute standard
  if (parsedAttrObj instanceof Error) throw (parsedAttrObj) // error object

  const objManager: Record<string, any> = {}
  if (Object.hasOwn(parsedAttrObj, 'manager')) {
    objManager.manager = parsedAttrObj.manager
    if (objManager.manager === '') objManager.manager = null
    delete parsedAttrObj.manager
  }

  // const fnArr: Array<() => Promise<any>> = []
  const fnArr: { fn: () => Promise<any> }[] = []

  const getValueByDisplayName = async (display: string): Promise<string | undefined> => {
    const res = await scimgateway.getRoles(baseEntity, { attribute: 'displayName', operator: 'eq', value: display }, [], ctx)
    if (Array.isArray(res?.Resources) && res.Resources.length === 1) return res.Resources[0]?.id
    return undefined
  }

  if (Object.hasOwn(parsedAttrObj, 'roles') && Array.isArray(parsedAttrObj.roles)) {
    const r: Record<string, any>[] = []
    for (const el of parsedAttrObj.roles) {
      if (!el.type) { // set default according to tenant type (PIM vs no PIM)
        if (permission[baseEntity].eligible) el.type = 'Eligible'
        else el.type = 'Permanent'
      }
      if (el.type !== 'Permanent' && el.type !== 'Eligible') throw new Error(`${action} error: roles.type must set to 'Permanent' or 'Eligible'`)
      if (el.type === 'Eligible' && !permission[baseEntity]?.eligible) throw new Error(`${action} error: roles.type 'Eligible' is not supported by the endpoint or current configuration. Use 'Permanent' instead.`)
      if (!el.value) {
        if (el.display) el.value = await getValueByDisplayName(el.display)
        if (!el.value) throw new Error(`${action} error: Role modification is missing the 'value' key, or the optional 'display' key is not found or unique.`)
      }

      const res: Record<string, any> = { value: el.value, type: el.type }
      if (el.display) res.display = el.display
      if (el.operation === 'delete') {
        if (el.value === '62e90394-69f5-4237-9190-012177145e10') throw new Error(`${action} error: Removal of the 'Global Administrator' role is not allowed for security reasons.`)
        res.operation = el.operation
      }
      r.push(res)
    }
    delete parsedAttrObj.roles

    const rolesAdd: Record<string, any> [] = r.filter(m => m.operation !== 'delete')
    const rolesRemove: Record<string, any> [] = r.filter(m => m.operation === 'delete')
    let isRolesChanged = false

    if (rolesAdd.length > 0 || rolesRemove.length > 0) {
      const currentRoles = await getUserRoles(baseEntity, id, [], ctx, true)

      for (const r of rolesAdd) {
        const roleExist = currentRoles.filter(m => m.value === r.value && m.type === r.type)
        if (roleExist.length > 0) continue // exlude adding already assigned

        const method = 'POST'
        let path = `/roleManagement/directory/roleAssignments`
        const body: Record<string, any> = {
          principalId: id,
          roleDefinitionId: r.value,
          directoryScopeId: '/',
        }
        if (r.type === 'Eligible') {
          path = '/roleManagement/directory/roleEligibilityScheduleRequests'
          body.action = 'AdminAssign'
          body.justification = 'Assigned by SCIM Gateway'
          body.scheduleInfo = {
            startDateTime: new Date().toISOString(),
            expiration: {
              type: 'noExpiration',
            },
          }
        }

        const fn = () => helper.doRequest(baseEntity, method, path, body, ctx)
        fnArr.push({ fn })
        isRolesChanged = true
      }

      for (const r of rolesRemove) {
        const arrRemove: Record<string, any> [] = []
        const removeAssignments = currentRoles.filter(m => m.value === r.value && m.type === r.type && m.assignmentId).map((m) => { return { assignmentId: m.assignmentId, value: m.value, type: m.type } })
        arrRemove.push(...removeAssignments)

        for (const rm of arrRemove) {
          let method = 'DELETE'
          let path = `/roleManagement/directory/roleAssignments/${rm.assignmentId}`
          let body = null
          if (rm.type === 'Eligible') {
            method = 'POST'
            path = '/roleManagement/directory/roleEligibilityScheduleRequests'
            body = {
              action: 'AdminRemove',
              principalId: id,
              roleDefinitionId: rm.value,
              directoryScopeId: '/',
              justification: 'Revoked by SCIM Gateway',
            }
          }
          const fn = () => helper.doRequest(baseEntity, method, path, body, ctx)
          fnArr.push({ fn })
          isRolesChanged = true
        }
      }

      try {
        await fnCunckExecute(fnArr)
        if (isRolesChanged) {
          (async () => {
            await new Promise(resolve => setTimeout(resolve, 15000))
            await getRolesAssignments(baseEntity, ctx, true) // make sure internal assignments list become updated
          })()
        }
      } catch (err: any) {
        throw new Error(`${action} roles modify error: ${err.message}`)
      }
    }
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

  if (attributes.length === 0) includeMembers = true
  else {
    for (const attr of attributes) {
      if (attr.startsWith('members')) {
        includeMembers = true
        break
      }
    }
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
      path = `/users/${getObj.value}/transitiveMemberOf/microsoft.graph.group?$top=${getObj.count}&$count=true&$select=id,displayName`
    } else {
      // optional - simpel filtering
      throw new Error(`${action} error: Entra ID only supports group filter operator 'eq' for a limited set of attributes ('id', 'displayName' and 'members.value') and therefore not supporting filter: ${getObj.rawFilter}`)
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
    // note: when using $expand, the $count=true might be ignored by target endpoint and the ctx.paging.totalResults updated by doReqest() will be incremental
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
      const pathMemberOf = `/users/${getObj.value}/memberOf/microsoft.graph.group?$top=${getObj.count}&$count=true&$select=id,displayName`
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
  // getEntitlements() should return all 'type' (categories) of supported entitlements
  // Response format: Resources[{type: <category e.g, License>, value: <unique id>, displayName: <display name>}]
  //
  const action = 'getEntitlements'
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes} passThrough=${ctx ? 'true' : 'false'}`)

  const ret: any = {
    Resources: [],
    totalResults: null,
    startIndex: 1, // no paging support for Entitlements
  }

  let searchAttr

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.attribute === 'value') {
      searchAttr = 'value' // License skuId or AccessPackage id 
    } else if (getObj.attribute === 'type') {
      searchAttr = 'type' // License or AccessPackage
    } else if (getObj.attribute === 'displayName') {
      searchAttr = 'displayName'
    } else {
      // optional - simpel filtering
      searchAttr = getObj.attribute
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: advanced filtering not supported: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering
  }

  // Licenses: entitlement type=License
  const licenses = async (): Promise<Record<string, any>[]> => {
    const result: Record<string, any>[] = []
    const method = 'GET'
    const body = null
    const path = '/subscribedSkus?$select=skuId,skuPartNumber,consumedUnits,prepaidUnits'

    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (!response.body?.value) {
      if (response.body?.skuId) response.body.value = [response.body]
      else throw new Error(`invalid response: ${JSON.stringify(response)}`)
    }
    for (let i = 0; i < response.body.value.length; i++) {
      const skuPartNumber = response.body.value[i].skuPartNumber
      const displayName = licenseMapping[skuPartNumber] ? licenseMapping[skuPartNumber].displayName : skuPartNumber
      const usedSeats = response.body.value[i].consumedUnits
      const warning = response.body.value[i].prepaidUnits?.warning
      const lockedOut = response.body.value[i].prepaidUnits?.lockedOut
      let suspendedSeats = response.body.value[i].prepaidUnits?.suspended
      let totalSeats = response.body.value[i].prepaidUnits?.enabled
      if (!isNaN(lockedOut) && !isNaN(suspendedSeats)) suspendedSeats += lockedOut
      if (!isNaN(warning) && !isNaN(totalSeats)) totalSeats += warning
      if (!isNaN(suspendedSeats) && !isNaN(totalSeats)) totalSeats += suspendedSeats

      const typeInfo: Record<string, any> = {} // typeInfo is included in the Entitlement schema for general purpose
      typeInfo.skuPartNumber = skuPartNumber
      typeInfo.seats = { totalSeats, usedSeats, suspendedSeats }
      if (licenseMapping[skuPartNumber]) {
        typeInfo.licenseCategory = licenseMapping[skuPartNumber].licenseCategory
        typeInfo.isBillable = licenseMapping[skuPartNumber].isBillable
        typeInfo.priceUSD = licenseMapping[skuPartNumber].priceUSD
        typeInfo.derivedIncludes = licenseMapping[skuPartNumber].derivedIncludes
      }
      result.push({
        type: 'License', id: response.body.value[i].skuId, displayName, typeInfo,
      })
    }
    return result
  }

  // Access Packages: entitlement type=AccessPackage
  const accessPackages = async (): Promise<Record<string, any>[]> => {
    const result: Record<string, any>[] = []
    if (!permission[baseEntity]?.accessPackage) return result
    const method = 'GET'
    const body = null
    const path = '/identityGovernance/entitlementManagement/accessPackages?$select=id,displayName'

    const response = await helper.doRequest(baseEntity, method, path, body, ctx)
    if (!response.body?.value) {
      if (response.body?.skuId) response.body.value = [response.body]
      else throw new Error(`invalid response: ${JSON.stringify(response)}`)
    }
    for (let i = 0; i < response.body.value.length; i++) {
      result.push({
        type: 'AccessPackage', id: response.body.value[i].id, displayName: response.body.value[i].displayName,
      })
    }
    return result
  }

  try {
    const arrResolve = await Promise.all([
      licenses(),
      accessPackages(),
    ])
    ret.Resources = [...arrResolve[0], ...arrResolve[1]]
  } catch (err: any) {
    throw new Error(`${action} error: ${err.message}`)
  }

  if (searchAttr && ret.Resources.length > 0) {
    const arrAttr = searchAttr.split('.')
    ret.Resources = ret.Resources.filter((el: any) => {
      let elValue
      if (arrAttr.length === 1) elValue = el[arrAttr[0]]
      else if (arrAttr.length === 2) elValue = el[arrAttr[0]][arrAttr[1]]
      else return false
      switch (getObj.operator) {
        case 'eq': return elValue?.toLowerCase() === getObj.value?.toLowerCase()
        case 'co': return elValue?.toLowerCase().includes(getObj.value?.toLowerCase())
        case 'sw': return elValue?.toLowerCase().startsWith(getObj.value?.toLowerCase())
        default: return false
      }
    })
  }

  ret.totalResults = ret.Resources.length // no paging support for Entitlements
  return ret
}

// =================================================
// getRoles
// =================================================
scimgateway.getRoles = async (baseEntity, getObj, attributes, ctx) => {
  const action = 'getRoles'
  scimgateway.logDebug(baseEntity, `handling ${action} getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes} passThrough=${ctx ? 'true' : 'false'}`)

  const ret: any = {
    Resources: [],
    totalResults: null,
  }

  const method = 'GET'
  const body = null
  let path
  let searchAttr
  let options: Record<string, any> = {}

  // mandatory if-else logic - start
  if (getObj.operator) {
    if (getObj.operator === 'eq' && ['id'].includes(getObj.attribute)) path = `/roleManagement/directory/roleDefinitions/${getObj.value}`
    else if (getObj.operator === 'eq' && getObj.attribute === 'displayName') path = `/roleManagement/directory/roleDefinitions?$filter=displayName eq '${getObj.value}'`
    else {
      path = '/roleManagement/directory/roleDefinitions'
      searchAttr = getObj.attribute
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: advanced filtering not supported: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering
    path = `/roleManagement/directory/roleDefinitions`
  }

  if (!path) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)
  if (path.includes('?')) path += '&'
  else path += '?'
  path += '$select=id,displayName,isBuiltIn'

  try {
    let response = await helper.doRequest(baseEntity, method, path, body, ctx, options)
    if (!response.body?.value) {
      if (response.body?.id) response.body.value = [response.body]
      else throw new Error(`invalid response: ${JSON.stringify(response)}`)
    }

    for (let i = 0; i < response.body.value.length; i++) {
      const id = response.body.value[i].id
      const displayName = response.body.value[i].displayName
      const type = response.body.value[i].isBuiltIn ? 'BuiltIn' : 'Custom'
      ret.Resources.push({
        type, id, displayName,

      })
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

    ret.totalResults = response.body.value.length // '/roleManagement' does not support paging
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
  'eq': (a, v) => `${a} eq ${['true', 'false'].includes(v as string) ? v : `'${v}'`}`,
  'ne': (a, v) => `${a} ne ${['true', 'false'].includes(v as string) ? v : `'${v}'`}`,
  // co: (a, v) => `contains(${a}, '${v}')`, // not supported by Entra ID
  // co: (a, v) => `$search="${a}:${v}"`, // comment out - Entra ID do not support true “contains”
  'co': (a, v) => { // Entra ID supports "contains" only for a limted set of indexed attributes
    if (['displayName', 'userPrincipalName', 'mail', 'proxyAddresses'].includes(a)) {
      return `$search="${a}:${v}"`
    }
    return ''
  },
  'sw': (a, v) => `startswith(${a}, '${v}')`,
  // 'ew': (a, v) => `endswith(${a}, '${v}')`, // not supported by Entra ID
  'pr': a => `${a} ne null`,
  'not pr': a => `${a} eq null`,
  'gt': (a, v) => `${a} gt ${v}`,
  'ge': (a, v) => `${a} ge ${v}`,
  'lt': (a, v) => `${a} lt ${v}`,
  'le': (a, v) => `${a} le ${v}`,
}

//
// getSkuIdDefs returns entitlements keys having the entitlements as values
// {entitlement1.value: [type1, value1, display1], entitlement2.value: [type2, value2, display2], ...}
// entitlement.value = skuId
// Keep an updated entitlementsByValues in memory
// We can then use users/assignedLicenses instead of costly users/licenseDetails
//
const getSkuIdDefs = async (baseEntity: string, getObj: Record<string, any>, attributes: string[], ctx?: undefined | Record<string, any>): Promise<Record<string, any>> => {
  if (!entitlementsByValues[baseEntity]) entitlementsByValues[baseEntity] = {}
  if (!entitlementsByValues[baseEntity].validTo || Date.now() > entitlementsByValues[baseEntity].validTo) {
    await lockEntitlement.acquire()
    if (entitlementsByValues[baseEntity].validTo && Date.now() < entitlementsByValues[baseEntity].validTo) {
      lockEntitlement.release()
      return entitlementsByValues[baseEntity]
    }
    const entitlements = await scimgateway.getEntitlements(baseEntity, getObj, attributes, ctx)
    Object.keys(entitlementsByValues[baseEntity]).forEach(key => delete entitlementsByValues[baseEntity][key])
    for (const r of entitlements.Resources) {
      if (r.type === 'License' && r.id && r.displayName) {
        const entitlement = {
          type: r.type,
          value: r.id, // skUId
          display: r.displayName,
        }
        entitlementsByValues[baseEntity][entitlement.value] = entitlement
      }
    }
    entitlementsByValues[baseEntity].validTo = Date.now() + 24 * 60 * 60 * 1000 // 24 hours
    lockEntitlement.release()
  }
  return entitlementsByValues[baseEntity]
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
        else if (attribute === 'display' && skuIdDefs[key]?.display?.toLowerCase().includes(getObjValue?.toLowerCase())) skuIds.push(key)
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

const isAccessPackageScheduleValid = (now: Date, expiredDateTime: string, schedule: Record<string, any>): boolean => {
  if (expiredDateTime) return false
  if (typeof schedule !== 'object' || schedule === null) return false
  if (schedule?.startDateTime && now < new Date(schedule.startDateTime)) return false
  if (schedule?.expiration?.endDateTime && now > new Date(schedule.expiration.endDateTime)) return false
  return true
}

/**
* getUsersByAccessPackage returns an object with keys of user object id`s that includes an elements array of users Access Packages.
* @returns { "UserID": { "id": \<UserID\, "displayName": \<UserDisplayName\>, entitlements: [ {"type": "AccessPackage", "value": \<AP-id\>, "display": \<AP-displayName\>}, ...] } }
**/
const getUsersByAccessPackage = async (baseEntity: string, getObj: Record<string, any>, ctx?: Record<string, any> | undefined): Promise<Record<string, any>> => {
  const action = 'getUsersByAccessPackage'
  const result: Record<string, any> = {}
  if (!getObj?.value) return result
  const count = 100
  let path

  if (getObj.operator === 'eq') {
    if (getObj.attribute === 'entitlements.type') {
    // return all users having access packages
      path = `/identityGovernance/entitlementManagement/assignments?$expand=accessPackage($select=id,displayName),target($select=id,displayName)&$top=${count}`
    } else {
      let attribute
      if (getObj.attribute === 'entitlements.display') attribute = 'displayName'
      else if (getObj.attribute === 'entitlements.value') attribute = 'id'
      if (attribute) {
        path = `/identityGovernance/entitlementManagement/assignments?$filter=accessPackage/${attribute} eq '${getObj.value}'&$expand=accessPackage($select=id,displayName),target($select=id,displayName)&$top=100`
      }
    }
  }

  if (path) {
    let previousStartIndext = 0
    let startIndex = 1
    const method = 'GET'
    const body = null

    while (startIndex > previousStartIndext) {
      previousStartIndext = startIndex

      // enable doRequest() OData paging support 
      let paging = { startIndex: startIndex }
      if (!ctx) ctx = { paging }
      else ctx.paging = paging

      const res = await helper.doRequest(baseEntity, method, path, body, ctx)
      if (!res.body?.value || !Array.isArray(res.body.value)) throw new Error(`${action} error: invalid response: ${JSON.stringify(res)}`)
      const now = new Date()
      for (const el of res.body.value) {
        if (!isAccessPackageScheduleValid(now, el.expiredDateTime, el.schedule)) continue
        if (!el.target || !el.target.id) continue
        const ap: Record<string, any> = el.accessPackage
        if (!ap || !ap.id || !ap.displayName) continue
        if (!result[el.target.id]) result[el.target.id] = { id: el.target.id, displayName: el.target.displayName, entitlements: [] }
        result[el.target.id].entitlements.push({
          type: 'AccessPackage', value: ap.id, display: ap.displayName,
        })
      }
      const itemsPerPage = res.body.value.length
      if (ctx.paging.totalResults !== undefined && ctx.paging.totalResults > itemsPerPage + startIndex - 1) startIndex += itemsPerPage
    }
  }

  return result
}

//
// getRoleDefs returns role keys having the roles as values
// {role1.value: [type1, value1, display1], role2.value: [type2, value2, display2], ...}
// Keep an updated rolesByValues in memory
//
const getRoleDefs = async (baseEntity: string, getObj: Record<string, any>, attributes: string[], ctx?: Record<string, any> | undefined): Promise<Record<string, any>> => {
  if (!rolesByValues[baseEntity]) rolesByValues[baseEntity] = {}
  if (!rolesByValues[baseEntity].validTo || Date.now() > rolesByValues[baseEntity].validTo) {
    await lockRole.acquire()
    if (rolesByValues[baseEntity].validTo && Date.now() < rolesByValues[baseEntity].validTo) {
      lockRole.release()
      return rolesByValues[baseEntity]
    }
    const roles = await scimgateway.getRoles(baseEntity, getObj, attributes, ctx)
    Object.keys(rolesByValues[baseEntity]).forEach(key => delete rolesByValues[baseEntity][key])
    for (const resource of roles.Resources) {
      if (resource.id) rolesByValues[baseEntity][resource.id] = resource
    }
    rolesByValues[baseEntity].validTo = Date.now() + 24 * 60 * 60 * 1000 // 24 hours
    lockRole.release()
  }
  return rolesByValues[baseEntity]
}

const getRolesAssignments = async (baseEntity: string, ctx?: undefined | Record<string, any>, force?: undefined | boolean): Promise<Record<string, any>> => {
  if (!rolesAssignments[baseEntity]) rolesAssignments[baseEntity] = {}
  if (force === true && rolesAssignments[baseEntity].validTo) delete rolesAssignments[baseEntity].validTo
  if (!rolesAssignments[baseEntity].validTo || Date.now() > rolesAssignments[baseEntity].validTo) {
    await lockRole.acquire()
    if (rolesAssignments[baseEntity].validTo && Date.now() < rolesAssignments[baseEntity].validTo) {
      lockRole.release()
      return rolesAssignments[baseEntity]
    }

    // permanent roles
    const permanantRoles = async (): Promise<Record<string, any>[]> => {
      const path = `/roleManagement/directory/roleAssignments?$select=id,roleDefinitionId,principalId`
      const res = await helper.doRequest(baseEntity, 'GET', path, null, ctx)
      if (!res.body?.value) throw new Error(`permanant roles error: invalid response: ${JSON.stringify(res)}`)
      return res.body.value
    }

    // eligible roles - requires P2 and api permissions RoleEligibilitySchedule.Read.Directory
    const eligibleRoles = async (): Promise<Record<string, any>[]> => {
      if (!permission[baseEntity]?.eligible) return []
      const path = `/roleManagement/directory/roleEligibilitySchedules?$select=id,roleDefinitionId,principalId,scheduleInfo`
      const res = await helper.doRequest(baseEntity, 'GET', path, null, ctx)
      if (!res.body?.value) throw new Error(`eligible roles error: invalid response: ${JSON.stringify(res)}`)
      return res.body.value
    }

    try {
      const arrResolve = await Promise.all([
        permanantRoles(),
        eligibleRoles(),
      ])
      rolesAssignments[baseEntity].permanent = arrResolve[0]
      rolesAssignments[baseEntity].eligible = arrResolve[1]
    } catch (err: any) {
      lockRole.release()
      throw new Error(`getRolesAsignments error: ${err.message}`)
    }
    rolesAssignments[baseEntity].validTo = Date.now() + 1 * 60 * 60 * 1000 // 1 hour
    lockRole.release()
  }
  return rolesAssignments[baseEntity]
}

const isEligibleActive = (scheduleInfo: Record<string, any>) => {
  if (typeof scheduleInfo !== 'object' || scheduleInfo === null) return false
  const now = new Date()
  const start = new Date(scheduleInfo.startDateTime)
  if (now < start) return false
  const exp = scheduleInfo.expiration
  if (exp.type === 'noExpiration') return true
  if (exp.type === 'afterDateTime') {
    return now < new Date(exp.endDateTime)
  }
  return false
}

//
// getUserRoles returns user´s Entra ID roles as a SCIM roles array having type=Permanent/Eligible.
// includeAssignmentId=true is only used for modifyUser when deleting roles, roles array then includes the required assignmentId
//
const getUserRoles = async (baseEntity: string, userId: string, groups: Record<string, any>[], ctx?: undefined | Record<string, any>, includeAssignmentId?: boolean): Promise<Record<string, any>[]> => {
  let roleDefs: Record<string, any> = {}
  let rolesAssignments: Record<string, any> = {}

  try {
    const arrResolve = await Promise.all([
      getRoleDefs(baseEntity, {}, [], ctx),
      getRolesAssignments(baseEntity, ctx),
    ])
    roleDefs = arrResolve[0]
    rolesAssignments = arrResolve[1]
  } catch (err: any) {
    throw new Error(`getUserRoles error: ${err.message}`)
  }

  // permanent roles
  let groupIds: string[] = []
  if (Array.isArray(groups)) groupIds = groups.map(g => g.value)
  const Ids = [userId, ...groupIds]

  // eligible roles
  const eligibleRoles = rolesAssignments.eligible.filter((role: any) => role.principalId === userId).map((role: any) => {
    const roleDef = roleDefs[role.roleDefinitionId]
    if (roleDef && isEligibleActive(role.scheduleInfo)) {
      if (includeAssignmentId === true) return { type: 'Eligible', value: roleDef.id, display: roleDef.displayName, assignmentId: role.id }
      return { type: 'Eligible', value: roleDef.id, display: roleDef.displayName }
    }
    return null
  })

  const permanentRoles = rolesAssignments.permanent.filter((role: any) => Ids.includes(role.principalId)).map((role: any) => {
    const roleDef = roleDefs[role.roleDefinitionId]
    if (roleDef) {
      if (includeAssignmentId === true) return { type: 'Permanent', value: roleDef.id, display: roleDef.displayName, assignmentId: role.id }
      return { type: 'Permanent', value: roleDef.id, display: roleDef.displayName }
    }
    return null
  })

  return [...permanentRoles, ...eligibleRoles].filter((role: any) => role !== null)
}

/**
* getUsersByRole returns an array of user IDs having a specific role assigned
* @param baseEntity 
* @param getObj { attribute: "xxx", operator: <eq/co/sw>, value: <value> }
* @param ctx 
* @param type "Permanent", "Eligible" or undefined
* @returns string[] user-ids
*/
const getUsersByRole = async (baseEntity: string, getObj: Record<string, any>, type?: 'Permanent' | 'Eligible', ctx?: Record<string, any> | undefined): Promise<string[]> => {
  // 1. Identify Role ID(s) based on getObj (supporting display, value, type)
  if (typeof getObj !== 'object' || getObj === null) return []
  let obj: Record<string, any> = { operator: getObj.operator, value: getObj.value }
  if (getObj.attribute === 'roles.value') obj.attribute = 'id'
  else if (getObj.attribute === 'roles.display') obj.attribute = 'displayName'
  else if (getObj.attribute === 'roles.type') obj = {} // no getRoles() filtering
  else return []

  const roles = await scimgateway.getRoles(baseEntity, obj, ['id'], ctx)
  if (!roles.Resources || roles.Resources.length === 0) return []
  const roleIds = roles.Resources.map((r: any) => r.id)

  // 2. Get all directory assignments (cached for 1h by getRolesAssignments)
  const assignments = await getRolesAssignments(baseEntity, ctx)
  const activePrincipals = new Set<string>()

  const check = (list: any[], isEligible: boolean) => {
    for (const a of list) {
      if (roleIds.includes(a.roleDefinitionId)) {
        if (isEligible && !isEligibleActive(a.scheduleInfo)) continue
        activePrincipals.add(a.principalId)
      }
    }
  }
  if (!type || type === 'Permanent') {
    check(assignments.permanent || [], false)
  }
  if (!type || type === 'Eligible') {
    check(assignments.eligible || [], true)
  }

  if (activePrincipals.size === 0) return []

  // 3. Resolve Principals (determine if User or Group)
  const userIds = new Set<string>()
  const principalsToResolve: { fn: () => Promise<any> }[] = []
  for (const pId of activePrincipals) {
    const path = `/directoryObjects/${pId}`
    principalsToResolve.push({ fn: () => helper.doRequest(baseEntity, 'GET', path, null, ctx?.headers ? { headers: ctx?.headers } : undefined) })
  }
  const principalObjects: any[] = []
  await fnCunckExecute(principalsToResolve, principalObjects)

  // 4. Handle Users directly and fetch transitive members for Groups
  const groupMembersToFetch: { fn: () => Promise<any> }[] = []
  for (const obj of principalObjects) {
    if (!obj || !obj.id) continue
    if (obj['@odata.type'] === '#microsoft.graph.user') userIds.add(obj.id)
    else if (obj['@odata.type'] === '#microsoft.graph.group') {
      // Use a custom function to fetch all transitive members including paging
      const fetchAllMembers = async (groupId: string) => {
        let members: any[] = []
        let nextPath: string | null = `/groups/${groupId}/transitiveMembers/microsoft.graph.user?$select=id`
        while (nextPath) {
          const res = await helper.doRequest(baseEntity, 'GET', nextPath, null, ctx?.headers ? { headers: ctx?.headers } : undefined)
          if (!res.body?.value) break
          members.push(...res.body.value)
          // extract nextLink and convert to relative path
          nextPath = res.body['@odata.nextLink'] ? res.body['@odata.nextLink'].split('/v1.0')[1] : null
        }
        return { body: { value: members } } // Wrap results for fnCunckExecute compatibility
      }
      groupMembersToFetch.push({ fn: () => fetchAllMembers(obj.id) })
    }
  }
  const groupResults: any[] = []
  if (groupMembersToFetch.length > 0) await fnCunckExecute(groupMembersToFetch, groupResults)
  groupResults.forEach((m: any) => m.id && userIds.add(m.id.toLowerCase()))

  return Array.from(userIds)
}

/**
* fnCunckExecute runs functions asynchronous in chunks
* @param fnArr array of objects that must include function and optionally index [{fn, index}]. If `index` is included, it represent the index of `objArr` that should be updated with `key` set to the value of the function result.
* @param objArr optionally array of objects. `objArr[index].key` will be set to function result. If objArr included e.g. empty, but no index and no key, function result will be inserted to objArr.
* @param key optionally key
* @returns undefined, but updated objArr if objArr argument is included
**/
const fnCunckExecute = async (fnArr: { index?: number, fn: () => Promise<any> }[], objArr?: Record<string, any>[], key?: string) => {
  if (!Array.isArray(fnArr)) throw new Error(`fnCunckExecute get ${key} error: fnArr and/or objArr is not array`)
  if (fnArr.length > 0) {
    if (typeof fnArr[0] !== 'object' || !fnArr[0].fn) throw new Error(`fnCunckExecute error: fnArr missing fn object(s)`)
    else if (fnArr[0].index !== undefined && !(objArr || key)) throw new Error(`fnCunckExecute error: missing reponseValue/key`)
    const chunk = 5
    do {
      const arrChunk = fnArr.splice(0, chunk)
      const results = await Promise.allSettled(arrChunk.map(o => o.fn())) as { status: 'fulfilled' | 'rejected', reason: any, value: any }[] // processing max chunk async              
      const errors = results.filter(result => result.status === 'rejected').map(result => result.reason.message)
      if (errors.length > 0) {
        let errMsg
        let statusCode
        try {
          const res = JSON.parse(errors[0])
          statusCode = res?.statusCode
          errMsg = res?.body?.error?.message
        } catch (err) { errMsg = errors.join(', ') }
        if (statusCode !== 404) throw new Error(errMsg)
      }
      results.forEach((result, idx) => {
        if (result.status === 'fulfilled') {
          if (!result.value?.body) return
          const res = result.value.body
          if (typeof arrChunk[idx].index === 'number' && objArr && key) {
            if (res.value) objArr[arrChunk[idx].index][key] = res.value
            else objArr[arrChunk[idx].index][key] = res // Assign the result to the specific index and key
          } else if (arrChunk[idx].index === undefined && objArr && key === undefined) { // When index and key are undefined, append to objArr if objArr provided
            if (Array.isArray(res.value)) objArr.push(...res.value) // If res.value is an array, spread its elements into objArr
            else objArr.push(res) // Otherwise, push the entire res object
          }
        }
      })
    } while (fnArr.length > 0)
  }
}

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})
