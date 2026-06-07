// =====================================================================================================================
// File:    plugin-entra-id.js
//
// Author:  Jarle Elshaug
//
// Purpose: Entra ID user and group provisioning including roles and access packages in addition to retrieving license, MFA and sign-in information
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
//        'GET /Roles' retrieves a list of all available roles specified by type (Permanent or Eligible) and corresponds with the users attribute roles.
//        'GET /Entitlements' retrieves a list of all available entitlements specified by type (License or AccessPackage) and corresponds with the users attribute entitlements.
//
//        Using "Custom SCIM" attributes defined in configuration endpoint.entity.map
//        Schema generated according mapping configuration.
//        Note:
//          - 'map.user.signInActivity' requires Entra ID Premium license and API permissions 'AuditLog.Read.All'.
//          - 'map.user.mfa' provides MFA status information and requires API permissions 'UserAuthenticationMethod.Read.All'
//          - 'map.user.entitlements' relates to Licenses and Access Packages. Access Packages requires API permissions 'EntitlementManagement.ReadWrite.All' 
//          - 'map.user.roles relates to standard Permanent roles and PIM Permanent and Eligible roles.
//            PIM is included on tenant having P2 or Governance License and requires following API permissions:
//            - PIM Eligible roles requires API permissions 'RoleEligiblitySchedule.ReadWrite.All'
//            - PIM Permanent roles requires API permissions 'RoleManagement.ReadWrite.Directory'
//          - Remove mapping if conditions not met or consider using only 'Read' if no management needed
//
// /User                                      SCIM (custom)                       Endpoint (Entra ID)
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
// SignInActivity                             signInActivity                      signInActivity (lastSignInDateTime, lastSuccessfulSignInDateTime and lastNonInteractiveSignInDateTime)
// MFA                                        mfa                                 mfa (mfa.isMfaCapable and mfa.isLegacyEnabled)
//
// /Group                                     SCIM (custom)                       Endpoint (Entra ID)
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
scimgateway.pluginAndOrFilterEnabled = true
// end - mandatory plugin initialization

const entitlementsByValues: Record<string, any> = {}
const rolesByValues: Record<string, any> = {}
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
    if (config.map.user[key].mapTo === 'mfa') attr = 'perUserMfaState'
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
      let probeUserId: string | undefined
      try {
        const res = await helper.doRequest(baseEntity, 'GET', '/users?$top=1&$select=id', null, null)
        probeUserId = res?.body?.value?.[0]?.id
      } catch (err) { }

      const [signInResult, eligibleResult, permanentScheduleResult, accessPackageResult, mfaResult] = await Promise.allSettled([
        (async () => {
          if (!mapAttributesTo.includes('signInActivity')) throw new Error('skipping signInActivity check')
          await helper.doRequest(baseEntity, 'GET', '/users?$top=1&$select=id,signInActivity', null, { skipLogAsError: true })
        })(),
        (async () => {
          if (!mapAttributesTo.includes('roles')) throw new Error('skipping eligible check')
          await helper.doRequest(baseEntity, 'GET', '/roleManagement/directory/roleEligibilityScheduleInstances?$top=1', null, { skipLogAsError: true })
        })(),
        (async () => {
          if (!mapAttributesTo.includes('roles')) throw new Error('skipping permanent schedule check')
          await helper.doRequest(baseEntity, 'GET', '/roleManagement/directory/roleAssignmentScheduleInstances?$top=1', null, { skipLogAsError: true })
        })(),
        (async () => {
          if (!mapAttributesTo.includes('entitlements')) throw new Error('skipping access package check')
          await helper.doRequest(baseEntity, 'GET', '/identityGovernance/entitlementManagement/accessPackages?$top=1&$select=id', null, { skipLogAsError: true })
        })(),
        (async () => {
          if (!mapAttributesTo.includes('mfa') || !probeUserId) throw new Error('skipping mfaMethods check')
          await helper.doRequest(baseEntity, 'GET', `/users/${probeUserId}/authentication/methods`, null, { skipLogAsError: true })
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
        if (mapAttributesTo.includes('roles')) scimgateway.logError(baseEntity, `PIM eligible role functionality has been deactivated because it requires either a P2 or Governance license, as well as the minimum API permission 'RoleEligibilitySchedule.Read.All'`)
      }
      if (permanentScheduleResult.status === 'fulfilled') {
        permission[baseEntity].permanentSchedule = true
      } else {
        permission[baseEntity].permanentSchedule = false
        if (mapAttributesTo.includes('roles')) scimgateway.logError(baseEntity, `PIM permanent role functionality has been deactivated because it requires either a P2 or Governance license, as well as the minimum API permission 'RoleManagement.Read.Directory'`)
      }
      if (accessPackageResult.status === 'fulfilled') {
        permission[baseEntity].accessPackage = true
      } else {
        permission[baseEntity].accessPackage = false
        if (mapAttributesTo.includes('roles')) scimgateway.logError(baseEntity, `IGA Access Packages functionality has been deactivated because it requires minimum API permission 'EntitlementManagement.Read.All'`)
      }
      if (mfaResult.status === 'fulfilled') {
        permission[baseEntity].mfa = true
      } else {
        permission[baseEntity].mfa = false
        if (mapAttributesTo.includes('mfa')) scimgateway.logError(baseEntity, `MFA Methods functionality has been deactivated because it requires API permissions 'UserAuthenticationMethod.Read.All'`)
      }
    } catch (err) {}
  }
})()

// =================================================
// getUsers
// =================================================
scimgateway.getUsers = async (baseEntity, getObj, attributes, ctx) => {
  //
  // "getObj" = { attribute: <>, operator: <>, value: <>, rawFilter: <>, startIndex: <>, count: <>, and/or: <getObj> }
  // rawFilter is always included when filtering
  // attribute, operator and value are included when requesting unique object or simpel filtering
  // and/or will be included and the value set to corresponding getObj if the mandatory plugin initialization have 'scimgateway.pluginAndOrFilterEnabled = true' and the request query filter includes simple and/or logic 
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
  let response: Record<string, any> = {}
  let selectAttributes: string[] = []

  if (attributes.length > 0) {
    for (const attribute of attributes) {
      const [endpointAttr] = scimgateway.endpointMapper('outbound', attribute, config.map.user)
      let attr = endpointAttr.split('.')[0]
      if (!attr) continue
      // complexArray/complexObject are special
      if (attribute.startsWith('entitlements')) attr = 'assignedLicenses'
      if (attribute.startsWith('mfa')) attr = 'perUserMfaState'
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
              if (!type && obj.operator === 'pr') obj = { attribute: 'roles.type' } // 'filter=roles pr' - precense => filter all objects having roles
              const o = await getUsersByRole(baseEntity, obj, (type) ? decodeURIComponent(type) as 'Permanent' | 'Eligible' : undefined, ctx)
              if (!Array.isArray(o) || o.length === 0) return ret
              const fnArr: { fn: () => Promise<any>, index?: number, objArr?: any, key?: string }[] = []
              response.body = { value: [] }
              if (!response.body?.value) response.body = { value: [] }
              for (const id of o) {
                const userPath = `/users/${id}?$select=${selectAttributes.join(',')}`
                const fn = () => helper.doRequest(baseEntity, 'GET', userPath, null, ctx?.headers ? { headers: ctx?.headers } : undefined)
                fnArr.push({ fn, objArr: response.body.value })
              }
              await fnCunckExecute(fnArr) // fnCunckExecute results in response.body.value and evaluated later
              if (response.body.value.length === 0) return ret
            } else if (arr[0] === 'entitlements') { // using entitlements for licenses and access packages
              if (getObj.attribute !== 'entitlements.type' && getObj.and?.attribute !== 'entitlements.type') throw new Error(`${action} filter error: mandatory entitlements.type is missing, examples: entitlements[type eq "xxx"], entitlements[type eq "xxx" and value eq "xxx"], entitlements[type eq "xxx" and display <eq/co/sw> "xxx"]`)
              if (type === 'License') {
                if (obj.operator === 'eq' && obj.attribute === 'entitlements.type') { // entitlements[type eq "License"]
                  path = `/users?$top=${getObj.count}&$count=true&$filter=assignedLicenses/$count ne 0&$select=${selectAttributes.join(',')}`
                  isExpandManager = false
                } else { // entitlements[type eq "License" and value eq "xxx"], entitlements[type eq "License" and display <eq/co/sw> "xxx"]
                  const skuIdArr = await searchEntitlementsByValues(baseEntity, obj, 'License', ctx)
                  if (skuIdArr.length === 0) return ret
                  if (skuIdArr.length === 1) odataFilter = `assignedLicenses/any(x:x/skuId eq ${skuIdArr[0]})`
                  else throw new Error(`${action} filter error: not supporting: ${getObj.rawFilter} - entitlements filter resulted in more than one skuId which is not supported. For guaranteed uniqueness use: filter=entitlements[type eq "License" and value eq "<skuId>"]`)
                }
              } else if (type === 'AccessPackage') {
                let o: Record<string, any> | undefined
                if (obj.operator === 'eq' && obj.attribute === 'entitlements.type') { // entitlements[type eq "AccessPackage"]
                  o = await getUsersByAccessPackage(baseEntity, obj, ctx?.headers ? { headers: ctx?.headers } : undefined)
                } else { // entitlements[type eq "AccessPackage" and value eq "xxx"], entitlements[type eq "AccessPackage" and display <eq/co/sw> "xxx"]
                  const idArr = await searchEntitlementsByValues(baseEntity, obj, 'AccessPackage', ctx)
                  if (idArr.length === 0) return ret
                  else if (idArr.length > 1) throw new Error(`${action} filter error: not supporting: ${getObj.rawFilter} - entitlements filter resulted in more than one id which is not supported. For guaranteed uniqueness use: filter=entitlements[type eq "AccessPackage" and value eq "<id>"]`)
                  o = await getUsersByAccessPackage(baseEntity, { attribute: 'entitlements.value', operator: 'eq', value: idArr[0] }, ctx?.headers ? { headers: ctx?.headers } : undefined)
                }
                if (typeof o !== 'object' || o === null || Object.keys(o).length === 0) return ret
                const isAttrsOk = attributes.length > 0 && attributes.length < 3 && (attributes.includes('id') || attributes.includes('displayName'))
                const fnArr: { fn: () => Promise<any>, index?: number, objArr?: any, key?: string }[] = []
                response.body = { value: [] }
                if (!response.body?.value) response.body = { value: [] }
                for (const key in o) {
                  if (isAttrsOk) ret.Resources.push(o[key])
                  else {
                    const userPath = `/users/${key}?$select=${selectAttributes.join(',')}`
                    const fn = () => helper.doRequest(baseEntity, 'GET', userPath, null, ctx?.headers ? { headers: ctx?.headers } : undefined)
                    fnArr.push({ fn, objArr: response.body.value })
                  }
                }
                if (isAttrsOk) return ret
                else {
                  await fnCunckExecute(fnArr)
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
    // plugin have enabled 'scimgateway.pluginAndOrFilterEnabled' and the query includes an additonal and/or getObj that must to be handled and combined with the initial getObj
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
    const fnArr: { fn: () => Promise<any>, index?: number, objArr?: any, key?: string }[] = []
    const byValues = await getEntitlementsByValues(baseEntity, ctx)

    for (let i = 0; i < response.body.value.length; ++i) {
      if (!response.body.value[i].id) break

      // include manager
      if (!isExpandManager && selectAttributes.includes('manager')) {
        const singleUserPath = `/users/${response.body.value[i].id}/manager?$select=userPrincipalName`
        const fn = () => helper.doRequest(baseEntity, 'GET', singleUserPath, null, ctx?.headers ? { headers: ctx?.headers } : undefined, options)
        // fnArr.push({ index: i, fn })
        fnArr.push({ index: i, fn, objArr: response.body.value, key: 'manager' })
      }

      // include groups (before roles)
      if (attributes.length === 0 || attributes.includes('groups')) {
        const fn = () => scimgateway.getUserGroups(baseEntity, response.body.value[i].id, ctx?.headers ? { headers: ctx?.headers } : undefined)
        fnArr.push({ index: i, fn, objArr: response.body.value, key: 'groups' })
      }
    }

    if (fnArr.length > 0) await fnCunckExecute(fnArr)

    // attribute mapping and cleanup
    for (let i = 0; i < response.body.value.length; ++i) {
      const obj = response.body.value[i]
      if (obj.manager?.userPrincipalName) {
        let managerId = obj.manager.userPrincipalName
        if (managerId) obj.manager = managerId
        else delete obj.manager
      }

      if (obj.perUserMfaState && permission[baseEntity]?.mfa) {
        const isLegacyEnabled = obj.perUserMfaState === 'enabled' || obj.perUserMfaState === 'enforced'
        if (!obj.mfa) obj.mfa = {}
        obj.mfa.isLegacyEnabled = isLegacyEnabled
      }

      if (obj.signInActivity) {
        delete obj.signInActivity.lastSignInRequestId
        delete obj.signInActivity.lastNonInteractiveSignInRequestId
        delete obj.signInActivity.lastSuccessfulSignInRequestId
      }

      // include roles, entitlements and MFA - MFA here and not in above fnArr/fnCunckExecute to reduce throttle noise
      if (obj.id) {
        const roles = async (obj: Record<string, any>): Promise<Record<string, any>[]> => {
          // roles type=Permanent/Eligible
          if ((attributes.includes('roles') || attributes.length === 0) && mapAttributesTo.includes('roles')) {
            return await getUserRoles(baseEntity, obj.id, obj.groups, false, ctx?.headers ? { headers: ctx?.headers } : undefined)
          } else return []
        }
        const entitlements = async (obj: Record<string, any>): Promise<Record<string, any>[]> => {
          const result: Record<string, any>[] = []
          if ((attributes.includes('entitlements') || attributes.length === 0) && mapAttributesTo.includes('entitlements')) {
            // entitlements type=License => assignedLicenses
            if (obj.assignedLicenses && Array.isArray(obj.assignedLicenses)) {
              for (const lic of response.body.value[i].assignedLicenses) {
                if (lic.skuId && byValues[lic.skuId]) result.push(byValues[lic.skuId])
              }
            }
            // entitlements type=AccessPackage
            if (permission[baseEntity]?.accessPackage) {
              const aps = await getUserAccessPackages(baseEntity, obj.id, false, ctx?.headers ? { headers: ctx?.headers } : undefined)
              result.push(...aps)
            }
          }
          return result
        }
        const mfa = async (obj: Record<string, any>): Promise<boolean | undefined> => {
          // include MFA 'isMfaCapable', which indicates whether the user has registered authentication methods eligible for MFA.
          if (attributes.length === 0 || attributes.includes('mfa') || attributes.includes('mfa.isMfaCapable')) {
            if (permission[baseEntity]?.mfa) {
              return await getUserisMfaCapable(baseEntity, obj.id, ctx?.headers ? { headers: ctx?.headers } : undefined)
            } else return undefined
          }
        }

        const arrResolve = await Promise.all([
          roles(obj),
          entitlements(obj),
          mfa(obj),
        ])
        obj.roles = arrResolve[0]
        obj.entitlements = arrResolve[1]
        if (arrResolve[2] !== undefined) {
          if (!obj.mfa) obj.mfa = {}
          obj.mfa.isMfaCapable = arrResolve[2]
        }
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

  const [parsedAttrObj]: Record<string, any>[] = scimgateway.endpointMapper('outbound', attrObj, config.map.user) // SCIM/CustomSCIM => endpoint attribute standard
  if (parsedAttrObj instanceof Error) throw (parsedAttrObj) // error object

  const objManager: Record<string, any> = {}
  if (Object.hasOwn(parsedAttrObj, 'manager')) {
    objManager.manager = parsedAttrObj.manager
    if (objManager.manager === '') objManager.manager = null
    delete parsedAttrObj.manager
  }

  const fnArr: { fn: () => Promise<any> }[] = []
  let isRolesChanged = false

  const getValueByDisplayName = async (display: string): Promise<string | undefined> => {
    const res = await scimgateway.getRoles(baseEntity, { attribute: 'displayName', operator: 'eq', value: display }, [], ctx)
    if (Array.isArray(res?.Resources) && res.Resources.length === 1) return res.Resources[0]?.id
    return undefined
  }

  // MFA Reset
  if (Object.hasOwn(parsedAttrObj, 'mfa')) {
    if (parsedAttrObj.mfa.reset === true) {
      if (!permission[baseEntity]?.mfa || !permission[baseEntity]?.eligible) throw new Error(`${action} error: MFA reset is not supported by the endpoint - missing permissions.`)
      const res = await scimgateway.getGroups(baseEntity, { attribute: 'members.value', operator: 'eq', value: id }, ['id', 'displayName'], ctx)
      let userGroups: Record<string, any>[] = []
      if (res?.Resources && Array.isArray(res.Resources)) {
        userGroups = res.Resources.map((r: Record<string, any>) => { return { value: r.id } })
      }
      const currentRoles = await getUserRoles(baseEntity, id, userGroups, true, ctx)
      const isPrivileged = currentRoles.some(r => isPrivilegedRole(r.value))
      if (isPrivileged) throw new Error(`${action} error: MFA reset is not allowed for users with high-privilege roles for security reasons.`)
      await resetUserMfa(baseEntity, id, ctx)
    }
    delete parsedAttrObj.mfa
  }

  // Roles
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
        if (isPrivilegedRole(el.value)) throw new Error(`${action} error: Removal of high-privilege roles is not allowed for security reasons.`)
        res.operation = el.operation
      }
      r.push(res)
    }
    delete parsedAttrObj.roles

    const rolesAdd: Record<string, any> [] = r.filter(m => m.operation !== 'delete')
    const rolesRemove: Record<string, any> [] = r.filter(m => m.operation === 'delete')

    if (rolesAdd.length > 0 || rolesRemove.length > 0) {
      const currentRoles = await getUserRoles(baseEntity, id, [], true, ctx)

      for (const r of rolesAdd) {
        const roleExist = currentRoles.filter(c => c.value === r.value && c.type === r.type)
        if (roleExist.length > 0) continue // exlude adding already assigned
        let method = 'POST'
        let path = ''
        let body: Record<string, any> = {}

        if ((r.type === 'Eligible' && permission[baseEntity]?.eligible) || (r.type === 'Permanent' && permission[baseEntity]?.permanentSchedule)) {
          path = (r.type === 'Eligible') ? '/roleManagement/directory/roleEligibilityScheduleRequests' : '/roleManagement/directory/roleAssignmentScheduleRequests'
          body = {
            action: 'AdminAssign',
            principalId: id,
            roleDefinitionId: r.value,
            directoryScopeId: '/',
            justification: 'Automated assignment submitted by SCIM Gateway',
            scheduleInfo: {
              startDateTime: new Date().toISOString(),
              expiration: {
                type: 'noExpiration',
              },
            },
          }
        } else {
          if (r.type === 'Eligible') throw new Error(`${action} error: add/remove eligible roles requires permission RoleEligibilitySchedule.ReadWrite.All`)
          path = '/roleManagement/directory/roleAssignments'
          body = {
            principalId: id,
            roleDefinitionId: r.value,
            directoryScopeId: '/',
          }
        }

        const fn = () => helper.doRequest(baseEntity, method, path, body, ctx)
        fnArr.push({ fn })
        isRolesChanged = true
      }

      for (const r of rolesRemove) {
        const arrRemove: Record<string, any> [] = []
        const removeAssignments = currentRoles.filter(c => c.value === r.value && c.type === r.type && c.assignmentId).map((n) => { return { assignmentId: n.assignmentId, value: n.value, type: n.type } })
        arrRemove.push(...removeAssignments)

        for (const rm of arrRemove) {
          let method = 'POST'
          let path = ''
          let body: Record<string, any> | null = {}

          if (rm.type === 'Eligible' && permission[baseEntity]?.eligible) {
            path = '/roleManagement/directory/roleEligibilityScheduleRequests'
            body = {
              action: 'AdminRemove',
              principalId: id,
              roleDefinitionId: rm.value,
              directoryScopeId: '/',
              justification: 'Automated revoke submitted by SCIM Gateway',
            }
          } else {
            if (r.type === 'Eligible') throw new Error(`${action} error: add/remove eligible roles requires permission RoleEligibilitySchedule.ReadWrite.All`)
            method = 'DELETE'
            path = `/roleManagement/directory/roleAssignments/${rm.assignmentId}`
            body = null
          }
          const fn = () => helper.doRequest(baseEntity, method, path, body, ctx)
          fnArr.push({ fn })
          isRolesChanged = true
        }
      }
    }
  }

  // Entitlements - Access Packages - Note, License management not supported through entitlements, instead use groups
  if (Object.hasOwn(parsedAttrObj, 'entitlements') && Array.isArray(parsedAttrObj.entitlements)) {
    const accessPackagesAdd: Record<string, any> [] = parsedAttrObj.entitlements.filter(m => m.type === 'AccessPackage' && m.operation !== 'delete')
    const accessPackagesRemove: Record<string, any> [] = parsedAttrObj.entitlements.filter(m => m.type === 'AccessPackage' && m.operation === 'delete')

    if (accessPackagesAdd.length > 0) {
      const byValues = await getEntitlementsByValues(baseEntity, ctx)
      for (const a of accessPackagesAdd) {
        if (!byValues[a.value]) continue
        const assignmentPolicyId = byValues[a.value]?.typeInfo?.assignmentPolicies[0]?.id // TODO: note, using the first policy and this might be wrong if more than one defined...
        if (!assignmentPolicyId) throw new Error(`${action} error: Access Package could not be assigned to user - entitlements value ${a.value} (Access Package ID) - no policy found for this Access Package`)
        const method = 'POST'
        let path = `/identityGovernance/entitlementManagement/accessPackageAssignmentRequests`
        const body: Record<string, any> = {
          requestType: 'AdminAdd',
          accessPackageAssignment: {
            target: {
              '@odata.type': '#microsoft.graph.accessPackageSubject',
              'objectId': id,
            },
            assignmentPolicyId,
            accessPackageId: a.value,
          },
          justification: 'Automated assignment request submitted by SCIM Gateway',
        }
        const fn = () => helper.doRequest(baseEntity, method, path, body, ctx)
        fnArr.push({ fn })
      }
    }

    if (accessPackagesRemove.length > 0) {
      const arrRemove: Record<string, any> [] = []
      const currentAPs = await getUserAccessPackages(baseEntity, id, true, ctx)
      for (const r of accessPackagesRemove) {
        const removeAssignments = currentAPs.filter(c => c.value === r.value && c.type === r.type && c.assignmentId)
        arrRemove.push(...removeAssignments)
      }
      for (const rm of arrRemove) {
        const method = 'POST'
        let path = `/identityGovernance/entitlementManagement/accessPackageAssignmentRequests`
        const body: Record<string, any> = {
          requestType: 'adminRemove',
          accessPackageAssignment: {
            id: rm.assignmentId,
          },
          justification: 'Automated revoke request submitted by SCIM Gateway',
        }
        const fn = () => helper.doRequest(baseEntity, method, path, body, ctx)
        fnArr.push({ fn })
      }
    }
  }

  if (fnArr.length > 0) { // update roles/entitlements
    try {
      await fnCunckExecute(fnArr)
      if (isRolesChanged) {
        (async () => {
          await new Promise(resolve => setTimeout(resolve, 15000))
          await getRolesAssignments(baseEntity, ctx, true) // make sure the internal assignments list becomes updated
        })()
      }
    } catch (err: any) {
      throw new Error(`${action} roles modify error: ${err.message}`)
    }
  }

  if (parsedAttrObj.roles) delete parsedAttrObj.roles
  if (parsedAttrObj.entitlements) delete parsedAttrObj.entitlements

  const profile = () => { // patch
    return new Promise((resolve, reject) => {
      (async () => {
        if (Object.keys(parsedAttrObj).length === 0) return resolve(null)
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

  return Promise.all([profile(), manager()])
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
        path = `/groups/${getObj.value}?$select=${attrs.join()}`
      } else {
        path = `/groups?$filter=${getObj.attribute} eq '${getObj.value}'&$select=${attrs.join()}`
      }
    } else if (isUserMemberOf) {
      // mandatory - return all groups the user 'id' (getObj.value) is member of - correspond to getGroupMembers() in versions < 4.x.x
      // Resources = [{ id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }]
      includeMembers = false
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
    path = `/groups?$top=${getObj.count}&$count=true&$select=${attrs.join()}`
  }
  if (getObj.and || getObj.or) {
    // plugin have enabled 'scimgateway.pluginAndOrFilterEnabled' and the query includes an additonal and/or getObj that must to be handled and combined with the initial getObj
    // we could have this logic above, if not it must be defined here
    throw new Error(`${action} error: logic for handling and/or filter is not implemented by plugin, not supporting: ${getObj.rawFilter}`)
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

  const newCtx: Record<string, any> = ctx?.headers ? { headers: ctx?.headers } : {}
  newCtx.paging = { startIndex: 1 }

  try {
    let response: any
    let responseMemberOf: any
    if (!isUserMemberOf) response = await helper.doRequest(baseEntity, method, path, body, ctx, options)
    else {
      // request both the default transitiveMemberOf (includes nested groups) and memberOf because we want to distinguish SCIM type=direct/indirect
      let pathMemberOf = `/users/${getObj.value}/memberOf/microsoft.graph.group?$count=true&$select=id,displayName`
      const allErrors: string[] = []
      const results = await Promise.allSettled([
        helper.doRequest(baseEntity, method, path, body, ctx, options),
        helper.doRequest(baseEntity, method, pathMemberOf, body, newCtx, options),
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
      responseMemberOf = (results[1] as PromiseFulfilledResult<any>).value // does not include nested groups
      while (newCtx.paging.nextLink) {
        let res: any
        pathMemberOf = newCtx.paging.nextLink
        delete newCtx.paging.nextLink
        try {
          res = await helper.doRequest(baseEntity, method, pathMemberOf, body, newCtx, options)
        } catch (err: any) {
          delete newCtx.paging.nextLink
          break
        }
        if (res?.body && res.body.value && Array.isArray(res.body.value) && res.body.value.length > 0) {
          for (let i = 0; i < res.body.value.length; i++) {
            if (!res.body.value[i].id) continue
            responseMemberOf.body.value.push(res.body.value[i])
          }
        }
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
      if (includeMembers) {
        const id = response.body.value[i].id
        if (!id) break
        let path = `/groups/${id}/members?$select=id,displayName`
        const newCtx: Record<string, any> = ctx?.headers ? { headers: ctx?.headers } : {}
        newCtx.paging = { startIndex: 1 }
        const r = await helper.doRequest(baseEntity, 'GET', path, null, newCtx, options)
        response.body.value[i].members = r.body?.value || []
        while (newCtx.paging.nextLink) {
          const path = newCtx.paging.nextLink
          delete newCtx.paging.nextLink
          const r = await helper.doRequest(baseEntity, 'GET', path, null, newCtx, options)
          response.body.value[i].members.push(...r.body?.value || [])
        }
      }

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

    const response = await helper.doRequest(baseEntity, method, path, body, ctx?.headers ? { headers: ctx?.headers } : undefined)
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
    const path = '/identityGovernance/entitlementManagement/accessPackages?$select=id,displayName&$expand=accessPackageAssignmentPolicies' // v1.0 $expand=assignmentPolicies

    const response = await helper.doRequest(baseEntity, method, path, body, ctx?.headers ? { headers: ctx?.headers } : undefined)
    if (!response.body?.value) {
      if (response.body?.skuId) response.body.value = [response.body]
      else throw new Error(`invalid response: ${JSON.stringify(response)}`)
    }
    for (let i = 0; i < response.body.value.length; i++) {
      const typeInfo: Record<string, any> = {}
      if (Array.isArray(response.body.value[i].accessPackageAssignmentPolicies)) {
        typeInfo.assignmentPolicies = response.body.value[i].accessPackageAssignmentPolicies.map((a: Record<string, any>) => { // accessPackageAssignmentPolicies.id needed for assign access package to user
          return { id: a.id, displayName: a.displayName }
        })
      }
      result.push({
        type: 'AccessPackage', id: response.body.value[i].id, displayName: response.body.value[i].displayName, typeInfo,
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
// getEntitlementsByValues returns entitlements keys having the entitlements as values
// {entitlement1.value: [type1, value1, display1], entitlement2.value: [type2, value2, display2], ...}
// entitlement.value = skuId
// Keep an updated entitlementsByValues in memory
// We can then use users/assignedLicenses instead of costly users/licenseDetails
//
const getEntitlementsByValues = async (baseEntity: string, ctx?: undefined | Record<string, any>): Promise<Record<string, any>> => {
  if (!entitlementsByValues[baseEntity]) entitlementsByValues[baseEntity] = {}
  if (!entitlementsByValues[baseEntity].validTo || Date.now() > entitlementsByValues[baseEntity].validTo) {
    await lockEntitlement.acquire()
    if (entitlementsByValues[baseEntity].validTo && Date.now() < entitlementsByValues[baseEntity].validTo) {
      lockEntitlement.release()
      return entitlementsByValues[baseEntity]
    }
    const entitlements = await scimgateway.getEntitlements(baseEntity, {}, [], ctx)
    Object.keys(entitlementsByValues[baseEntity]).forEach(key => delete entitlementsByValues[baseEntity][key])
    for (const r of entitlements.Resources) {
      const entitlement: Record<string, any> = {
        type: r.type,
        value: r.id,
        display: r.displayName,
      }
      if (r.type === 'AccessPackage') entitlement.typeInfo = r.typeInfo // only used by modifyUser() entitlements

      entitlementsByValues[baseEntity][entitlement.value] = entitlement
    }
    entitlementsByValues[baseEntity].validTo = Date.now() + 24 * 60 * 60 * 1000 // 24 hours
    lockEntitlement.release()
  }
  return entitlementsByValues[baseEntity]
}

//
// searchEntitlementsByValues returns array of entitlements value (id) matching getObj filter
//
const searchEntitlementsByValues = async (baseEntity: string, getObj: Record<string, any>, type?: string, ctx?: undefined | Record<string, any>): Promise<string[]> => { // (getObj: Record<string, any>): string[] => {
  const byValues = await getEntitlementsByValues(baseEntity, ctx)
  const arr = getObj.attribute.split('.')
  if (arr.length !== 2 || arr[0] !== 'entitlements') return []
  const attribute = arr[1]
  const ids: string[] = []
  const getObjValue = decodeURIComponent(getObj.value)

  for (const key in byValues) {
    if (type && byValues[key].type !== type) continue
    switch (getObj.operator) {
      case 'eq':
        if (attribute === 'value' && byValues[key]?.value === getObjValue) ids.push(key)
        else if (attribute === 'type' && byValues[key]?.type === getObjValue) ids.push(key)
        else if (attribute === 'display' && byValues[key]?.display === getObjValue) ids.push(key)
        break
      case 'co':
        if (attribute === 'value' && byValues[key]?.value?.toLowerCase().includes(getObjValue?.toLowerCase())) ids.push(key)
        else if (attribute === 'type' && byValues[key]?.type?.toLowerCase().includes(getObjValue?.toLowerCase())) ids.push(key)
        else if (attribute === 'display' && byValues[key]?.display?.toLowerCase().includes(getObjValue?.toLowerCase())) ids.push(key)
        break
      case 'sw':
        if (attribute === 'value' && byValues[key]?.value?.toLowerCase().startsWith(getObjValue.toLowerCase())) ids.push(key)
        else if (attribute === 'type' && byValues[key]?.type?.toLowerCase().startsWith(getObjValue?.toLowerCase())) ids.push(key)
        else if (attribute === 'display' && byValues[key]?.display?.toLowerCase().startsWith(getObjValue?.toLowerCase())) ids.push(key)
        break
      default: break
    }
  }
  return ids
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
      path = `/identityGovernance/entitlementManagement/accessPackageAssignments?$expand=accessPackage($select=id,displayName),target($select=id,displayName)&$top=${count}` // v1.0 /assignments?$filter=accessPackage/${attribute}
    } else {
      let attribute
      if (getObj.attribute === 'entitlements.display') attribute = 'displayName'
      else if (getObj.attribute === 'entitlements.value') attribute = 'id'
      if (attribute) {
        path = `/identityGovernance/entitlementManagement/accessPackageAssignments?$filter=accessPackage/${attribute} eq '${getObj.value}'&$expand=accessPackage($select=id,displayName),target($select=id,displayName)&$top=100` // v1.0 /assignments?$filter=accessPackage/${attribute}
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
const getUserRoles = async (baseEntity: string, userId: string, groups: Record<string, any>[], includeAssignmentId: boolean, ctx?: undefined | Record<string, any>): Promise<Record<string, any>[]> => {
  const action = 'getUserRoles'
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
    throw new Error(`${action} error: ${err.message}`)
  }

  // permanent roles
  let groupIds: string[] = []
  if (Array.isArray(groups)) groupIds = groups.map(g => g.value)
  const Ids = [userId, ...groupIds]

  // eligible roles
  const eligibleRoles = rolesAssignments.eligible.filter((role: any) => role.principalId === userId).map((role: any) => {
    const roleDef = roleDefs[role.roleDefinitionId]
    if (roleDef && isEligibleActive(role.scheduleInfo)) {
      const entitlement: Record<string, any> = { type: 'Eligible', value: roleDef.id, display: roleDef.displayName }
      if (includeAssignmentId === true) entitlement.assignmentId = role.id
      return entitlement
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

//
// getUserRoles returns user´s Entra ID Access Packaes as a SCIM entitlements array having type=AccessPackage.
// includeAssignmentId=true is only used for modifyUser when deleting AccessPackage, entitlement array then includes the required assignmentId
//
const getUserAccessPackages = async (baseEntity: string, userId: string, includeAssignmentId: boolean, ctx?: undefined | Record<string, any>): Promise<Record<string, any>[]> => {
  const action = 'getUserAccessPackages'
  const result: Record<string, any>[] = []
  const method = 'GET'
  const body = null
  const path = `/identityGovernance/entitlementManagement/accessPackageAssignments?$filter=target/objectId eq '${userId}'&$expand=accessPackage($select=id,displayName)` // v1.0 /assignments
  const r = await helper.doRequest(baseEntity, method, path, body, ctx?.headers ? { headers: ctx?.headers } : undefined)
  if (!r.body?.value) {
    if (r.body?.id) r.body.value = [r.body]
    else throw new Error(`${action} error: invalid response: ${JSON.stringify(r)}`)
  }
  const now = new Date()
  for (let j = 0; j < r.body.value.length; j++) {
    if (!isAccessPackageScheduleValid(now, r.body.value[j].expiredDateTime, r.body.value[j].schedule)) continue
    const ap: Record<string, any> = r.body.value[j].accessPackage
    if (!ap || !ap.id || !ap.displayName) continue
    const entitlement: Record<string, any> = { type: 'AccessPackage', value: ap.id, display: ap.displayName }
    if (includeAssignmentId === true) entitlement.assignmentId = r.body.value[j].id
    result.push(entitlement)
  }
  return result
}

const isPrivilegedRole = (roleId: string): boolean => {
  return [
    '62e90394-69f5-4237-9190-012177145e10', // Global Administrator
    'e8611ab8-c189-46e8-94e1-60213ab1f814', // Privileged Role Administrator
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', // Privileged Authentication Administrator
    'c4e39bd9-1100-46d3-8c65-fb160da0071f', // Authentication Administrator
  ].includes(roleId)
}

const isMethodMfaCapable = (odataType: string): boolean => {
  return [
    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
    '#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod',
    '#microsoft.graph.phoneAuthenticationMethod',
    '#microsoft.graph.softwareOathAuthenticationMethod',
    '#microsoft.graph.fido2AuthenticationMethod',
  ].includes(odataType)
}

const getAuthMethodCollectionFromODataType = (odataType: string): string => {
  const map: Record<string, string> = {
    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod': 'microsoftAuthenticatorMethods',
    '#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod': 'microsoftAuthenticatorMethods',
    '#microsoft.graph.phoneAuthenticationMethod': 'phoneMethods',
    '#microsoft.graph.softwareOathAuthenticationMethod': 'softwareOathMethods',
    '#microsoft.graph.fido2AuthenticationMethod': 'fido2Methods',
    '#microsoft.graph.emailAuthenticationMethod': 'emailMethods',
    '#microsoft.graph.temporaryAccessPassAuthenticationMethod': 'temporaryAccessPassMethods',
    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod': 'windowsHelloForBusinessMethods',
    '#microsoft.graph.passwordAuthenticationMethod': 'passwordMethods',
  }
  const collection = map[odataType]
  return collection
}

const getUserisMfaCapable = async (baseEntity: string, userId: string, ctx?: undefined | Record<string, any>): Promise<boolean> => {
  const action = 'getUserisMfaCapable'
  const method = 'GET'
  const body = null
  const path = `/users/${userId}/authentication/methods`
  const r = await helper.doRequest(baseEntity, method, path, body, ctx?.headers ? { headers: ctx?.headers } : undefined)
  if (!r.body?.value) {
    if (r.body?.id) r.body.value = [r.body]
    else throw new Error(`${action} error: invalid response: ${JSON.stringify(r)}`)
  }
  const methodTypes = r.body.value.map((m: any) => m['@odata.type'])
  if (methodTypes.length < 1) return false
  return methodTypes.some(isMethodMfaCapable)
}

const resetUserMfa = async (baseEntity: string, userId: string, ctx?: undefined | Record<string, any>): Promise<boolean> => {
  const action = 'resetUserMfa'
  const method = 'GET'
  const body = null
  const path = `/users/${userId}/authentication/methods`
  const r = await helper.doRequest(baseEntity, method, path, body, ctx?.headers ? { headers: ctx?.headers } : undefined)
  if (!r.body?.value) {
    if (r.body?.id) r.body.value = [r.body]
    else throw new Error(`${action} error: invalid response: ${JSON.stringify(r)}`)
  }
  const methods = r.body.value.map((m: any) => { return { 'id': m.id, '@odata.type': m['@odata.type'] } })
  if (methods.length < 1) return false
  const fnArr: { fn: () => Promise<any>, index?: number, objArr?: any, key?: string }[] = []
  for (const m of methods) {
    if (!isMethodMfaCapable(m['@odata.type'])) continue
    const methodName = getAuthMethodCollectionFromODataType(m['@odata.type'])
    if (!methodName) continue
    const path = `/users/${userId}/authentication/${methodName}/${m.id}`
    const fn = () => helper.doRequest(baseEntity, 'DELETE', path, null, ctx?.headers ? { headers: ctx?.headers } : undefined)
    fnArr.push({ fn })
  }
  if (fnArr.length === 0) return false
  // include revoke sessions
  const fn = () => helper.doRequest(baseEntity, 'POST', `/users/${userId}/invalidateAllRefreshTokens`, null, ctx?.headers ? { headers: ctx?.headers } : undefined)
  fnArr.push({ fn })
  await fnCunckExecute(fnArr)
  return true
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

  // 3. Resolve principals (determine if user or group)
  const userIds = new Set<string>()
  const fnArrPrincipalObjects: { fn: () => Promise<any>, index?: number, objArr?: any, key?: string }[] = []
  const principalObjects: any[] = []
  for (const pId of activePrincipals) {
    const path = `/directoryObjects/${pId}`
    fnArrPrincipalObjects.push({ fn: () => helper.doRequest(baseEntity, 'GET', path, null, ctx?.headers ? { headers: ctx?.headers } : undefined), objArr: principalObjects })
  }
  if (fnArrPrincipalObjects.length > 0) await fnCunckExecute(fnArrPrincipalObjects)

  // 4. Handle users directly and fetch transitive members for groups
  const fnArrGroupResults: { fn: () => Promise<any>, index?: number, objArr?: any, key?: string }[] = []
  const groupResults: any[] = []
  for (const obj of principalObjects) {
    if (!obj || !obj.id) continue
    if (obj['@odata.type'] === '#microsoft.graph.user') userIds.add(obj.id)
    else if (obj['@odata.type'] === '#microsoft.graph.group') {
      // fetch all transitive members including paging
      const fetchAllMembers = async (groupId: string) => {
        let members: any[] = []
        let nextPath: string | null = `/groups/${groupId}/transitiveMembers/microsoft.graph.user?$select=id`
        while (nextPath) {
          const res = await helper.doRequest(baseEntity, 'GET', nextPath, null, ctx?.headers ? { headers: ctx?.headers } : undefined)
          if (!res.body?.value) break
          members.push(...res.body.value)
          nextPath = res.body['@odata.nextLink'] ? res.body['@odata.nextLink'].split('/beta')[1] : null
        }
        return { body: { value: members } }
      }
      fnArrGroupResults.push({ fn: () => fetchAllMembers(obj.id), objArr: groupResults })
    }
  }

  if (fnArrGroupResults.length > 0) await fnCunckExecute(fnArrGroupResults)
  groupResults.forEach((m: any) => m.id && userIds.add(m.id.toLowerCase()))

  return Array.from(userIds)
}

/**
* fnCunckExecute runs array of functions asynchronous in chunks
* @param fnArr array of objects that must include function and optionally index, objArr and key [{fn, index, objArr, key}]. Function will always be executed. Any optional objArr will be updated according to provided index/key
* @param fnArr.index optional and represent the index of `objArr` that should be updated with `key` set to the value of the function result
* @param fnArr.objArr optionally array of objects or a single object that will be updated based on fn result. If index, `objArr[index].key` will be set to function result. If key, but no index, function result will be inserted to objArr[key].
* @param fnArr.key optionally key
* @param chunkSize optinally size of chunks used, default 5
* @returns undefined, but updated objArr if objArr is included
**/
const fnCunckExecute = async (fnArr: { fn: () => Promise<any>, index?: number, objArr?: Record<string, any>[] | Record<string, any>, key?: string }[], chunkSize?: number) => {
  if (!Array.isArray(fnArr)) throw new Error(`fnCunckExecute error: fnArr is not array`)
  if (fnArr.length === 0) return
  if (typeof fnArr[0] !== 'object' || !fnArr[0].fn) throw new Error(`fnCunckExecute error: fnArr missing fn object(s)`)
  else if (fnArr[0].index !== undefined && !(fnArr[0].objArr || fnArr[0].key)) throw new Error(`fnCunckExecute error: missing reponseValue/key`)
  if (!chunkSize || chunkSize < 1) chunkSize = 5
  do {
    const arrChunk = fnArr.splice(0, chunkSize)
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
        const objArr: any = arrChunk[idx].objArr
        const key = arrChunk[idx].key
        const index = arrChunk[idx].index
        if (result.value === undefined) return
        const res: any = result.value.body || result.value
        const val = (res && res.value !== undefined) ? res.value : res
        if (typeof index === 'number' && objArr && key) {
          const keyArr = key.split('.')
          if (keyArr.length > 2) throw new Error(`fnCunckExecute error: key ${key} can not be more than 2 levels deep`)
          if (keyArr.length === 2 && !objArr[index][keyArr[0]]) objArr[index][keyArr[0]] = {}
          if (keyArr.length === 1) objArr[index][keyArr[0]] = val
          else objArr[index][keyArr[0]][keyArr[1]] = val
        } else if (index === undefined && objArr) {
          if (key === undefined) { // When index and key are undefined, append to objArr if objArr provided
            if (Array.isArray(objArr)) {
              if (Array.isArray(res.value)) objArr.push(...res.value) // If res.value is an array, spread its elements into objArr
              else objArr.push(res) // Otherwise, push the entire res object
            }
          } else {
            const keyArr = key.split('.')
            if (keyArr.length > 2) throw new Error(`fnCunckExecute error: key ${key} can not be more than 2 levels deep`)
            if (keyArr.length === 2 && !objArr[keyArr[0]]) objArr[keyArr[0]] = {}
            if (keyArr.length === 1) objArr[keyArr[0]] = val
            else objArr[keyArr[0]][keyArr[1]] = val
          }
        }
      }
    })
  } while (fnArr.length > 0)
}

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})
