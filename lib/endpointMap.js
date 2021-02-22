// ============================================================================
// File:    endpointMap.js
// Author:  Jarle Elshaug
// Purpose: Maps enpoint attributes to SCIM/CustomSCIM attributes
//          Used by method scimgateway.endpointMapper
//
// Plugin examples:
//   let parsedAttr = scimgateway.endpointMapper('outbound', attributes, scimgateway.endpointMap.microsoftGraphUser)
//   let parsedAttr = scimgateway.endpointMapper('inbound', attributes, scimgateway.endpointMap.microsoftGraphUser)
// ============================================================================

//
// User mapping - used by plugin-azure-aad.js
//
module.exports.microsoftGraphUser = {
  'id': {
    'mapTo': 'id', // mandatory
    'type': 'string'
  },
  'userPrincipalName': {
    'mapTo': 'userName', // mandatory - changed
    'type': 'string'
  },
  'accountEnabled': {
    'mapTo': 'active', // changed
    'type': 'boolean'
  },
  'assignedLicenses': {
    'mapTo': 'assignedLicenses',
    'type': 'array'
  },
  'assignedPlans': {
    'mapTo': 'assignedPlans',
    'type': 'array'
  },
  'businessPhones': { // singleton value
    'mapTo': 'businessPhones',
    'type': 'array' // changed
  },
  'city': {
    'mapTo': 'city',
    'type': 'string'
  },
  'companyName': {
    'mapTo': 'companyName',
    'type': 'string'
  },
  'country': {
    'mapTo': 'country',
    'type': 'string'
  },
  'department': {
    'mapTo': 'department',
    'type': 'string'
  },
  'displayName': {
    'mapTo': 'displayName',
    'type': 'string'
  },
  'givenName': {
    'mapTo': 'name.givenName', // changed
    'type': 'string'
  },
  'imAddresses': {
    'mapTo': 'imAddresses',
    'type': 'array'
  },
  'jobTitle': {
    'mapTo': 'jobTitle',
    'type': 'string'
  },
  'mail': {
    'mapTo': 'mail',
    'type': 'string'
  },
  'mailNickname': {
    'mapTo': 'mailNickname',
    'type': 'string'
  },
  'manager': {
    'mapTo': 'manager.managerId', // changed
    'type': 'string'
  },
  'mobilePhone': {
    'mapTo': 'mobilePhone',
    'type': 'string'
  },
  'onPremisesImmutableId': {
    'mapTo': 'onPremisesImmutableId',
    'type': 'string'
  },
  'onPremisesLastSyncDateTime': {
    'mapTo': 'onPremisesLastSyncDateTime',
    'type': 'string'
  },
  'onPremisesSecurityIdentifier': {
    'mapTo': 'onPremisesSecurityIdentifier',
    'type': 'string'
  },
  'onPremisesSyncEnabled': {
    'mapTo': 'onPremisesSyncEnabled',
    'type': 'boolean'
  },
  'passwordPolicies': {
    'mapTo': 'passwordPolicies',
    'type': 'string'
  },
  'passwordProfile.forceChangePasswordNextSignIn': { // changed
    'mapTo': 'passwordProfile.forceChangePasswordNextSignIn',
    'type': 'string'
  },
  'passwordProfile.password': { // changed
    'mapTo': 'passwordProfile.password',
    'type': 'string'
  },
  'officeLocation': {
    'mapTo': 'officeLocation',
    'type': 'string'
  },
  'postalCode': {
    'mapTo': 'postalCode',
    'type': 'string'
  },
  'preferredLanguage': {
    'mapTo': 'preferredLanguage',
    'type': 'string'
  },
  'provisionedPlans': {
    'mapTo': 'provisionedPlans',
    'type': 'array'
  },
  'proxyAddresses': {
    'mapTo': 'proxyAddresses.value', // changed
    'type': 'array',
    'items': {
      'type': 'string'
    }
  },
  'servicePlan': { // added
    'mapTo': 'servicePlan.value',
    'type': 'array'
  },
  'state': {
    'mapTo': 'state',
    'type': 'string'
  },
  'streetAddress': {
    'mapTo': 'streetAddress',
    'type': 'string'
  },
  'surname': {
    'mapTo': 'name.familyName', // changed
    'type': 'string'
  },
  'usageLocation': {
    'mapTo': 'usageLocation',
    'type': 'string'
  },
  'userType': {
    'mapTo': 'userType',
    'type': 'string'
  },
  'mailboxSettings': {
    'mapTo': 'mailboxSettings',
    'type': 'string'
  },
  'aboutMe': {
    'mapTo': 'aboutMe',
    'type': 'string'
  },
  'birthday': {
    'mapTo': 'birthday',
    'type': 'string'
  },
  'hireDate': {
    'mapTo': 'hireDate',
    'type': 'string'
  },
  'interests': {
    'mapTo': 'interests',
    'type': 'array'
  },
  'mySite': {
    'mapTo': 'mySite',
    'type': 'string'
  },
  'pastProjects': {
    'mapTo': 'pastProjects',
    'type': 'array'
  },
  'preferredName': {
    'mapTo': 'preferredName',
    'type': 'string'
  },
  'responsibilities': {
    'mapTo': 'responsibilities',
    'type': 'array'
  },
  'schools': {
    'mapTo': 'schools',
    'type': 'array'
  },
  'skills': {
    'mapTo': 'skills',
    'type': 'array'
  }
}

//
// Group mapping - used by plugin-azure-aad.js
//
module.exports.microsoftGraphGroup = {
  'id': { // mandatory
    'mapTo': 'id',
    'type': 'string'
  },
  'displayName': { // mandatory
    'mapTo': 'displayName',
    'type': 'string'
  },
  'members.value': { // new - no mapping changes - plugin could exclude on outbound but needs to be included on inbound
    'mapTo': 'members.value',
    'type': 'string'
  },
  'classification': {
    'mapTo': 'classification',
    'type': 'string'
  },
  'description': {
    'mapTo': 'description',
    'type': 'string'
  },
  'groupTypes': {
    'mapTo': 'groupTypes',
    'type': 'array',
    'items': {
      'type': 'string'
    }
  },
  'mail': {
    'mapTo': 'mail',
    'type': 'string'
  },
  'mailEnabled': {
    'mapTo': 'mailEnabled',
    'type': 'boolean'
  },
  'mailNickname': {
    'mapTo': 'mailNickname',
    'type': 'string'
  },
  'onPremisesLastSyncDateTime': {
    'mapTo': 'onPremisesLastSyncDateTime',
    'type': 'string',
    'format': 'date-time'
  },
  'onPremisesSecurityIdentifier': {
    'mapTo': 'onPremisesSecurityIdentifier',
    'type': 'string'
  },
  'onPremisesSyncEnabled': {
    'mapTo': 'onPremisesSyncEnabled',
    'type': 'boolean'
  },
  'proxyAddresses': {
    'mapTo': 'proxyAddresses.value', // changed
    'type': 'array',
    'items': {
      'type': 'string'
    }
  },
  'securityEnabled': {
    'mapTo': 'securityEnabled',
    'type': 'boolean'
  },
  'visibility': {
    'mapTo': 'visibility',
    'type': 'string'
  },
  'allowExternalSenders': {
    'mapTo': 'allowExternalSenders',
    'type': 'boolean'
  },
  'autoSubscribeNewMembers': {
    'mapTo': 'autoSubscribeNewMembers',
    'type': 'boolean'
  },
  'isSubscribedByMail': {
    'mapTo': 'isSubscribedByMail',
    'type': 'boolean'
  },
  'unseenCount': {
    'mapTo': 'unseenCount',
    'type': 'integer'
  }
}

module.exports.microsoftGraphLicenseDetails = { // also includes servicePlanInfo
  /*
  'id': {
    'mapTo': 'id',
    'type': 'string'
  }, */
  'servicePlans': {
    'mapTo': 'servicePlans',
    'type': 'array'
  },
  'skuId': {
    'mapTo': 'skuId',
    'type': 'string'
  },
  'skuPartNumber': {
    'mapTo': 'skuPartNumber',
    'type': 'string'
  },
  'servicePlanId': {
    'mapTo': 'id', // changed
    'type': 'string'
  },
  'servicePlanName': { // (skuPartNumber::servicePlanName)
    'mapTo': 'servicePlanName',
    'type': 'string'
  },
  'provisioningStatus': {
    'mapTo': 'provisioningStatus',
    'type': 'string'
  },
  'appliesTo': {
    'mapTo': 'appliesTo',
    'type': 'string'
  }
}
