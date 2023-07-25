// ==================================
// File:    scimdef.js
//
// Author:  Jarle Elshaug
// ==================================

module.exports.ServiceProviderConfigs = {
  "schemas": ["urn:scim:schemas:core:1.0"],
  "id": "urn:scim:schemas:core:1.0",
  "patch": { "supported": true },
  "bulk": {
    "supported": false,
    "maxOperations": 10000,
    "maxPayloadSize": 1048576
  },
  "filter": {
    "supported": true,
    "maxResults": 200
  },
  "changePassword": { "supported": true },
  "sort": { "supported": false },
  "etag": { "supported": false },
  "authenticationSchemes": [
    {
      "type": "httpbasic",
      "name": "HTTP Basic",
      "description": "Authentication scheme using the HTTP Basic Standard",
      "specURI": "http://www.rfc-editor.org/info/rfc2617",
      "documentationUri": "https://elshaug.xyz",
      "primary": true
    },
    {
      "type": "oauthbearertoken",
      "name": "OAuth Bearer Token",
      "description": "Authentication scheme using the OAuth Bearer Token Standard",
      "specUri": "http://www.rfc-editor.org/info/rfc6750",
      "documentationUri": "https://elshaug.xyz"
    },
    {
      "type": "oauth2",
      "name": "OAuth v2.0",
      "description": "Authentication Scheme using the OAuth Standard",
      "specUri": "http://tools.ietf.org/html/rfc6749",
      "documentationUri": "https://elshaug.xyz"
    }
  ],
  "xmlDataFormat": { "supported": false }
}

module.exports.ResourceType = { // not used in scim v1
}

module.exports.Schemas = {
  "Resources": [
    {
      "name": "User",
      "description": "SCIM core resource for representing users",
      "schema": "urn:scim:schemas:core:1.0",
      "endpoint": "Users",
      "attributes": [
        {
          "name": "id",
          "type": "string",
          "multiValued": false,
          "description": "Unique identifier for the SCIM Resource as defined by the Service Provider",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": true,
          "required": true,
          "caseExact": false
        },
        {
          "name": "meta",
          "type": "complex",
          "multiValued": false,
          "description": "A complex type containing metadata about the resource",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false,
          "subAttributes": [
            {
              "name": "created",
              "type": "datetime",
              "multiValued": false,
              "description": "The DateTime the Resource was added to the Service Provider",
              "readOnly": false,
              "required": false,
              "caseExact": false
            },
            {
              "name": "lastModified",
              "type": "datetime",
              "multiValued": false,
              "description": "The most recent DateTime the details of this Resource were updated at the Service Provider",
              "readOnly": false,
              "required": false,
              "caseExact": false
            },
            {
              "name": "location",
              "type": "string",
              "multiValued": false,
              "description": "The URI of the Resource being returned",
              "readOnly": false,
              "required": false,
              "caseExact": false
            },
            {
              "name": "version",
              "type": "string",
              "multiValued": false,
              "description": "The version of the Resource being returned",
              "readOnly": false,
              "required": false,
              "caseExact": false
            },
            {
              "name": "attributes",
              "type": "string",
              "multiValued": true,
              "multiValuedAttributeChildName": "attribute",
              "description": "The names of the attributes to remove from the Resource during a PATCH operation",
              "readOnly": false,
              "required": false,
              "caseExact": false
            }
          ]
        },
        {
          "name": "userName",
          "type": "string",
          "multiValued": false,
          "description": "Unique identifier for the User, typically used by the user\n          to directly authenticate to the Service Provider",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": true,
          "caseExact": false
        },
        {
          "name": "name",
          "type": "complex",
          "multiValued": false,
          "description": "The components of the User's real name",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false,
          "subAttributes": [
            {
              "name": "formatted",
              "type": "string",
              "multiValued": false,
              "description": "The full name, including all middle names, titles,\n              and suffixes as appropriate, formatted for display (e.g. Ms.\n              Barbara Jane Jensen, III.)",
              "readOnly": false,
              "required": true,
              "caseExact": false
            },
            {
              "name": "familyName",
              "type": "string",
              "multiValued": false,
              "description": "The family name of the User, or \"Last Name\" in most\n              Western languages (e.g. Jensen given the full name Ms. Barbara\n              Jane Jensen, III.)",
              "readOnly": false,
              "required": true,
              "caseExact": false
            },
            {
              "name": "middleName",
              "type": "string",
              "multiValued": false,
              "description": "The middle name(s) of the User (e.g. Jane given the full\n              name Ms. Barbara Jane Jensen, III.)",
              "readOnly": false,
              "required": false,
              "caseExact": false
            },
            {
              "name": "givenName",
              "type": "string",
              "multiValued": false,
              "description": "The given name of the User, or \"First Name\" in most\n              Western languages (e.g. Barbara given the full name Ms. Barbara\n              Jane Jensen, III.)",
              "readOnly": false,
              "required": false,
              "caseExact": false
            },
            {
              "name": "honorificPrefix",
              "type": "string",
              "multiValued": false,
              "description": "The honorific prefix(es) of the User, or \"Title\" in most\n              Western languages (e.g. Ms. given the full name Ms. Barbara\n              Jane Jensen, III.)",
              "readOnly": false,
              "required": false,
              "caseExact": false
            },
            {
              "name": "honorificSuffix",
              "type": "string",
              "multiValued": false,
              "description": "The honorific suffix(es) of the User, or \"Suffix\" in most\n              Western languages (e.g. III. given the full name Ms. Barbara\n              Jane Jensen, III.)",
              "readOnly": false,
              "required": false,
              "caseExact": false
            }
          ]
        },
        {
          "name": "displayName",
          "type": "string",
          "multiValued": false,
          "description": "The name of the User, suitable for display to\n          end-users",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false
        },
        {
          "name": "nickName",
          "type": "string",
          "multiValued": false,
          "description": "The casual way to address the user in real life, e.g. \"Bob\"\n          or \"Bobby\" instead of \"Robert\"",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false
        },
        {
          "name": "profileUrl",
          "type": "string",
          "multiValued": false,
          "description": "URL to a page representing the User's online\n          profile",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false
        },
        {
          "name": "title",
          "type": "string",
          "multiValued": false,
          "description": "The User's title, such as \"Vice President\"",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false
        },
        {
          "name": "userType",
          "type": "string",
          "multiValued": false,
          "description": "The organization-to-user relationship",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false
        },
        {
          "name": "preferredLanguage",
          "type": "string",
          "multiValued": false,
          "description": "The User's preferred written or spoken language. Generally\n          used for selecting a localized User interface.  Valid values are\n          concatenation of the ISO 639-1 two-letter language code, an\n          underscore, and the ISO 3166-1 two-letter country code; e.g., 'en_US'\n          specifies the language English and country US",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false
        },
        {
          "name": "locale",
          "type": "string",
          "multiValued": false,
          "description": "Used to indicate the User's default location for purposes of\n          localizing items such as currency, date time format, numerical\n          representations, etc. A locale value is a concatenation of the\n          ISO 639-1 two letter language code an underscore, and the ISO 3166-1\n          2 letter country code; e.g., 'en_US' specifies the language English\n          and country US",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false
        },
        {
          "name": "timezone",
          "type": "string",
          "multiValued": false,
          "description": "The User's time zone in the \"Olson\" timezone database format;\n          e.g.,'America/Los_Angeles'",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false
        },
        {
          "name": "x509Certificates",
          "type": "complex",
          "multiValued": true,
          "multiValuedAttributeChildName": "cert",
          "description": "x509 Certificate",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false,
          "subAttributes": [
            {
              "name": "value",
              "type": "string",
              "multiValued": false,
              "description": "The attribute's significant value",
              "readOnly": false,
              "required": true,
              "caseExact": false
            },
            {
              "name": "type",
              "type": "string",
              "multiValued": false,
              "description": "A label indicating the attribute's function; e.g., \"work\" or \"home\"",
              "readOnly": false,
              "required": false,
              "caseExact": false,
              "canonicalValues": [
                { "value": "cert" },
                { "value": "thumbnail" }
              ]
            }
          ]
        },
        {
          "name": "active",
          "type": "boolean",
          "multiValued": false,
          "description": "A Boolean value indicating the User's administrative\n          status",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false
        },
        {
          "name": "password",
          "type": "string",
          "multiValued": false,
          "description": "The User's clear text password. This attribute is intended\n          to be used as a means to specify an initial password when creating\n          a new User or to reset an existing User's password. This value will\n          never be returned by a Service Provider in any form",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false
        },
        {
          "name": "emails",
          "type": "complex",
          "multiValued": true,
          "multiValuedAttributeChildName": "email",
          "description": "E-mail addresses for the User",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false,
          "subAttributes": [
            {
              "name": "value",
              "type": "string",
              "multiValued": false,
              "description": "The attribute's significant value",
              "readOnly": false,
              "required": true,
              "caseExact": false
            },
            {
              "name": "type",
              "type": "string",
              "multiValued": false,
              "description": "A label indicating the attribute's function; e.g., \"work\" or \"home\"",
              "readOnly": false,
              "required": false,
              "caseExact": false,
              "canonicalValues": [
                { "value": "work" },
                { "value": "home" },
                { "value": "other" }
              ]
            }
          ]
        },
        {
          "name": "phoneNumbers",
          "type": "complex",
          "multiValued": true,
          "multiValuedAttributeChildName": "phoneNumber",
          "description": "Phone numbers for the User",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false,
          "subAttributes": [
            {
              "name": "value",
              "type": "string",
              "multiValued": false,
              "description": "The attribute's significant value",
              "readOnly": false,
              "required": true,
              "caseExact": false
            },
            {
              "name": "type",
              "type": "string",
              "multiValued": false,
              "description": "A label indicating the attribute's function; e.g., \"work\" or \"home\"",
              "readOnly": false,
              "required": false,
              "caseExact": false,
              "canonicalValues": [
                { "value": "work" },
                { "value": "home" },
                { "value": "mobile" },
                { "value": "fax" },
                { "value": "pager" },
                { "value": "other" }
              ]
            }
          ]
        },
        {
          "name": "ims",
          "type": "complex",
          "multiValued": true,
          "multiValuedAttributeChildName": "im",
          "description": "Instant messaging address for the User",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false,
          "subAttributes": [
            {
              "name": "value",
              "type": "string",
              "multiValued": false,
              "description": "The attribute's significant value",
              "readOnly": false,
              "required": true,
              "caseExact": false
            },
            {
              "name": "type",
              "type": "string",
              "multiValued": false,
              "description": "A label indicating the attribute's function; e.g., \"work\" or \"home\"",
              "readOnly": false,
              "required": false,
              "caseExact": false,
              "canonicalValues": [
                { "value": "aim" },
                { "value": "gtalk" },
                { "value": "icq" },
                { "value": "xmpp" },
                { "value": "msn" },
                { "value": "skype" },
                { "value": "qq" },
                { "value": "yahoo" }
              ]
            }
          ]
        },
        {
          "name": "photos",
          "type": "complex",
          "multiValued": true,
          "multiValuedAttributeChildName": "photo",
          "description": "URL of photos of the User",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false,
          "subAttributes": [
            {
              "name": "value",
              "type": "string",
              "multiValued": false,
              "description": "The attribute's significant value",
              "readOnly": false,
              "required": true,
              "caseExact": false
            },
            {
              "name": "type",
              "type": "string",
              "multiValued": false,
              "description": "A label indicating the attribute's function; e.g., \"work\" or \"home\"",
              "readOnly": false,
              "required": false,
              "caseExact": false,
              "canonicalValues": [
                { "value": "photo" },
                { "value": "thumbnail" }
              ]
            }
          ]
        },
        {
          "name": "addresses",
          "type": "complex",
          "multiValued": true,
          "multiValuedAttributeChildName": "address",
          "description": "The full mailing address, formatted for display or use with\n          a mailing label",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false,
          "subAttributes": [
            {
              "name": "formatted",
              "type": "string",
              "multiValued": false,
              "description": "The full street address component, which may include\n              house number, street name, P.O. box, and multi-line extended\n              street address information",
              "readOnly": false,
              "required": false,
              "caseExact": false
            },
            {
              "name": "streetAddress",
              "type": "string",
              "multiValued": false,
              "description": "The full street address component, which may include\n              house number, street name, P.O. box, and multi-line extended\n              street address information",
              "readOnly": false,
              "required": false,
              "caseExact": false
            },
            {
              "name": "locality",
              "type": "string",
              "multiValued": false,
              "description": "The city or locality component",
              "readOnly": false,
              "required": false,
              "caseExact": false
            },
            {
              "name": "region",
              "type": "string",
              "multiValued": false,
              "description": "The state or region component",
              "readOnly": false,
              "required": false,
              "caseExact": false
            },
            {
              "name": "postalCode",
              "type": "string",
              "multiValued": false,
              "description": "The zipcode or postal code component",
              "readOnly": false,
              "required": false,
              "caseExact": false
            },
            {
              "name": "country",
              "type": "string",
              "multiValued": false,
              "description": "The country name component",
              "readOnly": false,
              "required": false,
              "caseExact": false
            },
            {
              "name": "type",
              "type": "string",
              "multiValued": false,
              "description": "A label indicating the attribute's function; e.g., \"work\" or \"home\"",
              "readOnly": false,
              "required": false,
              "caseExact": false,
              "canonicalValues": [
                { "value": "work" },
                { "value": "home" },
                { "value": "other" }
              ]
            }
          ]
        },
        {
          "name": "groups",
          "type": "complex",
          "multiValued": true,
          "multiValuedAttributeChildName": "group",
          "description": "A list of groups that the user belongs to",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": true,
          "required": false,
          "caseExact": false,
          "subAttributes": [
            {
              "name": "value",
              "type": "string",
              "multiValued": false,
              "description": "The attribute's significant value",
              "readOnly": false,
              "required": true,
              "caseExact": false
            },
            {
              "name": "type",
              "type": "string",
              "multiValued": false,
              "description": "A label indicating the attribute's function; e.g., \"work\" or \"home\"",
              "readOnly": false,
              "required": false,
              "caseExact": false,
              "canonicalValues": [
                { "value": "direct" },
                { "value": "indirect" }
              ]
            }
          ]
        },
        {
          "name": "entitlements",
          "type": "complex",
          "multiValued": true,
          "multiValuedAttributeChildName": "entitlement",
          "description": "A list of entitlements for the User that represent a thing\n          the User has. That is, an entitlement is an additional right to a\n          thing, object or service",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false,
          "subAttributes": [
            {
              "name": "value",
              "type": "string",
              "multiValued": false,
              "description": "The attribute's significant value",
              "readOnly": false,
              "required": true,
              "caseExact": false
            },
            {
              "name": "type",
              "type": "string",
              "multiValued": false,
              "description": "A label indicating the attribute's function; e.g., \"work\" or \"home\"",
              "readOnly": false,
              "required": false,
              "caseExact": false,
              "canonicalValues": [{ "value": "newentitlement" }]
            }
          ]
        },
        {
          "name": "roles",
          "type": "complex",
          "multiValued": true,
          "multiValuedAttributeChildName": "role",
          "description": "A list of roles for the User that collectively represent who\n          the User is",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false,
          "subAttributes": [
            {
              "name": "value",
              "type": "string",
              "multiValued": false,
              "description": "The attribute's significant value",
              "readOnly": false,
              "required": true,
              "caseExact": false
            },
            {
              "name": "type",
              "type": "string",
              "multiValued": false,
              "description": "A label indicating the attribute's function; e.g., \"work\" or \"home\"",
              "readOnly": false,
              "required": false,
              "caseExact": false,
              "canonicalValues": [{ "value": "newrole" }]
            }
          ]
        },
        {
          "name": "employeeNumber",
          "type": "string",
          "multiValued": false,
          "description": "Numeric or alphanumeric identifier assigned to a person,\n          typically based on order of hire or association with an\n          organization",
          "schema": "urn:scim:schemas:extension:enterprise:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false
        },
        {
          "name": "organization",
          "type": "string",
          "multiValued": false,
          "description": "Identifies the name of an organization",
          "schema": "urn:scim:schemas:extension:enterprise:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false
        },
        {
          "name": "division",
          "type": "string",
          "multiValued": false,
          "description": "Identifies the name of a division",
          "schema": "urn:scim:schemas:extension:enterprise:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false
        },
        {
          "name": "department",
          "type": "string",
          "multiValued": false,
          "description": "Identifies the name of a department",
          "schema": "urn:scim:schemas:extension:enterprise:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false
        },
        {
          "name": "manager",
          "type": "complex",
          "multiValued": false,
          "description": "The User's manager",
          "schema": "urn:scim:schemas:extension:enterprise:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false,
          "subAttributes": [
            {
              "name": "managerId",
              "type": "string",
              "multiValued": false,
              "description": "The id of the SCIM resource representing the User's\n              manager",
              "readOnly": false,
              "required": true,
              "caseExact": false
            },
            {
              "name": "displayName",
              "type": "string",
              "multiValued": false,
              "description": "The displayName of the User's manager",
              "readOnly": true,
              "required": false,
              "caseExact": false
            }
          ]
        }
      ],
      "id": "urn:scim:schemas:core:1.0:User",
      "meta": { "location": "/Schemas/urn:scim:schemas:core:1.0:User" }
    },
    {
      "name": "Group",
      "description": "SCIM core resource for representing groups",
      "schema": "urn:scim:schemas:core:1.0",
      "endpoint": "Groups",
      "attributes": [
        {
          "name": "id",
          "type": "string",
          "multiValued": false,
          "description": "Unique identifier for the SCIM Resource as defined by the Service Provider",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": true,
          "required": true,
          "caseExact": false
        },
        {
          "name": "meta",
          "type": "complex",
          "multiValued": false,
          "description": "A complex type containing metadata about the resource",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false,
          "subAttributes": [
            {
              "name": "created",
              "type": "datetime",
              "multiValued": false,
              "description": "The DateTime the Resource was added to the Service Provider",
              "readOnly": false,
              "required": false,
              "caseExact": false
            },
            {
              "name": "lastModified",
              "type": "datetime",
              "multiValued": false,
              "description": "The most recent DateTime the details of this Resource were updated at the Service Provider",
              "readOnly": false,
              "required": false,
              "caseExact": false
            },
            {
              "name": "location",
              "type": "string",
              "multiValued": false,
              "description": "The URI of the Resource being returned",
              "readOnly": false,
              "required": false,
              "caseExact": false
            },
            {
              "name": "version",
              "type": "string",
              "multiValued": false,
              "description": "The version of the Resource being returned",
              "readOnly": false,
              "required": false,
              "caseExact": false
            },
            {
              "name": "attributes",
              "type": "string",
              "multiValued": true,
              "multiValuedAttributeChildName": "attribute",
              "description": "The names of the attributes to remove from the Resource during a PATCH operation",
              "readOnly": false,
              "required": false,
              "caseExact": false
            }
          ]
        },
        {
          "name": "displayName",
          "type": "string",
          "multiValued": false,
          "description": "A human readable name for the Group",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": true,
          "caseExact": false
        },
        {
          "name": "members",
          "type": "complex",
          "multiValued": true,
          "multiValuedAttributeChildName": "member",
          "description": "A list of members of the Group",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false,
          "subAttributes": [
            {
              "name": "value",
              "type": "string",
              "multiValued": false,
              "description": "The attribute's significant value",
              "readOnly": false,
              "required": true,
              "caseExact": false
            },
            {
              "name": "type",
              "type": "string",
              "multiValued": false,
              "description": "A label indicating the attribute's function; e.g., \"work\" or \"home\"",
              "readOnly": false,
              "required": false,
              "caseExact": false,
              "canonicalValues": [
                { "value": "User" },
                { "value": "Group" }
              ]
            }
          ]
        }
      ],
      "id": "urn:scim:schemas:core:1.0:Group",
      "meta": { "location": "/Schemas/urn:scim:schemas:core:1.0:Group" }
    },

    { // Custom SCIM
      "name": "servicePlan",
      "description": "SCIM core resource for representing AAD ServicePlan",
      "schema": "urn:scim:schemas:core:1.0",
      "endpoint": "servicePlans",
      "attributes": [
        {
          "name": "id",
          "type": "string",
          "multiValued": false,
          "description": "Unique identifier for the SCIM Resource as defined by the Service Provider",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": true,
          "required": true,
          "caseExact": false
        },
        {
          "name": "skuId",
          "type": "string",
          "multiValued": false,
          "description": "A human readable name for the ServicePlan",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": true,
          "caseExact": false
        },
        {
          "name": "skuPartNumber",
          "type": "string",
          "multiValued": false,
          "description": "A human readable name for the ServicePlan",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": true,
          "caseExact": false
        },
        {
          "name": "members",
          "type": "complex",
          "multiValued": true,
          "multiValuedAttributeChildName": "member",
          "description": "A list of members of the ServicePlan",
          "schema": "urn:scim:schemas:core:1.0",
          "readOnly": false,
          "required": false,
          "caseExact": false,
          "subAttributes": [
            {
              "name": "value",
              "type": "string",
              "multiValued": false,
              "description": "The attribute's significant value",
              "readOnly": false,
              "required": true,
              "caseExact": false
            },
            {
              "name": "type",
              "type": "string",
              "multiValued": false,
              "description": "A label indicating the attribute's function; e.g., \"work\" or \"home\"",
              "readOnly": false,
              "required": false,
              "caseExact": false,
              "canonicalValues": [
                { "value": "User" },
                { "value": "ServicePlan" }
              ]
            }
          ]
        }
        
      ],
      "id": "urn:scim:schemas:core:1.0:ServicePlan",
      "meta": { "location": "/Schemas/urn:scim:schemas:core:1.0:ServicePlan" }
    }

  ]
}

//==============================================================//
//======= Dummy testdata used by testmode (loki-plugin)  =======//
//==============================================================//

module.exports.TestmodeUsers = {
  "Resources": [
    {
      "id": "bjensen",
      "externalId": "bjensen",
      "userName": "bjensen",
      "name": {
        "formatted": "Ms. Barbara J Jensen, III",
        "familyName": "Jensen",
        "givenName": "Barbara",
        "middleName": "Jane",
        "honorificPrefix": "Ms.",
        "honorificSuffix": "III"
      },
      "displayName": "Babs Jensen",
      "nickName": "Babs",
      "profileUrl": "https://login.example.com/bjensen",
      "emails": [
        {
          "value": "bjensen@example.com",
          "type": "work",
          "primary": true
        },
        {
          "value": "babs@jensen.org",
          "type": "home"
        }
      ],
      "addresses": [
        {
          "streetAddress": "100 Universal City Plaza",
          "locality": "Hollywood",
          "region": "CA",
          "postalCode": "91608",
          "country": "USA",
          "formatted": "100 Universal City Plaza\nHollywood, CA 91608 USA",
          "type": "work",
          "primary": true
        },
        {
          "streetAddress": "456 Hollywood Blvd",
          "locality": "Hollywood",
          "region": "CA",
          "postalCode": "91608",
          "country": "USA",
          "formatted": "456 Hollywood Blvd\nHollywood, CA 91608 USA",
          "type": "home"
        }
      ],
      "phoneNumbers": [
        {
          "value": "555-555-5555",
          "type": "work"
        },
        {
          "value": "555-555-4444",
          "type": "mobile"
        }
      ],
      "roles": [
        {
        "value": "Role-A"
        }
      ],
      "ims": [
        {
          "value": "someaimhandle",
          "type": "aim"
        }
      ],
      "photos": [
        {
          "value":
            "https://photos.example.com/profilephoto/72930000000Ccne/F",
          "type": "photo"
        },
        {
          "value":
            "https://photos.example.com/profilephoto/72930000000Ccne/T",
          "type": "thumbnail"
        }
      ],
      "entitlements": [
        {
        "value": "bjensen entitlement",
        "type": "newentitlement"
        }
      ],
      "userType": "Employee",
      "title": "Tour Guide",
      "preferredLanguage": "en-US",
      "locale": "en-US",
      "timezone": "America/Los_Angeles",
      "active": true,
      "password": "t1meMa$heen",
      "x509Certificates": [
        {
        "value": "MIIDQzCCAqy...",
        }
      ],
      "urn:scim:schemas:extension:enterprise:1.0": {
        "employeeNumber": "701984",
        "division": "Theme Park",
        "department": "Tour Operations",
        "manager": {
          "managerId": "jsmith",
          "displayName": "John Smith"
        }
      },
      "meta": {
        "created": "2016-01-11T08:42:21.596Z",
        "lastModified": "2016-01-11T08:42:21.596Z",
        "location": "https://example.com/v1/Users/bjensen",
        "version": "\"20160111084221.596Z\""
      }
    },
    {
      "id": "jsmith",
      "externalId": "jsmith",
      "userName": "jsmith",
      "name": {
        "formatted": "Mr. John Smith",
        "familyName": "Smith",
        "givenName": "John",
        "middleName": "",
        "honorificPrefix": "Mr.",
        "honorificSuffix": "III"
      },
      "displayName": "John Smith",
      "nickName": "JohnS",
      "profileUrl": "https://login.example.com/johns",
      "emails": [
        {
          "value": "jsmith@example.com",
          "type": "work",
          "primary": true
        },
        {
          "value": "john@smith.org",
          "type": "home"
        }
      ],
      "addresses": [
        {
          "streetAddress": "100 Universal City Plaza",
          "locality": "Hollywood",
          "region": "CA",
          "postalCode": "91608",
          "country": "USA",
          "formatted": "100 Universal City Plaza\nHollywood, CA 91608 USA",
          "type": "work",
          "primary": true
        },
        {
          "streetAddress": "987 Highstreet",
          "locality": "New York",
          "region": "CA",
          "postalCode": "12345",
          "country": "USA",
          "formatted": "987 Highstreet\nNew York, CA 12345 USA",
          "type": "home"
        }
      ],
      "phoneNumbers": [
        {
          "value": "555-555-1256",
          "type": "work"
        },
        {
          "value": "555-555-6521",
          "type": "mobile"
        }
      ],
      "roles": [
        {
        "value": "Role-B"
        }
      ],
      "ims": [
        {
          "value": "anything",
          "type": "aim"
        }
      ],
      "photos": [
        {
          "value":
            "https://photos.example.com/profilephoto/12340000000Ccne/F",
          "type": "photo"
        },
        {
          "value":
            "https://photos.example.com/profilephoto/12340000000Ccne/T",
          "type": "thumbnail"
        }
      ],
      "entitlements": [
        {
        "value": "jsmith entitlement",
        "type": "newentitlement"
        }
      ],
      "userType": "Employee",
      "title": "Consultant",
      "preferredLanguage": "en-US",
      "locale": "en-US",
      "timezone": "America/Los_Angeles",
      "active": true,
      "password": "MySecret",
      "x509Certificates": [
        {
        "value": "MIIDQzCCAqy...",
        }
      ],
      "urn:scim:schemas:extension:enterprise:1.0": {
        "employeeNumber": "991999",
        "organization": "Universal Studios",
        "division": "Theme Park",
        "department": "Tour Operations",
        "manager": {
          "managerId": "bjensen",
          "displayName": "Babs Jensen"
        }
      },
      "meta": {
        "created": "2016-01-11T08:42:21.597Z",
        "lastModified": "2016-01-11T08:42:21.597Z",
        "location": "https://example.com/v1/Users/jsmith",
        "version": "\"20160111084221.597Z\""
      }
    }
  ]
}

module.exports.TestmodeGroups = {
  "Resources": [{
    "displayName": "Admins",
    "id": "Admins",
    "members": [
      {
        "value": "bjensen",
        "display": "Babs Jensen"
      }
    ],
    "meta": {
      "created": "2010-01-23T04:56:22Z",
      "lastModified": "2011-05-13T04:42:34Z",
      "location": "https://example.com/v1/Groups/Admins",
      "version": "W\/\"3694e05e9dff592\""
    }
  },
  {
    "displayName": "Employees",
    "id": "Employees",
    "members": [
      {
        "value": "jsmith",
        "display": "John Smith"
      }
    ],
    "meta": {
      "created": "2010-01-23T04:56:22Z",
      "lastModified": "2011-05-13T04:42:34Z",
      "location": "https://example.com/v1/Groups/Employees",
      "version": "W\/\"3694e05e9dff592\""
    }
  }
  ]
}