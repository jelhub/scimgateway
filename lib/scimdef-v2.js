//==================================
// File:    scimdef.js
//
// Author:  Jarle Elshaug
//==================================

module.exports.ServiceProviderConfigs = {
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
  "patch": {
    "supported": true
  },
  "bulk": {
    "supported": false,
    "maxPayloadSize": 1048576,
    "maxOperations": 1000
  },
  "filter": {
    "supported": true,
    "maxResults": 200
  },
  "changePassword": {
    "supported": true
  },
  "sort": {
    "supported": false
  },
  "etag": {
    "supported": false
  },
  "documentationUri": "http://example.com/help/scim.html",
  "authenticationSchemes": [
    {
      "name": "HTTP Basic",
      "description": "Authentication scheme using the HTTP Basic Standard",
      "specURI": "http://www.rfc-editor.org/info/rfc2617",
      "documentationUri": "http://en.wikipedia.org/wiki/Basic_access_authentication",
      "type": "httpbasic",
      "primary": true
    }
  ],
  "xmlDataFormat": { "supported": false }
}

module.exports.ResourceType = {
  "totalResults": 2,
  "itemsPerPage": 2,
  "startIndex": 1,
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "Resources": [{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
    "id": "urn:ietf:params:scim:schemas:core:2.0:User",
    "name": "User",
    "endpoint": "/Users",
    "description": "User Account",
    "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
    "schemaExtensions": [{
      "schema":
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
      "required": false
    }],
    "meta": {
      "resourceType": "ResourceType",
      "location":
        "/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"
    }
  },
  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
    "id": "urn:ietf:params:scim:schemas:core:2.0:Group",
    "name": "Group",
    "endpoint": "/Groups",
    "description": "Group",
    "schema": "urn:ietf:params:scim:schemas:core:2.0:Group",
    "meta": {
      "resourceType": "Schema",
      "location":
        "/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group"
    }
  }]
}

module.exports.Schemas = {
  "Resources":
    [
      {
        "id": "urn:ietf:params:scim:schemas:core:2.0:User",
        "name": "User",
        "description": "User Account",
        "attributes": [
          {
            "name": "userName",
            "type": "string",
            "multiValued": false,
            "description": "Unique identifier for the User typically usedby the user to directly authenticate to the service provider. Each User MUST include a non-empty userName value.  This identifier MUST be unique across the Service Consumer's entire set of Users.  REQUIRED",
            "required": true,
            "caseExact": false,
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "server"
          },
          {
            "name": "name",
            "type": "complex",
            "multiValued": false,
            "description": "The components of the user's real name. Providers MAY return just the full name as a single string in the formatted sub-attribute, or they MAY return just the individual component attributes using the other sub-attributes, or they MAY return both. If both variants are returned, they SHOULD be describing the same name, with the formatted name indicating how the component attributes should be combined.",
            "required": false,
            "subAttributes": [
              {
                "name": "formatted",
                "type": "string",
                "multiValued": false,
                "description": "The full name, including all middle names, titles, and suffixes as appropriate, formatted for display (e.g., Ms.Barbara J Jensen, III.).",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "familyName",
                "type": "string",
                "multiValued": false,
                "description": "The family name of the User, or Last Namein most Western languages (e.g. Jensen given the full name Ms. Barbara JJensen, III.).",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "givenName",
                "type": "string",
                "multiValued": false,
                "description": "The given name of the User, or First Namein most Western languages (e.g. Barbara given the full name Ms. BarbaraJ Jensen, III.).",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "middleName",
                "type": "string",
                "multiValued": false,
                "description": "The middle name(s) of the User (e.g. Robert given the full name Ms. Barbara J Jensen, III.).",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "honorificPrefix",
                "type": "string",
                "multiValued": false,
                "description": "The honorific prefix(es) of the User, or Title in most Western languages (e.g., Ms. given the full name Ms.  Barbara J Jensen, III.).",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "honorificSuffix",
                "type": "string",
                "multiValued": false,
                "description": "The honorific suffix(es) of the User, or Suffix in most Western languages (e.g., III. given the full name Ms. Barbara J Jensen, III.).",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              }
            ],
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "displayName",
            "type": "string",
            "multiValued": false,
            "description": "The name of the User, suitable for display to end-users. The name SHOULD be the full name of the User being described if known",
            "required": false,
            "caseExact": false,
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "nickName",
            "type": "string",
            "multiValued": false,
            "description": "The casual way to address the user in real life, e.g.'Bob' or 'Bobby' instead of 'Robert'. This attribute SHOULD NOT be used to represent a User's username (e.g., bjensen or mpepperidge)",
            "required": false,
            "caseExact": false,
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "profileUrl",
            "type": "reference",
            "referenceTypes": ["external"],
            "multiValued": false,
            "description": "A fully qualified URL to a page representing the User's online profile",
            "required": false,
            "caseExact": false,
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "title",
            "type": "string",
            "multiValued": false,
            "description": "The user's title, such as \"Vice President.\"",
            "required": false,
            "caseExact": false,
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "userType",
            "type": "string",
            "multiValued": false,
            "description": "Used to identify the organization to user relationship. Typical values used might be 'Contractor', 'Employee', 'Intern', 'Temp', 'External', and 'Unknown' but any value may be used.",
            "required": false,
            "caseExact": false,
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "preferredLanguage",
            "type": "string",
            "multiValued": false,
            "description": "Indicates the User's preferred written or spoken language.  Generally used for selecting a localized User interface. e.g., 'en_US' specifies the language English and country US.",
            "required": false,
            "caseExact": false,
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "locale",
            "type": "string",
            "multiValued": false,
            "description": "Used to indicate the User's default location for purposes of localizing items such as currency, date time format, numerical representations, etc.",
            "required": false,
            "caseExact": false,
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "timezone",
            "type": "string",
            "multiValued": false,
            "description": "The User's time zone in the 'Olson' timezone database format; e.g.,'America/Los_Angeles'",
            "required": false,
            "caseExact": false,
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "active",
            "type": "boolean",
            "multiValued": false,
            "description": "A Boolean value indicating the User's administrative status.",
            "required": false,
            "mutability": "readWrite",
            "returned": "default"
          },
          {
            "name": "password",
            "type": "string",
            "multiValued": false,
            "description": "The User's clear text password.  This attribute is intended to be used as a means to specify an initial password when creating a new User or to reset an existing User's password.",
            "required": false,
            "caseExact": false,
            "mutability": "writeOnly",
            "returned": "never",
            "uniqueness": "none"
          },
          {
            "name": "emails",
            "type": "complex",
            "multiValued": true,
            "description": "E-mail addresses for the user. The value SHOULD be canonicalized by the Service Provider, e.g., bjensen@example.com instead of bjensen@EXAMPLE.COM. Canonical Type values of work, home, and other.",
            "required": false,
            "subAttributes": [
              {
                "name": "value",
                "type": "string",
                "multiValued": false,
                "description": "E-mail addresses for the user. The value SHOULD be canonicalized by the Service Provider, e.g. bjensen@example.com instead of bjensen@EXAMPLE.COM. Canonical Type values of work, home, and other.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "display",
                "type": "string",
                "multiValued": false,
                "description": "A human readable name, primarily used for display purposes. READ-ONLY.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "type",
                "type": "string",
                "multiValued": false,
                "description": "A label indicating the attribute's function; e.g., 'work' or 'home'.",
                "required": false,
                "caseExact": false,
                "canonicalValues": [
                  "work",
                  "home",
                  "other"
                ],
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "primary",
                "type": "boolean",
                "multiValued": false,
                "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute, e.g., the preferred mailing address or primary e-mail address. The primary attribute value 'true' MUST appear no more than once.",
                "required": false,
                "mutability": "readWrite",
                "returned": "default"
              }
            ],
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "phoneNumbers",
            "type": "complex",
            "multiValued": true,
            "description": "Phone numbers for the User.  The value SHOULD be canonicalized by the Service Provider according to format in RFC3966 e.g., 'tel:+1-201-555-0123'.  Canonical Type values of work, home, mobile, fax, pager and other.",
            "required": false,
            "subAttributes": [
              {
                "name": "value",
                "type": "string",
                "multiValued": false,
                "description": "Phone number of the User",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "display",
                "type": "string",
                "multiValued": false,
                "description": "A human readable name, primarily used for display purposes. READ-ONLY.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "type",
                "type": "string",
                "multiValued": false,
                "description": "A label indicating the attribute's function; e.g., 'work' or 'home' or 'mobile' etc.",
                "required": false,
                "caseExact": false,
                "canonicalValues": [
                  "work",
                  "home",
                  "mobile",
                  "fax",
                  "pager",
                  "other"
                ],
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "primary",
                "type": "boolean",
                "multiValued": false,
                "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute, e.g., the preferred phone number or primary phone number. The primary attribute value 'true' MUST appear no more than once.",
                "required": false,
                "mutability": "readWrite",
                "returned": "default"
              }
            ],
            "mutability": "readWrite",
            "returned": "default"
          },
          {
            "name": "ims",
            "type": "complex",
            "multiValued": true,
            "description": "Instant messaging addresses for the User.",
            "required": false,
            "subAttributes": [
              {
                "name": "value",
                "type": "string",
                "multiValued": false,
                "description": "Instant messaging address for the User.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "display",
                "type": "string",
                "multiValued": false,
                "description": "A human readable name, primarily used for display purposes. READ-ONLY.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "type",
                "type": "string",
                "multiValued": false,
                "description": "A label indicating the attribute's function; e.g., 'aim', 'gtalk', 'mobile' etc.",
                "required": false,
                "caseExact": false,
                "canonicalValues": [
                  "aim",
                  "gtalk",
                  "icq",
                  "xmpp",
                  "msn",
                  "skype",
                  "qq",
                  "yahoo"
                ],
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "primary",
                "type": "boolean",
                "multiValued": false,
                "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute, e.g., the preferred messenger or primary messenger. The primary attribute value 'true' MUST appear no more than once.",
                "required": false,
                "mutability": "readWrite",
                "returned": "default"
              }
            ],
            "mutability": "readWrite",
            "returned": "default"
          },
          {
            "name": "photos",
            "type": "complex",
            "multiValued": true,
            "description": "URLs of photos of the User.",
            "required": false,
            "subAttributes": [
              {
                "name": "value",
                "type": "reference",
                "referenceTypes": ["external"],
                "multiValued": false,
                "description": "URL of a photo of the User.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "display",
                "type": "string",
                "multiValued": false,
                "description": "A human readable name, primarily used for display purposes. READ-ONLY.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "type",
                "type": "string",
                "multiValued": false,
                "description": "A label indicating the attribute's function; e.g., 'photo' or 'thumbnail'.",
                "required": false,
                "caseExact": false,
                "canonicalValues": [
                  "photo",
                  "thumbnail"
                ],
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "primary",
                "type": "boolean",
                "multiValued": false,
                "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute, e.g., the preferred photo or thumbnail. The primary attribute value 'true' MUST appear no more than once.",
                "required": false,
                "mutability": "readWrite",
                "returned": "default"
              }
            ],
            "mutability": "readWrite",
            "returned": "default"
          },
          {
            "name": "addresses",
            "type": "complex",
            "multiValued": true,
            "description": "A physical mailing address for this User, as described in (address Element). Canonical Type Values of work, home, and other. The value attribute is a complex type with the following sub-attributes.",
            "required": false,
            "subAttributes": [
              {
                "name": "formatted",
                "type": "string",
                "multiValued": false,
                "description": "The full mailing address, formatted for display or use with a mailing label. This attribute MAY contain newlines.", "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "streetAddress",
                "type": "string",
                "multiValued": false,
                "description": "The full street address component, which may include house number, street name, PO BOX, and multi-line extended street address information. This attribute MAY contain newlines.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "locality",
                "type": "string",
                "multiValued": false,
                "description": "The city or locality component.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "region",
                "type": "string",
                "multiValued": false,
                "description": "The state or region component.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "postalCode",
                "type": "string",
                "multiValued": false,
                "description": "The zipcode or postal code component.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "country",
                "type": "string",
                "multiValued": false,
                "description": "The country name component.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "type",
                "type": "string",
                "multiValued": false,
                "description": "A label indicating the attribute's function; e.g., 'work' or 'home'.",
                "required": false,
                "caseExact": false,
                "canonicalValues": [
                  "work",
                  "home",
                  "other"
                ],
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              }
            ],
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "groups",
            "type": "complex",
            "multiValued": true,
            "description": "A list of groups that the user belongs to, either thorough direct membership, nested groups, or dynamically calculated",
            "required": false,
            "subAttributes": [
              {
                "name": "value",
                "type": "string",
                "multiValued": false,
                "description": "The identifier of the User's group.",
                "required": false,
                "caseExact": false,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "$ref",
                "type": "reference",
                "referenceTypes": [
                  "User",
                  "Group"
                ],
                "multiValued": false,
                "description": "The URI of the corresponding Group resource to which the user belongs",
                "required": false,
                "caseExact": false,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "display",
                "type": "string",
                "multiValued": false,
                "description": "A human readable name, primarily used for display purposes. READ-ONLY.",
                "required": false,
                "caseExact": false,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "type",
                "type": "string",
                "multiValued": false,
                "description": "A label indicating the attribute's function; e.g., 'direct' or 'indirect'.",
                "required": false,
                "caseExact": false,
                "canonicalValues": [
                  "direct",
                  "indirect"
                ],
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
              }
            ],
            "mutability": "readOnly",
            "returned": "default"
          },
          {
            "name": "entitlements",
            "type": "complex",
            "multiValued": true,
            "description": "A list of entitlements for the User that represent a thing the User has.",
            "required": false,
            "subAttributes": [
              {
                "name": "value",
                "type": "string",
                "multiValued": false,
                "description": "The value of an entitlement.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "display",
                "type": "string",
                "multiValued": false,
                "description": "A human readable name, primarily used for display purposes. READ-ONLY.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "type",
                "type": "string",
                "multiValued": false,
                "description": "A label indicating the attribute's function.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "primary",
                "type": "boolean",
                "multiValued": false,
                "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute. The primary attribute value 'true' MUST appear no more than once.",
                "required": false,
                "mutability": "readWrite",
                "returned": "default"
              }
            ],
            "mutability": "readWrite",
            "returned": "default"
          },
          {
            "name": "roles",
            "type": "complex",
            "multiValued": true,
            "description": "A list of roles for the User that collectively represent who the User is; e.g., 'Student', 'Faculty'.",
            "required": false,
            "subAttributes": [
              {
                "name": "value",
                "type": "string",
                "multiValued": false,
                "description": "The value of a role.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "display",
                "type": "string",
                "multiValued": false,
                "description": "A human readable name, primarily used for display purposes. READ-ONLY.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "type",
                "type": "string",
                "multiValued": false,
                "description": "A label indicating the attribute's function.",
                "required": false,
                "caseExact": false,
                "canonicalValues": [],
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "primary",
                "type": "boolean",
                "multiValued": false,
                "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute. The primary attribute value 'true' MUST appear no more than once.",
                "required": false,
                "mutability": "readWrite",
                "returned": "default"
              }
            ],
            "mutability": "readWrite",
            "returned": "default"
          },
          {
            "name": "x509Certificates",
            "type": "complex",
            "multiValued": true,
            "description": "A list of certificates issued to the User.",
            "required": false,
            "caseExact": false,
            "subAttributes": [
              {
                "name": "value",
                "type": "binary",
                "multiValued": false,
                "description": "The value of a X509 certificate.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "display",
                "type": "string",
                "multiValued": false,
                "description": "A human readable name, primarily used for display purposes. READ-ONLY.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "type",
                "type": "string",
                "multiValued": false,
                "description": "A label indicating the attribute's function.",
                "required": false,
                "caseExact": false,
                "canonicalValues": [],
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "primary",
                "type": "boolean",
                "multiValued": false,
                "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute. The primary attribute value 'true' MUST appear no more than once.",
                "required": false,
                "mutability": "readWrite",
                "returned": "default"
              }
            ],
            "mutability": "readWrite",
            "returned": "default"
          }
        ],
        "meta": {
          "resourceType": "Schema",
          "location":
            "/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"
        }
      },
      {
        "id": "urn:ietf:params:scim:schemas:core:2.0:Group",
        "name": "Group",
        "description": "Group",
        "attributes": [
          {
            "name": "displayName",
            "type": "string",
            "multiValued": false,
            "description": "Human readable name for the Group. REQUIRED.",
            "required": false,
            "caseExact": false,
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "members",
            "type": "complex",
            "multiValued": true,
            "description": "A list of members of the Group.",
            "required": false,
            "subAttributes": [
              {
                "name": "value",
                "type": "string",
                "multiValued": false,
                "description": "Identifier of the member of this Group.",
                "required": false,
                "caseExact": false,
                "mutability": "immutable",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "$ref",
                "type": "reference",
                "referenceTypes": [
                  "User",
                  "Group"
                ],
                "multiValued": false,
                "description": "The URI of the corresponding to the memberre source of this Group.",
                "required": false,
                "caseExact": false,
                "mutability": "immutable",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "type",
                "type": "string",
                "multiValued": false,
                "description": "A label indicating the type of resource; e.g., 'User' or 'Group'.",
                "required": false,
                "caseExact": false,
                "canonicalValues": [
                  "User",
                  "Group"
                ],
                "mutability": "immutable",
                "returned": "default",
                "uniqueness": "none"
              }
            ],
            "mutability": "readWrite",
            "returned": "default"
          }
        ],
        "meta": {
          "resourceType": "Schema",
          "location":
            "/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group"
        }
      },
      {
        "id": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        "name": "EnterpriseUser",
        "description": "Enterprise User",
        "attributes": [
          {
            "name": "employeeNumber",
            "type": "string",
            "multiValued": false,
            "description": "Numeric or alphanumeric identifier assigned to a person, typically based on order of hire or association with an organization.",
            "required": false,
            "caseExact": false,
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "costCenter",
            "type": "string",
            "multiValued": false,
            "description": "Identifies the name of a cost center.",
            "required": false,
            "caseExact": false,
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "organization",
            "type": "string",
            "multiValued": false,
            "description": "Identifies the name of an organization.",
            "required": false,
            "caseExact": false,
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "division",
            "type": "string",
            "multiValued": false,
            "description": "Identifies the name of a division.",
            "required": false,
            "caseExact": false,
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "department",
            "type": "string",
            "multiValued": false,
            "description": "Identifies the name of a department.",
            "required": false,
            "caseExact": false,
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "manager",
            "type": "complex",
            "multiValued": false,
            "description": "The User's manager. A complex type that optionally allows Service Providers to represent organizational hierarchy by referencing the 'id' attribute of another User.",
            "required": false,
            "subAttributes": [
              {
                "name": "value",
                "type": "string",
                "multiValued": false,
                "description": "The id of the SCIM resource representing the User's  manager.  REQUIRED.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "$ref",
                "type": "reference",
                "referenceTypes": [
                  "User"
                ],
                "multiValued": false,
                "description": "The URI of the SCIM resource representing the User's manager.  REQUIRED.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "displayName",
                "type": "string",
                "multiValued": false,
                "description": "The displayName of the User's manager. OPTIONAL and READ-ONLY.",
                "required": false,
                "caseExact": false,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
              }
            ],
            "mutability": "readWrite",
            "returned": "default"
          }
        ],
        "meta": {
          "resourceType": "Schema",
          "location":
            "/v2/Schemas/urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        }
      },
      {
        "id": "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig",
        "name": "Service Provider Configuration",
        "description": "Schema for representing the service provider's configuration",
        "attributes": [
          {
            "name": "documentationUri",
            "type": "reference",
            "referenceTypes": [
              "external"
            ],
            "multiValued": false,
            "description": "An HTTP addressable URL pointing to the service provider's human consumable help documentation.",
            "required": false,
            "caseExact": false,
            "mutability": "readOnly",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "patch",
            "type": "complex",
            "multiValued": false,
            "description": "A complex type that specifies PATCH configuration options.",
            "required": true,
            "returned": "default",
            "mutability": "readOnly",
            "subAttributes": [
              {
                "name": "supported",
                "type": "boolean",
                "multiValued": false,
                "description": "Boolean value specifying whether the operation is supported.",
                "required": true,
                "mutability": "readOnly",
                "returned": "default"
              }
            ]
          },
          {
            "name": "bulk",
            "type": "complex",
            "multiValued": false,
            "description": "A complex type that specifies BULK configuration options.",
            "required": true,
            "returned": "default",
            "mutability": "readOnly",
            "subAttributes": [
              {
                "name": "supported",
                "type": "boolean",
                "multiValued": false,
                "description": "Boolean value specifying whether the operation is supported.",
                "required": true,
                "mutability": "readOnly",
                "returned": "default"
              },
              {
                "name": "maxOperations",
                "type": "integer",
                "multiValued": false,
                "description": "An integer value specifying the maximum number of operations.",
                "required": true,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "maxPayloadSize",
                "type": "integer",
                "multiValued": false,
                "description": "An integer value specifying the maximum payload size in bytes.",
                "required": true,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
              }
            ]
          },
          {
            "name": "filter",
            "type": "complex",
            "multiValued": false,
            "description": "A complex type that specifies FILTER options.",
            "required": true,
            "returned": "default",
            "mutability": "readOnly",
            "subAttributes": [
              {
                "name": "supported",
                "type": "boolean",
                "multiValued": false,
                "description": "Boolean value specifying whether the operation is supported.",
                "required": true,
                "mutability": "readOnly",
                "returned": "default"
              },
              {
                "name": "maxResults",
                "type": "integer",
                "multiValued": false,
                "description": "Integer value specifying the maximum number of resources returned in a response.",
                "required": true,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
              }
            ]
          },
          {
            "name": "changePassword",
            "type": "complex",
            "multiValued": false,
            "description": "A complex type that specifies change password options.",
            "required": true,
            "returned": "default",
            "mutability": "readOnly",
            "subAttributes": [
              {
                "name": "supported",
                "type": "boolean",
                "multiValued": false,
                "description": "Boolean value specifying whether the operation is supported.",
                "required": true,
                "mutability": "readOnly",
                "returned": "default"
              }
            ]
          },
          {
            "name": "sort",
            "type": "complex",
            "multiValued": false,
            "description": "A complex type that specifies sort result options.",
            "required": true,
            "returned": "default",
            "mutability": "readOnly",
            "subAttributes": [
              {
                "name": "supported",
                "type": "boolean",
                "multiValued": false,
                "description": "Boolean value specifying whether the operation is supported.",
                "required": true,
                "mutability": "readOnly",
                "returned": "default"
              }
            ]
          },
          {
            "name": "authenticationSchemes",
            "type": "complex",
            "multiValued": true,
            "description": "A complex type that specifies supported Authentication Scheme properties.",
            "required": true,
            "returned": "default",
            "mutability": "readOnly",
            "subAttributes": [
              {
                "name": "name",
                "type": "string",
                "multiValued": false,
                "description": "The common authentication scheme name; e.g., HTTP Basic.",
                "required": true,
                "caseExact": false,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "description",
                "type": "string",
                "multiValued": false,
                "description": "A description of the authentication scheme.",
                "required": true,
                "caseExact": false,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "specUri",
                "type": "reference",
                "referenceTypes": [
                  "external"
                ],
                "multiValued": false,
                "description": "An HTTP addressable URL pointing to the Authentication Scheme's specification.",
                "required": false,
                "caseExact": false,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "documentationUri",
                "type": "reference",
                "referenceTypes": [
                  "external"
                ],
                "multiValued": false,
                "description": "An HTTP addressable URL pointing to the Authentication Scheme's usage documentation.",
                "required": false,
                "caseExact": false,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
              }
            ]
          }
        ]
      },
      {
        "id": "urn:ietf:params:scim:schemas:core:2.0:ResourceType",
        "name": "ResourceType",
        "description": "Specifies the schema that describes a SCIM Resource Type",
        "attributes": [
          {
            "name": "id",
            "type": "string",
            "multiValued": false,
            "description": "The resource type's server unique id. May be the same as the 'name' attribute.",
            "required": false,
            "caseExact": false,
            "mutability": "readOnly",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "name",
            "type": "string",
            "multiValued": false,
            "description": "The resource type name. When applicable service providers MUST specify the name specified in the core schema specification; e.g., User",
            "required": true,
            "caseExact": false,
            "mutability": "readOnly",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "description",
            "type": "string",
            "multiValued": false,
            "description": "The resource type's human readable description. When applicable service providers MUST specify the description specified in the core schema specification.",
            "required": false,
            "caseExact": false,
            "mutability": "readOnly",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "endpoint",
            "type": "reference",
            "referenceTypes": [
              "uri"
            ],
            "multiValued": false,
            "description": "The resource type's HTTP addressable endpoint relative to the Base URL; e.g., /Users",
            "required": true,
            "caseExact": false,
            "mutability": "readOnly",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "schema",
            "type": "reference",
            "referenceTypes": [
              "uri"
            ],
            "multiValued": false,
            "description": "The resource types primary/base schema URI",
            "required": true,
            "caseExact": true,
            "mutability": "readOnly",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "schemaExtensions",
            "type": "complex",
            "multiValued": false,
            "description": "A list of URIs of the resource type's schema extensions",
            "required": true,
            "mutability": "readOnly",
            "returned": "default",
            "subAttributes": [
              {
                "name": "schema",
                "type": "reference",
                "referenceTypes": [
                  "uri"
                ],
                "multiValued": false,
                "description": "The URI of a schema extension.",
                "required": true,
                "caseExact": true,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "required",
                "type": "boolean",
                "multiValued": false,
                "description": "A Boolean value that specifies whether the schema extension is required for the resource type. If true, a resource of this type MUST include this schema extension and include any attributes declared as required in this schema extension. If false, a resource of this type MAY omit this schema extension.",
                "required": true,
                "mutability": "readOnly",
                "returned": "default"
              }
            ]
          }
        ]
      },
      {
        "id": "urn:ietf:params:scim:schemas:core:2.0:Schema",
        "name": "Schema",
        "description": "Specifies the schema that describes a SCIM Schema",
        "attributes": [
          {
            "name": "id",
            "type": "string",
            "multiValued": false,
            "description": "The unique URI of the schema. When applicable service providers MUST specify the URI specified in the core schema specification",
            "required": true,
            "caseExact": false,
            "mutability": "readOnly",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "name",
            "type": "string",
            "multiValued": false,
            "description": "The schema's human readable name. When applicable service providers MUST specify the name specified in the core schema specification; e.g., User",
            "required": true,
            "caseExact": false,
            "mutability": "readOnly",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "description",
            "type": "string",
            "multiValued": false,
            "description": "The schema's human readable name. When applicable service providers MUST specify the name specified in the core schema specification; e.g., User",
            "required": false,
            "caseExact": false,
            "mutability": "readOnly",
            "returned": "default",
            "uniqueness": "none"
          },
          {
            "name": "attributes",
            "type": "complex",
            "multiValued": true,
            "description": "A complex attribute that includes the attributes of a schema",
            "required": true,
            "mutability": "readOnly",
            "returned": "default",
            "subAttributes": [
              {
                "name": "name",
                "type": "string",
                "multiValued": false,
                "description": "The attribute's name",
                "required": true,
                "caseExact": true,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "type",
                "type": "string",
                "multiValued": false,
                "description": "The attribute's data type. Valid values include: 'string', 'complex', 'boolean', 'decimal', 'integer', 'dateTime', 'reference'. ", "required": true,
                "canonicalValues": [
                  "string",
                  "complex",
                  "boolean",
                  "decimal",
                  "integer",
                  "dateTime",
                  "reference"
                ],
                "caseExact": false,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "multiValued",
                "type": "boolean",
                "multiValued": false,
                "description": "Boolean indicating an attribute's plurality.",
                "required": true,
                "mutability": "readOnly",
                "returned": "default"
              },
              {
                "name": "description",
                "type": "string",
                "multiValued": false,
                "description": "A human readable description of the attribute.",
                "required": false,
                "caseExact": true,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "required",
                "type": "boolean",
                "multiValued": false,
                "description": "A boolean indicating if the attribute is required.",
                "required": false,
                "mutability": "readOnly",
                "returned": "default"
              },
              {
                "name": "canonicalValues",
                "type": "string",
                "multiValued": true,
                "description": "A collection of canonical values.  When applicable service providers MUST specify the canonical types specified in the core schema specification; e.g., 'work', 'home'.",
                "required": false,
                "caseExact": true,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "caseExact",
                "type": "boolean",
                "multiValued": false,
                "description": "Indicates if a string attribute is case-sensitive.",
                "required": false,
                "mutability": "readOnly",
                "returned": "default"
              },
              {
                "name": "mutability",
                "type": "string",
                "multiValued": false,
                "description": "Indicates if an attribute is modifiable.",
                "required": false,
                "caseExact": true,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none",
                "canonicalValues": [
                  "readOnly",
                  "readWrite",
                  "immutable",
                  "writeOnly"
                ]
              },
              {
                "name": "returned",
                "type": "string",
                "multiValued": false,
                "description": "Indicates when an attribute is returned in a response (e.g., to a query).",
                "required": false,
                "caseExact": true,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none",
                "canonicalValues": [
                  "always",
                  "never",
                  "default",
                  "request"
                ]
              },
              {
                "name": "uniqueness",
                "type": "string",
                "multiValued": false,
                "description": "Indicates how unique a value must be.",
                "required": false,
                "caseExact": true,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none",
                "canonicalValues": [
                  "none",
                  "server",
                  "global"
                ]
              },
              {
                "name": "referenceTypes",
                "type": "string",
                "multiValued": true,
                "description": "Used only with an attribute of type 'reference'. Specifies a SCIM resourceType that a reference attribute MAY refer to. e.g., User",
                "required": false,
                "caseExact": true,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
              },
              {
                "name": "subAttributes",
                "type": "complex",
                "multiValued": true,
                "description": "Used to define the sub-attributes of a complex attribute",
                "required": false,
                "mutability": "readOnly",
                "returned": "default",
                "subAttributes": [
                  {
                    "name": "name",
                    "type": "string",
                    "multiValued": false,
                    "description": "The attribute's name",
                    "required": true,
                    "caseExact": true,
                    "mutability": "readOnly",
                    "returned": "default",
                    "uniqueness": "none"
                  },
                  {
                    "name": "type",
                    "type": "string",
                    "multiValued": false,
                    "description": "The attribute's data type. Valid values include: 'string', 'complex', 'boolean', 'decimal', 'integer', 'dateTime', 'reference'. ",
                    "required": true,
                    "caseExact": false,
                    "mutability": "readOnly",
                    "returned": "default",
                    "uniqueness": "none",
                    "canonicalValues": [
                      "string",
                      "complex",
                      "boolean",
                      "decimal",
                      "integer",
                      "dateTime",
                      "reference"
                    ]
                  },
                  {
                    "name": "multiValued",
                    "type": "boolean",
                    "multiValued": false,
                    "description": "Boolean indicating an attribute's plurality.",
                    "required": true,
                    "mutability": "readOnly",
                    "returned": "default"
                  },
                  {
                    "name": "description",
                    "type": "string",
                    "multiValued": false,
                    "description": "A human readable description of the attribute.",
                    "required": false,
                    "caseExact": true,
                    "mutability": "readOnly",
                    "returned": "default",
                    "uniqueness": "none"
                  },
                  {
                    "name": "required",
                    "type": "boolean",
                    "multiValued": false,
                    "description": "A boolean indicating if the attribute is required.",
                    "required": false,
                    "mutability": "readOnly",
                    "returned": "default"
                  },
                  {
                    "name": "canonicalValues",
                    "type": "string",
                    "multiValued": true,
                    "description": "A collection of canonical values.  When applicable service providers MUST specify the canonical types specified in the core schema specification; e.g., 'work', 'home'.",
                    "required": false,
                    "caseExact": true,
                    "mutability": "readOnly",
                    "returned": "default",
                    "uniqueness": "none"
                  },
                  {
                    "name": "caseExact",
                    "type": "boolean",
                    "multiValued": false,
                    "description": "Indicates if a string attribute is case-sensitive.",
                    "required": false,
                    "mutability": "readOnly",
                    "returned": "default"
                  },
                  {
                    "name": "mutability",
                    "type": "string",
                    "multiValued": false,
                    "description": "Indicates if an attribute is modifiable.",
                    "required": false,
                    "caseExact": true,
                    "mutability": "readOnly",
                    "returned": "default",
                    "uniqueness": "none",
                    "canonicalValues": [
                      "readOnly",
                      "readWrite",
                      "immutable",
                      "writeOnly"
                    ]
                  },
                  {
                    "name": "returned",
                    "type": "string",
                    "multiValued": false,
                    "description": "Indicates when an attribute is returned in a response (e.g., to a query).",
                    "required": false,
                    "caseExact": true,
                    "mutability": "readOnly",
                    "returned": "default",
                    "uniqueness": "none",
                    "canonicalValues": [
                      "always",
                      "never",
                      "default",
                      "request"
                    ]
                  },
                  {
                    "name": "uniqueness",
                    "type": "string",
                    "multiValued": false,
                    "description": "Indicates how unique a value must be.",
                    "required": false,
                    "caseExact": true,
                    "mutability": "readOnly",
                    "returned": "default",
                    "uniqueness": "none",
                    "canonicalValues": [
                      "none",
                      "server",
                      "global"
                    ]
                  },
                  {
                    "name": "referenceTypes",
                    "type": "string",
                    "multiValued": false,
                    "description": "Used only with an attribute of type 'reference'. Specifies a SCIM resourceType that a reference attribute MAY refer to. e.g., 'User'",
                    "required": false,
                    "caseExact": true,
                    "mutability": "readOnly",
                    "returned": "default",
                    "uniqueness": "none"
                  }
                ]
              }
            ]
          }
        ]
      }


    ]



}


//========================================================//
//======= Dummy testdata used for testmode plugin  =======//
//========================================================//


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
      "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
        "employeeNumber": "701984",
        "costCenter": "4130",
        "organization": "Universal Studios",
        "division": "Theme Park",
        "department": "Tour Operations",
        "manager": {
          "value": "jsmith",
          "$ref": "../Users/jsmith",
          "displayName": "John Smith"
        }
      },
      "meta": {
        "resourceType": "User",
        "created": "2010-01-23T04:56:22Z",
        "lastModified": "2011-05-13T04:42:34Z",
        "version": "W\/\"3694e05e9dff591\"",
        "location":
          "https://example.com/v2/Users/bjensen"
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
      "ims": [
        {
          "value": "anything",
          "type": "aim"
        }
      ],
      "roles": [
        {
        "value": "Role-B"
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
      "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
        "employeeNumber": "991999",
        "costCenter": "4188",
        "organization": "Universal Studios",
        "division": "Theme Park",
        "department": "Tour Operations",
        "manager": {
          "value": "bjensen",
          "displayName": "Babs Jensen"
        }
      },
      "meta": {
        "resourceType": "User",
        "created": "2016-01-23T04:56:22Z",
        "lastModified": "2016-05-13T04:42:34Z",
        "version": "W\/\"3694e05e9dff591\"",
        "location":
          "https://example.com/v2/Users/jsmith"
      }
    }
  ]
}

module.exports.TestmodeGroups = {
  "Resources": [
    {
    "displayName": "Admins",
    "id": "Admins",
    "members": [
      {
        "value": "bjensen",
        "display": "Babs Jensen"
      },
    ],
    "meta": {
      "resourceType": "Group",
      "created": "2010-01-23T04:56:22Z",
      "lastModified": "2011-05-13T04:42:34Z",
      "location": "https://example.com/v2/Groups/Admins",
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
      "resourceType": "Group",
      "created": "2010-01-23T04:56:22Z",
      "lastModified": "2011-05-13T04:42:34Z",
      "location": "https://example.com/v2/Groups/Employees",
      "version": "W\/\"3694e05e9dff592\""
    }
  }
  ]
}