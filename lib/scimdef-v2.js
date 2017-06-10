//==================================
// File:    scimdef.js
//
// Author:  Jarle Elshaug
//==================================

module.exports.ScimResource = function () {
  this.schemas = ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]
  this.Resources = [];
}

module.exports.Response = {
  "group": {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"]
  },
  "user": {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]
  }
}

module.exports.ServiceProviderConfigs = {
  "schemas":
  ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
  "documentationUri": "http://example.com/help/scim.html",
  "patch": {
    "supported": true
  },
  "bulk": {
    "supported": false,
    "maxOperations": 1000,
    "maxPayloadSize": 1048576
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
  "authenticationSchemes": [
    {
      "name": "OAuth Bearer Token",
      "description":
      "Authentication scheme using the OAuth Bearer Token Standard",
      "specUri": "http://www.rfc-editor.org/info/rfc6750",
      "documentationUri": "http://example.com/help/oauth.html",
      "type": "oauthbearertoken",
      "primary": true
    },
    {
      "name": "HTTP Basic",
      "description":
      "Authentication scheme using the HTTP Basic Standard",
      "specUri": "http://www.rfc-editor.org/info/rfc2617",
      "documentationUri": "http://example.com/help/httpBasic.html",
      "type": "httpbasic"
    }
  ],
  "meta": {
    "location": "https://example.com/v2/ServiceProviderConfig",
    "resourceType": "ServiceProviderConfig",
    "created": "2010-01-23T04:56:22Z",
    "lastModified": "2011-05-13T04:42:34Z",
    "version": "W\/\"3694e05e9dff594\""
  }
}



module.exports.Schemas = {
  "totalResults": 2,
  "itemsPerPage": 2,
  "startIndex": 1,
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0"],
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
          "description": "Unique identifier for the User, typically used by the user to directly authenticate to the service provider. Each User MUST include a non- empty userName value.This identifier MUST be unique across the service provider's entire set of Users. REQUIRED.",
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
          "description": "The components of the user's real name. Providers MAY return just the full name as a single string in the formatted sub- attribute, or they MAY return just the individual component attributes using the other sub- attributes, or they MAY return both.If both variants are turned, they SHOULD be describing the same name, with the formatted name indicating how the component attributes should be combined.",
          "required": false,
          "subAttributes": [
            {
              "name": "formatted",
              "type": "string",
              "multiValued": false,
              "description": "The full name, including all middle names, titles, and suffixes as appropriate, formatted for display                   (e.g., 'Ms. Barbara J Jensen, III').",
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
              "description": "The family name of the User, or last name in most Western languages (e.g., 'Jensen' given the full name 'Ms. Barbara J Jensen, III').",
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
              "description": "The given name of the User, or first name in most Western languages (e.g., 'Barbara' given the full name 'Ms. Barbara J Jensen, III').",
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
              "description": "The middle name(s) of the User (e.g., 'Jane' given the full name 'Ms. Barbara J Jensen, III').",
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
              "description": "The honorific prefix(es) of the User, or title in most Western languages (e.g., 'Ms.' given the full name 'Ms. Barbara J Jensen, III').",
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
              "description": "The honorific suffix(es) of the User, or suffix in most Western languages (e.g., 'III' given the full name 'Ms. Barbara J Jensen, III').",
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
          "description": "The name of the User, suitable for display to end- users.The name SHOULD be the full name of the User being described, if known.",
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
          "description": "The casual way to address the user in real life, e.g., 'Bob' or 'Bobby' instead of 'Robert'.This attribute SHOULD NOT be used to represent a User's username (e.g., 'bjensen' or 'mpepperidge').",
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
          "description": "A fully qualified URL pointing to a page representing the User's online profile.",
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
          "description": "Used to identify the relationship between the organization and the user.  Typical values used might be 'Contractor', 'Employee', 'Intern', 'Temp', 'External', and 'Unknown', but any value may be used.",
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
          "description": "Indicates the User's preferred written or spoken language.Generally used for selecting a localized user interface; e.g., 'en_US' specifies the language English and country US.",
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
          "description": "Used to indicate the User's default location for purposes of localizing items such as currency, date time format, or numerical representations.",
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
          "description": "The User's time zone in the 'Olson' time zone database format, e.g., 'America/Los_Angeles'.",
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
          "description": "The User's cleartext password.  This attribute is intended to be used as a means to specify an initial password when creating a new User or to reset an existing User's password.",
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
          "description": "Email addresses for the user.  The value SHOULD be canonicalized by the service provider, e.g., 'bjensen@example.com' instead of 'bjensen@EXAMPLE.COM'. Canonical type values of 'work', 'home', and 'other'.",
          "required": false,
          "subAttributes": [
            {
              "name": "value",
              "type": "string",
              "multiValued": false,
              "description": "Email addresses for the user.  The value SHOULD be canonicalized by the service provider, e.g., 'bjensen@example.com' instead of 'bjensen@EXAMPLE.COM'. Canonical type values of 'work', 'home', and 'other'.",
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
              "description": "A human-readable name, primarily used for display purposes.  READ - ONLY.",
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
              "description": "A label indicating the attribute's function, e.g., 'work' or 'home'.",
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
              "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute, e.g., the preferred mailing address or primary email address.The primary attribute value 'true' MUST appear no more than once.",
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
          "description": "Phone numbers for the User.  The value SHOULD be canonicalized by the service provider according to the format specified in RFC 3966, e.g., 'tel:+1-201-555-0123'. Canonical type values of 'work', 'home', 'mobile', 'fax', 'pager',             and 'other'.",
          "required": false,
          "subAttributes": [
            {
              "name": "value",
              "type": "string",
              "multiValued": false,
              "description": "Phone number of the User.",
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
              "description": "A human-readable name, primarily used for display purposes.  READ - ONLY.",
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
              "description": "A label indicating the attribute's function, e.g., 'work', 'home', 'mobile'.",
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
              "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute, e.g., the preferred phone number or primary phone number.The primary attribute value 'true' MUST appear no more than once.",
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
              "description": "A human-readable name, primarily used for display purposes.  READ - ONLY.",
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
              "description": "A label indicating the attribute's function, e.g., 'aim', 'gtalk', 'xmpp'.",
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
              "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute, e.g., the preferred messenger or primary messenger.The primary attribute value 'true' MUST appear no more than once.",
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
              "description": "A human-readable name, primarily used for display purposes.  READ - ONLY.",
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
              "description": "A label indicating the attribute's function, i.e., 'photo' or 'thumbnail'.",
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
              "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute, e.g., the preferred photo or thumbnail.  The primary attribute value 'true' MUST appear no more than once.",
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
          "description": "A physical mailing address for this User. Canonical type values of 'work', 'home', and 'other'.This attribute is a complex type with the following sub- attributes.",
          "required": false,
          "subAttributes": [
            {
              "name": "formatted",
              "type": "string",
              "multiValued": false,
              "description": "The full mailing address, formatted for display or use with a mailing label.This attribute MAY contain newlines.",
              "required": false,
              "caseExact": false,
              "mutability": "readWrite",
              "returned": "default",
              "uniqueness": "none"
            },
            {
              "name": "streetAddress",
              "type": "string",
              "multiValued": false,
              "description": "The full street address component, which may include house number, street name, P.O.box, and multi- line extended street address information.This attribute MAY contain newlines.",
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
              "description": "The zip code or postal code component.",
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
              "description": "A label indicating the attribute's function, e.g., 'work' or 'home'.",
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
          "description": "A list of groups to which the user belongs, either through direct membership, through nested groups, or dynamically calculated.",
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
              "description": "The URI of the corresponding 'Group' resource to which the user belongs.",
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
              "description": "A human-readable name, primarily used for display purposes.  READ - ONLY.",
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
              "description": "A label indicating the attribute's function, e.g., 'direct' or 'indirect'.",
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
              "description": "A human-readable name, primarily used for display purposes.  READ - ONLY.",
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
              "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute.  The primary attribute value 'true' MUST appear no more than once.",
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
          "description": "A list of roles for the User that collectively represent who the User is, e.g., 'Student', 'Faculty'.",
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
              "description": "A human-readable name, primarily used for display purposes.  READ - ONLY.",
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
              "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute.  The primary attribute value 'true' MUST appear no more than once.",
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
              "description": "The value of an X.509 certificate.",
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
              "description": "A human-readable name, primarily used for display purposes.  READ - ONLY.",
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
              "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute.  The primary attribute value 'true' MUST appear no more than once.",
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
        "/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"
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
          "description": "A human-readable name for the Group. REQUIRED.",
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
              "description": "The URI corresponding to a SCIM resource that is a member of this Group.",
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
              "description": "A label indicating the type of resource, e.g., 'User' or 'Group'.",
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
        "/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group"
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
          "description": "The User's manager.  A complex type that optionally allows service providers to represent organizational hierarchy by referencing the 'id' attribute of another User.",
          "required": false,
          "subAttributes": [
            {
              "name": "value",
              "type": "string",
              "multiValued": false,
              "description": "The id of the SCIM resource representing the User's manager.  REQUIRED.",
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
    }
  ]



}


//========================================================//
//======= Dummy testdata used for testmode plugin  =======//
//========================================================//


module.exports.TestmodeUsers = {
  "totalResults": 2,
  "itemsPerPage": 2,
  "startIndex": 1,
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User",
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
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
      "userType": "Employee",
      "title": "Tour Guide",
      "preferredLanguage": "en-US",
      "locale": "en-US",
      "timezone": "America/Los_Angeles",
      "active": true,
      "password": "t1meMa$heen",
      "groups": [
        {
          "value": "UserGroup-1",
          "display": "UserGroup-1",
        }

      ],
      "x509Certificates": [
        {
          "value": ""
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
      "userType": "Employee",
      "title": "Consultant",
      "preferredLanguage": "en-US",
      "locale": "en-US",
      "timezone": "America/Los_Angeles",
      "active": true,
      "password": "MySecret",
      "groups": [
        {
          "value": "UserGroup-2",
          "display": "UserGroup-2"
        }
      ],
      "x509Certificates": [
        {
          "value": ""
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
  "totalResults": 3,
  "itemsPerPage": 3,
  "startIndex": 1,
  "schemas": [
    "urn:ietf:params:scim:schemas:core:2.0:Group",
  ],
  "Resources": [
    {
      "id": "Admins",
      "displayName": "Admins",
      "members": [
        {
          "value": "bjensen",
          "display": "Babs Jensen"
        },
        {
          "value": "jsmith",
          "display": "John Smith"
        }
      ]
    },

    {
      "id": "UserGroup-1",
      "displayName": "UserGroup-1",
    },
    {
      "id": "UserGroup-2",
      "displayName": "UserGroup-2"
    }
  ]
}
