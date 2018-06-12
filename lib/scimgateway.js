// =================================================================================
// File:    scimgateway.js
//
// Author:  Jarle Elshaug
//
// Purpose: Started by endpoint plugin
//          Listens and replies on incoming SCIM requests
//          Communicates with plugin using event callback
// =================================================================================

'use strict'

const http = require('http')
const https = require('https')
const express = require('express')
const expressBearerToken = require('express-bearer-token')
const basicAuth = require('basic-auth')
const jwt = require('jsonwebtoken')
const passport = require('passport')
const OIDCBearerStrategy = require('passport-azure-ad').BearerStrategy
const async = require('async')
const EventEmitter = require('events').EventEmitter
const dot = require('dot-object')
const util = require('util')
const fs = require('fs')
const path = require('path')
const callsite = require('callsite')
const utils = require('../lib/utils')
const { Lock } = require('../lib/utils')
const endpointMap = require('../lib/endpointMap')
let scimDef = null

/**
 * @constructor
 */
let ScimGateway = function () {
  let server = null
  let stack = callsite()
  let requester = stack[1].getFileName()
  let pluginName = path.basename(requester, '.js')
  let configDir = path.join(path.dirname(requester), '..', 'config')
  let configFile = path.join(`${configDir}`, `${pluginName}.json`) // config name prefix same as pluging name prefix
  let config = require(configFile).scimgateway
  let gwName = path.basename(__filename, '.js') // prefix of current file
  let logDir = path.join(path.dirname(requester), '..', 'logs')
  let log = require('../lib/logger')(config.loglevel, path.join(`${logDir}`, `${pluginName}.log`))
  let logger = log.logger
  this.logger = logger                           // exposed to plugin-code
  this.notValidAttributes = notValidAttributes   // exposed to plugin-code
  let pwErrCount = 0

  let handler = {}
  handler.Users = handler.users = {
    'description': 'User',
    'uniqueAttr': 'userName',
    'exploreEmitter': 'exploreUsers',
    'getEmitter': 'getUser',
    'inclusionEmitter': 'getGroupUsers',
    'modifyEmitter': 'modifyUser',
    'createEmitter': 'createUser'
  }
  handler.Groups = handler.groups = {
    'description': 'Group',
    'uniqueAttr': 'displayName',
    'exploreEmitter': 'exploreGroups',
    'getEmitter': 'getGroup',
    'inclusionEmitter': 'getGroupMembers',
    'modifyEmitter': 'modifyGroupMembers',
    'createEmitter': 'createGroup'
  }
  handler.servicePlans = handler.serviceplans = { // plugin-azure using "CustomSCIM"
    'description': 'ServicePlan',
    'uniqueAttr': 'servicePlanName',
    'exploreEmitter': 'exploreServicePlans',
    'getEmitter': 'getServicePlan',
    'inclusionEmitter': 'getServicePlanMembers',
    'modifyEmitter': 'modifyServicePlanMembers',
    'createEmitter': 'createServicePlan'
  }

  if (!config['auth']) config['auth'] = {}
  if (!config['auth']['basic']) config['auth']['basic'] = {}
  if (!config['auth']['bearer']) config['auth']['bearer'] = {}
  if (!config['auth']['bearer']['jwt']) config['auth']['bearer']['jwt'] = {}
  if (!config['auth']['bearer']['jwt']['azure']) config['auth']['bearer']['jwt']['azure'] = {}
  if (!config['auth']['bearer']['jwt']['standard']) config['auth']['bearer']['jwt']['standard'] = {}
  if (!config['auth']['bearer']['jwt']['standard']['options']) config['auth']['bearer']['jwt']['standard']['options'] = {}
  if (!config['certificate']) config['certificate'] = {}
  if (!config['certificate']['pfx']) config['certificate']['pfx'] = {}

  let pwBasicPassword = null
  let pwBearerToken = null
  let pwJwtStandardSecret = null
  let pwPfxPassword = null
  if (config.auth.basic.password) pwBasicPassword = ScimGateway.prototype.getPassword('scimgateway.auth.basic.password', configFile)
  if (config.auth.bearer.token) pwBearerToken = ScimGateway.prototype.getPassword('scimgateway.auth.bearer.token', configFile)
  if (config.auth.bearer.jwt.standard.secret) pwJwtStandardSecret = ScimGateway.prototype.getPassword('scimgateway.auth.bearer.jwt.standard.secret', configFile)
  if (config.certificate.pfx.password) pwPfxPassword = ScimGateway.prototype.getPassword('scimgateway.certificate.pfx.password', configFile)

  if (pwBasicPassword === '' || pwBearerToken === '' || pwJwtStandardSecret === '' || pwPfxPassword === '') {
    logger.error(`${gwName} Scimgateway password decryption failed`)
    logger.error(`${gwName} Stopping...`)
    console.log()
    // process.exit(1) // may miss unflushed logger updates to logfile
    throw (new Error('Using exception to stop further asynchronous code execution (ensure synchronous logger flush to logfile and exit program), please ignore this one...'))
  }
  if (!fs.existsSync(logDir)) fs.mkdirSync(logDir)
  if (!fs.existsSync(configDir + '/wsdls')) fs.mkdirSync(configDir + '/wsdls')
  if (!fs.existsSync(configDir + '/certs')) fs.mkdirSync(configDir + '/certs')

  let isScimv2 = false
  if (config.scimversion === '2.0' || config.scimversion === 2) {
    isScimv2 = true
    scimDef = require('../lib/scimdef-v2')
  } else scimDef = require('../lib/scimdef-v1')
  this.testmodeusers = scimDef.TestmodeUsers.Resources // exported and used by plugin-testmode
  this.testmodegroups = scimDef.TestmodeGroups.Resources // exported and used by plugin-testmode

  let azureOptions = {
    validateIssuer: true,
    passReqToCallback: false,
    loggingLevel: null,
    identityMetadata: `https://login.microsoftonline.com/${config.auth.bearer.jwt.azure.tenantIdGUID}/.well-known/openid-configuration`,
    clientID: '00000014-0000-0000-c000-000000000000', // Well known appid: Microsoft.Azure.SyncFabric
    audience: '00000002-0000-0000-c000-000000000000', // Well know appid: Issued for accessing Windows Azure Active Directory Graph Webservice
    issuer: `https://sts.windows.net/${config.auth.bearer.jwt.azure.tenantIdGUID}/`
  }

  passport.use(new OIDCBearerStrategy(azureOptions, function (token, callback) {
    callback(null, token.sub, token)  // Azure SyncFabric don't send user info claims, returning claim token.sub as user
  }))

  let app = express()
  app.disable('etag') // no etag header - disable local browser caching of headers - content type header changes will then be reflected
  app.disable('x-powered-by') // no nodejs-express information in header

  app.use(require('morgan')('combined', { 'stream': log.stream }))   // express logging to log.stream (combined/common) instead of: app.use(express.logger('dev'));  /* 'default', 'short', 'tiny', 'dev' */
  app.use(passport.initialize())
  app.use(expressBearerToken())

  app.use(function (req, res, next) { // authentication/authorization
    async.parallel(
      [
        function (callback) { // basic auth
          let user = basicAuth(req)
          if (user && user.name !== '' && user.pass !== '') { // basic auth
            if (!config.auth.basic.username || !config.auth.basic.password) {
              let err = new Error(`basic authentication is not configured - rejected request from user "${user.name}"`)
              return callback(err, false)
            }
            if (user.name === config.auth.basic.username && user.pass === pwBasicPassword) {
              return callback(null, true) // authentication OK
            } else {
              let err = new Error(`authentication failed for user "${user.name}"`)
              return callback(err, false)
            }
          } else {
            callback(null, false) // baic auth not set
          }
        },

        function (callback) { // bearer token
          if (req.token && (req.token === pwBearerToken)) return callback(null, true) // authorization OK
          else callback(null, false)
        },

        function (callback) { // Azure jwt
          if (req.token && config.auth.bearer.jwt.azure.tenantIdGUID) {
            let payload = jwt.decode(req.token)
            if (payload && payload.iss && payload.iss.indexOf('https://sts.windows.net') === 0) { // Azure
              passport.authenticate('oauth-bearer', { session: false }, function (err, user, info) {
                if (err) { }
                if (!user) {
                  let err = new Error(`authorization failed for Azure jwt: "${info}"`)
                  return callback(err, false)
                } else return callback(null, true) // authorization OK
              })(req, res, next)
            } else return callback(null, false)
          } else callback(null, false)
        },

        function (callback) { // standard jwt
          if (req.token && config.auth.bearer.jwt.standard.options.issuer && (config.auth.bearer.jwt.standard.secret || config.auth.bearer.jwt.standard.publicKey)) {
            let payload = jwt.decode(req.token)
            if (payload && payload.iss.indexOf('https://sts.windows.net') < 0) { // avoid err for azure verify
              if (config.auth.bearer.jwt.standard.publicKey) { // using public key or certificate
                let cert = null
                try {
                  cert = fs.readFileSync(`${configDir}/certs/${config.auth.bearer.jwt.standard.publicKey}`)
                } catch (err) {
                  err.message = `failed reading file defined in configuration auth.bearer.jwt.standard.publicKey: "${err.message}"`
                  return callback(err, false)
                }
                jwt.verify(req.token, cert, config.auth.bearer.jwt.standard.options, function (err, decoded) {
                  if (err) {
                    err.message = `authorization failed for standard jwt: "${err.message}"`
                    return callback(err, false)
                  } else callback(null, true) // authorization OK
                })
              } else { // using secret
                jwt.verify(req.token, pwJwtStandardSecret, config.auth.bearer.jwt.standard.options, function (err, decoded) {
                  if (err) {
                    err.message = `authorization failed for standard jwt: "${err.message}"`
                    return callback(err, false)
                  } else callback(null, true) // authorization OK
                })
              }
            } else return callback(null, false)
          } else callback(null, false)
        }

      ],

      function (err, results) { // final callback
        let isAuthenticated = false
        for (let i in results) {
          if (results[i] === true) {
            isAuthenticated = true
            break
          }
        }
        if (!isAuthenticated && !err) {
          if (!req.token) err = new Error(`request without authentication information`)
          else {
            err = new Error(`request with unsupported authorization bearer or missing plugin configuration`)
            logger.debug(`${gwName} request bearer token = ${req.token}`)
            logger.debug(`${gwName} request bearer token jwt payload = ${JSON.stringify(jwt.decode(req.token))}`)
          }
          res.setHeader('WWW-Authenticate', 'Basic realm=""')
          res.status(401).end('Access denied')
          logger.error(`${gwName} ${err.message}`)
        } else if (!isAuthenticated || err) {
          res.setHeader('WWW-Authenticate', 'Basic realm=""')
          if (pwErrCount < 3) {
            pwErrCount += 1
            res.status(401).end('Access denied')
            logger.error(`${gwName} request not authorized`)
          } else { // delay brute force attempts
            setTimeout(function () {
              res.status(401).end('Access denied')
            }, 1000 * 60 * 2)
            logger.error(`${gwName} request not authorized => delaying response with 2 minutes to prevent any brute force`)
          }
        } else {
          res.setHeader('Content-Type', 'application/scim+json; charset=utf-8')
          return next()
        }
      }
    ) // async
  })

  // Initial connection, step #1: GET /ServiceProviderConfigs
  // If not included => Provisioning will always use GET /Users without any paramenters
  // scimv1 = ServiceProviderConfigs, scimv2 0 ServiceProviderConfig
  app.get(`(|/:baseEntity)(|/scim)/(!${undefined}|ServiceProviderConfigs|ServiceProviderConfig)`, (req, res) => {
    let tx = scimDef.ServiceProviderConfigs // obfuscator friendly
    let protocol = 'http'
    if (req.socket._tlsOptions) protocol = 'https'
    let location = `${protocol}://${req.headers.host}${req.originalUrl}`
    if (tx.meta) tx.meta.location = location
    else {
      tx.meta = {}
      tx.meta.location = location
    }
    res.send(tx)
    logger.debug(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(tx)}`)
  })

  // Initial connection, step #2: GET /Schemas
  app.get('(|/:baseEntity)(|/scim)/Schemas', (req, res) => {
    let tx = scimDef.Schemas
    res.send(tx)
    logger.debug(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(tx)}`)
  })

  app.get('(|/:baseEntity)(|/scim)/Schemas/:id', (req, res) => { // e.g /Schemas/Users | Groups | ServiceProviderConfigs
    let schemaName = req.params.id
    if (schemaName.substr(schemaName.length - 1) === 's') schemaName = schemaName.substr(0, schemaName.length - 1)
    const tx = scimDef.Schemas.Resources.find(el => el.name === schemaName)
    if (!tx) {
      let err = new Error(`Schema '${schemaName}' not found`)
      err = jsonErr(config.scimversion, pluginName, '404', err)
      res.status(404).send(err)
      logger.error(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
    } else {
      res.send(tx)
      logger.debug(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(tx)}`)
    }
  })

  app.get(`(|/:baseEntity)(|/scim)/(!${undefined}|ResourceTypes|ResourceType)`, (req, res) => { // ResourceTypes according to v2 specification
    let tx = scimDef.ResourceType
    res.send(tx)
    logger.debug(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(tx)}`)
  })

  app.get(`(|/:baseEntity)(|/scim)/(!${undefined}|Users|Groups|servicePlans)/:id`, (req, res) => {
    let u = req.originalUrl.substr(0, req.originalUrl.lastIndexOf('/'))
    u = u.substr(u.lastIndexOf('/') + 1) // u = Users, Groups
    let handle = handler[u]
    let id = require('path').basename(req.params.id, '.json') // supports <id>.json
    logger.debug(`${gwName} [Get ${handle.description}] id=${id}`)
    logger.debug(`${gwName} emitting event "${handle.getEmitter}" and awaiting result`)
    this.emit(handle.getEmitter, req.params.baseEntity, id, req.query.attributes ? req.query.attributes : '', function (err, data) {
      if (err) {
        err = jsonErr(config.scimversion, pluginName, '404', err)
        res.status(404).send(err)
        logger.error(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
      } else {
        let protocol = 'http'
        if (req.socket._tlsOptions) protocol = 'https'
        let location = `${protocol}://${req.headers.host}${req.originalUrl}`
        data = addSchemas(data, handle.description, isScimv2)
        if (data.meta) data.meta.location = location
        else {
          data.meta = {}
          data.meta.location = location
        }
        res.send(data)
        logger.debug(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(data)}`)
      }
    })
  })

  app.get(`(|/:baseEntity)(|/scim)/(!${undefined}|Users|Groups|servicePlans)`, (req, res) => {
    let u = req.originalUrl.substr(req.originalUrl.lastIndexOf('/') + 1) // u = Users, Groups, servicePlans, ...
    let ui = u.indexOf('?')
    if (ui > 0) u = u.substr(0, ui)
    let handle = handler[u]
    if (!req.query.filter) {
      // ==========================================
      //             EXPLORE
      // ==========================================
      //
      // GET /Users?attributes=userName&startIndex=1&count=100
      // GET /Groups?attributes=displayName
      // GET /servicePlans?attributes=servicePlanName
      // GET /Users /Groups
      // Note, not emitting attributes to plugin
      //
      logger.debug(`${gwName} [Explore ${handle.description}]`)
      logger.debug(`${gwName} emitting event "${handle.exploreEmitter}" and awaiting result`)
      this.emit(handle.exploreEmitter, req.params.baseEntity, parseInt(req.query.startIndex), parseInt(req.query.count), function (err, data) {
        if (err) {
          err = jsonErr(config.scimversion, pluginName, '500', err)
          res.status(500).send(err)
          logger.error(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
        } else {
          let scimdata = data
          scimdata = addResources(scimdata, req.query.startIndex)
          scimdata = addSchemas(scimdata, handle.description, isScimv2)
          res.send(scimdata)
          logger.debug(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(scimdata)}`)
        }
      })
    } else {
      // ==========================================
      //             GET USER  - getUser
      //             GET GROUP - getGroup
      // ==========================================
      //
      // GET /Users?filter=userName eq "bjensen"&attributes=ims,locale,name.givenName,externalId,preferredLanguage,userType,id,title,timezone,name.middleName,name.familyName,nickName,name.formatted,meta.location,userName,name.honorificSuffix,meta.version,meta.lastModified,meta.created,name.honorificPrefix,emails,phoneNumbers,photos,x509Certificates.value,profileUrl,roles,active,addresses,displayName,entitlements
      //
      // Get user request before/after updating a user:
      // GET = /Users?filter=userName eq "jsmith"&attributes=id,userName
      //
      // Get user request for retreving all attributes:
      // GET = /Users?filter=userName eq "jsmith"&attributes=ims,locale,name.givenName,externalId,preferredLanguage,userType,id,title,timezone,name.middleName,name.familyName,nickName,name.formatted,meta.location,userName,name.honorificSuffix,meta.version,meta.lastModified,meta.created,name.honorificPrefix,emails,phoneNumbers,photos,x509Certificates.value,profileUrl,roles,active,addresses,displayName,entitlements
      //
      //  ---- retreive all users for a spesific group ----
      //
      // "user member of group" => CA IM default scim endpoint config - Group having multivalue attribute members containing userName
      // GET = /Users?filter=id eq "jsmith"&attributes=id,userName
      //
      // "group member of user" => User having multivalue attribute groups containing value=GroupName
      // GET = /Users?filter=groups.value eq "UserGroup-1"&attributes=groups.value,userName
      //
      //   ---- Azure AD to SCIM Users ----
      //
      // Default SCIM attribute mapping have:
      //   externalId mapped to mailNickname (matching precedence #1)
      //   userName mapped to userPrincipalName
      //
      // Precedence decides filter attribute sent to ScimGateway
      // GET = /scim/Users?filter=externalId eq "jarle_elshaug"
      //
      // ScimGateway accepts externalId (as matching precedence) instead of userName, but userName and externalId must
      // then be mapped to the same AD attribte e.g:
      //
      //   externalId mapped to mailNickname (matching precedence #1)
      //   userName mapped to mailNickname
      // or:
      //   externalId mapped to userPrincipalName (matching precedence #1)
      //   userName mapped to userPrincipalName
      //
      // ---- GROUP ----
      //
      // Get group:
      // GET /Groups?filter=displayName eq "Employees"&attributes=externalId,id,members.value,displayName
      //
      // Azure AD:
      // GET /scim/Groups?excludedAttributes=members&filter=externalId eq "MyGroup"
      //
      // Get group members:
      // GET = /Groups?filter=members.value eq "<user-id>"&attributes=members.value,displayName&startIndex=1&count=100
      //
      //   ---- Azure AD to SCIM Groups ----
      //
      // Default SCIM attribute for GROUP mapping have:
      //   externalId mapped to displayName (matching precedence #1)
      //   displayName mapped to mailNickname
      //
      // ScimGateway accepts externalId (as matching precedence) instead of displayName, but displayName and externalId must
      // then be mapped to the same AD attribute e.g:
      //
      //   externalId mapped to displayName (matching precedence #1)
      //   displayName mapped to displayName
      //
      // ---- servicePlans ----
      // GET /servicePlans?filter=servicePlanName+eq+%22EXCHANGE_S_FOUNDATION%22&attributes=servicePlanName
      //
      let arrFilter = req.query.filter.split(' ') // userName eq "bjensen"
      if (arrFilter.length > 2 && arrFilter[1] === 'eq') {
        if ((arrFilter[0] === handle.uniqueAttr || arrFilter[0] === 'id' || arrFilter[0] === 'externalId' || arrFilter[0] === 'members')) {
          let identifier = req.query.filter.substring(req.query.filter.indexOf('"')).replace(/"/g, '') // bjensen
          logger.debug(`${gwName} [Get ${handle.description}] ${handle.uniqueAttr}=${identifier}`)
          logger.debug(`${gwName} emitting event "${handle.getEmitter}" and awaiting result`)
          this.emit(handle.getEmitter, req.params.baseEntity, identifier, req.query.attributes ? req.query.attributes : '', function (err, data) {
            if (err) {
              err = jsonErr(config.scimversion, pluginName, '404', err)
              res.status(404).send(err)
              logger.error(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
            } else {
              if (data) {
                let protocol = 'http'
                if (req.socket._tlsOptions) protocol = 'https'
                let location = `${protocol}://${req.headers.host}${req.originalUrl.substring(0, req.originalUrl.indexOf('?'))}/${data[handle.uniqueAttr]}`
                for (let key in data) { // exludes null and empty objects/arrays
                  if (data[key] === null) delete data[key]
                  else if (JSON.stringify(data[key]) === '{}') delete data[key]
                  else if (Array.isArray(data[key]) && data[key].length < 1) delete data[key]
                }
                if (!data.meta) data.meta = {}
                data.meta.location = location
              }
              let scimdata = data
              scimdata = addResources(scimdata, req.query.startIndex)
              scimdata = addSchemas(scimdata, handle.description, isScimv2)
              res.send(scimdata)
              logger.debug(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(scimdata)}`)
            }
          })
        } else if (arrFilter[0].split('.').length > 1) {
          // User (groups.value) -  get all users for a spesific group ("group member of user" - using groups attribute on user)
          // User (manager.managerId) AAD
          // Groups (members.value) - get users for a spesific groups
          let identifier = req.query.filter.substring(req.query.filter.indexOf('"')).replace(/"/g, '') // UserGroup-1
          logger.debug(`${gwName} [Get ${handle.description} Inclusion] ${arrFilter[0]}=${identifier}`)
          logger.debug(`${gwName} emitting event "${handle.inclusionEmitter}" and awaiting result`)
          this.emit(handle.inclusionEmitter, req.params.baseEntity, identifier, req.query.attributes, function (err, data) {
            if (err) {
              err = jsonErr(config.scimversion, pluginName, '500', err)
              res.status(500).send(err)
              logger.error(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
            } else {
              let scimdata = data
              scimdata = addResources(scimdata, req.query.startIndex)
              scimdata = addSchemas(scimdata, handle.description, isScimv2)
              res.send(scimdata)
              logger.debug(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(scimdata)}`)
            }
          })
        } else {
          let err = `GET /${handle.description}?filter="Incorrect filter definition" must include ${handle.handle.uniqueAttr} (or id) and eq"`
          err = jsonErr(config.scimversion, '', '400', err)
          res.status(400).send(err)
          logger.error(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
        }
      } else {
        let err = `GET /${handle.description}?filter="Incorrect filter definition"`
        err = jsonErr(config.scimversion, '', '400', err)
        res.status(400).send(err)
        logger.error(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
      }
    }
  })

  // ==========================================
  //           CREATE USER
  //           CREATE GROUP
  // ==========================================
  //
  // POST = /Users
  // Body contains user attributes including userName (userID)
  // Body example:
  // {"active":true,"name":{"familyName":"Elshaug","givenName":"Jarle"},"schemas":["urn:scim:schemas:core:1.0"],"userName":"jael01"}
  //
  // POST = /Groups
  // Body contains group attributes including displayName (group name)
  // Body example:
  // {"displayName":"MyGroup","externalId":"MyExternal","schemas":["urn:scim:schemas:core:1.0"]}
  //

  app.post(`(|/:baseEntity)(|/scim)/(!${undefined}|Users|Groups)(|.json)(|.xml)`, (req, res) => {
    let u = req.originalUrl.substr(req.originalUrl.lastIndexOf('/') + 1) // u = Users<.json|.xml>, Groups<.json|.xml>
    let handle = handler[u.split('.')[0]]
    logger.debug(`${gwName} [Create ${handle.description}]`)
    let strBody = ''

    req.on('data', function (data) { // Get body
      strBody += data
    })

    req.on('end', () => {
      let obj = null
      try {
        obj = JSON.parse(strBody)
      } catch (err) { }
      if (obj === null) {
        let err = new Error('Accepting only JSON formatted requests')
        logger.error(`${gwName} ${err.message}`)
        res.status(500).send(`${gwName}[${pluginName}] ${err.message}`)
      } else {
        logger.debug(`${gwName} POST = ${req.originalUrl} Body = ${strBody}`)
        obj = ScimGateway.prototype.convertedScim(obj)
        logger.debug(`${gwName} convertedBody = ${JSON.stringify(obj)}`)
        logger.debug(`${gwName} emitting event "${handle.createEmitter}" and awaiting result`)
        this.emit(handle.createEmitter, req.params.baseEntity, obj, function (err) {
          if (err) {
            err = jsonErr(config.scimversion, pluginName, '500', err)
            res.status(500).send(err)
            logger.error(`${gwName}[${pluginName}] POST = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
          } else {
            let scimdata = JSON.parse(strBody)
            let protocol = 'http'
            if (req.socket._tlsOptions) protocol = 'https'
            let location = `${protocol}://${req.headers.host}${req.originalUrl}/${scimdata.userName ? scimdata.userName : scimdata.displayName}`
            if (!scimdata.meta) scimdata.meta = {}
            scimdata.meta.location = location
            scimdata.id = scimdata.userName ? scimdata.userName : scimdata.displayName
            delete scimdata.password
            res.setHeader('Location', `${location}`)
            res.status(201).send(scimdata)
            logger.debug(`${gwName}[${pluginName}] POST = ${req.originalUrl} Response = ${JSON.stringify(scimdata)}`)
          }
        })
      }
    })
  }) // post

  // ==========================================
  //           DELETE USER
  // ==========================================
  //
  // DELETE /Users/4aa37ddc-4985-4009-ab24-df42d37e2810
  // Note, using id (not username). Explore should therefore set id = username (userID)
  // We then have: DELETE /Users/bjensen
  //
  app.delete('(|/:baseEntity)(|/scim)/Users/:id', (req, res) => {
    let id = req.params.id
    logger.debug(`${gwName} [Delete User] id=${id}`)
    logger.debug(`${gwName} emitting event "deleteUser" and awaiting result`)
    this.emit('deleteUser', req.params.baseEntity, id, function (err) {
      if (err) {
        err = jsonErr(config.scimversion, pluginName, '500', err)
        res.status(500).send(err)
        logger.error(`${gwName}[${pluginName}] DELETE = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
      } else {
        res.status(204).send()
        logger.debug(`${gwName}[${pluginName}] DELETE = ${req.originalUrl} Response = 204 (no content)`)
      }
    })
  }) // delete

  // ==========================================
  //           DELETE GROUP
  // ==========================================
  //
  // DELETE /Groups/4aa37ddc-4985-4009-ab24-df42d37e2810
  // Note, using id (not displayName). Explore should therefore set id = displayName (groupID)
  // We then have: DELETE /Groups/Employees
  //
  app.delete('(|/:baseEntity)(|/scim)/Groups/:id', (req, res) => {
    let id = req.params.id
    logger.debug(`${gwName} [Delete group] id=${id}`)
    logger.debug(`${gwName} emitting event "deleteGroup" and awaiting result`)
    this.emit('deleteGroup', req.params.baseEntity, id, function (err) {
      if (err) {
        err = jsonErr(config.scimversion, pluginName, '500', err)
        res.status(500).send(err)
        logger.error(`${gwName}[${pluginName}] DELETE = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
      } else {
        res.status(204).send()
        logger.debug(`${gwName}[${pluginName}] DELETE = ${req.originalUrl} Response = 204 (no content)`)
      }
    })
  }) // delete

  // ==========================================
  //          MODIFY USER
  //          MODIFY GROUP MEMBERS
  // ==========================================
  //
  // PATCH /Users/4aa37ddc-4985-4009-ab24-df42d37e2810
  // Note, using id (not userName). Explore should therefore set id = userName (userID)
  // We then have: PATCH /Users/bjensen
  //
  // Body contains user attributes to be updated
  // example: {"active":true}
  //
  // Multi-value attributes excluding user attribute 'groups' are customized from array to object based on type
  // This is done for simplifying plugin-code. For more information please see method convertedScim / convertedScim20
  //
  //          MODIFY GROUP MEMBERS
  //
  // PATCH = /Groups/<id>
  // example: PATCH = /Groups/Employees
  //
  // Body contains user attributes to be updated
  // example: {"members":[{"value":"bjensen"}],"schemas":["urn:scim:schemas:core:1.0"]}
  //
  app.patch(`(|/:baseEntity)(|/scim)/(!${undefined}|Users|Groups|servicePlans)/:id`, (req, res) => {
    let u = req.originalUrl.substr(0, req.originalUrl.lastIndexOf('/'))
    u = u.substr(u.lastIndexOf('/') + 1) // u = Users, Groups
    let handle = handler[u]
    let id = req.params.id
    let strBody = ''
    logger.debug(`${gwName} [Modify ${handle.description}] id=${id}`)

    req.on('data', function (data) { // get body
      strBody += data
    })

    req.on('end', () => {
      logger.debug(`${gwName} PATCH = ${req.originalUrl} Body = ${strBody}`)
      let scimdata = JSON.parse(strBody)
      if (scimdata.Operations) scimdata = convertedScim20(scimdata) // SCIM 2.0
      else scimdata = ScimGateway.prototype.convertedScim(scimdata) // SCIM 1.1
      logger.debug(`${gwName} convertedBody = ${JSON.stringify(scimdata)}`)
      logger.debug(`${gwName} emitting event "${handle.modifyEmitter}" and awaiting result`)
      this.emit(handle.modifyEmitter, req.params.baseEntity, id, scimdata.members ? scimdata.members : scimdata, function (err) {
        if (err) {
          err = jsonErr(config.scimversion, pluginName, '500', err)
          res.status(500).send(err)
          logger.error(`${gwName}[${pluginName}] PATCH = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
        } else {
          let scimdata = JSON.parse(strBody)
          let protocol = 'http'
          if (req.socket._tlsOptions) protocol = 'https'
          let location = `${protocol}://${req.headers.host}${req.originalUrl}`
          scimdata.id = id
          delete scimdata.password
          res.setHeader('Location', `${location}`)
          res.status(200).send(scimdata) // using patch body instead of retrieving actual data
          logger.debug(`${gwName}[${pluginName}] PATCH = ${req.originalUrl} Response = 200  ${JSON.stringify(scimdata)}`)
        }
      })
    })
  }) // patch

  // ==========================================
  //          REPLACE USER
  //          REPLACE GROUP MEMBERS
  //          => Using same as patch
  // ==========================================
  app.put(`(|/:baseEntity)(|/scim)/(!${undefined}|Users|Groups|servicePlans)/:id`, (req, res) => {
    let u = req.originalUrl.substr(0, req.originalUrl.lastIndexOf('/'))
    u = u.substr(u.lastIndexOf('/') + 1) // u = Users, Groups
    let handle = handler[u]
    let id = req.params.id
    let strBody = ''
    logger.debug(`${gwName} [Modify ${handle.description}] id=${id}`)

    req.on('data', function (data) { // get body
      strBody += data
    })

    req.on('end', () => {
      logger.debug(`${gwName} PUT = ${req.originalUrl} Body = ${strBody}`)
      let scimdata = JSON.parse(strBody)
      if (scimdata.Operations) scimdata = convertedScim20(scimdata) // SCIM 2.0
      else scimdata = ScimGateway.prototype.convertedScim(scimdata) // SCIM 1.1
      logger.debug(`${gwName} convertedBody = ${JSON.stringify(scimdata)}`)
      logger.debug(`${gwName} emitting event "${handle.modifyEmitter}" and awaiting result`)
      this.emit(handle.modifyEmitter, req.params.baseEntity, id, scimdata.members ? scimdata.members : scimdata, function (err) {
        if (err) {
          err = jsonErr(config.scimversion, pluginName, '500', err)
          res.status(500).send(err)
          logger.error(`${gwName}[${pluginName}] PUT = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
        } else {
          let scimdata = JSON.parse(strBody)
          let protocol = 'http'
          if (req.socket._tlsOptions) protocol = 'https'
          let location = `${protocol}://${req.headers.host}${req.originalUrl}`
          scimdata.id = id
          delete scimdata.password
          res.setHeader('Location', `${location}`)
          res.status(200).send(scimdata)
          logger.debug(`${gwName}[${pluginName}] PUT = ${req.originalUrl} Response = 200  ${JSON.stringify(scimdata)}`)
        }
      })
    })
  }) // put

  // ==========================================
  //           API POST (no SCIM)
  // ==========================================
  //
  // POST = /api + body
  // Send body "as is" to plugin-api
  // Body example:
  // {"eventName":"AsignAccessRoleEvent","subjectName":"RACF_System-B","userID":"peter01"}
  //
  app.post('(|/:baseEntity)/api(|.json)(|.xml)', (req, res) => {
    logger.debug(`${gwName} [POST api]`)
    let strBody = ''

    req.on('data', function (data) { // Get body
      strBody += data
    })

    req.on('end', () => {
      let apiObj = null
      try {
        apiObj = JSON.parse(strBody)
      } catch (err) { }
      if (apiObj === null) {
        let err = new Error('Accepting only JSON formatted requests')
        let errResult = {
          'meta': {
            'result': 'error',
            'description': `${gwName} ${err.message}`
          }
        }
        logger.debug(`${gwName} POST = ${req.originalUrl} Body = ${strBody}`)
        logger.error(`${gwName} ${err.message}`)
        res.status(500).send(errResult)
      } else {
        logger.debug(`${gwName} POST = ${req.originalUrl} Body = ${JSON.stringify(apiObj)}`)
        logger.debug(`${gwName} emitting event "postApi" and awaiting result`)

        this.emit('postApi', req.params.baseEntity, apiObj, function (err, result) {
          if (err) {
            let errResult = {
              result,
              'meta': {
                'result': 'error',
                'description': `${gwName}[${pluginName}] ${err.message}`
              }
            }
            res.status(500).send(errResult)
            logger.error(`${gwName}[${pluginName}] POST = ${req.originalUrl} Response = ${JSON.stringify(errResult)}`)
          } else {
            let protocol = 'http'
            if (req.socket._tlsOptions) protocol = 'https'
            let location = `${protocol}://${req.headers.host}${req.originalUrl}`
            if (result) {
              try {
                JSON.parse(result)
              } catch (err) {
                result = { 'noJSONresponse': result }
              }
            } else result = {}
            if (!result.meta) result.meta = {}
            result.meta.result = 'success'
            result.meta.location = location
            res.status(201).send(result)
            logger.debug(`${gwName}[${pluginName}] POST = ${req.originalUrl} Response = ${JSON.stringify(result)}`)
          }
        })
      }
    })
  }) // post

  // ==========================================
  //           API PUT (no SCIM)
  // ==========================================
  //
  // PUT = /api/{id} + body
  // Send body "as is" to plugin-api
  // Body example:
  // {"eventName":"AsignAccessRoleEvent","subjectName":"RACF_System-B","userID":"peter01"}
  //
  app.put('(|/:baseEntity)/api/:id', (req, res) => {
    let id = req.params.id
    logger.debug(`${gwName} [PUT api ] id=${id}`)
    let strBody = ''

    req.on('data', function (data) { // Get body
      strBody += data
    })

    req.on('end', () => {
      let apiObj = null
      try {
        apiObj = JSON.parse(strBody)
      } catch (err) { }
      if (apiObj === null) {
        let err = new Error('Accepting only JSON formatted requests')
        let errResult = {
          'meta': {
            'result': 'error',
            'description': `${gwName} ${err.message}`
          }
        }
        logger.debug(`${gwName} PUT = ${req.originalUrl} Body = ${strBody}`)
        logger.error(`${gwName} ${err.message}`)
        res.status(500).send(errResult)
      } else {
        logger.debug(`${gwName} PUT = ${req.originalUrl} Body = ${JSON.stringify(apiObj)}`)
        logger.debug(`${gwName} emitting event "putApi" and awaiting result`)
        this.emit('putApi', req.params.baseEntity, id, apiObj, function (err, result) {
          if (err) {
            let errResult = {
              result,
              'meta': {
                'result': 'error',
                'description': `${gwName}[${pluginName}] ${err.message}`
              }
            }
            res.status(500).send(errResult)
            logger.error(`${gwName}[${pluginName}] PUT = ${req.originalUrl} Response = ${JSON.stringify(errResult)}`)
          } else {
            let protocol = 'http'
            if (req.socket._tlsOptions) protocol = 'https'
            let location = `${protocol}://${req.headers.host}${req.originalUrl}`
            if (result) {
              try {
                JSON.parse(result)
              } catch (err) {
                result = { 'noJSONresponse': result }
              }
            } else result = {}
            if (!result.meta) result.meta = {}
            result.meta.result = 'success'
            result.meta.location = location
            res.status(200).send(result)
            logger.debug(`${gwName}[${pluginName}] PUT = ${req.originalUrl} Response = 200 ${JSON.stringify(result)}`)
          }
        })
      }
    })
  }) // put

  // ==========================================
  //           API PATCH (no SCIM)
  // ==========================================
  //
  // PATCH = /api/{id} + body
  // Send body "as is" to plugin-api
  // Body example:
  // {"eventName":"AsignAccessRoleEvent","subjectName":"RACF_System-B","userID":"peter01"}
  //
  app.patch('(|/:baseEntity)/api/:id', (req, res) => {
    let id = req.params.id
    logger.debug(`${gwName} [PATCH api ] id=${id}`)
    let strBody = ''

    req.on('data', function (data) { // Get body
      strBody += data
    })

    req.on('end', () => {
      let apiObj = null
      try {
        apiObj = JSON.parse(strBody)
      } catch (err) { }
      if (apiObj === null) {
        let err = new Error('Accepting only JSON formatted requests')
        let errResult = {
          'meta': {
            'result': 'error',
            'description': `${gwName} ${err.message}`
          }
        }
        logger.debug(`${gwName} PATCH = ${req.originalUrl} Body = ${strBody}`)
        logger.error(`${gwName} ${err.message}`)
        res.status(500).send(errResult)
      } else {
        logger.debug(`${gwName} PATCH = ${req.originalUrl} Body = ${JSON.stringify(apiObj)}`)
        logger.debug(`${gwName} emitting event "patchApi" and awaiting result`)
        this.emit('patchApi', req.params.baseEntity, id, apiObj, function (err, result) {
          if (err) {
            let errResult = {
              result,
              'meta': {
                'result': 'error',
                'description': `${gwName}[${pluginName}] ${err.message}`
              }
            }
            res.status(500).send(errResult)
            logger.error(`${gwName}[${pluginName}] PATCH = ${req.originalUrl} Response = ${JSON.stringify(errResult)}`)
          } else {
            let protocol = 'http'
            if (req.socket._tlsOptions) protocol = 'https'
            let location = `${protocol}://${req.headers.host}${req.originalUrl}`
            if (result) {
              try {
                JSON.parse(result)
              } catch (err) {
                result = { 'noJSONresponse': result }
              }
            } else result = {}
            if (!result.meta) result.meta = {}
            result.meta.result = 'success'
            result.meta.location = location
            res.status(200).send(result)
            logger.debug(`${gwName}[${pluginName}] PATCH = ${req.originalUrl} Response = 200 ${JSON.stringify(result)}`)
          }
        })
      }
    })
  }) // patch

  // ==========================================
  //           API GET (no SCIM)
  // ==========================================
  //
  //  GET = /api
  //  GET = /api?queries
  //  GET = /api/{id}
  //
  app.get('(|/:baseEntity)/api(|/:id)', (req, res) => {
    let id = null
    if (req.params.id) {
      id = require('path').basename(req.params.id, '.json') // supports <id>.json
      logger.debug(`${gwName} [GET api] id=${id}`)
    } else {
      logger.debug(`${gwName} [GET api]`)
    }

    logger.debug(`${gwName} emitting event "getApi" and awaiting result`)
    this.emit('getApi', req.params.baseEntity, id, req.query, function (err, result) {
      if (err) {
        let errResult = {
          result,
          'meta': {
            'result': 'error',
            'description': `${gwName}[${pluginName}] ${err.message}`
          }
        }
        res.status(404).send(errResult)
        logger.error(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = 404 ${JSON.stringify(errResult)}`)
      } else {
        let protocol = 'http'
        if (req.socket._tlsOptions) protocol = 'https'
        let location = `${protocol}://${req.headers.host}${req.originalUrl}`
        let i = location.indexOf('?')
        if (i > 0) location = location.substring(0, i)
        if (result) {
          try {
            JSON.parse(result)
          } catch (err) {
            result = { 'noJSONresponse': result }
          }
        } else result = {}
        if (!result.meta) result.meta = {}
        result.meta.result = 'success'
        result.meta.location = location
        res.status(200).send(result)
        logger.debug(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = 200 ${JSON.stringify(result)}`)
      }
    })
  }) // get

  // ==========================================
  //           API DELETE (no SCIM)
  // ==========================================
  //
  //  DELETE = /api/{id}
  //
  app.delete('(|/:baseEntity)/api/:id', (req, res) => {
    let id = req.params.id
    logger.debug(`${gwName} [DELETE api] id=${id}`)
    logger.debug(`${gwName} emitting event "deleteApi" and awaiting result`)
    this.emit('deleteApi', req.params.baseEntity, id, function (err, result) {
      if (err) {
        let errResult = {
          result,
          'meta': {
            'result': 'error',
            'description': `${gwName}[${pluginName}] ${err.message}`
          }
        }
        res.status(500).send(errResult)
        logger.error(`${gwName}[${pluginName}] DELETE = ${req.originalUrl} Response = 500 ${JSON.stringify(errResult)}`)
      } else {
        if (result) {
          try {
            JSON.parse(result)
          } catch (err) {
            result = { 'noJSONresponse': result }
          }
        } else result = {}
        if (!result.meta) result.meta = {}
        result.meta.result = 'success'
        res.status(200).send(result)
        logger.debug(`${gwName}[${pluginName}] DELETE = ${req.originalUrl} Response = 200 ${JSON.stringify(result)}`)
      }
    })
  }) // delete

  // ==========================================
  // Starting up...
  // ==========================================

  let orgLevelConsole = logger.transports.console.level
  let orgLevelFile = logger.transports.file.level
  logger.transports.console.level = 'info'
  logger.transports.file.level = 'info'

  let processEnv = 'process.env.' // config.port could be set to "process.env.xxx" e.g process.env.PORT then using environment PORT
  if (isNaN(config.port) && config.port.indexOf(processEnv) > -1) config.port = process.env[config.port.substring(processEnv.length)]

  console.log()
  logger.info('===================================================================')
  if (config.localhostonly === true) {
    logger.info(`${gwName} using ${pluginName} denying other clients than localhost (127.0.0.1)`)
    if (config.certificate && config.certificate.key && config.certificate.cert) {
      // SSL
      server = https.createServer({
        'key': fs.readFileSync(configDir + '/certs/' + config.certificate.key),
        'cert': fs.readFileSync(configDir + '/certs/' + config.certificate.cert)
      }, app).listen(config.port, 'localhost')
      logger.info(`${gwName} using ${pluginName} now listening on SSL/TLS port ${config.port}...`)
    } else if (config.certificate && config.certificate.pfx && config.certificate.pfx.bundle) {
      // SSL using PFX / PKCS#12
      server = https.createServer({
        'pfx': fs.readFileSync(configDir + '/certs/' + config.certificate.pfx.bundle),
        'passphrase': pwPfxPassword
      }, app).listen(config.port, 'localhost')
      logger.info(`${gwName} using ${pluginName} now listening on SSL/TLS port ${config.port}...`)
    } else {
      // none SSL
      server = http.createServer(app).listen(config.port, 'localhost')
      logger.info(`${gwName} using ${pluginName} now listening on port ${config.port}...`)
    }
  } else {
    logger.info(`${gwName} using ${pluginName} accepting requests from all clients`)
    if (config.certificate && config.certificate.key && config.certificate.cert) {
      // SSL self signed cert e.g: openssl req -nodes -newkey rsa:2048 -x509 -sha256 -days 3650 -keyout key.pem -out cert.pem -subj "/O=NodeJS/OU=Testing/CN=<FQDN>"
      // Note, self signed certificate (cert.pem) also needs to be imported at the CA Connector Server
      server = https.createServer({
        'key': fs.readFileSync(configDir + '/certs/' + config.certificate.key),
        'cert': fs.readFileSync(configDir + '/certs/' + config.certificate.cert),
        'ca': (config.certificate.ca) ? fs.readFileSync(configDir + '/certs/' + config.certificate.ca) : null
      }, app).listen(config.port)
      logger.info(`${gwName} using ${pluginName} now listening on SSL/TLS port ${config.port}...`)
    } else if (config.certificate && config.certificate.pfx && config.certificate.pfx.bundle) {
      // SSL using PFX / PKCS#12
      server = https.createServer({
        'pfx': fs.readFileSync(configDir + '/certs/' + config.certificate.pfx.bundle),
        'passphrase': pwPfxPassword
      }, app).listen(config.port)
      logger.info(`${gwName} using ${pluginName} now listening on SSL/TLS port ${config.port}...`)
    } else {
      // none SSL
      server = http.createServer(app).listen(config.port)
      logger.info(`${gwName} using ${pluginName} now listening on port ${config.port}...`)
    }
  }

  logger.transports.console.level = orgLevelConsole
  logger.transports.file.level = orgLevelFile

  let gracefulShutdown = function () {
    server.close(function () {
      logger.debug(`${gwName} using ${pluginName} received kill signal - closed out remaining connections`)
      setTimeout(function () { // plugins may also use SIGTERM/SIGINT
        process.exit(1)
      }, 0.5 * 1000)
    })
    setTimeout(function () {
      logger.debug(`${gwName} using ${pluginName} received kill signal - Could not close connections in time, forcefully shutting down`)
      process.exit(2)
    }, 5 * 1000)
  }

  process.on('SIGTERM', gracefulShutdown) // kill
  process.on('SIGINT', gracefulShutdown)  // Ctrl+C
  process.on('unhandledRejection', (err) => { // older versions of V8, unhandled promise rejections are silently dropped
    logger.error(`${gwName} Async function with unhandledRejection: ${err.stack}`)
  })
} // scimgateway

// methods
ScimGateway.prototype.endpointMap = endpointMap

ScimGateway.prototype.getPassword = function (pwEntity, configFile) {
  return utils.getPassword(pwEntity, configFile) // utils.getPassword('scimgateway.password', './config/plugin-testmode.json');
}

ScimGateway.prototype.timestamp = function () {
  return utils.timestamp()
}

ScimGateway.prototype.Lock = Lock

ScimGateway.prototype.getArrayObject = function (Obj, element, type) {
  if (Obj[element]) { // element is case sensitive
    return Obj[element].find(function (el) {
      return (el.type && (el.type).toLowerCase() === type.toLowerCase())
    })
  }
  return null
}

ScimGateway.prototype.isMultivalue = function isMultiValue (objName, attr) { // objName = 'User' or 'Group'
  let ret = false
  let obj = scimDef.Schemas.Resources.find(function (el) {
    return (el.name === objName)
  })
  if (obj) {
    ret = obj.attributes.find(function (el) {
      return (el.name === attr && el.multiValued === true)
    })
  }
  if (ret) return true
  else return false
}

// Multi-value attributes excluding user attribute 'groups' are customized from array to object based on type
// e.g "emails":[{"value":"bjensen@example.com","type":"work"}] => {"emails": {"work": {"value":"bjensen@example.com","type":"work"}}}
// Cleared values are set as user attributes with blank value ""
// e.g {meta:{attributes:['name.givenName','title']}} => {"name": {"givenName": ""}), "title": ""}
ScimGateway.prototype.convertedScim = function convertedScim (scimdata) {
  if (scimdata.schemas) delete scimdata.schemas
  let newMulti = {}
  for (let key in scimdata) {
    if (Array.isArray(scimdata[key]) && (scimdata[key].length > 0) && scimdata[key][0].type) { // exclude "none type" multivalue attributes (e.g groups and x509Certificates)
      scimdata[key].forEach(function (element, index) {
        if (element.operation && element.operation === 'delete') {
          // add as deleted if only element
          scimdata[key].find(function (newelement, newindex) {
            if (element.type && newelement.type && newelement.type === element.type && (newelement.operation !== element.operation)) {
              return true
            } else {
              if (!newMulti[key]) newMulti[key] = {}
              newMulti[key][element.type.toLowerCase()] = {}
              for (let i in element) {
                newMulti[key][element.type.toLowerCase()][i] = element[i]
              }
              newMulti[key][element.type.toLowerCase()].value = '' // delete
              return false
            }
          })
        } else {
          if (!newMulti[key]) newMulti[key] = {}
          newMulti[key][element.type.toLowerCase()] = {}
          for (let i in element) {
            newMulti[key][element.type.toLowerCase()][i] = element[i]
          }
        }
      })
      delete scimdata[key]
    }
  }
  if (scimdata.meta) { // cleared attributes e.g { meta: { attributes: [ 'name.givenName', 'title' ] } }
    if (Array.isArray(scimdata.meta.attributes)) {
      scimdata.meta.attributes.forEach(function (element, index) {
        dot.str(element, '', scimdata)
      })
    }
    delete scimdata.meta
  }
  for (let key in newMulti) {
    dot.copy(key, key, newMulti, scimdata)
  }
  return scimdata
}

// SCIM/CustomScim <=> endpoint attribute parsing used by plugins
ScimGateway.prototype.endpointMapper = function endpointMapper (direction, parseObj, mapObj) {
  let str = ''
  let isObj = false
  let arrUnsupported = []
  let dotParseObj = null
  if (parseObj.constructor === String) str = parseObj
  else {
    isObj = true
    if (parseObj['@odata.context']) delete parseObj['@odata.context'] // AAD cleanup
    dotParseObj = dot.dot(parseObj) // {"name": {"givenName": "myName"}} => {"name.givenName": "myName"}
    str = JSON.stringify(dotParseObj)
  }

  switch (direction) {
    case 'outbound':
      if (isObj) { // body (patch/put)
        for (let key in dotParseObj) { // {"active": "true"}
          let found = false
          let arrIndex = null
          let arr = key.split('.') // multivalue/array - servicePlan.0.value
          let keyOrg = key
          if (arr[arr.length - 1] === 'value' && !isNaN(arr[arr.length - 2])) {
            for (let i = 0; i < (arr.length - 2); i++) { // servicePlan.0.value => servicePlan
              if (i === 0) key = arr[i]
              else key += `.${arr[i]}`
            }
            arrIndex = arr[arr.length - 2]
          }
          for (let key2 in mapObj) {
            if (mapObj[key2].mapTo === key) {
              found = true
              if (mapObj[key2].type === 'array' && arrIndex) {
                str = str.replace(`"${keyOrg}"`, `"${key2}.${arrIndex}"`) // servicePlan.0.value => servicePlan.0
              }
              str = str.replace(`"${key}"`, `"${key2}"`) // {"accountEnabled": {"mapTo": "active"} => str.replace("accountEnabled", "active")
              break
            }
          }
          if (!found) arrUnsupported.push(key)
        }
      } else { // string (get)
        let strArr = []
        strArr = str.split(',')
        for (let i = 0; i < strArr.length; i++) {
          // let found = false
          for (let key in mapObj) {
            if (mapObj[key].mapTo === strArr[i]) {
              // found = true
              strArr[i] = key
              break
            }
          }
          // if (!found) arrUnsupported.push(strArr[i]) // comment out - don't handle unsupported on GET requests (string) - only PATCH create/update (object)
        }
        str = strArr.toString()
      }
      break

    case 'inbound':
      let dotArrFound = ''
      for (let key in dotParseObj) {
        if (key === dotArrFound) continue
        if (Array.isArray(dotParseObj[key]) && dotParseObj[key].length < 1) continue // avoid including 'value' in empty array if mapTo xx.value
        let lastDot = key.lastIndexOf('.')
        let dotArrIndex = null
        if (lastDot > 0 && !isNaN(key.substr(lastDot + 1))) { // array
          dotArrFound = key
          dotArrIndex = key.substr(lastDot + 1)
          key = key.substring(0, lastDot) // "proxyAddresses.0" => "proxyAddresses"
        }
        if (mapObj[key]) {
          if (mapObj[key].type === 'array' && dotArrIndex !== null) { // array e.g proxyAddresses.value mapTo proxyAddresses converts proxyAddresses.0 => proxyAddresses.0.value
            let newStr = mapObj[key].mapTo
            let multiValue = true
            if (newStr.indexOf('.value') > 0) newStr = newStr.substring(0, newStr.indexOf('.value')) // multivalue to back to ScimGateway - remove .value if defined
            else multiValue = false
            if (multiValue) str = str.replace(new RegExp(`"${key}.${dotArrIndex}"`, 'g'), `"${newStr}.${dotArrIndex}.value"`)
            else str = str.replace(new RegExp(`"${key}.${dotArrIndex}"`, 'g'), `"${newStr}.${dotArrIndex}"`)
          } else { // none array
            str = str.replace(`"${key}"`, `"${mapObj[key].mapTo}"`) // {"active": {"mapTo": "accountEnabled"} => str.replace("accountEnabled", "active")
          }
        }
      }
      break

    default:
      ScimGateway.logger.error(`Plugin using endpointMapper(direction, parseObj, mapObj) with incorrect direction - direction must be set to 'outbound' or 'inbound'`)
      str = parseObj
  }

  if (arrUnsupported.length > 0) {
    let err = new Error(`Unsupported SCIM plugin attributes: ${arrUnsupported.toString()}`)
    return err
  } else if (isObj) {
    let strObj = JSON.parse(str)
    strObj = dot.object(strObj)
    let recursiveStrMap = function (obj, dotPath) { // converts inbound/outbound regarding endpointMap type of attribute
      for (let key in obj) {
        if (obj[key] && obj[key].constructor === Object) return recursiveStrMap(obj[key], (dotPath ? `${dotPath}.${key}` : key))
        if (direction === 'outbound') { // outbound
          let dotKey = ''
          if (!dotPath) dotKey = key
          else dotKey = `${dotPath}.${key}`
          if (obj[key] === '') obj[key] = null
          if (mapObj[dotKey] && mapObj[dotKey].type) {
            let type = (mapObj[dotKey].type).toLowerCase()
            if (type === 'boolean' && obj[key].constructor === String) {
              if ((obj[key]).toLowerCase() === 'true') obj[key] = true
              else if ((obj[key]).toLowerCase() === 'false') obj[key] = false
            } else if (type === 'array' && !Array.isArray(obj[key])) {
              if (!obj[key]) obj[key] = []
              else obj[key] = [obj[key]]
            }
          }
        } else { // inbound - convert all values to string
          if (obj[key] === null) delete obj[key] // or set to ''
          else if ((direction === 'inbound') && (obj[key] || obj[key] === false)) {
            obj[key] = obj[key].toString()
          }
        }
      }
    }
    recursiveStrMap(strObj, null)

    return (strObj)
  } else return (str)
}

util.inherits(ScimGateway, EventEmitter)
module.exports = ScimGateway

function addResources (data, startIndex) {
  let res = { Resources: [] }
  if (Array.isArray(data)) res.Resources = data
  else if (data.Resources) res.Resources = data.Resources
  else res.Resources.push(data)

  // If plugin not using pagination, setting totalResults = itemsPerPage
  if (!res.totalResults) res.totalResults = res.Resources.length // Specifies the total number of results matching the Consumer query
  res.itemsPerPage = res.Resources.length                         // Specifies the number of search results returned in a query response page
  res.startIndex = parseInt(startIndex)                            // The 1-based index of the first result in the current set of search results
  if (!res.startIndex) res.startIndex = 1
  if (res.startIndex > res.totalResults) { // invalid request
    res.Resources = []
    res.itemsPerPage = 0
  }
  return res
}

function addSchemas (data, obj, isScimv2) {
  if (!isScimv2) {
    if (obj === 'User') {
      data.schemas = ['urn:scim:schemas:core:1.0', 'urn:scim:schemas:extension:enterprise:1.0']
    } else if (obj === 'Group') {
      data.schemas = ['urn:scim:schemas:core:1.0']
    }
  } else {
    if (data.Resources) data.schemas = ['urn:ietf:params:scim:api:messages:2.0:ListResponse']
    else if (obj === 'User') {
      data.schemas = ['urn:ietf:params:scim:schemas:core:2.0:User', 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']
    } else if (obj === 'Group') {
      data.schemas = ['urn:ietf:params:scim:schemas:core:2.0:Group']
    }
  }
  return data
}

//
// Check and return none supported attributes
//
let notValidAttributes = function notValidAttributes (obj, validScimAttr) {
  if (validScimAttr.length < 1) return ''
  let tgt = dot.dot(obj)
  let ret = (Object.keys(tgt).filter(function (key) { // {'name.givenName': 'Jarle', emails.0.type': 'work'}
    let arrKey = key.split('.')
    if (arrKey.length > 2) key = `${arrKey[0]}.${arrKey[1]}` // e.g emails.work.value => emails.work
    if (key.indexOf('meta.attributes') === 0 || key.indexOf('schemas.') === 0) return false // attributes to be cleard or schema not needed in validScimAttr
    else return (validScimAttr.indexOf(key) === -1)
  }))
  if (ret.length > 0) return ret
  else return null
}

//
// Convert SCIM 2.0 patch to SCIM 1.1 standard (with multivalues customized from array to object based on type)
//
// Scim 2.0:
// {"Operations":[{"op":"Replace","path":"displayName","value":[{"$ref":null,"value":"Peter Hansen"}]},{"op":"Replace","path":"name.familyName","value":[{"$ref":null,"value":"Hansen"}]}]}
//
// Scim 1.1
//   {"displayName": "Peter Hansen", "name": {familyName: "Hansen"}}
//   Multivalues should follow same standards as defined in method convertedScim
//
let convertedScim20 = function convertedScim20 (data) {
  let scimdata = {}
  let groupMembers = []
  if (!Array.isArray(data.Operations)) return scimdata

  data.Operations.forEach(function (element, index) {
    let type = null
    let path = null
    let pathRoot = null
    let rePattern = new RegExp(/^.*(\[type eq .*\]).*$/)
    let arrMatches = null

    if (element.path) {
      arrMatches = element.path.match(rePattern)
      if (Array.isArray(arrMatches) && arrMatches.length === 2) { // [type eq "work"]
        rePattern = new RegExp(/^\[type eq (.*)\]$/)
        arrMatches = arrMatches[1].match(rePattern)
        if (Array.isArray(arrMatches) && arrMatches.length === 2) { // "work"
          type = arrMatches[1].replace(/"/g, '') // work
        }
      }

      rePattern = new RegExp(/^(.*)\[type eq .*\](.*)$/) // "path":"addresses[type eq \"work\"].streetAddress"
      arrMatches = element.path.match(rePattern)
      if (Array.isArray(arrMatches) && arrMatches.length === 2) {
        if (type) path = `${arrMatches[1]}.${type}`
        else path = arrMatches[1]
        pathRoot = arrMatches[1]
      } else if (Array.isArray(arrMatches) && arrMatches.length === 3) {
        if (type) path = `${arrMatches[1]}.${type}${arrMatches[2]}`
        else path = `${arrMatches[1]}${arrMatches[2]}` // NA
        pathRoot = arrMatches[1]
      }
      if ((element.op).toLowerCase() === 'replace' || (element.op).toLowerCase() === 'add') {
        if (element.path === 'members' || element.path === 'groups') {  // members => Group attribute, groups => User attribute
          element.value.forEach(function (el) {
            let eladd = {}
            for (let key in el) {
              eladd[key] = el[key]
            };
            groupMembers.push(eladd)
          })
        }
        if (ScimGateway.prototype.isMultivalue('User', pathRoot)) {
          if (Array.isArray(element.value)) {
            if (type) element.value[0].type = type
            scimdata[pathRoot] = element.value[0]
          } else { // entire set and sub attributes
            dot.str(path, element.value, scimdata)
          }
        } else dot.str(element.path, element.value[0].value, scimdata) // handle e.g name.familyName
      } else if ((element.op).toLowerCase() === 'remove') {
        if (element.path === 'members' || element.path === 'groups') {  // members => Group attribute, groups => User attribute
          element.value.forEach(function (el) {
            groupMembers.push({ 'operation': 'delete', 'value': el.value })
          })
        } else { // User
          if (ScimGateway.prototype.isMultivalue('User', pathRoot)) dot.str(`${pathRoot}.${type}.value`, '', scimdata)
          else {
            if (path) dot.str(path, '', scimdata)
            else dot.str(element.path, '', scimdata)
          }
        }
      }
    } else { // no path - op=remove using path
      for (let key in element.value) {
        if (Array.isArray(element.value[key])) {
          element.value[key].forEach(function (el, i) {
            dot.str(`${key}.${el.type}`, el, scimdata)
          })
        } else {
          dot.str(key, element.value[key], scimdata)
        }
      }
    }
  })

  if (groupMembers.length > 0) scimdata.members = groupMembers
  return scimdata
}

//
// SCIM error formatting
//
let jsonErr = function jsonErr (scimVersion, pluginName, htmlErrCode, err) {
  let errJson = {}
  if (pluginName.length > 0) pluginName = ` [${pluginName}]`
  if (!(typeof err === 'object')) err = { 'message': err }
  if (!err.message) err.message = JSON.stringify(err)
  if (scimVersion !== '2.0' && scimVersion !== 2) { // v1.1
    errJson =
    {
      'Errors': [
        {
          'description': `ScimGateway${pluginName} ${err.message}`,
          'code': htmlErrCode
        }
      ]
    }
  } else { // v2.0
    errJson =
    {
      'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
      'detail': `ScimGateway${pluginName} ${err.message}`,
      'status': htmlErrCode
    }
  }
  return errJson
}
