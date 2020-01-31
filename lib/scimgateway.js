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
const Koa = require('koa')
const Router = require('koa-router')
const bodyParser = require('koa-bodyparser')
const jwt = require('jsonwebtoken')
const passport = require('passport')
const OIDCBearerStrategy = require('passport-azure-ad').BearerStrategy
const dot = require('dot-object')
const nodemailer = require('nodemailer')
const fs = require('fs')
const path = require('path')
const callsite = require('callsite')
const utils = require('../lib/utils')
const endpointMap = require('../lib/endpointMap')
let scimDef = null
let isMailLock = false

/**
 * @constructor
 */
const ScimGateway = function () {
  let server = null
  const stack = callsite()
  const requester = stack[1].getFileName()
  const pluginName = path.basename(requester, '.js')
  const configDir = path.join(path.dirname(requester), '..', 'config')
  const configFile = path.join(`${configDir}`, `${pluginName}.json`) // config name prefix same as pluging name prefix
  let config = require(configFile).scimgateway
  const gwName = path.basename(__filename, '.js') // prefix of current file
  const logDir = path.join(path.dirname(requester), '..', 'logs')
  const Log = require('../lib/logger').Log
  var log = new Log(utils.extendObj(utils.copyObj(config.log), { category: pluginName, colorize: process.stdout.isTTY || false, loglevel: { file: 'debug', console: 'debug' } }), path.join(`${logDir}`, `${pluginName}.log`), config.log)
  const logger = log.logger
  this.logger = logger // exposed to plugin-code
  this.notValidAttributes = notValidAttributes // exposed to plugin-code
  let pwErrCount = 0
  let requestCounter = 0
  const startTime = utils.timestamp()

  if (!config.scim) config.scim = {}
  if (!config.scim.customUniqueAttrMapping) config.scim.customUniqueAttrMapping = {}
  if (!config.log) config.log = {}
  if (!config.log.loglevel) config.log.loglevel = {}
  if (config.loglevel) config.log.loglevel = config.loglevel // legacy support
  if (!config.auth) config.auth = {}
  if (!config.auth.basic) config.auth.basic = {}
  if (!config.auth.bearer) config.auth.bearer = {}
  if (!config.auth.bearer.jwt) config.auth.bearer.jwt = {}
  if (!config.auth.bearer.jwt.azure) config.auth.bearer.jwt.azure = {}
  if (!config.auth.bearer.jwt.standard) config.auth.bearer.jwt.standard = {}
  if (!config.auth.bearer.jwt.standard.options) config.auth.bearer.jwt.standard.options = {}
  if (!config.certificate) config.certificate = {}
  if (!config.certificate.pfx) config.certificate.pfx = {}
  if (!config.emailOnError) config.emailOnError = {}
  if (!config.emailOnError.smtp) config.emailOnError.smtp = {}

  try {
    config = ScimGateway.prototype.processExtConfig(pluginName, config, true) // external config support process.env and process.file
  } catch (err) {
    logger.error(`${gwName}[${pluginName}] ${err.message}`)
    logger.error(`${gwName}[${pluginName}] stopping...\n`)
    throw (new Error('Using exception to stop further asynchronous code execution (ensure synchronous logger flush to logfile and exit program), please ignore this one...'))
  }

  const handler = {}
  handler.Users = handler.users = {
    description: 'User',
    uniqueAttr: 'userName',
    exploreMethod: 'exploreUsers',
    getMethod: 'getUser',
    inclusionMethod: 'getGroupUsers',
    modifyMethod: 'modifyUser',
    createMethod: 'createUser',
    deleteMethod: 'deleteUser'
  }
  handler.Groups = handler.groups = {
    description: 'Group',
    uniqueAttr: 'displayName',
    exploreMethod: 'exploreGroups',
    getMethod: 'getGroup',
    inclusionMethod: 'getGroupMembers',
    modifyMethod: 'modifyGroupMembers',
    createMethod: 'createGroup',
    deleteMethod: 'deleteGroup'
  }
  handler.servicePlans = handler.serviceplans = { // plugin-azure using "CustomSCIM"
    description: 'ServicePlan',
    uniqueAttr: 'servicePlanName',
    exploreMethod: 'exploreServicePlans',
    getMethod: 'getServicePlan',
    inclusionMethod: 'getServicePlanMembers',
    modifyMethod: 'modifyServicePlanMembers',
    createMethod: 'createServicePlan',
    deleteMethod: null
  }

  if (config.scim.customUniqueAttrMapping.userName) handler.Users.uniqueAttr = config.scim.customUniqueAttrMapping.userName
  if (config.scim.customUniqueAttrMapping.displayName) handler.Groups.uniqueAttr = config.scim.customUniqueAttrMapping.displayName

  let pwBasicPassword
  let pwBearerToken
  let pwJwtStandardSecret
  let pwPfxPassword
  if (config.auth.basic.password) pwBasicPassword = ScimGateway.prototype.getPassword('scimgateway.auth.basic.password', configFile)
  if (config.auth.bearer.token) pwBearerToken = ScimGateway.prototype.getPassword('scimgateway.auth.bearer.token', configFile)
  if (config.auth.bearer.jwt.standard.secret) pwJwtStandardSecret = ScimGateway.prototype.getPassword('scimgateway.auth.bearer.jwt.standard.secret', configFile)
  if (config.certificate.pfx.password) pwPfxPassword = ScimGateway.prototype.getPassword('scimgateway.certificate.pfx.password', configFile)
  if (config.emailOnError.smtp.password) config.emailOnError.smtp.password = ScimGateway.prototype.getPassword('scimgateway.emailOnError.smtp.password', configFile)

  if (!(!!pwBasicPassword || !!pwBearerToken || !!pwJwtStandardSecret || !!pwPfxPassword)) { // all null, undefined, false or empty string
    logger.error(`${gwName}[${pluginName}] Scimgateway password decryption failed`)
    logger.error(`${gwName}[${pluginName}] stopping...\n`)
    throw (new Error('Using exception to stop further asynchronous code execution (ensure synchronous logger flush to logfile and exit program), please ignore this one...'))
  }
  if (!fs.existsSync(logDir)) fs.mkdirSync(logDir)
  if (!fs.existsSync(configDir + '/wsdls')) fs.mkdirSync(configDir + '/wsdls')
  if (!fs.existsSync(configDir + '/certs')) fs.mkdirSync(configDir + '/certs')
  if (!fs.existsSync(configDir + '/schemas')) fs.mkdirSync(configDir + '/schemas')

  let isScimv2 = false
  if (config.scim.version === '2.0' || config.scim.version === 2) {
    isScimv2 = true
    scimDef = require('../lib/scimdef-v2')
  } else scimDef = require('../lib/scimdef-v1')

  if (config.scim.customSchema) { // merge plugin custom schema extension into core schemas
    let custom
    try {
      custom = JSON.parse(fs.readFileSync(`${configDir}/schemas/${config.scim.customSchema}`, 'utf8'))
    } catch (err) {
      throw new Error(`failed reading file defined in configuration "scim.customSchema": ${err.message}`)
    }
    if (!Array.isArray(custom)) custom = [custom]
    const schemas = ['User', 'Group']
    let customMerged = false
    for (let i = 0; i < schemas.length; i++) {
      const schema = scimDef.Schemas.Resources.find(el => el.name === schemas[i])
      const customSchema = custom.find(el => el.name === schemas[i])
      if (schema && customSchema && Array.isArray(customSchema.attributes)) {
        const arr1 = schema.attributes // core:1.0/2.0 schema
        const arr2 = customSchema.attributes
        schema.attributes = arr2.filter(arr2Obj => { // only merge attributes (objects) having unique name into core schema
          if (!arr1.some(arr1Obj => arr1Obj.name === arr2Obj.name)) {
            customMerged = true
            if (!isScimv2) arr2Obj.schema = 'urn:scim:schemas:core:1.0'
            return arr2Obj
          }
        }).concat(arr1)
      }
    }
    if (!customMerged) {
      const err = [
        'No custom SCIM schema attributes have been merged. Make sure using correct format e.g. ',
        '[{"name": "User", "attributes" : [...]}]. ',
        'Also make sure attribute names in attributes array do not conflict with core:1.0/2.0 SCIM attribute names'
      ].join()
      throw new Error(err)
    }
  }

  this.testmodeusers = scimDef.TestmodeUsers.Resources // exported and used by plugin-loki
  this.testmodegroups = scimDef.TestmodeGroups.Resources // exported and used by plugin-loki

  const azureOptions = {
    validateIssuer: true,
    passReqToCallback: false,
    loggingLevel: null,
    identityMetadata: `https://login.microsoftonline.com/${config.auth.bearer.jwt.azure.tenantIdGUID}/.well-known/openid-configuration`,
    clientID: '00000014-0000-0000-c000-000000000000', // Well known appid: Microsoft.Azure.SyncFabric
    audience: [
      // New appid used for SCIM provisioning for non-gallery applications. See changes introduced, in reverse cronological order:
      // - https://github.com/MicrosoftDocs/azure-docs/commit/f6997c0952d2ad4f33ce7f5339eeb83c21b51f1e
      // - https://github.com/MicrosoftDocs/azure-docs/commit/64525fea0675a73b2e6b8fe42fbd03ee568cadfc
      '8adf8e6e-67b2-4cf2-a259-e3dc5476c621',
      // Well known appid: Issued for accessing Windows Azure Active Directory Graph Webservice
      '00000002-0000-0000-c000-000000000000'
    ],
    issuer: `https://sts.windows.net/${config.auth.bearer.jwt.azure.tenantIdGUID}/`
  }

  passport.use(new OIDCBearerStrategy(azureOptions, (token, callback) => {
    callback(null, token.sub, token) // Azure SyncFabric don't send user info claims, returning claim token.sub as user
  }))

  const logResult = async (ctx, next) => {
    const started = Date.now()
    await next() // once all middleware below completes, this continues
    const ellapsed = (Date.now() - started) + 'ms' // ctx.set('X-ResponseTime', ellapsed)
    const res = {
      statusCode: ctx.response.status,
      statusMessage: ctx.response.message,
      body: ctx.response.body
    }
    let userName
    const [authType, authToken] = (ctx.request.header.authorization || '').split(' ') // [0] = 'Basic' or 'Bearer'
    if (authType === 'Basic') [userName] = (Buffer.from(authToken, 'base64').toString() || '').split(':')
    if (!userName && authType === 'Bearer') userName = 'token'
    if (ctx.request.url !== '/favicon.ico') {
      if (ctx.response.status < 200 || ctx.response.status > 299) {
        logger.error(`${gwName}[${pluginName}] ${ellapsed} ${ctx.request.ip} ${userName} ${ctx.request.method} ${ctx.request.href} Body = ${JSON.stringify(ctx.request.body)} Response = ${JSON.stringify(res)}${(config.log.loglevel.file === 'debug' && ctx.request.url !== '/ping') ? '\n' : ''}`)
      } else logger.info(`${gwName}[${pluginName}] ${ellapsed} ${ctx.request.ip} ${userName} ${ctx.request.method} ${ctx.request.href} Body = ${JSON.stringify(ctx.request.body)} Response = ${JSON.stringify(res)}${(config.log.loglevel.file === 'debug' && ctx.request.url !== '/ping') ? '\n' : ''}`)
      requestCounter += 1 // logged on exit (not win process termination)
    }
  }

  const auth = async (ctx, next) => { // authentication/authorization
    const [authType, authToken] = (ctx.request.header.authorization || '').split(' ') // [0] = 'Basic' or 'Bearer'

    const unauth = (ctx) => {
      return new Promise((resolve, reject) => {
        if (ctx.url === '/ping') resolve(true) // ping - no auth
        else resolve(false)
      })
    }

    const basic = (ctx) => {
      return new Promise((resolve, reject) => { // basic auth
        if (authType === 'Basic') {
          const [userName, userPassword] = (Buffer.from(authToken, 'base64').toString() || '').split(':')
          if (!config.auth.basic.username || !config.auth.basic.password) {
            const err = new Error(`basic authentication is not configured - rejected request from user ${userName}`)
            reject(err)
          } else if (userName === config.auth.basic.username && userPassword === pwBasicPassword) {
            resolve(true) // authentication OK
          } else {
            const err = new Error(`authentication failed for user ${userName}`)
            reject(err)
          }
        } else {
          resolve(false) // basic auth not used
        }
      })
    }

    const bearerToken = (ctx) => {
      return new Promise((resolve, reject) => { // bearer token
        if (authType === 'Bearer' && !jwt.decode(authToken)) {
          if (pwBearerToken && pwBearerToken === authToken) resolve(true) // authentication OK
          else {
            const err = new Error('bearer token authentication failed')
            reject(err)
          }
        } else resolve(false) // bearer token auth not used
      })
    }

    const bearerAzure = (ctx) => {
      return new Promise((resolve, reject) => { // bearer jwt azure
        if (authType === 'Bearer' && config.auth.bearer.jwt.azure.tenantIdGUID) {
          const payload = jwt.decode(authToken)
          if (payload && payload.iss && payload.iss.indexOf('https://sts.windows.net') === 0) { // Azure
            passport.authenticate('oauth-bearer', { session: false }, (err, user, info) => {
              if (err) { }
              if (user) resolve(true) // authentication OK
              else {
                const err = new Error(`authorization failed for Azure jwt: ${info}`)
                reject(err)
              }
            })(ctx, next)
          } else resolve(false) // no azure bearer token
        } else resolve(false) // no azure bearer token
      })
    }

    const bearerJwt = (ctx) => {
      return new Promise((resolve, reject) => { // bearer jwt azure
        if (authType === 'Bearer' && config.auth.bearer.jwt.standard.options.issuer && (config.auth.bearer.jwt.standard.secret || config.auth.bearer.jwt.standard.publicKey)) {
          const payload = jwt.decode(authToken)
          if (payload && payload.iss.indexOf('https://sts.windows.net') < 0) { // avoid err for azure verify
            if (config.auth.bearer.jwt.standard.publicKey) { // using public key or certificate
              let cert = null
              try {
                cert = fs.readFileSync(`${configDir}/certs/${config.auth.bearer.jwt.standard.publicKey}`)
              } catch (err) {
                err.message = `failed reading file defined in configuration auth.bearer.jwt.standard.publicKey: ${err.message}`
                reject(err)
              }
              jwt.verify(authToken, cert, config.auth.bearer.jwt.standard.options, (err, decoded) => {
                if (err) {
                  err.message = `authorization failed for standard jwt: ${err.message}`
                  reject(err)
                } else resolve(true) // authorization OK
              })
            } else { // using secret
              jwt.verify(authToken, pwJwtStandardSecret, config.auth.bearer.jwt.standard.options, (err, decoded) => {
                if (err) {
                  err.message = `authorization failed for standard jwt: ${err.message}`
                  reject(err)
                } else resolve(true) // authorization OK
              })
            }
          } else resolve(false) // no standard jwt bearer token
        } else resolve(false) // no standard jwt bearer token
      })
    }

    try { // authenticate
      const arrResolve = await Promise.all([unauth(ctx), basic(ctx), bearerToken(ctx), bearerAzure(ctx), bearerJwt(ctx)]).catch((err) => { throw (err) })
      for (const i in arrResolve) {
        if (arrResolve[i]) {
          ctx.set('Content-Type', 'application/scim+json; charset=utf-8') // IE don't support JSON content to be shown in browser, pre IE/Edge versions did not support 'application/scim+json'
          return next() // auth OK - continue with routes
        }
      }
      // all false - no auth method defined
      let err
      if (!authType) err = new Error(`${ctx.url} request without authentication information`)
      else {
        err = new Error(`${ctx.url} request with unsupported authorization bearer or missing plugin configuration`)
        logger.debug(`${gwName}[${pluginName}] request bearer token = ${authToken}`)
        logger.debug(`${gwName}[${pluginName}] request bearer token jwt payload = ${JSON.stringify(jwt.decode(authToken))}`)
      }
      ctx.set('WWW-Authenticate', 'Basic realm=""')
      ctx.status = 401
      ctx.body = 'Access denied'
      if (ctx.url !== '/favicon.ico') logger.error(`${gwName}[${pluginName}] ${err.message}`)
    } catch (err) {
      ctx.set('WWW-Authenticate', 'Basic realm=""')
      if (pwErrCount < 3) {
        pwErrCount += 1
        ctx.status = 401
        ctx.body = 'Access denied'
        logger.error(`${gwName}[${pluginName}] ${ctx.url} ${err.message}`)
      } else { // delay brute force attempts
        logger.error(`${gwName}[${pluginName}] ${ctx.url} ${err.message} => delaying response with 2 minutes to prevent brute force`)
        return new Promise((resolve) => {
          setTimeout(() => {
            ctx.status = 401
            ctx.body = 'Access denied'
            resolve(ctx)
          }, 1000 * 60 * 2)
        })
      }
    }
  } // authentication

  const verifyContentType = (ctx, next) => {
    return new Promise((resolve) => {
      if (ctx.request.length) { // body is included - invalid content-type gives empty body (koa-bodyparser)
        const contentType = ctx.request.type.toLowerCase()
        if (contentType === 'application/json' || contentType === 'application/scim+json') {
          return resolve(next())
        }
        ctx.status = 415
        ctx.body = 'Content-Type header must be \'application/json\' or \'application/scim+json\''
        return resolve(ctx)
      }
      resolve(next())
    })
  }

  const app = new Koa()
  const router = new Router()

  // Middleware run in the order they are defined and communicates through ctx
  // There is no return value, if there were it would be ignored
  app.use(logResult)
  app.use(bodyParser({ // parsed body store in ctx.request.body
    enableTypes: ['json'],
    extendTypes: { json: ['application/scim+json', 'text/plain'] }
  }))
  app.use(auth) // authentication before routes
  app.use(verifyContentType)
  app.use(router.routes())
  app.use(router.allowedMethods())

  app.on('error', (err, ctx) => { // catching none try/catch in app middleware, also bodyparser and body not json
    logger.error(`${gwName}[${pluginName}] Koa method: ${ctx.method} url: ${ctx.origin + ctx.path} body: ${JSON.stringify(ctx.request.body)} error: ${err.message}`)
  })

  router.get('/ping', async (ctx) => { // auth not required
    const tx = 'hello'
    ctx.set('Content-Type', 'text/plain; charset=utf-8')
    ctx.body = tx
  })

  // Initial connection, step #1: GET /ServiceProviderConfigs
  // If not included => Provisioning will always use GET /Users without any paramenters
  // scimv1 = ServiceProviderConfigs, scimv2 ServiceProviderConfig
  router.get(['/(|scim/)(ServiceProviderConfigs|ServiceProviderConfig)',
    '/:baseEntity/(|scim/)(ServiceProviderConfigs|ServiceProviderConfig)'], async (ctx) => {
    const tx = scimDef.ServiceProviderConfigs // obfuscator friendly
    const location = ctx.origin + ctx.path
    if (tx.meta) tx.meta.location = location
    else {
      tx.meta = {}
      tx.meta.location = location
    }
    ctx.body = tx
    logger.debug(`${gwName}[${pluginName}] GET ${ctx.originalUrl} Response = ${JSON.stringify(tx)}`)
  })

  // Initial connection, step #2: GET /Schemas
  router.get(['/(|scim/)Schemas', '/:baseEntity/(|scim/)Schemas'], async (ctx) => {
    let tx = scimDef.Schemas
    tx = addResources(tx)
    tx = addSchemas(tx, null, isScimv2)
    ctx.body = tx
  })

  router.get(['/(|scim/)Schemas/:id', '/:baseEntity/(|scim/)Schemas/:id'], async (ctx) => { // e.g /Schemas/Users | Groups | ServiceProviderConfigs
    let schemaName = ctx.params.id
    if (schemaName.substr(schemaName.length - 1) === 's') schemaName = schemaName.substr(0, schemaName.length - 1)
    const tx = scimDef.Schemas.Resources.find(el => el.name === schemaName)
    if (!tx) {
      let err = new Error(`Schema '${schemaName}' not found`)
      err = jsonErr(config.scim.version, pluginName, ctx.status, err)
      ctx.status = 404
      ctx.body = err
    } else {
      ctx.body = tx
    }
  })

  router.get(['/(|scim/)(ResourceTypes|ResourceType)',
    '/:baseEntity/(|scim/)(ResourceTypes|ResourceType)'], async (ctx) => { // ResourceTypes according to v2 specification
    const tx = scimDef.ResourceType
    ctx.body = tx
  })

  router.get([`/(|scim/)(!${undefined}|Users|Groups|servicePlans)/:id`,
    `/:baseEntity/(|scim/)(!${undefined}|Users|Groups|servicePlans)/:id`], async (ctx) => {
    let u = ctx.originalUrl.substr(0, ctx.originalUrl.lastIndexOf('/'))
    u = u.substr(u.lastIndexOf('/') + 1) // u = Users, Groups
    const handle = handler[u]
    const id = require('path').basename(ctx.params.id, '.json') // supports <id>.json
    logger.debug(`${gwName}[${pluginName}] [Get ${handle.description}] id=${id}`)
    logger.debug(`${gwName}[${pluginName}] calling "${handle.getMethod}" and awaiting result`)

    try {
      let data = await this[handle.getMethod](ctx.params.baseEntity, id, ctx.query.attributes ? ctx.query.attributes : '')
      if (!data || JSON.stringify(data) === '{}') {
        let err = new Error(`${handle.description} ${id} not found`)
        err = jsonErr(config.scim.version, pluginName, ctx.status, err)
        ctx.status = 404
        ctx.body = err
      } else {
        const location = ctx.origin + ctx.path
        data = addSchemas(data, handle.description, isScimv2)
        delete data.password
        if (data.meta) data.meta.location = location
        else {
          data.meta = {}
          data.meta.location = location
        }
        ctx.body = data
      }
    } catch (err) {
      const e = jsonErr(config.scim.version, pluginName, ctx.status, err)
      ctx.status = 404
      ctx.body = e
    }
  })

  router.get(['/(|scim/)(Users|Groups|servicePlans)',
    '/:baseEntity/(|scim/)(Users|Groups|servicePlans)'], async (ctx) => {
    let u = ctx.originalUrl.substr(ctx.originalUrl.lastIndexOf('/') + 1) // u = Users, Groups, servicePlans, ...
    const ui = u.indexOf('?')
    if (ui > 0) u = u.substr(0, ui)
    const handle = handler[u]
    if (!ctx.query.filter) {
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
      logger.debug(`${gwName}[${pluginName}] [Explore ${handle.description}]`)
      logger.debug(`${gwName}[${pluginName}] calling "${handle.exploreMethod}" and awaiting result`)
      try {
        const data = await this[handle.exploreMethod](ctx.params.baseEntity, ctx.query.attributes ? ctx.query.attributes : '', parseInt(ctx.query.startIndex), parseInt(ctx.query.count))
        let scimdata = data
        scimdata = addResources(scimdata, ctx.query.startIndex)
        scimdata = addSchemas(scimdata, handle.description, isScimv2)
        ctx.body = scimdata
        return null
      } catch (err) {
        const e = jsonErr(config.scim.version, pluginName, ctx.status, err)
        ctx.status = 500
        ctx.body = e
        return null
      }
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
      const arrFilter = ctx.query.filter.split(' ') // userName eq "bjensen"
      if (arrFilter.length > 2 && arrFilter[1] === 'eq') {
        if ((arrFilter[0] === handle.uniqueAttr || arrFilter[0] === 'id' || arrFilter[0] === 'externalId' || arrFilter[0] === 'members')) {
          const identifier = ctx.query.filter.substring(ctx.query.filter.indexOf('"')).replace(/"/g, '') // bjensen
          logger.debug(`${gwName}[${pluginName}] [Get ${handle.description}] ${handle.uniqueAttr}=${identifier}`)
          logger.debug(`${gwName}[${pluginName}] calling "${handle.getMethod}" and awaiting result`)

          try {
            let data = await this[handle.getMethod](ctx.params.baseEntity, identifier, ctx.query.attributes ? ctx.query.attributes : '')
            if (!data) data = {}
            if (!isScimv2 && JSON.stringify(data) === '{}') { // user/group not found, scim1.1 => http 404, scim2.0 http 200 and empty resource
              let err = new Error(`${handle.description} ${identifier} not found`)
              err = jsonErr(config.scim.version, pluginName, ctx.status, err)
              ctx.status = 404
              ctx.body = err
              return null
            } else {
              for (const key in data) { // exludes null and empty objects/arrays
                if (data[key] === null) delete data[key]
                else if (JSON.stringify(data[key]) === '{}') delete data[key]
                else if (Array.isArray(data[key]) && data[key].length < 1) delete data[key]
              }
              let scimdata = data
              delete scimdata.password
              scimdata = addResources(scimdata, ctx.query.startIndex)
              scimdata = addSchemas(scimdata, handle.description, isScimv2)
              ctx.body = scimdata
              return null
            }
          } catch (err) {
            const e = jsonErr(config.scim.version, pluginName, ctx.status, err)
            ctx.status = 404
            ctx.body = e
            return null
          }
        } else if (arrFilter[0].split('.').length > 1) {
          // User (groups.value) -  get all users for a spesific group ("group member of user" - using groups attribute on user)
          // User (manager.managerId) AAD
          // Groups (members.value) - get users for a spesific groups
          const identifier = ctx.query.filter.substring(ctx.query.filter.indexOf('"')).replace(/"/g, '') // UserGroup-1
          logger.debug(`${gwName}[${pluginName}] [Get ${handle.description} Inclusion] ${arrFilter[0]}=${identifier}`)
          logger.debug(`${gwName}[${pluginName}] calling "${handle.inclusionMethod}" and awaiting result`)

          try {
            const data = await this[handle.inclusionMethod](ctx.params.baseEntity, identifier, ctx.query.attributes)
            let scimdata = data
            scimdata = addResources(scimdata, ctx.query.startIndex)
            scimdata = addSchemas(scimdata, handle.description, isScimv2)
            ctx.body = scimdata
            return null
          } catch (err) {
            const e = jsonErr(config.scim.version, pluginName, ctx.status, err)
            ctx.status = 500
            ctx.body = e
            return null
          }
        } else {
          let err = `GET /${handle.description}?filter="Incorrect filter definition" must include ${handle.uniqueAttr} (or id) and eq"`
          err = jsonErr(config.scim.version, '', ctx.status, err)
          ctx.status = 400
          ctx.body = err
          return null
        }
      } else {
        let err = `GET /${handle.description}?filter="Incorrect filter definition"`
        err = jsonErr(config.scim.version, '', ctx.status, err)
        ctx.status = 400
        ctx.body = err
        return null
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
  router.post([`/(|scim/)(!${undefined}|Users|Groups)(|.json)(|.xml)`,
    `/:baseEntity/(|scim/)(!${undefined}|Users|Groups)(|.json)(|.xml)`], async (ctx) => {
    const u = ctx.originalUrl.substr(ctx.originalUrl.lastIndexOf('/') + 1) // u = Users<.json|.xml>, Groups<.json|.xml>
    const handle = handler[u.split('.')[0]]
    logger.debug(`${gwName}[${pluginName}] [Create ${handle.description}]`)
    let jsonBody = ctx.request.body
    const strBody = JSON.stringify(jsonBody)
    if (strBody === '{}') {
      let err = new Error('Not accepting empty or none JSON formatted POST requests')
      err = jsonErr(config.scim.version, pluginName, ctx.status, err)
      ctx.status = 500
      ctx.body = err
      return null
    } else if (handle.createMethod === 'createUser' && !jsonBody.userName && !jsonBody.externalId) {
      let err = new Error('userName or externalId is mandatory')
      err = jsonErr(config.scim.version, pluginName, ctx.status, err)
      ctx.status = 500
      ctx.body = err
      return null
    } else if (handle.createMethod === 'createGroup' && !jsonBody.displayName && !jsonBody.externalId) {
      let err = new Error('displayName or externalId is mandatory')
      err = jsonErr(config.scim.version, pluginName, ctx.status, err)
      ctx.status = 500
      ctx.body = err
      return null
    }

    logger.debug(`${gwName}[${pluginName}] POST ${ctx.originalUrl} Body = ${strBody}`)
    jsonBody = JSON.parse(strBody) // using a copy
    const scimdata = ScimGateway.prototype.convertedScim(jsonBody)
    logger.debug(`${gwName}[${pluginName}] convertedBody = ${JSON.stringify(scimdata)}`)
    logger.debug(`${gwName}[${pluginName}] calling "${handle.createMethod}" and awaiting result`)
    try {
      const data = await this[handle.createMethod](ctx.params.baseEntity, scimdata)
      const location = `${ctx.origin}${ctx.path}/${jsonBody.userName || jsonBody.displayName || jsonBody.externalId}`
      if (!jsonBody.meta) jsonBody.meta = {}
      jsonBody.meta.location = location
      jsonBody.id = jsonBody.userName ? jsonBody.userName : jsonBody.displayName
      for (const key in data) { // merge any result e.g: data = {'id': 'xxxx'} when endpoint id different than userName/displayName
        jsonBody[key] = data[key]
      }
      delete jsonBody.password
      ctx.set('Location', location)
      ctx.status = 201
      ctx.body = jsonBody
    } catch (err) {
      const e = jsonErr(config.scim.version, pluginName, ctx.status, err)
      if (err.name && err.name === 'DuplicateKeyError') ctx.status = 409
      else ctx.status = 500
      ctx.body = e
    }
  }) // post

  // ==========================================
  //           DELETE USER/GROUP
  // ==========================================
  //
  // DELETE /Users/4aa37ddc-4985-4009-ab24-df42d37e2810
  // DELETE /Groups/4aa37ddc-4985-4009-ab24-df42d37e2810
  // Note user: using id (not username). Explore should therefore set id = username (userID)
  // Then have: DELETE /Users/bjensen
  // Note groups: using id (not displayName). Explore should therefore set id = displayName (groupID)
  // Then have: DELETE /Groups/Employees
  //
  router.delete([`/(|scim/)(!${undefined}|Users|Groups)/:id`,
    `/:baseEntity/(|scim/)(!${undefined}|Users|Groups)/:id`], async (ctx) => {
    let u = ctx.originalUrl.substr(0, ctx.originalUrl.lastIndexOf('/'))
    u = u.substr(u.lastIndexOf('/') + 1) // u = Users, Groups
    const handle = handler[u]
    const id = ctx.params.id
    logger.debug(`${gwName}[${pluginName}] [Delete ${handle.description}] id=${id}`)
    logger.debug(`${gwName}[${pluginName}] calling "${handle.deleteMethod}" and awaiting result`)

    try {
      await this[handle.deleteMethod](ctx.params.baseEntity, id)
      ctx.status = 204
    } catch (err) {
      const e = jsonErr(config.scim.version, pluginName, ctx.status, err)
      ctx.status = 500
      ctx.body = e
    }
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
  router.patch([`/(|scim/)(!${undefined}|Users|Groups|servicePlans)/:id`,
    `/:baseEntity/(|scim/)(!${undefined}|Users|Groups|servicePlans)/:id`], async (ctx) => {
    let u = ctx.originalUrl.substr(0, ctx.originalUrl.lastIndexOf('/'))
    u = u.substr(u.lastIndexOf('/') + 1) // u = Users, Groups
    const handle = handler[u]
    const id = ctx.params.id
    let jsonBody = ctx.request.body
    const strBody = JSON.stringify(jsonBody)
    if (strBody === '{}') {
      let err = new Error('Not accepting empty or none JSON formatted POST requests')
      err = jsonErr(config.scim.version, pluginName, ctx.status, err)
      ctx.status = 500
      ctx.body = err
    } else {
      logger.debug(`${gwName}[${pluginName}] [Modify ${handle.description}] id=${id}`)
      logger.debug(`${gwName}[${pluginName}] PATCH ${ctx.originalUrl} Body = ${strBody}`)
      jsonBody = JSON.parse(strBody) // using a copy
      let scimdata
      if (isScimv2) scimdata = convertedScim20(jsonBody) // patch/put differences v1/v2
      else scimdata = ScimGateway.prototype.convertedScim(jsonBody)
      logger.debug(`${gwName}[${pluginName}] convertedBody = ${JSON.stringify(scimdata)}`)
      logger.debug(`${gwName}[${pluginName}] calling "${handle.modifyMethod}" and awaiting result`)
      try {
        await this[handle.modifyMethod](ctx.params.baseEntity, id, scimdata.members ? scimdata.members : scimdata)
        const location = ctx.origin + ctx.path
        jsonBody.id = id
        delete jsonBody.password
        ctx.set('Location', location)
        ctx.status = 200
        ctx.body = jsonBody // using original body instead of retrieving actual data
      } catch (err) {
        const e = jsonErr(config.scim.version, pluginName, ctx.status, err)
        ctx.status = 500
        ctx.body = e
      }
    }
  }) // patch

  // ==========================================
  //          REPLACE USER
  //          REPLACE GROUP MEMBERS
  //          => Using same as patch
  // ==========================================
  router.put([`/(|scim/)(!${undefined}|Users|Groups|servicePlans)/:id`,
    `/:baseEntity/(|scim/)(!${undefined}|Users|Groups|servicePlans)/:id`], async (ctx) => {
    let u = ctx.originalUrl.substr(0, ctx.originalUrl.lastIndexOf('/'))
    u = u.substr(u.lastIndexOf('/') + 1) // u = Users, Groups
    const handle = handler[u]
    const id = ctx.params.id
    let jsonBody = ctx.request.body
    const strBody = JSON.stringify(jsonBody)
    if (strBody === '{}') {
      let err = new Error('Not accepting empty or none JSON formatted POST requests')
      err = jsonErr(config.scim.version, pluginName, ctx.status, err)
      ctx.status = 500
      ctx.body = err
    } else {
      logger.debug(`${gwName}[${pluginName}] [Modify ${handle.description}] id=${id}`)
      logger.debug(`${gwName}[${pluginName}] PUT ${ctx.originalUrl} Body = ${strBody}`)
      jsonBody = JSON.parse(strBody) // using a copy
      let scimdata
      if (isScimv2) scimdata = convertedScim20(jsonBody) // patch/put differences v1/v2
      else scimdata = ScimGateway.prototype.convertedScim(jsonBody)
      logger.debug(`${gwName}[${pluginName}] convertedBody = ${JSON.stringify(scimdata)}`)
      logger.debug(`${gwName}[${pluginName}] calling "${handle.modifyMethod}" and awaiting result`)
      try {
        await this[handle.modifyMethod](ctx.params.baseEntity, id, scimdata.members ? scimdata.members : scimdata)
        const location = ctx.origin + ctx.path
        jsonBody.id = id
        delete jsonBody.password
        ctx.set('Location', location)
        ctx.status = 200
        ctx.body = jsonBody // using original body instead of retrieving actual data
      } catch (err) {
        const e = jsonErr(config.scim.version, pluginName, ctx.status, err)
        ctx.status = 500
        ctx.body = e
      }
    }
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
  router.post(['/api', '/:baseEntity/api'], async (ctx) => {
    logger.debug(`${gwName}[${pluginName}] [POST api]`)
    const jsonBody = ctx.request.body
    let apiObj = null
    try {
      apiObj = jsonBody
    } catch (err) { }
    if (apiObj === null) {
      const err = new Error('Accepting only JSON formatted requests')
      ctx.status = 500
      ctx.body = apiErr(pluginName, err)
    } else {
      logger.debug(`${gwName}[${pluginName}] POST ${ctx.originalUrl} Body = ${JSON.stringify(apiObj)}`)
      logger.debug(`${gwName}[${pluginName}] calling "postApi" and awaiting result`)

      try {
        let result = await this.postApi(ctx.params.baseEntity, apiObj)
        const location = ctx.origin + ctx.path
        if (result) {
          if (typeof result === 'object') result = { result: result }
          else {
            try {
              result = { result: JSON.parse(result) }
            } catch (err) {
              result = { result: result }
            }
          }
        } else result = {}
        if (!result.meta) result.meta = {}
        result.meta.result = 'success'
        result.meta.location = location
        ctx.status = 201
        ctx.body = result
      } catch (err) {
        ctx.status = 500
        ctx.body = apiErr(pluginName, err)
      }
    }
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
  router.put(['/api/:id', '/:baseEntity/api/:id'], async (ctx) => {
    const id = ctx.params.id
    logger.debug(`${gwName}[${pluginName}] [PUT api ] id=${id}`)
    const jsonBody = ctx.request.body
    let apiObj = null
    try {
      apiObj = jsonBody
    } catch (err) { }
    if (apiObj === null) {
      const err = new Error('Accepting only JSON formatted requests')
      ctx.status = 500
      ctx.body = apiErr(pluginName, err)
    } else {
      logger.debug(`${gwName}[${pluginName}] PUT ${ctx.originalUrl} Body = ${JSON.stringify(apiObj)}`)
      logger.debug(`${gwName}[${pluginName}] calling "putApi" and awaiting result`)

      try {
        let result = await this.putApi(ctx.params.baseEntity, id, apiObj)
        const location = ctx.origin + ctx.path
        if (result) {
          if (typeof result === 'object') result = { result: result }
          else {
            try {
              result = { result: JSON.parse(result) }
            } catch (err) {
              result = { result: result }
            }
          }
        } else result = {}
        if (!result.meta) result.meta = {}
        result.meta.result = 'success'
        result.meta.location = location
        ctx.status = 200
        ctx.body = result
      } catch (err) {
        ctx.status = 500
        ctx.body = apiErr(pluginName, err)
      }
    }
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
  router.patch(['/api/:id', '/:baseEntity/api/:id'], async (ctx) => {
    const id = ctx.params.id
    logger.debug(`${gwName}[${pluginName}] [PATCH api ] id=${id}`)
    const jsonBody = ctx.request.body
    let apiObj = null
    try {
      apiObj = jsonBody
    } catch (err) { }
    if (apiObj === null) {
      const err = new Error('Accepting only JSON formatted requests')
      ctx.status = 500
      ctx.body = apiErr(pluginName, err)
    } else {
      logger.debug(`${gwName}[${pluginName}] PATCH ${ctx.originalUrl} Body = ${JSON.stringify(apiObj)}`)
      logger.debug(`${gwName}[${pluginName}] calling "patchApi" and awaiting result`)

      try {
        let result = await this.patchApi(ctx.params.baseEntity, id, apiObj)
        const location = ctx.origin + ctx.path
        if (result) {
          if (typeof result === 'object') result = { result: result }
          else {
            try {
              result = { result: JSON.parse(result) }
            } catch (err) {
              result = { result: result }
            }
          }
        } else result = {}
        if (!result.meta) result.meta = {}
        result.meta.result = 'success'
        result.meta.location = location
        ctx.status = 200
        ctx.body = result
      } catch (err) {
        ctx.status = 500
        ctx.body = apiErr(pluginName, err)
      }
    }
  }) // patch

  // ==========================================
  //           API GET (no SCIM)
  // ==========================================
  //
  //  GET = /api
  //  GET = /api?queries
  //  GET = /api/{id}
  //
  router.get(['/api', '/api/:id',
    '/:baseEntity/api', '/:baseEntity/api/:id'], async (ctx) => {
    if (ctx.params.id) logger.debug(`${gwName}[${pluginName}] [GET api] id=${ctx.params.id}`)
    else logger.debug(`${gwName}[${pluginName}] [GET api]`)
    logger.debug(`${gwName}[${pluginName}] calling "getApi" and awaiting result`)

    try {
      let result = await this.getApi(ctx.params.baseEntity, ctx.params.id, ctx.query)
      const location = ctx.origin + ctx.path
      if (result) {
        if (typeof result === 'object') result = { result: result }
        else {
          try {
            result = { result: JSON.parse(result) }
          } catch (err) {
            result = { result: result }
          }
        }
      } else result = {}
      if (!result.meta) result.meta = {}
      result.meta.result = 'success'
      result.meta.location = location
      ctx.status = 200
      ctx.body = result
    } catch (err) {
      ctx.status = 404
      ctx.body = apiErr(pluginName, err)
    }
  })

  // ==========================================
  //           API DELETE (no SCIM)
  // ==========================================
  //
  //  DELETE = /api/{id}
  //
  router.delete(['/api/:id', '/:baseEntity/api/:id'], async (ctx) => {
    const id = ctx.params.id
    logger.debug(`${gwName}[${pluginName}] [DELETE api] id=${id}`)
    logger.debug(`${gwName}[${pluginName}] calling "deleteApi" and awaiting result`)

    try {
      let result = await this.deleteApi(ctx.params.baseEntity, id)
      if (result) {
        if (typeof result === 'object') result = { result: result }
        else {
          try {
            result = { result: JSON.parse(result) }
          } catch (err) {
            result = { result: result }
          }
        }
      } else result = {}
      if (!result.meta) result.meta = {}
      result.meta.result = 'success'
      ctx.status = 200
      ctx.body = result
    } catch (err) {
      ctx.status = 500
      ctx.body = apiErr(pluginName, err)
    }
  }) // delete

  // ==========================================
  // Starting up...
  // ==========================================

  logger.info('===================================================================')

  if (config.localhostonly === true) {
    logger.info(`${gwName}[${pluginName}] denying other clients than localhost (127.0.0.1)`)
    if (config.certificate && config.certificate.key && config.certificate.cert) {
      // SSL
      server = https.createServer({
        key: fs.readFileSync(configDir + '/certs/' + config.certificate.key),
        cert: fs.readFileSync(configDir + '/certs/' + config.certificate.cert)
      }, app.callback()).listen(config.port, 'localhost')
      logger.info(`${gwName}[${pluginName}] now listening on TLS port ${config.port}...\n`)
    } else if (config.certificate && config.certificate.pfx && config.certificate.pfx.bundle) {
      // SSL using PFX / PKCS#12
      server = https.createServer({
        pfx: fs.readFileSync(configDir + '/certs/' + config.certificate.pfx.bundle),
        passphrase: pwPfxPassword
      }, app.callback()).listen(config.port, 'localhost')
      logger.info(`${gwName}[${pluginName}] now listening on TLS port ${config.port}...\n`)
    } else {
      // none SSL
      server = http.createServer(app.callback()).listen(config.port, 'localhost')
      logger.info(`${gwName}[${pluginName}] now listening on port ${config.port}...\n`)
    }
  } else {
    logger.info(`${gwName}[${pluginName}] accepting requests from all clients`)
    if (config.certificate && config.certificate.key && config.certificate.cert) {
      // SSL self signed cert e.g: openssl req -nodes -newkey rsa:2048 -x509 -sha256 -days 3650 -keyout key.pem -out cert.pem -subj "/O=NodeJS/OU=Testing/CN=<FQDN>"
      // Note, self signed certificate (cert.pem) also needs to be imported at the CA Connector Server
      server = https.createServer({
        key: fs.readFileSync(configDir + '/certs/' + config.certificate.key),
        cert: fs.readFileSync(configDir + '/certs/' + config.certificate.cert),
        ca: (config.certificate.ca) ? fs.readFileSync(configDir + '/certs/' + config.certificate.ca) : null
      }, app.callback()).listen(config.port)
      logger.info(`${gwName}[${pluginName}] now listening on TLS port ${config.port}...\n`)
    } else if (config.certificate && config.certificate.pfx && config.certificate.pfx.bundle) {
      // SSL using PFX / PKCS#12
      server = https.createServer({
        pfx: fs.readFileSync(configDir + '/certs/' + config.certificate.pfx.bundle),
        passphrase: pwPfxPassword
      }, app.callback()).listen(config.port)
      logger.info(`${gwName}[${pluginName}] now listening on TLS port ${config.port}...\n`)
    } else {
      // none SSL
      server = http.createServer(app.callback()).listen(config.port)
      logger.info(`${gwName}[${pluginName}] now listening on port ${config.port}...\n`)
    }
  }


  console.log(config.log)

  // set loglevel according to config
  const arrValidLevel = ['silly', 'debug', 'verbose', 'info', 'warn', 'error']
  for (let i = 0; i < logger.transports.length; i++) {
    if (logger.transports[i].name === 'file') config.log.loglevel.file && arrValidLevel.includes(config.log.loglevel.file.toLowerCase()) ? logger.transports[i].level = config.log.loglevel.file : logger.transports[i].level = 'debug'
    else if (logger.transports[i].name === 'console') config.log.loglevel.console && arrValidLevel.includes(config.log.loglevel.console.toLowerCase()) ? logger.transports[i].level = config.log.loglevel.console : logger.transports[i].level = 'debug'
  }

  log.emailOnError = async (msg) => { // sending mail on error
    if (!config.emailOnError || !config.emailOnError.smtp || !(config.emailOnError.smtp.enabled === true) || isMailLock) return null // not sending mail
    isMailLock = true

    setTimeout(function () { // release lock after "sendInterval" minutes
      isMailLock = false
    }, (config.emailOnError.smtp.sendInterval || 15) * 1000 * 60)

    const bodyHtml = `<html><body> 
          <p>${msg}</p> 
          <br> 
          <p><strong>This is an automatically generated email - please do NOT reply to this email or forward to others</strong></p> 
          </body></html>`

    const smtpConfig = {
      host: config.emailOnError.smtp.host, // e.g. smtp.office365.com
      port: config.emailOnError.smtp.port || 587,
      proxy: config.emailOnError.smtp.proxy || null,
      secure: (config.emailOnError.smtp.port === 465), // false on 25/587
      tls: { ciphers: 'TLSv1.2' }
    }
    if (config.emailOnError.smtp.authenticate) {
      smtpConfig.auth = {}
      smtpConfig.auth.user = config.emailOnError.smtp.username
      smtpConfig.auth.pass = config.emailOnError.smtp.password
    }

    const transporter = nodemailer.createTransport(smtpConfig)
    const mailOptions = {
      from: config.emailOnError.smtp.username, // sender address
      to: config.emailOnError.smtp.to, // list of receivers - comma separated
      cc: config.emailOnError.smtp.cc,
      subject: 'ScimGateway error message',
      html: bodyHtml // 'text': bodyText
    }

    transporter.sendMail(mailOptions, function (err, info) {
      if (err) logger.error(`${gwName}[${pluginName}] mailOnError sending failed: ${err.message}`)
      else logger.debug(`${gwName}[${pluginName}] mailOnError sent to: ${config.emailOnError.smtp.to}${(config.emailOnError.smtp.cc) ? ',' + config.emailOnError.smtp.cc : ''}`)
    })
    return null
  } // emailOnError

  const gracefulShutdown = function () {
    logger.debug(`${gwName}[${pluginName}] received terminate/kill signal - closing connections and exit`)
    for (let i = logger.transports.length - 1; i >= 0; i--) { // enable info logging
      try { logger.transports[i].level = 'info' } catch (e) { }
    }
    logger.info(`${gwName}[${pluginName}] pheww... ${requestCounter} requests have been processed in the period ${startTime} - ${utils.timestamp()}\n`)
    logger.close()
    server.close(function () {
      setTimeout(function () { // plugins may also use SIGTERM/SIGINT
        process.exit(1)
      }, 0.5 * 1000)
    })
    setTimeout(function () { // problem closing server connections in time due to keep-alive sessions (active browser connection?), now forcing exit
      process.exit(2)
    }, 2 * 1000)
  }

  process.on('unhandledRejection', (err) => { // older versions of V8, unhandled promise rejections are silently dropped
    logger.error(`${gwName}[${pluginName}] Async function with unhandledRejection: ${err.stack}`)
  })
  process.once('SIGTERM', gracefulShutdown) // kill (windows subsystem lacks signaling support for process.kill)
  process.once('SIGINT', gracefulShutdown) // Ctrl+C
} // scimgateway

// methods
ScimGateway.prototype.endpointMap = endpointMap

ScimGateway.prototype.getPassword = (pwEntity, configFile) => {
  return utils.getPassword(pwEntity, configFile) // utils.getPassword('scimgateway.password', './config/plugin-testmode.json');
}

ScimGateway.prototype.timestamp = () => {
  return utils.timestamp()
}

ScimGateway.prototype.copyObj = (o) => {
  return utils.copyObj(o)
}

ScimGateway.prototype.extendObj = (obj, src) => {
  return utils.extendObj(obj, src)
}

ScimGateway.prototype.Lock = utils.Lock

ScimGateway.prototype.getArrayObject = (Obj, element, type) => {
  if (Obj[element]) { // element is case sensitive
    return Obj[element].find(function (el) {
      return (el.type && (el.type).toLowerCase() === type.toLowerCase())
    })
  }
  return null
}

ScimGateway.prototype.isMultivalue = function isMultiValue (objName, attr) { // objName = 'User' or 'Group'
  let ret = false
  const obj = scimDef.Schemas.Resources.find(function (el) {
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
ScimGateway.prototype.convertedScim = function convertedScim (obj) {
  const scimdata = utils.copyObj(obj)
  if (scimdata.schemas) delete scimdata.schemas
  const newMulti = {}
  for (const key in scimdata) {
    if (Array.isArray(scimdata[key]) && (scimdata[key].length > 0) && scimdata[key][0].type) { // exclude "none type" multivalue attributes (e.g groups and x509Certificates)
      scimdata[key].forEach(function (element, index) {
        if (element.operation && element.operation === 'delete') { // add as deleted if the only type element
          const arr = scimdata[key]
          const arrMap = arr
            .map(arr => arr.type)
          if (arrMap.length === 1) {
            if (!newMulti[key]) newMulti[key] = {}
            newMulti[key][element.type.toLowerCase()] = {}
            for (const i in element) {
              newMulti[key][element.type.toLowerCase()][i] = element[i]
            }
            newMulti[key][element.type.toLowerCase()].value = '' // delete
          }
        } else {
          if (!newMulti[key]) newMulti[key] = {}
          newMulti[key][element.type.toLowerCase()] = {}
          for (const i in element) {
            if (i !== 'type') newMulti[key][element.type.toLowerCase()][i] = element[i]
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
  for (const key in newMulti) {
    dot.copy(key, key, newMulti, scimdata)
  }
  return scimdata
}

// config can also be set based on environment variables
// config can also be set based on correspondig json-content in external file (supports also dot notation)
// syntax environment = "process.env.<ENVIRONMENT>" e.g. config.port could have value "process.env.PORT", then using environment variable PORT
// syntax file = "process.file.<PATH>" e.g. config.password could have value "process.file./tmp/myconf.json"
ScimGateway.prototype.processExtConfig = function processExtConfig (pluginName, config, isMain) {
  const processEnv = 'process.env.'
  const processFile = 'process.file.'
  const dotConfig = dot.dot(config)
  let content
  let filePath

  for (const key in dotConfig) {
    let value = dotConfig[key]
    if (value && value.constructor === String && value.includes(processEnv)) {
      const envKey = value.substring(processEnv.length)
      value = process.env[envKey]
      dotConfig[key] = value
      if (!value) {
        const newErr = new Error(`configuration failed - can't use none existing environment: "${envKey}"`)
        newErr.name = 'processExtConfig'
        throw newErr
      }
    } else if (value && value.constructor === String && value.includes(processFile)) {
      const newFilePath = value.substring(processFile.length)
      try {
        if (filePath !== newFilePath) { // avoid reading previous file
          filePath = newFilePath
          content = fs.readFileSync(filePath, 'utf8')
        }
        try {
          const jContent = JSON.parse(content) // json or json-dot-notation formatting is supported
          const dotContent = dot.dot(dot.object(jContent))
          let newKey = null
          if (isMain) newKey = `${pluginName}.scimgateway.${key}`
          else newKey = `${pluginName}.endpoint.${key}`
          value = dotContent[newKey]
          if (value === undefined) {
            const newErr = new Error(`configuration failed - external JSON file "${filePath}" does not contain key: "${newKey}"`)
            newErr.name = 'processExtConfig'
            throw newErr
          }
        } catch (err) {
          if (err.name && err.name === 'processExtConfig') throw err
          else {
            const newErr = new Error(`configuration failed - can't JSON parse external file: "${filePath}"`)
            newErr.name = 'processExtConfig'
            throw newErr
          }
        }
      } catch (err) {
        value = undefined
        if (err.name && err.name === 'processExtConfig') throw err
        else throw (new Error(`configuration failed - can't read external configuration file: ${err.message}`))
      }
      dotConfig[key] = value
    }
  }
  content = null
  return dot.object(dotConfig)
}

// SCIM/CustomScim <=> endpoint attribute parsing used by plugins
ScimGateway.prototype.endpointMapper = function endpointMapper (direction, parseObj, mapObj) {
  let str = ''
  let isObj = false
  const arrUnsupported = []
  let dotParseObj = null
  if (parseObj.constructor === String) str = parseObj
  else {
    isObj = true
    if (parseObj['@odata.context']) delete parseObj['@odata.context'] // AAD cleanup
    dotParseObj = dot.dot(parseObj) // {"name": {"givenName": "myName"}} => {"name.givenName": "myName"}
    str = JSON.stringify(dotParseObj)
  }

  let dotArrFound = ''
  switch (direction) {
    case 'outbound':
      if (isObj) { // body (patch/put)
        for (let key in dotParseObj) { // {"active": "true"}
          let found = false
          let arrIndex = null
          const arr = key.split('.') // multivalue/array - servicePlan.0.value
          const keyOrg = key
          if (arr[arr.length - 1] === 'value' && !isNaN(arr[arr.length - 2])) {
            for (let i = 0; i < (arr.length - 2); i++) { // servicePlan.0.value => servicePlan
              if (i === 0) key = arr[i]
              else key += `.${arr[i]}`
            }
            arrIndex = arr[arr.length - 2]
          }
          for (const key2 in mapObj) {
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
          for (const key in mapObj) {
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
      for (let key in dotParseObj) {
        if (key === dotArrFound) continue
        if (Array.isArray(dotParseObj[key]) && dotParseObj[key].length < 1) continue // avoid including 'value' in empty array if mapTo xx.value
        const lastDot = key.lastIndexOf('.')
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
      ScimGateway.logger.error('Plugin using endpointMapper(direction, parseObj, mapObj) with incorrect direction - direction must be set to \'outbound\' or \'inbound\'')
      str = parseObj
  }

  if (arrUnsupported.length > 0) {
    const err = new Error(`Unsupported SCIM plugin attributes: ${arrUnsupported.toString()}`)
    return err
  } else if (isObj) {
    let strObj = JSON.parse(str)
    strObj = dot.object(strObj)
    const recursiveStrMap = function (obj, dotPath) { // converts inbound/outbound regarding endpointMap type of attribute
      for (const key in obj) {
        if (obj[key] && obj[key].constructor === Object) return recursiveStrMap(obj[key], (dotPath ? `${dotPath}.${key}` : key))
        if (direction === 'outbound') { // outbound
          let dotKey = ''
          if (!dotPath) dotKey = key
          else dotKey = `${dotPath}.${key}`
          if (obj[key] === '') obj[key] = null
          if (mapObj[dotKey] && mapObj[dotKey].type) {
            const type = (mapObj[dotKey].type).toLowerCase()
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

module.exports = ScimGateway // plugins can now use ScimGateway

const addResources = (data, startIndex) => {
  if (!data || JSON.stringify(data) === '{}') data = [] // no user/group found
  const res = { Resources: [] }
  if (Array.isArray(data)) res.Resources = data
  else if (data.Resources) {
    res.Resources = data.Resources
    res.totalResults = data.totalResults
  } else res.Resources.push(data)

  // If plugin not using pagination, setting totalResults = itemsPerPage
  if (!res.totalResults) res.totalResults = res.Resources.length // Specifies the total number of results matching the Consumer query
  res.itemsPerPage = res.Resources.length // Specifies the number of search results returned in a query response page
  res.startIndex = parseInt(startIndex) // The 1-based index of the first result in the current set of search results
  if (!res.startIndex) res.startIndex = 1
  if (res.startIndex > res.totalResults) { // invalid paging request, or scim 2.0 no user/group found
    res.Resources = []
    res.itemsPerPage = 0
  }
  for (let i = 0; i < res.Resources.length; i++) { delete res.Resources[i].password }
  return res
}

const addSchemas = (data, obj, isScimv2) => {
  if (!isScimv2) {
    if (data.Resources) data.schemas = ['urn:scim:schemas:core:1.0', 'urn:scim:schemas:extension:enterprise:1.0']
    else if (obj === 'User') {
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
const notValidAttributes = (obj, validScimAttr) => {
  if (validScimAttr.length < 1) return ''
  const tgt = dot.dot(obj)
  const ret = (Object.keys(tgt).filter(function (key) { // {'name.givenName': 'Jarle', emails.0.type': 'work'}
    const arrKey = key.split('.')
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
const convertedScim20 = (data) => {
  const scimdata = {}
  const groupMembers = []
  if (!Array.isArray(data.Operations)) return scimdata
  data.Operations.forEach(function (element, index) {
    let type = null
    let typeElement = null
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

      rePattern = new RegExp(/^(.*)\[type eq .*\]\.(.*)$/) // "path":"addresses[type eq \"work\"].streetAddress"
      arrMatches = element.path.match(rePattern)
      if (Array.isArray(arrMatches) && arrMatches.length === 2) {
        if (type) path = `${arrMatches[1]}.${type}`
        else path = arrMatches[1]
        pathRoot = arrMatches[1]
      } else if (Array.isArray(arrMatches) && arrMatches.length === 3) {
        if (type) {
          path = `${arrMatches[1]}.${type}.${arrMatches[2]}`
          typeElement = arrMatches[2] // streetAddress
        } else path = `${arrMatches[1]}.${arrMatches[2]}` // NA
        pathRoot = arrMatches[1]
      }
      if ((element.op).toLowerCase() === 'replace' || (element.op).toLowerCase() === 'add') {
        if (element.path === 'members' || element.path === 'groups') { // members => Group attribute, groups => User attribute
          if (Array.isArray(element.value)) {
            element.value.forEach(function (el) { // {"value": [{ "value": "jsmith" }]}
              const eladd = {}
              for (const key in el) {
                eladd[key] = el[key]
              };
              groupMembers.push(eladd)
            })
          } else groupMembers.push(element.value) // {"value": { "value": "jsmith" }}
        }
        if (ScimGateway.prototype.isMultivalue('User', pathRoot)) {
          if (Array.isArray(element.value) && type) {
            if (!scimdata[pathRoot]) scimdata[pathRoot] = {}
            if (!scimdata[pathRoot][type]) scimdata[pathRoot][type] = {}
            if (!scimdata[pathRoot][type].type) scimdata[pathRoot][type].type = type
            if (!scimdata[pathRoot][type][typeElement] && typeElement !== 'value') scimdata[pathRoot][type][typeElement] = {}
            if (typeElement === 'value') scimdata[pathRoot][type].value = element.value[0].value // { phoneNumbers: { work: '+47 12345678' } }
            else scimdata[pathRoot][type][typeElement] = element.value[0].value // { addresses: { work: { country: 'Norway'} } }
          } else dot.str(path, element.value, scimdata) // entire set and sub attributes
        } else { // handle e.g name.familyName {"op": "Add", "path": "name.familyName", "value": [{"$ref": null,"value": "Jensen"}]}
          if (Array.isArray(element.value)) dot.str(element.path, element.value[0].value, scimdata)
          else dot.str(element.path, element.value, scimdata)
        }
      } else if ((element.op).toLowerCase() === 'remove') {
        if (element.path === 'members' || element.path === 'groups') { // members => Group attribute, groups => User attribute
          if (element.value) {
            if (Array.isArray(element.value)) {
              element.value.forEach(function (el) {
                groupMembers.push({ operation: 'delete', value: el.value })
              })
            } else if (element.value.value) groupMembers.push({ operation: 'delete', value: element.value.value })
          } else groupMembers.push({ operation: 'delete' }) // no value => delete all groups
        } else { // User
          if (ScimGateway.prototype.isMultivalue('User', pathRoot)) dot.str(`${pathRoot}.${type}.value`, '', scimdata)
          else {
            if (path) dot.str(path, '', scimdata)
            else dot.str(element.path, '', scimdata)
          }
        }
      }
    } else { // no path - op=remove using path
      for (const key in element.value) {
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
const jsonErr = (scimVersion, pluginName, htmlErrCode, err) => {
  let errJson = {}
  let msg = `ScimGateway[${pluginName}] `
  err.constructor === Error ? msg += err.message : msg += err

  if (scimVersion !== '2.0' && scimVersion !== 2) { // v1.1
    errJson =
    {
      Errors: [
        {
          description: msg,
          code: htmlErrCode
        }
      ]
    }
  } else { // v2.0
    errJson =
    {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      detail: msg,
      status: htmlErrCode
    }
  }
  return errJson
}

//
// api plugin formatted error
//
const apiErr = (pluginName, err) => {
  let msg
  if (err.constructor !== Error) err = { message: err }
  try {
    msg = JSON.parse(err.message)
    msg.originator = `ScimGateway[${pluginName}]`
  } catch (e) { msg = `ScimGateway[${pluginName}] ${err.message}` }
  const errObj = {
    meta: {
      result: 'error',
      description: msg
    }
  }
  return errObj
}
