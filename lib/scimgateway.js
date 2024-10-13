// =================================================================================
// File:    scimgateway.js
//
// Author:  Jarle Elshaug
//
// Purpose: Started by endpoint plugin
//          Listens and replies on incoming SCIM requests
//          Optional SCIM Stream outbound subscription
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
const countries = require('../lib/countries')
const { createChecker } = require('is-in-subnet')
const { createTerminus } = require('@godaddy/terminus')
const Publisher = require('../lib/scim-stream').Publisher
const Subscriber = require('../lib/scim-stream').Subscriber
require('events').EventEmitter.prototype._maxListeners = Infinity

/**
 * @constructor
 */
const ScimGateway = function () {
  const startTime = utils.timestamp()
  const stack = callsite()
  const requester = stack[1].getFileName()
  let pluginName = path.basename(requester)
  pluginName = pluginName.substring(0, pluginName.lastIndexOf('.')) || pluginName
  const pluginDir = path.dirname(requester)
  const configDir = path.join(pluginDir, '..', 'config')
  const configFile = path.join(`${configDir}`, `${pluginName}.json`) // config name prefix same as pluging name prefix
  let config = require(configFile).scimgateway
  let extConfigErr
  try {
    config = ScimGateway.prototype.processExtConfig(pluginName, config, true) // external config support process.env and process.file
  } catch (err) { extConfigErr = err }

  const gwName = path.basename(__filename, '.js') // prefix of current file
  const logDir = path.join(pluginDir, '..', 'logs')
  const Log = require('../lib/logger').Log
  const log = new Log(utils.extendObj(utils.copyObj(config.log), { category: pluginName, colorize: process.stdout.isTTY || false, loglevel: { file: (!config.log.loglevel.file || config.log.loglevel.file === 'off') ? null : 'debug', console: 'debug' } }), path.join(`${logDir}`, `${pluginName}.log`))
  const logger = log.logger()
  this.logger = logger // exposed to plugin
  this.gwName = gwName
  this.pluginName = pluginName
  this.configDir = configDir
  this.configFile = configFile
  this.notValidAttributes = notValidAttributes
  this.authPassThroughAllowed = false // set to true by plugin if allowed
  this.publish = null
  let pwErrCount = 0
  let requestCounter = 0
  const oAuthTokenExpire = 3600 // seconds
  let isMailLock = false
  let ipAllowListChecker
  let scimDef
  let multiValueTypes
  let server

  if (extConfigErr) {
    logger.error(`${gwName}[${pluginName}] ${extConfigErr.message}`)
    logger.error(`${gwName}[${pluginName}] stopping...\n`)
    throw (new Error('Using exception to stop further asynchronous code execution (ensure synchronous logger flush to logfile and exit program), please ignore this one...'))
  }

  if (!config.scim) config.scim = {}
  if (!config.log) config.log = {}
  if (!config.log.loglevel) config.log.loglevel = {}
  if (!config.auth) config.auth = {}
  if (!config.auth.basic) config.auth.basic = []
  if (!config.auth.bearerToken) config.auth.bearerToken = []
  if (!config.auth.bearerJwt) config.auth.bearerJwt = []
  if (!config.auth.bearerJwtAzure) config.auth.bearerJwtAzure = []
  if (!config.auth.bearerOAuth) config.auth.bearerOAuth = []
  if (!config.auth.passThrough) config.auth.passThrough = {}
  config.auth.oauthTokenStore = {}
  if (!config.certificate) config.certificate = {}
  if (!config.certificate.pfx) config.certificate.pfx = {}
  if (!config.emailOnError) config.emailOnError = {}
  if (!config.emailOnError.smtp) config.emailOnError.smtp = {}
  if (!config.kubernetes) config.kubernetes = {}
  if (!config.stream) config.stream = {}
  if (!config.stream.subscriber) config.stream.subscriber = {}
  if (!config.stream.publisher) config.stream.publisher = {}

  if (config.ipAllowList && Array.isArray(config.ipAllowList) && config.ipAllowList.length > 0) {
    ipAllowListChecker = createChecker(config.ipAllowList)
  }

  const handler = {}
  handler.Users = handler.users = {
    description: 'User',
    getMethod: 'getUsers',
    modifyMethod: 'modifyUser',
    createMethod: 'createUser',
    deleteMethod: 'deleteUser'
  }
  handler.Groups = handler.groups = {
    description: 'Group',
    getMethod: 'getGroups',
    modifyMethod: 'modifyGroup',
    createMethod: 'createGroup',
    deleteMethod: 'deleteGroup'
  }
  handler.servicePlans = handler.serviceplans = { // plugin-entra
    description: 'ServicePlan',
    getMethod: 'getServicePlans',
    modifyMethod: 'modifyServicePlan',
    createMethod: 'createServicePlan',
    deleteMethod: 'deleteServicePlan'
  }
  handler.AppRoles = handler.approles = { // scim-stream
    description: 'AppRoles',
    getMethod: 'getAppRoles'
  }

  let foundBasic = false
  let foundBearerToken = false
  let foundBearerJwtAzure = false
  let foundBearerJwt = false
  let foundBearerOAuth = false
  let foundPassThrough = false
  let pwPfxPassword

  if (Array.isArray(config.auth.basic)) {
    const arr = config.auth.basic
    for (let i = 0; i < arr.length; i++) {
      try {
        if (arr[i].password) arr[i].password = ScimGateway.prototype.getPassword(`scimgateway.auth.basic[${i}].password`, configFile)
      } catch (err) {
        logger.error(`${gwName}[${pluginName}] getPassword error: ${err.message}`)
        throw err // above logger.error included because this unhanledExcepton will be handled by winston and may fail with an other internal winston error e.g. related to memoryUsage collection logic when running in unikernel
      }
      if (arr[i].username && arr[i].password) foundBasic = true
    }
    if (!foundBasic) config.auth.basic = []
  }

  if (Array.isArray(config.auth.bearerToken)) {
    const arr = config.auth.bearerToken
    for (let i = 0; i < arr.length; i++) {
      if (arr[i].token) {
        try {
          arr[i].token = ScimGateway.prototype.getPassword(`scimgateway.auth.bearerToken[${i}].token`, configFile)
        } catch (err) {
          logger.error(`${gwName}[${pluginName}] getPassword error: ${err.message}`)
          throw err
        }
        if (arr[i].token) foundBearerToken = true
      }
    }
    if (!foundBearerToken) config.auth.bearerToken = []
  }

  if (Array.isArray(config.auth.bearerJwtAzure)) {
    const issuers = []
    const arr = config.auth.bearerJwtAzure
    for (let i = 0; i < arr.length; i++) {
      if (arr[i].tenantIdGUID) {
        issuers.push(`https://sts.windows.net/${arr[i].tenantIdGUID}/`)
      }
    }
    if (issuers.length > 0) {
      foundBearerJwtAzure = true
      const azureOptions = {
        validateIssuer: true,
        passReqToCallback: false,
        loggingLevel: null,
        // identityMetadata: `https://login.microsoftonline.com/${tenantIdGUID}/.well-known/openid-configuration`,
        identityMetadata: 'https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration',
        clientID: '00000014-0000-0000-c000-000000000000', // Well known appid: Microsoft.Azure.SyncFabric
        audience: [
          // Well known appid: Issued for accessing Windows Azure Active Directory Graph Webservice
          '00000002-0000-0000-c000-000000000000',
          // Appid used for SCIM provisioning for non-gallery applications. See changes introduced, in reverse cronological order:
          // - https://github.com/MicrosoftDocs/azure-docs/commit/f6997c0952d2ad4f33ce7f5339eeb83c21b51f1e
          // - https://github.com/MicrosoftDocs/azure-docs/commit/64525fea0675a73b2e6b8fe42fbd03ee568cadfc
          '8adf8e6e-67b2-4cf2-a259-e3dc5476c621'
        ],
        issuer: issuers // array => passport.authenticate supports more than one AAD tenant
      }

      passport.use(new OIDCBearerStrategy(azureOptions, (token, callback) => { // using named strategy = tenantIdGUID, passport.authenticate then using name
        callback(null, token.sub, token) // Azure SyncFabric don't send user info claims, returning claim token.sub as user
      }))
    } else {
      config.auth.bearerJwtAzure = []
    }
  }

  if (Array.isArray(config.auth.bearerJwt)) {
    const arr = config.auth.bearerJwt
    for (let i = 0; i < arr.length; i++) {
      try {
        if (arr[i].secret) arr[i].secret = ScimGateway.prototype.getPassword(`scimgateway.auth.bearerJwt[${i}].secret`, configFile)
      } catch (err) {
        logger.error(`${gwName}[${pluginName}] getPassword error: ${err.message}`)
        throw err
      }
      if ((arr[i].options && arr[i].options.issuer) && (arr[i].secret || arr[i].publicKey)) {
        foundBearerJwt = true
        if (arr[i].publicKey) { // create publicKeyContent
          try {
            let file = path.join(configDir, '/certs/', arr[i].publicKey)
            if (arr[i].publicKey.startsWith('/') || arr[i].publicKey.includes('\\')) {
              file = arr[i].publicKey
            }
            arr[i].publicKeyContent = fs.readFileSync(file)
          } catch (err) {
            arr.splice(i, 1) // delete
            foundBearerJwt = false
            err.message = `failed reading file defined in configuration auth.bearerJwt: ${err.message}`
            logger.error(err.message)
          }
        }
      } else arr.splice(i, 1) // delete
    }
    if (!foundBearerJwt) config.auth.bearerJwt = []
  }

  if (Array.isArray(config.auth.bearerOAuth)) {
    const arr = config.auth.bearerOAuth
    for (let i = 0; i < arr.length; i++) {
      try {
        if (arr[i].client_secret) arr[i].client_secret = ScimGateway.prototype.getPassword(`scimgateway.auth.bearerOAuth[${i}].client_secret`, configFile)
      } catch (err) {
        logger.error(`${gwName}[${pluginName}] getPassword error: ${err.message}`)
        throw err // above logger.error included because this unhanledExcepton will be handled by winston and may fail with an other internal winston error e.g. related to memoryUsage collection logic when running in unikernel
      }
      if (arr[i].client_secret && arr[i].client_id) foundBearerOAuth = true
    }
    if (!foundBearerOAuth) config.auth.bearerOAuth = []
  }

  for (const baseEntity in config.stream.subscriber.entity) {
    if (config.stream.subscriber.entity[baseEntity]?.nats?.secret) {
      config.stream.subscriber.entity[baseEntity].nats.secret = ScimGateway.prototype.getPassword(`scimgateway.stream.subscriber.entity.${baseEntity}.nats.secret`, configFile)
    }
  }
  for (const baseEntity in config.stream.publisher.entity) {
    if (config.stream.publisher.entity[baseEntity]?.nats?.secret) {
      config.stream.publisher.entity[baseEntity].nats.secret = ScimGateway.prototype.getPassword(`scimgateway.stream.publisher.entity.${baseEntity}.nats.secret`, configFile)
    }
  }

  if (config.auth.passThrough.enabled === true) foundPassThrough = true

  if (config.certificate.pfx.password) pwPfxPassword = ScimGateway.prototype.getPassword('scimgateway.certificate.pfx.password', configFile)
  if (config.emailOnError.smtp.password) config.emailOnError.smtp.password = ScimGateway.prototype.getPassword('scimgateway.emailOnError.smtp.password', configFile)

  if (!foundBasic && !foundBearerToken && !foundBearerJwtAzure && !foundBearerJwt && !foundBearerOAuth && !foundPassThrough) {
    if (config.port) {
      logger.error(`${gwName}[${pluginName}] Scimgateway password decryption failed or no password defined, or no auth methods configured`)
      logger.error(`${gwName}[${pluginName}] stopping...\n`)
      throw (new Error('Using exception to stop further asynchronous code execution (ensure synchronous logger flush to logfile and exit program), please ignore this one...'))
    }
  }

  try {
    if (!fs.existsSync(configDir + '/wsdls')) fs.mkdirSync(configDir + '/wsdls')
    if (!fs.existsSync(configDir + '/certs')) fs.mkdirSync(configDir + '/certs')
    if (!fs.existsSync(configDir + '/schemas')) fs.mkdirSync(configDir + '/schemas')
  } catch (err) {}

  let isScimv2 = false
  if (config.scim.version === '2.0' || config.scim.version === 2) {
    isScimv2 = true
    if (fs.existsSync(pluginDir + '/scimdef-v2.js')) scimDef = require(pluginDir + '/scimdef-v2') // using custom
    else scimDef = require('../lib/scimdef-v2')
  } else {
    if (fs.existsSync(pluginDir + '/scimdef-v1.js')) scimDef = require(pluginDir + '/scimdef-v1') // using custom
    else scimDef = require('../lib/scimdef-v1')
  }

  if (config.scim.customSchema) { // legacy - merge plugin custom schema extension into core schemas
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
          return undefined
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

  // exposed and used by plugin-loki
  this.testmodeusers = []
  this.testmodegroups = []
  if (scimDef.TestmodeUsers && scimDef.TestmodeUsers.Resources) {
    this.testmodeusers = scimDef.TestmodeUsers.Resources
  }
  if (scimDef.TestmodeGroups && scimDef.TestmodeGroups.Resources) {
    this.testmodegroups = scimDef.TestmodeGroups.Resources
  }

  // multiValueTypes array contains attributes that will be used by "type converted objects" logic
  // groups, roles, and members are excluded
  // default: ['emails','phoneNumbers','ims','photos','addresses','entitlements','x509Certificates']
  // configuration skipTypeConvert = true disables logic by empty multiValueTypes array
  if (config.scim.skipTypeConvert === true) multiValueTypes = []
  else {
    multiValueTypes = getMultivalueTypes('User', scimDef) // not icluding 'Group' => 'members' are excluded
    for (let i = 0; i < multiValueTypes.length; i++) {
      if (multiValueTypes[i] === 'groups' || multiValueTypes[i] === 'roles' || multiValueTypes[i] === 'members') {
        multiValueTypes.splice(i, 1) // delete
        i -= 1
      }
    }
  }

  const logResult = async (ctx, next) => {
    const started = Date.now()
    await next() // once all middleware completes, below continues
    if (ctx.request.url === '/ping' || ctx.request.url === '/favicon.ico') return
    const ellapsed = (Date.now() - started) + 'ms' // ctx.set('X-ResponseTime', ellapsed)
    const res = {
      statusCode: ctx.response.status,
      statusMessage: ctx.response.message,
      body: ctx.response.body
    }
    let userName
    const [authType, authToken] = (ctx?.request?.header?.authorization || '').split(' ') // [0] = 'Basic' or 'Bearer'
    if (authType === 'Basic') [userName] = (Buffer.from(authToken, 'base64').toString() || '').split(':')
    if (!userName && authType === 'Bearer') userName = 'token'
    if (ctx.response.status < 200 || ctx.response.status > 299) {
      if (ctx.response.status === 401 || ctx.response.status === 403) { // don't reveal original SCIM error message details related to access denied (e.g. using Auth PassThrough and customErrCode)
        ctx.response.set('Content-Type', 'application/json; charset=utf-8')
        ctx.response.body = { error: 'Access denied' }
        res.body = ctx.response.body
      }
      logger.error(`${gwName}[${pluginName}] ${ellapsed} ${ctx.request.ip} ${userName} ${ctx.request.method} ${ctx.request.href} Inbound = ${JSON.stringify(ctx.request.body)} Outbound = ${JSON.stringify(res)}${(config.log.loglevel.file === 'debug' && ctx.request.url !== '/ping') ? '\n' : ''}`)
    } else logger.info(`${gwName}[${pluginName}] ${ellapsed} ${ctx.request.ip} ${userName} ${ctx.request.method} ${ctx.request.href} Inbound = ${JSON.stringify(ctx.request.body)} Outbound = ${JSON.stringify(res)}${(config.log.loglevel.file === 'debug' && ctx.request.url !== '/ping') ? '\n' : ''}`)
    requestCounter += 1 // logged on exit (not win process termination)
    if (ctx.response.body && typeof ctx.response.body === 'object' && ctx.response.status !== 401) ctx.set('Content-Type', 'application/scim+json; charset=utf-8')
  }

  // start auth methods - used by auth
  const basic = (baseEntity, method, authType, authToken, url) => {
    return new Promise((resolve, reject) => { // basic auth
      if (url === '/ping' || url.endsWith('/oauth/token') || url === '/_ah/start' || url === '/_ah/stop' || url === '/favicon.ico') resolve(true) // no auth
      if (authType !== 'Basic') resolve(false)
      if (!foundBasic) resolve(false)
      if (foundPassThrough && this.authPassThroughAllowed) resolve(false)
      const [userName, userPassword] = (Buffer.from(authToken, 'base64').toString() || '').split(':')
      if (!userName || !userPassword) {
        return reject(new Error(`authentication failed for user ${userName}`))
      }
      const arr = config.auth.basic
      for (let i = 0; i < arr.length; i++) {
        if (arr[i].username === userName && arr[i].password === userPassword) { // authentication OK
          if (arr[i].baseEntities) {
            if (Array.isArray(arr[i].baseEntities) && arr[i].baseEntities.length > 0) {
              if (!baseEntity) return reject(new Error(`baseEntity=${baseEntity} not allowed for user ${arr[i].username} according to basic configuration baseEntitites=${arr[i].baseEntities}`))
              if (!arr[i].baseEntities.includes(baseEntity)) return reject(new Error(`baseEntity=${baseEntity} not allowed for user ${arr[i].username} according to basic configuration baseEntitites=${arr[i].baseEntities}`))
            }
          }
          if (arr[i].readOnly === true && method !== 'GET') return reject(new Error(`only allowing readOnly for user ${arr[i].username} according to basic configuration readOnly=true`))
          return resolve(true)
        }
      }
      reject(new Error(`authentication failed for user ${userName}`))
    })
  }

  const bearerToken = (baseEntity, method, authType, authToken) => {
    return new Promise((resolve, reject) => { // bearer token
      if (authType !== 'Bearer' || !authToken) resolve(false)
      if (!foundBearerToken) resolve(false)
      const arr = config.auth.bearerToken
      for (let i = 0; i < arr.length; i++) {
        if (arr[i].token === authToken) { // authentication OK
          if (arr[i].baseEntities) {
            if (Array.isArray(arr[i].baseEntities) && arr[i].baseEntities.length > 0) {
              if (!baseEntity) return reject(new Error(`baseEntity=${baseEntity} not allowed for this bearerToken according to bearerToken configuration baseEntitites=${arr[i].baseEntities}`))
              if (!arr[i].baseEntities.includes(baseEntity)) return reject(new Error(`baseEntity=${baseEntity} not allowed for this bearerToken according to bearerToken configuration baseEntitites=${arr[i].baseEntities}`))
            }
          }
          if (arr[i].readOnly === true && method !== 'GET') return reject(new Error('only allowing readOnly for this bearerToken according to bearerToken configuration readOnly=true'))
          return resolve(true)
        }
      }
      reject(new Error('bearerToken authentication failed'))
    })
  }

  const bearerJwtAzure = (baseEntity, ctx, next, authType, authToken) => {
    return new Promise((resolve, reject) => {
      if (authType !== 'Bearer' || !foundBearerJwtAzure) resolve(false) // no azure bearer token
      const payload = jwt.decode(authToken)
      if (!payload) resolve(false)
      if (!payload.iss) resolve(false)
      if (payload.iss.indexOf('https://sts.windows.net') !== 0) resolve(false)
      passport.authenticate('oauth-bearer', { session: false }, (err, user, info) => {
        if (err) { return reject(err) }
        if (user) { // authenticated OK
          const arr = config.auth.bearerJwtAzure
          for (let i = 0; i < arr.length; i++) {
            if (arr[i].tenantIdGUID && payload.iss.includes(arr[i].tenantIdGUID)) {
              if (arr[i].baseEntities) {
                if (Array.isArray(arr[i].baseEntities) && arr[i].baseEntities.length > 0) {
                  if (!baseEntity) return reject(new Error(`baseEntity=${baseEntity} not allowed for user ${arr[i].tenantIdGUID} according to bearerJwtAzure configuration baseEntitites=${arr[i].baseEntities}`))
                  if (!arr[i].baseEntities.includes(baseEntity)) return reject(new Error(`baseEntity=${baseEntity} not allowed for user ${arr[i].tenantIdGUID} according to bearerJwtAzure configuration baseEntitites=${arr[i].baseEntities}`))
                }
              }
              if (arr[i].readOnly === true && ctx.request.method !== 'GET') return reject(new Error(`only allowing readOnly for user ${arr[i].tenantIdGUID} according to bearerJwtAzure configuration readOnly=true`))
            }
          }
          resolve(true)
        } else reject(new Error(`Azure JWT authorization failed: ${info}`))
      })(ctx, next)
    })
  }

  const jwtVerify = (baseEntity, method, el, authToken) => { // used by bearerJwt
    return new Promise((resolve, reject) => {
      jwt.verify(authToken, (el.secret) ? el.secret : el.publicKeyContent, el.options, (err, decoded) => {
        if (err) resolve(false)
        else {
          if (el.baseEntities) {
            if (Array.isArray(el.baseEntities) && el.baseEntities.length > 0) {
              if (!baseEntity) return resolve(false)
              if (!el.baseEntities.includes(baseEntity)) return resolve(false)
            }
          }
          if (el.readOnly === true && method !== 'GET') return resolve(false)
          resolve(true) // authorization OK
        }
      })
    })
  }

  const bearerJwt = async (baseEntity, method, authType, authToken) => {
    if (authType !== 'Bearer' || !foundBearerJwt) return false // no standard jwt bearer token
    const payload = jwt.decode(authToken)
    if (!payload) return false
    if (payload.iss && payload.iss.indexOf('https://sts.windows.net') === 0) return false // azure - handled by bearerJwtAzure
    const promises = []
    const arr = config.auth.bearerJwt
    for (let i = 0; i < arr.length; i++) {
      promises.push(jwtVerify(baseEntity, method, arr[i], authToken))
    }
    const arrResolve = await Promise.all(promises).catch((err) => { throw (err) })
    for (const i in arrResolve) {
      if (arrResolve[i]) return true
    }
    throw new Error('JWT authentication failed')
  }

  const bearerOAuth = (baseEntity, method, authType, authToken) => {
    return new Promise((resolve, reject) => { // bearer token
      if (authType !== 'Bearer' || !authToken) resolve(false)
      if (!foundBearerOAuth || !authToken) resolve(false)
      // config.auth.oauthTokenStore is autmatically generated by token create having syntax:
      // { config.auth.oauthTokenStore: <token>: { expireDate: <timestamp>, readOnly: <copy-from-config>, baseEntities: [ <copy-from-config> ], isTokenRequested: true }}
      const arr = config.auth.bearerOAuth
      if (config.auth.oauthTokenStore[authToken]) { // authentication OK
        const tokenObj = config.auth.oauthTokenStore[authToken]
        if (Date.now() > tokenObj.expireDate) {
          delete config.auth.oauthTokenStore[authToken]
          const err = new Error('OAuth access token expired')
          err.token_error = 'invalid_token'
          err.token_error_description = 'The access token expired'
          return reject(err)
        }
        if (tokenObj.baseEntities) {
          if (Array.isArray(tokenObj.baseEntities) && tokenObj.baseEntities.length > 0) {
            if (!baseEntity) return reject(new Error(`baseEntity=${baseEntity} not allowed for this bearerOAuth according to bearerOAuth configuration baseEntitites=${tokenObj.baseEntities}`))
            if (!tokenObj.baseEntities.includes(baseEntity)) return reject(new Error(`baseEntity=${baseEntity} not allowed for this bearerOAuth according to bearerOAuth configuration baseEntitites=${tokenObj.baseEntities}`))
          }
        }
        if (tokenObj.readOnly === true && method !== 'GET') return reject(new Error('only allowing readOnly for this bearerOAuth according to bearerOAuth configuration readOnly=true'))
        return resolve(true)
      } else {
        for (let i = 0; i < arr.length; i++) { // resolve if token memory store have been cleared because of a gateway restart
          if (utils.getEncrypted(authToken, arr[i].client_secret) === arr[i].client_secret && !arr[i].isTokenRequested) {
            arr[i].isTokenRequested = true // flagged as true to not allow repeated resolvements because token will also be cleared when expired
            const baseEntities = utils.copyObj(arr[i].baseEntities)
            let expires
            let readOnly = false
            if (arr[i].readOnly && arr[i].readOnly === true) readOnly = true
            if (arr[i].expires_in && !isNaN(arr[i].expires_in)) expires = arr[i].expires_in
            else expires = oAuthTokenExpire
            config.auth.oauthTokenStore[authToken] = {
              expireDate: Date.now() + expires * 1000,
              readOnly,
              baseEntities
            }
            return resolve(true)
          }
        }
      }
      reject(new Error('OAuth authentication failed'))
    })
  }

  const authPassThrough = async (baseEntity, method, authType, authToken, ctx) => {
    if (!foundPassThrough || !this.authPassThroughAllowed) return false
    if (!authToken) return false
    if (authType === 'Basic') {
      const [userName, userPassword] = (Buffer.from(authToken, 'base64').toString() || '').split(':')
      if (!userName || !userPassword) return false
    }
    const obj = config.auth.passThrough
    if (obj.baseEntities) {
      if (Array.isArray(obj.baseEntities) && obj.baseEntities.length > 0) {
        if (!baseEntity || !obj.baseEntities.includes(baseEntity)) throw new Error(`baseEntity=${baseEntity} not allowed for passThrough according to passThrough configuration baseEntitites=${obj.baseEntities}`)
      }
    }
    if (obj.readOnly === true && method !== 'GET') throw new Error('only allowing readOnly for passThrough according to passThrough configuration readOnly=true')
    ctx.passThrough = {}
    ctx.passThrough.request = {}
    ctx.passThrough.request.header = Object.assign({}, ctx.request.header)
    return true
  }

  // end auth methods - used by auth

  const auth = async (ctx, next) => { // authentication/authorization
    const [authType, authToken] = (ctx.request.header.authorization || '').split(' ') // [0] = 'Basic' or 'Bearer'
    let baseEntity
    const arr = ctx.request.url.split('/')
    if (arr.length > 0) {
      const entity = arr[1].split('?')[0]
      if (!['Users', 'Groups', 'Schemas', 'ServiceProviderConfigs', 'scim'].includes(entity)) baseEntity = entity
    }
    try { // authenticate
      const arrResolve = await Promise.all([
        basic(baseEntity, ctx.request.method, authType, authToken, ctx.url),
        bearerToken(baseEntity, ctx.request.method, authType, authToken),
        bearerJwtAzure(baseEntity, ctx, next, authType, authToken),
        bearerJwt(baseEntity, ctx.request.method, authType, authToken),
        bearerOAuth(baseEntity, ctx.request.method, authType, authToken),
        authPassThrough(baseEntity, ctx.request.method, authType, authToken, ctx)])
        .catch((err) => { throw (err) })
      for (const i in arrResolve) {
        if (arrResolve[i]) return next() // auth OK - continue with routes
      }
      // all false - invalid auth method or missing pluging config
      let err
      if (authType.length < 1) err = new Error(`${ctx.url} request is missing authentication information`)
      else {
        err = new Error(`${ctx.url} request having unsupported authentication or plugin configuration is missing`)
        logger.debug(`${gwName}[${pluginName}] request authToken = ${authToken}`)
        logger.debug(`${gwName}[${pluginName}] request jwt.decode(authToken) = ${JSON.stringify(jwt.decode(authToken))}`)
      }
      if (authType === 'Bearer') ctx.set('WWW-Authenticate', 'Bearer realm=""')
      else if (foundBasic) ctx.set('WWW-Authenticate', 'Basic realm=""')
      ctx.set('Content-Type', 'application/json; charset=utf-8')
      ctx.status = 401
      ctx.body = { error: 'Access denied' }
      if (ctx.url !== '/favicon.ico') logger.error(`${gwName}[${pluginName}] ${err.message}`)
    } catch (err) {
      const body = {}
      if (authType === 'Bearer') {
        let str = 'realm=""'
        if (err.token_error) {
          str += `, error="${err.token_error}"`
          body.error = err.token_error
        }
        if (err.token_error_description) {
          str += `, error_description="${err.token_error_description}"`
          body.error_description = err.token_error_description
        }
        ctx.set('WWW-Authenticate', `Bearer ${str}`)
      } else ctx.set('WWW-Authenticate', 'Basic realm=""')
      ctx.set('Content-Type', 'application/json; charset=utf-8')
      ctx.status = 401
      if (Object.keys(body).length > 0) ctx.body = body
      else ctx.body = { error: 'Access denied' }
      if (pwErrCount < 3) {
        pwErrCount += 1
        logger.error(`${gwName}[${pluginName}] ${ctx.url} ${err.message}`)
      } else { // delay brute force attempts
        logger.error(`${gwName}[${pluginName}] ${ctx.url} ${err.message} => delaying response with 2 minutes to prevent brute force`)
        return new Promise((resolve) => {
          setTimeout(() => {
            resolve(ctx)
          }, 1000 * 60 * 2)
        })
      }
    }
  }

  const verifyContentType = (ctx, next) => {
    return new Promise((resolve) => {
      if (ctx.request.length) { // body is included - invalid content-type gives empty body (koa-bodyparser)
        const contentType = ctx.request.type.toLowerCase()
        if (contentType === 'application/json' || contentType === 'application/scim+json') return resolve(next())
        if (ctx.url.endsWith('/oauth/token')) return resolve(next())
        ctx.status = 415
        ctx.body = 'Content-Type header must be \'application/json\' or \'application/scim+json\''
        return resolve(ctx)
      }
      resolve(next())
    })
  }

  const ipAllowList = (ctx, next) => {
    return new Promise((resolve) => {
      if (!ipAllowListChecker) return resolve(next())
      if (ipAllowListChecker(ctx.request.ip)) return resolve(next()) // if proxy, prereq: request includes header X-Forwarded-For and koa app.proxy=true
      logger.debug(`${gwName}[${pluginName}] client ip ${ctx.request.ip} not in ipAllowList`)
      ctx.status = 401
      ctx.body = { error: 'Access denied' }
      resolve(ctx)
    })
  }

  const app = new Koa({ proxy: true })
  const router = new Router()

  // Middleware run in the order they are defined and communicates through ctx
  // There is no return value, if there were it would be ignored
  app.use(logResult)
  app.use(bodyParser({ // parsed body store in ctx.request.body
    enableTypes: ['json', 'form'],
    extendTypes: { json: ['application/scim+json', 'text/plain'] },
    formTypes: { form: ['application/x-www-form-urlencoded'] },
    jsonLimit: (!config.payloadSize) ? undefined : config.payloadSize // default '1mb'
  }))
  app.use(ipAllowList)
  app.use(auth) // authentication before routes
  app.use(verifyContentType)
  app.use(router.routes())
  app.use(router.allowedMethods())

  app.on('error', (err, ctx) => { // catching none try/catch in app middleware, also bodyparser and body not json
    logger.error(`${gwName}[${pluginName}] Koa method: ${ctx.method} url: ${ctx.request.origin + ctx.path} body: ${JSON.stringify(ctx.request.body)} error: ${err.message}`)
  })

  router.get('/ping', async (ctx) => { // auth not required
    const tx = 'hello'
    ctx.set('Content-Type', 'text/plain; charset=utf-8')
    ctx.body = tx
  })

  // Google App Engine B-class instance start/stop request
  router.get(['/_ah/start', '/_ah/stop'], async (ctx) => {
    const ver = process.env.GAE_VERSION
    if (ctx.request.ip !== '0.1.0.3' || !ver || !ctx.request.origin.includes(`.${ver}.`)) { // ctx.request.origin = http://<instance>.<version>.<project-id>.<region>.r.appspot.com
      ctx.status = 403 // request not coming from GCP App Engine
      return
    }
    // could have some start/stop logic here
    ctx.status = 200
  })

  // Initial connection, step #1: GET /ServiceProviderConfigs
  // If not included => Provisioning will always use GET /Users without any paramenters
  // scimv1 = ServiceProviderConfigs, scimv2 ServiceProviderConfig
  router.get(['/(|scim/)(ServiceProviderConfigs|ServiceProviderConfig)',
    '/:baseEntity/(|scim/)(ServiceProviderConfigs|ServiceProviderConfig)'], async (ctx) => {
    const tx = scimDef.ServiceProviderConfigs
    if (!config.scim.skipMetaLocation) {
      const location = ctx.request.origin + ctx.path
      if (tx.meta) tx.meta.location = location
      else {
        tx.meta = {}
        tx.meta.location = location
      }
    }
    ctx.body = tx
    logger.debug(`${gwName}[${pluginName}] GET ${ctx.request.originalUrl} Response = ${JSON.stringify(tx)}`)
  })

  // Initial connection, step #2: GET /Schemas
  router.get(['/(|scim/)Schemas', '/:baseEntity/(|scim/)Schemas'], async (ctx) => {
    let tx = scimDef.Schemas
    tx = addResources(tx)
    tx = addSchemas(tx, null, isScimv2)
    ctx.body = tx
  })

  // oauth token request
  router.post(['/(|scim/)oauth/token', '/:baseEntity/(|scim/)oauth/token'], async (ctx) => {
    logger.debug(`${gwName}[${pluginName}] [oauth] token request`)
    if (!foundBearerOAuth) {
      logger.error(`${gwName}[${pluginName}] [oauth] token request, but plugin is missing config.auth.bearerOAuth configuration`)
      ctx.status = 500
      return
    }

    const jsonBody = ctx.request.body
    const [authType, authToken] = (ctx.request.header.authorization || '').split(' ') // [0] = 'Basic'
    if (authType === 'Basic') { // id and secret may be in authorization header if not already included in body
      const [id, secret] = (Buffer.from(authToken, 'base64').toString() || '').split(':')
      if (jsonBody.grant_type && id && secret) {
        if (jsonBody.grant_type === 'client_credentials' || jsonBody.grant_type === 'refresh_token') { // don't use refresh_token but allowing as type
          jsonBody.client_id = id
          jsonBody.client_secret = secret
        }
      }
    }

    let expires
    let token
    let readOnly = false
    let baseEntities
    let err
    let errDescr
    if (!jsonBody.grant_type || (jsonBody.grant_type !== 'client_credentials' && jsonBody.grant_type !== 'refresh_token')) {
      err = 'invalid_request'
      errDescr = 'request type must be Client Credentials (grant_type=client_credentials)'
    }

    if (!err) {
      const arr = config.auth.bearerOAuth
      for (let i = 0; i < arr.length; i++) {
        if (!arr[i].client_id || !arr[i].client_secret) continue
        if (arr[i].client_id === jsonBody.client_id && arr[i].client_secret === jsonBody.client_secret) { // authentication OK
          token = utils.getEncrypted(jsonBody.client_secret, jsonBody.client_secret)
          baseEntities = utils.copyObj(arr[i].baseEntities)
          if (arr[i].readOnly && arr[i].readOnly === true) readOnly = true
          if (arr[i].expires_in && !isNaN(arr[i].expires_in)) expires = arr[i].expires_in
          else expires = oAuthTokenExpire
          arr[i].isTokenRequested = true
          break
        }
      }
      if (!token) {
        err = 'invalid_client'
        errDescr = 'incorrect or missing client_id/client_secret'
        if (pwErrCount < 3) {
          pwErrCount += 1
        } else { // delay brute force attempts
          logger.error(`${gwName}[${pluginName}] [oauth] ${ctx.url} ${errDescr} => delaying response with 2 minutes to prevent brute force`)
          return new Promise((resolve) => {
            setTimeout(() => {
              resolve(ctx)
            }, 1000 * 60 * 2)
          })
        }
      }
    }

    if (err) {
      logger.error(`${gwName}[${pluginName}] [oauth] token request client_id: ${jsonBody ? jsonBody.client_id : ''} error: ${errDescr}`)
      ctx.status = 400
      ctx.body = {
        error: err,
        error_description: errDescr
      }
      return
    }

    const dtNow = Date.now()
    for (const i in config.auth.oauthTokenStore) { // cleanup any expired tokens
      const tokenObj = config.auth.oauthTokenStore[i]
      if (dtNow > tokenObj.expireDate) {
        delete config.auth.oauthTokenStore[i]
      }
    }

    config.auth.oauthTokenStore[token] = { // update token store
      expireDate: dtNow + expires * 1000, // 1 hour
      readOnly,
      baseEntities
    }

    const tx = {
      access_token: token,
      token_type: 'Bearer',
      expires_in: expires,
      refresh_token: token // ignored by scimgateway, but maybe used by client
    }

    ctx.set('Cache-Control', 'no-store')
    ctx.body = tx
  })

  // ==========================================
  //           Schemas
  // ==========================================
  router.get(['/(|scim/)Schemas/:id', '/:baseEntity/(|scim/)Schemas/:id'], async (ctx) => { // e.g /Schemas/Users | Groups | ServiceProviderConfigs
    let schemaName = ctx.params.id
    if (schemaName.substr(schemaName.length - 1) === 's') schemaName = schemaName.substr(0, schemaName.length - 1)
    const tx = scimDef.Schemas.Resources.find(el => el.name === schemaName)
    if (!tx) {
      ctx.status = 404
      const err = new Error(`Schema '${schemaName}' not found`)
      const [e, customErrorCode] = jsonErr(config.scim.version, pluginName, ctx.status, err)
      if (customErrorCode) ctx.status = customErrorCode
      ctx.body = e
    } else {
      ctx.body = tx
    }
  })

  // ==========================================
  //           ResourceTypes
  // ==========================================
  router.get(['/(|scim/)(ResourceTypes|ResourceType)',
    '/:baseEntity/(|scim/)(ResourceTypes|ResourceType)'], async (ctx) => { // ResourceTypes according to v2 specification
    const tx = scimDef.ResourceType
    ctx.body = tx
  })

  // ==========================================
  //           getUser by id
  //           getGroup by id
  // ==========================================
  const getById = async (ctx, next) => {
    if (ctx.query.attributes) ctx.query.attributes = ctx.query.attributes.split(',').map(item => item.trim()).join()
    if (ctx.query.excludedAttributes) ctx.query.excludedAttributes = ctx.query.excludedAttributes.split(',').map(item => item.trim()).join()
    let u = ctx.request.originalUrl.substr(0, ctx.request.originalUrl.lastIndexOf('/'))
    u = u.substr(u.lastIndexOf('/') + 1) // u = Users, Groups
    const handle = handler[u]
    let id = decodeURIComponent(ctx.params.id)
    if (id && id.endsWith('.json')) {
      id = decodeURIComponent(require('path').basename(id, '.json')) // supports <id>.json
    }

    const getObj = {
      attribute: 'id',
      operator: 'eq',
      value: id
    }

    logger.debug(`${gwName}[${pluginName}] [Get ${handle.description}s] ${getObj.attribute}=${getObj.value}`)

    let res
    try {
      const ob = utils.copyObj(getObj)
      const attributes = ctx.query.attributes ? ctx.query.attributes.split(',').map(item => item.trim()) : []
      if (config.stream.publisher.enabled) {
        const streamObj = {
          handle: handle.getMethod,
          baseEntity: ctx.params.baseEntity,
          obj: ob,
          attributes,
          ctxPassThrough: ctx.passThrough
        }
        logger.debug(`${gwName}[${pluginName}] publishing "${handle.getMethod}" to SCIM Stream and awaiting result`)
        res = await this.publish(streamObj)
      } else {
        logger.debug(`${gwName}[${pluginName}] calling "${handle.getMethod}" and awaiting result`)
        res = await this[handle.getMethod](ctx.params.baseEntity, ob, attributes, ctx.passThrough)
      }

      let scimdata = {
        Resources: [],
        totalResults: null
      }
      if (res) {
        if (res.Resources && Array.isArray(res.Resources)) {
          scimdata.Resources = res.Resources
          scimdata.totalResults = res.totalResults
        } else if (Array.isArray(res)) scimdata.Resources = res
        else if (typeof (res) === 'object' && Object.keys(res).length > 0) scimdata.Resources[0] = res
      }

      if (scimdata.Resources.length !== 1) {
        ctx.status = 404
        const err = new Error(`${handle.description} ${getObj.value} not found`)
        const [e, customErrorCode] = jsonErr(config.scim.version, pluginName, ctx.status, err)
        if (customErrorCode) ctx.status = customErrorCode
        ctx.body = e
        return
      }
      let userObj = scimdata.Resources[0]

      // check for user attribute groups and include if needed
      if (handle.getMethod === handler.users.getMethod && Object.keys(userObj).length > 0) {
        let arrAttr = []
        if (ctx.query.attributes) arrAttr = ctx.query.attributes.split(',')
        if ((!ctx.query.attributes || arrAttr.includes('groups'))) { // include groups
          if (!userObj.groups && userObj.id) {
            userObj.groups = await getMemberOf(ctx.params.baseEntity, userObj.id, handler.groups.getMethod, ctx.passThrough)
          }
        }
      }

      userObj = addPrimaryAttrs(userObj)
      scimdata = utils.stripObj(userObj, ctx.query.attributes, ctx.query.excludedAttributes)
      scimdata = addSchemas(scimdata, handle.description, isScimv2)
      if (!config.scim.skipMetaLocation) {
        const location = ctx?.request?.origin + ctx.path
        if (scimdata.meta) scimdata.meta.location = location
        else {
          scimdata.meta = {}
          scimdata.meta.location = location
        }
      }
      ctx.body = scimdata
    } catch (err) {
      ctx.status = 404
      const [e, customErrorCode] = jsonErr(config.scim.version, pluginName, ctx.status, err)
      if (customErrorCode) ctx.status = customErrorCode
      ctx.body = e
    }
  }

  router.get([`/(|scim/)(!${undefined}|Users|Groups|servicePlans)/:id`,
  `/:baseEntity/(|scim/)(!${undefined}|Users|Groups|servicePlans)/:id`], getById)

  // ==========================================
  //           getUsers
  //           getGroups
  // ==========================================
  router.get(['/(|scim/)(Users|Groups|servicePlans|AppRoles)',
    '/:baseEntity/(|scim/)(Users|Groups|servicePlans|AppRoles)'], async (ctx) => {
    if (ctx.query.attributes) ctx.query.attributes = ctx.query.attributes.split(',').map(item => item.trim()).join()
    if (ctx.query.excludedAttributes) ctx.query.excludedAttributes = ctx.query.excludedAttributes.split(',').map(item => item.trim()).join()
    let u = ctx.request.originalUrl.substr(ctx.request.originalUrl.lastIndexOf('/') + 1) // u = Users, Groups, servicePlans, ...
    const ui = u.indexOf('?')
    if (ui > 0) u = u.substr(0, ui)
    const handle = handler[u]

    const getObj = {
      attribute: undefined,
      operator: undefined,
      value: undefined,
      rawFilter: ctx.query.filter, // included for advanced filtering
      startIndex: undefined,
      count: undefined
    }

    if (ctx.query.filter) {
      ctx.query.filter = ctx.query.filter.trim()
      const arrFilter = ctx.query.filter.split(' ')
      if (arrFilter.length === 3 || (arrFilter.length > 2 && arrFilter[2].startsWith('"') && arrFilter[arrFilter.length - 1].endsWith('"'))) {
        getObj.attribute = arrFilter[0] // userName
        getObj.operator = arrFilter[1].toLowerCase() // eq
        getObj.value = decodeURIComponent(arrFilter.slice(2).join(' ').replace(/"/g, '')) // bjensen
      }
    }
    let err
    if (getObj.attribute) {
      if (multiValueTypes.includes(getObj.attribute) || getObj.attribute === 'roles') {
        getObj.attribute = `${getObj.attribute}.value` // emails => emails.value
      } else if (getObj.attribute.includes('[')) { // e.g. rawFilter = emails[type eq "work"]
        const rePattern = /^(.*)\[(.*) (.*) (.*)\]$/
        const arrMatches = ctx.query.filter.match(rePattern)
        if (Array.isArray(arrMatches) && arrMatches.length === 5) {
          getObj.attribute = `${arrMatches[1]}.${arrMatches[2]}` // emails.type
          getObj.operator = arrMatches[3]
          getObj.value = arrMatches[4].replace(/"/g, '')
        } else {
          getObj.attribute = undefined
          getObj.operator = undefined
          getObj.value = undefined
        }
      }
      if (getObj.attribute === 'password') {
        err = new Error(`Not accepting password filtering: ${getObj.rawFilter}`)
        err.name = 'invalidFilter'
      }
    } else if (getObj.rawFilter && ![' and ', ' or ', ' not '].some(el => getObj.rawFilter.includes(el))) { // advanced filtering
      // err = new Error(`Invalid filter: ${getObj.rawFilter}`)
      // err.name = 'invalidFilter'
    }
    if (err) {
      if (isScimv2) ctx.status = 400
      else ctx.status = 500
      const [e, customErrorCode] = jsonErr(config.scim.version, pluginName, ctx.status, err)
      if (customErrorCode) ctx.status = customErrorCode
      ctx.body = e
      return
    }

    //
    // Get user request for retreving common unique attributes:
    // GET = /Users?filter=userName eq "jsmith"&attributes=id,userName
    // GET = /Users?filter=id eq "jsmith"&attributes=id,userName
    //
    // Get user request for retreving all attributes:
    // GET = /Users?filter=userName eq "jsmith"&attributes=ims,locale,name.givenName,externalId,preferredLanguage,userType,id,title,timezone,name.middleName,name.familyName,nickName,name.formatted,meta.location,userName,name.honorificSuffix,meta.version,meta.lastModified,meta.created,name.honorificPrefix,emails,phoneNumbers,photos,x509Certificates.value,profileUrl,roles,active,addresses,displayName,entitlements
    //
    //  ---- retreive all users for a spesific group ----
    //
    // "user member of group" => default - Group having multivalue attribute members containing users userName/id
    // GET = /Groups?filter=members.value eq "bjensen"&attributes=id,displayName,members.value
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
    // ---- no filtering - simpel filtering - advanced filtering ----
    // GET /Users
    // GET /Groups
    // GET /Users?attributes=userName&startIndex=1&count=100
    // GET /Groups?attributes=displayName
    // GET /Users?filter=meta.created ge "2010-01-01T00:00:00Z"&attributes=userName,id,name.familyName,meta.created
    // GET /Users?filter=emails.value co "@example.com"&attributes=userName,name.familyName,emails&sortBy=name.familyName&sortOrder=descending

    let info = ''
    if (getObj.operator === 'eq' && ['id', 'userName', 'externalId', 'displayName', 'members.value'].includes(getObj.attribute)) info = ` ${getObj.attribute}=${getObj.value}`

    logger.debug(`${gwName}[${pluginName}] [Get ${handle.description}]${info}`)
    try {
      getObj.startIndex = ctx.query.startIndex ? parseInt(ctx.query.startIndex) : undefined
      getObj.count = ctx.query.count ? parseInt(ctx.query.count) : undefined
      if (getObj.startIndex && !getObj.count) getObj.count = 200 // defaults to 200 (plugin may override)
      if (getObj.count && !getObj.startIndex) getObj.startIndex = 1

      let res
      const ob = utils.copyObj(getObj)
      const attributes = ctx.query.attributes ? ctx.query.attributes.split(',').map(item => item.trim()) : []
      if (config.stream.publisher.enabled) {
        const streamObj = {
          handle: handle.getMethod,
          baseEntity: ctx.params.baseEntity,
          obj: ob,
          attributes,
          ctxPassThrough: ctx.passThrough
        }
        logger.debug(`${gwName}[${pluginName}] publishing "${handle.getMethod}" to SCIM Stream and awaiting result`)
        res = await this.publish(streamObj)
      } else {
        logger.debug(`${gwName}[${pluginName}] calling "${handle.getMethod}" and awaiting result`)
        res = await this[handle.getMethod](ctx.params.baseEntity, ob, attributes, ctx.passThrough)
        // check for user attribute groups and include if needed
        if (Array.isArray(res?.Resources)) {
          if (handle.getMethod === handler.users.getMethod) { // groupMemberOfUser can be set to true for skipping
            let arrAttr = []
            if (ctx.query.attributes) arrAttr = ctx.query.attributes.split(',')
            if ((!ctx.query.attributes || arrAttr.includes('groups'))) { // include groups
              for (let i = 0; i < res.Resources.length; i++) {
                const userObj = res.Resources[i]
                if (!userObj.id) break
                if (userObj.groups) break
                userObj.groups = await getMemberOf(ctx.params.baseEntity, userObj.id, handler.groups.getMethod, ctx.passThrough)
              }
            }
          }
        }
      }
      let scimdata = {
        Resources: [],
        totalResults: null
      }
      if (res) {
        if (res.Resources && Array.isArray(res.Resources)) {
          scimdata.Resources = res.Resources
          scimdata.totalResults = res.totalResults
        } else if (Array.isArray(res)) scimdata.Resources = res
        else if (typeof (res) === 'object' && Object.keys(res).length > 0) scimdata.Resources[0] = res
      }

      let location = ctx.request.origin + ctx.path
      if (ctx.query.attributes || (ctx.query.excludedAttributes && ctx.query.excludedAttributes.includes('meta'))) location = null
      if (config.scim.skipMetaLocation) location = null
      for (let i = 0; i < scimdata.Resources.length; i++) {
        scimdata.Resources[i] = addPrimaryAttrs(scimdata.Resources[i])
        scimdata.Resources[i] = utils.stripObj(scimdata.Resources[i], ctx.query.attributes, ctx.query.excludedAttributes)
      }
      scimdata = addResources(scimdata, ctx.query.startIndex, ctx.query.sortBy, ctx.query.sortOrder)
      scimdata = addSchemas(scimdata, handle.description, isScimv2, location)

      ctx.body = scimdata
    } catch (err) {
      if (isScimv2) ctx.status = 400
      else ctx.status = 500
      const [e, customErrorCode] = jsonErr(config.scim.version, pluginName, ctx.status, err)
      if (customErrorCode) ctx.status = customErrorCode
      ctx.body = e
    }
  })

  // ==========================================
  //           createUser
  //           createGroup
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
    let u = ctx.request.originalUrl.substr(ctx.request.originalUrl.lastIndexOf('/') + 1) // u = Users<.json|.xml>, Groups<.json|.xml>
    u = u.split('?')[0] // Users?AzureAdScimPatch062020
    const handle = handler[u.split('.')[0]]
    logger.debug(`${gwName}[${pluginName}] [Create ${handle.description}]`)
    let jsonBody = ctx.request.body
    const strBody = JSON.stringify(jsonBody)
    if (strBody === '{}') {
      ctx.status = 500
      const err = new Error('Not accepting empty or none JSON formatted POST requests')
      const [e, customErrorCode] = jsonErr(config.scim.version, pluginName, ctx.status, err)
      if (customErrorCode) ctx.status = customErrorCode
      ctx.body = e
      return
    } else if (handle.createMethod === 'createUser' && !jsonBody.userName && !jsonBody.externalId) {
      ctx.status = 500
      const err = new Error('userName or externalId is mandatory')
      const [e, customErrorCode] = jsonErr(config.scim.version, pluginName, ctx.status, err)
      if (customErrorCode) ctx.status = customErrorCode
      ctx.body = e
      return
    } else if (handle.createMethod === 'createGroup' && !jsonBody.displayName && !jsonBody.externalId) {
      ctx.status = 500
      const err = new Error('displayName or externalId is mandatory')
      const [e, customErrorCode] = jsonErr(config.scim.version, pluginName, ctx.status, err)
      if (customErrorCode) ctx.status = customErrorCode
      ctx.body = e
      return
    }

    logger.debug(`${gwName}[${pluginName}] POST ${ctx.request.originalUrl} body=${strBody}`)
    jsonBody = JSON.parse(strBody) // using a copy
    const [scimdata, err] = ScimGateway.prototype.convertedScim(jsonBody)
    logger.debug(`${gwName}[${pluginName}] convertedBody=${JSON.stringify(scimdata)}`)
    if (err) {
      ctx.status = 500
      const [e, customErrorCode] = jsonErr(config.scim.version, pluginName, ctx.status, err)
      if (customErrorCode) ctx.status = customErrorCode
      ctx.body = e
      return
    }
    delete jsonBody.id // in case included in request
    const addGrps = []
    try {
      let res
      if (config.stream.publisher.enabled) {
        const streamObj = {
          handle: handle.createMethod,
          baseEntity: ctx.params.baseEntity,
          obj: scimdata,
          ctxPassThrough: ctx.passThrough
        }
        logger.debug(`${gwName}[${pluginName}] publishing "${handle.createMethod}" to SCIM Stream and awaiting result`)
        res = await this.publish(streamObj)
      } else {
        if (scimdata.groups && Array.isArray(scimdata.groups) && handle.createMethod === 'createUser') {
          if (!config.scim.groupMemberOfUser) {
            for (let i = 0; i < scimdata.groups.length; i++) {
              if (!scimdata.groups[i].value) continue
              addGrps.push(decodeURIComponent(scimdata.groups[i].value))
            }
            delete scimdata.groups
          }
        }
        logger.debug(`${gwName}[${pluginName}] calling "${handle.createMethod}" and awaiting result`)
        res = await this[handle.createMethod](ctx.params.baseEntity, scimdata, ctx.passThrough)
      }
      for (const key in res) { // merge any result e.g: {'id': 'xxxx'}
        jsonBody[key] = res[key]
      }

      if (!jsonBody.id) { // retrieve all attributes including id
        let res
        try {
          if (handle.createMethod === 'createUser') {
            let ob = {}
            const attributes = []
            if (jsonBody.userName) ob = { attribute: 'userName', operator: 'eq', value: jsonBody.userName }
            else if (jsonBody.externalId) ob = { attribute: 'externalId', operator: 'eq', value: jsonBody.externalId }
            if (config.stream.publisher.enabled) {
              const streamObj = {
                handle: handle.getMethod,
                baseEntity: ctx.params.baseEntity,
                obj: ob,
                attributes,
                ctxPassThrough: ctx.passThrough
              }
              res = await this.publish(streamObj)
            } else {
              res = await this[handle.getMethod](ctx.params.baseEntity, ob, attributes, ctx.passThrough)
            }
          } else if (handle.createMethod === 'createGroup') {
            let ob = {}
            const attributes = []
            if (jsonBody.externalId) ob = { attribute: 'externalId', operator: 'eq', value: jsonBody.externalId }
            else if (jsonBody.displayName) ob = { attribute: 'displayName', operator: 'eq', value: jsonBody.displayName }
            if (config.stream.publisher.enabled) {
              const streamObj = {
                handle: handle.getMethod,
                baseEntity: ctx.params.baseEntity,
                obj: ob,
                attributes,
                ctxPassThrough: ctx.passThrough
              }
              res = await this.publish(streamObj)
            } else {
              res = await this[handle.getMethod](ctx.params.baseEntity, ob, attributes, ctx.passThrough)
            }
          }
        } catch (err) { }
        let obj
        if (res.Resources && Array.isArray(res.Resources) && res.Resources.length === 1) {
          obj = res.Resources[0]
        }
        if (obj && obj.id) jsonBody = obj // id found, using returned object
      }

      if (addGrps.length > 0 && handle.createMethod === 'createUser') { // add group membership
        const addGroups = async (groupId) => {
          if (config.stream.publisher.enabled) {
            const streamObj = {
              handle: handler.groups.modifyMethod,
              baseEntity: ctx.params.baseEntity,
              id: groupId,
              obj: { members: [{ value: jsonBody.id }] },
              ctxPassThrough: ctx.passThrough
            }
            return await this.publish(streamObj)
          } else {
            return await this[handler.groups.modifyMethod](ctx.params.baseEntity, groupId, { members: [{ value: jsonBody.id }] }, ctx.passThrough)
          }
        }
        const res = await Promise.allSettled(addGrps.map((groupId) => addGroups(groupId)))
        const errAdd = res.filter(result => result.status === 'rejected').map(result => result.reason.message)
        if (errAdd.length > 0) {
          const errMsg = `user created, but there are group membership errors: ${errAdd.join(', ')}`
          throw new Error(errMsg)
        }
        jsonBody.groups = []
        addGrps.forEach((el) => {
          jsonBody.groups.push({ value: el, type: 'direct' })
        })
      }

      if (!config.scim.skipMetaLocation) {
        const location = `${ctx.request.origin}${ctx.path}/${jsonBody.id}`
        if (!jsonBody.meta) jsonBody.meta = {}
        jsonBody.meta.location = location
        ctx.set('Location', location)
      }
      delete jsonBody.password
      jsonBody = addPrimaryAttrs(jsonBody)
      jsonBody = addSchemas(jsonBody, handle.description, isScimv2)
      ctx.status = 201
      ctx.body = jsonBody
    } catch (err) {
      if (isScimv2) ctx.status = 400
      else ctx.status = 500
      const [e, customErrorCode] = jsonErr(config.scim.version, pluginName, ctx.status, err)
      if (customErrorCode) ctx.status = customErrorCode
      ctx.body = e
    }
  }) // post

  // ==========================================
  //           deleteUser
  //           deleteGroup
  // ==========================================
  //
  // DELETE /Users/<id>
  // DELETE /Groups/<id>
  // Note user: using id (not userName). getUsers should therefore set id = userName (userID) e.g. bjensen
  // => We then have: DELETE /Users/bjensen
  // Note groups: using id (not displayName). getGroups should therefore set id = displayName (groupID) e.g. Employees
  // => We then have: DELETE /Groups/Employees
  //
  router.delete([`/(|scim/)(!${undefined}|Users|Groups)/:id`,
  `/:baseEntity/(|scim/)(!${undefined}|Users|Groups)/:id`], async (ctx) => {
    let u = ctx.request.originalUrl.substr(0, ctx.request.originalUrl.lastIndexOf('/'))
    u = u.substr(u.lastIndexOf('/') + 1) // u = Users, Groups
    const handle = handler[u]
    const id = decodeURIComponent(ctx.params.id)
    logger.debug(`${gwName}[${pluginName}] [Delete ${handle.description}] id=${id}`)

    try {
      if (config.stream.publisher.enabled) {
        const streamObj = {
          handle: handle.deleteMethod,
          baseEntity: ctx.params.baseEntity,
          id,
          ctxPassThrough: ctx.passThrough
        }
        logger.debug(`${gwName}[${pluginName}] publishing "${handle.deleteMethod}" to SCIM Stream and awaiting result`)
        await this.publish(streamObj)
      } else {
        if (handle.deleteMethod === 'deleteUser') {
          // remove user from groups before deleting user
          const groups = await getMemberOf(ctx.params.baseEntity, id, handler.groups.getMethod, ctx.passThrough)
          if (Array.isArray(groups) && groups.length > 0) {
            const revokeGroupMember = async (grpId) => {
              return await this[handler.groups.modifyMethod](ctx.params.baseEntity, grpId, { members: [{ operation: 'delete', value: id }] }, ctx.passThrough)
            }
            await Promise.allSettled(groups.map((grp) => {
              if (grp.value) return revokeGroupMember(grp.value)
              return Promise.resolve()
            })) // result not handled - ignore any failures
          }
        }
        logger.debug(`${gwName}[${pluginName}] calling "${handle.deleteMethod}" and awaiting result`)
        await this[handle.deleteMethod](ctx.params.baseEntity, id, ctx.passThrough)
      }
      ctx.status = 204
    } catch (err) {
      ctx.status = 500
      const [e, customErrorCode] = jsonErr(config.scim.version, pluginName, ctx.status, err)
      if (customErrorCode) ctx.status = customErrorCode
      ctx.body = e
    }
  }) // delete

  // ==========================================
  //          modifyUser
  //          modifyGroup
  // ==========================================
  //
  // PATCH = /Users/<id>
  // PATCH = /Users/4aa37ddc-4985-4009-ab24-df42d37e2810
  // Note, using id (not userName). getUsers should therefore set id = userName (userID)
  // => We then have: PATCH /Users/bjensen
  //
  // Body contains user attributes to be updated
  // example: {"active":true}
  //
  // Multi-value attributes excluding user attribute 'groups' are customized from array to object based on type
  // This is done for simplifying plugin-code. For more information please see method convertedScim / convertedScim20
  //
  // PATCH = /Groups/<id>
  // PATCH = /Groups/4aa37ddc-4985-4009-ab24-df42d37e2810
  // Note, using id (not displayName). getGroups should therefore set id = displayName
  // => We then have: PATCH = /Groups/Employees
  //
  // Body contains groups attributes to be updated
  // example: {"members":[{"value":"bjensen"}],"schemas":["urn:scim:schemas:core:1.0"]}
  //
  router.patch([`/(|scim/)(!${undefined}|Users|Groups|servicePlans)/:id`,
  `/:baseEntity/(|scim/)(!${undefined}|Users|Groups|servicePlans)/:id`], async (ctx) => {
    if (ctx.query.attributes) ctx.query.attributes = ctx.query.attributes.split(',').map(item => item.trim()).join()
    if (ctx.query.excludedAttributes) ctx.query.excludedAttributes = ctx.query.excludedAttributes.split(',').map(item => item.trim()).join()
    let u = ctx.request.originalUrl.substr(0, ctx.request.originalUrl.lastIndexOf('/'))
    u = u.substr(u.lastIndexOf('/') + 1) // u = Users, Groups
    const handle = handler[u]
    const id = decodeURIComponent(ctx.params.id)
    const jsonBody = ctx.request.body
    const strBody = JSON.stringify(jsonBody)
    if (strBody === '{}') {
      ctx.status = 500
      const err = new Error('Not accepting empty or none JSON formatted PATCH request')
      const [e, customErrorCode] = jsonErr(config.scim.version, pluginName, ctx.status, err)
      if (customErrorCode) ctx.status = customErrorCode
      ctx.body = e
    } else {
      logger.debug(`${gwName}[${pluginName}] [Modify ${handle.description}] id=${id}`)
      let scimdata, err
      if (jsonBody.Operations) [scimdata, err] = ScimGateway.prototype.convertedScim20(jsonBody) // v2.0
      else [scimdata, err] = ScimGateway.prototype.convertedScim(jsonBody) // v1.1
      logger.debug(`${gwName}[${pluginName}] convertedBody=${JSON.stringify(scimdata)}`)
      if (err) {
        ctx.status = 500
        const [e, customErrorCode] = jsonErr(config.scim.version, pluginName, ctx.status, err)
        if (customErrorCode) ctx.status = customErrorCode
        ctx.body = e
        return
      }
      delete scimdata.id
      const groups = []
      if (scimdata.groups && Array.isArray(scimdata.groups) && handle.modifyMethod === 'modifyUser') {
        if (!config.scim.groupMemberOfUser) {
          for (let i = 0; i < scimdata.groups.length; i++) {
            if (!scimdata.groups[i].value) continue
            const obj = utils.copyObj(scimdata.groups[i])
            obj.value = decodeURIComponent(obj.value)
            groups.push(obj)
          }
          delete scimdata.groups
        }
      }
      try {
        if (config.stream.publisher.enabled) {
          let streamObj = {
            handle: handle.modifyMethod,
            baseEntity: ctx.params.baseEntity,
            id,
            obj: scimdata,
            ctxPassThrough: ctx.passThrough
          }
          if (Array.isArray(scimdata.members) && scimdata.members.length === 0 && handle.modifyMethod === 'modifyGroup') {
            ctx.request.body = scimdata
            streamObj = {
              handle: 'replaceUsrGrp',
              baseEntity: ctx.params.baseEntity,
              originalUrl: ctx.request.originalUrl,
              id,
              obj: scimdata,
              ctxPassThrough: ctx.passThrough
            }
          }
          logger.debug(`${gwName}[${pluginName}] publishing "${handle.modifyMethod}" to SCIM Stream and awaiting result`)
          await this.publish(streamObj)
        } else {
          if (Array.isArray(scimdata.members) && scimdata.members.length === 0 && handle.modifyMethod === 'modifyGroup') {
            ctx.request.body = scimdata
            await replaceUsrGrp(ctx, config.scim.usePutSoftSync)
          } else {
            logger.debug(`${gwName}[${pluginName}] calling "${handle.modifyMethod}" and awaiting result`)
            await this[handle.modifyMethod](ctx.params.baseEntity, id, scimdata, ctx.passThrough)
          }
        }

        if (groups.length > 0 && handle.modifyMethod === 'modifyUser') { // modify user includes groups, add/remove group membership
          const updateGroup = async (groupsObj) => {
            const groupId = groupsObj.value
            const memberObj = { value: id }
            if (groupsObj.operation) memberObj.operation = groupsObj.operation
            if (config.stream.publisher.enabled) {
              const streamObj = {
                handle: handler.groups.modifyMethod,
                baseEntity: ctx.params.baseEntity,
                id: groupId,
                obj: { members: [memberObj] },
                ctxPassThrough: ctx.passThrough
              }
              return await this.publish(streamObj)
            } else {
              return await this[handler.groups.modifyMethod](ctx.params.baseEntity, groupId, { members: [memberObj] }, ctx.passThrough)
            }
          }
          const res = await Promise.allSettled(groups.map((groupsObj) => updateGroup(groupsObj)))
          const errRes = res.filter(result => result.status === 'rejected').map(result => result.reason.message)
          if (errRes.length > 0) {
            const errMsg = `modify user group membership error: ${errRes.join(', ')}`
            throw new Error(errMsg)
          }
        }

        // include full object in response
        // TODO: include groups
        if (handle.getMethod !== handler.users.getMethod && handle.getMethod !== handler.groups.getMethod && !config.stream.publisher.enabled) { // getUsers or getGroups not implemented
          ctx.status = 204
          return
        }
        let res
        const ob = { attribute: 'id', operator: 'eq', value: id }
        const attributes = ctx.query.attributes ? ctx.query.attributes.split(',').map(item => item.trim()) : []
        if (config.stream.publisher.enabled) {
          const streamObj = {
            handle: handle.getMethod,
            baseEntity: ctx.params.baseEntity,
            obj: ob,
            attributes,
            ctxPassThrough: ctx.passThrough
          }
          logger.debug(`${gwName}[${pluginName}] publishing "${handle.getMethod}" to SCIM Stream and awaiting result`)
          res = await this.publish(streamObj)
        } else {
          logger.debug(`${gwName}[${pluginName}] calling "${handle.getMethod}" and awaiting result`)
          res = await this[handle.getMethod](ctx.params.baseEntity, ob, attributes, ctx.passThrough)
        }

        scimdata = {
          Resources: []
        }
        if (res) {
          if (res.Resources && Array.isArray(res.Resources)) {
            scimdata.Resources = res.Resources
          } else if (Array.isArray(res)) scimdata.Resources = res
          else if (typeof (res) === 'object') scimdata.Resources[0] = res
          else scimdata.Resources = []
        } else scimdata.Resources = []
        if (scimdata.Resources.length === 0 || scimdata.Resources.length > 1) {
          ctx.status = 204
          return
        }

        if (!config.scim.skipMetaLocation) {
          const location = ctx.request.origin + ctx.path
          ctx.set('Location', location)
        }
        const userObj = addPrimaryAttrs(scimdata.Resources[0])
        scimdata = utils.stripObj(userObj, ctx.query.attributes, ctx.query.excludedAttributes)
        scimdata = addSchemas(scimdata, handle.description, isScimv2)
        ctx.status = 200
        ctx.body = scimdata
      } catch (err) {
        ctx.status = 500
        const [e, customErrorCode] = jsonErr(config.scim.version, pluginName, ctx.status, err)
        if (customErrorCode) ctx.status = customErrorCode
        ctx.body = e
      }
    }
  }) // patch

  // ==========================================
  //          Replace User
  //          Replace Group
  // ==========================================
  const replaceUsrGrp = async (ctx, usePutSoftSync) => {
    const requestBody = utils.copyObj(ctx.request.body)
    let u = ctx.request.originalUrl.substr(0, ctx.request.originalUrl.lastIndexOf('/'))
    u = u.substr(u.lastIndexOf('/') + 1) // u = Users, Groups
    const handle = handler[u]
    const id = decodeURIComponent(ctx.params.id)
    const obj = ctx.request.body
    const strObj = JSON.stringify(obj)
    if (strObj === '{}' || !handle) {
      ctx.status = 500
      const err = new Error('malformatted PUT requests')
      const [e, customErrorCode] = jsonErr(config.scim.version, pluginName, ctx.status, err)
      if (customErrorCode) ctx.status = customErrorCode
      ctx.body = e
      return
    }
    logger.debug(`${gwName}[${pluginName}] PUT ${ctx.request.originalUrl} body=${strObj}`)

    // get current object
    logger.debug(`${gwName}[${pluginName}] calling "${handle.getMethod}" and awaiting result`)
    const res = await this[handle.getMethod](ctx.params.baseEntity, { attribute: 'id', operator: 'eq', value: id }, [], ctx.passThrough)
    let currentObj
    if (res && res.Resources && Array.isArray(res.Resources)) {
      if (res.Resources.length === 1) currentObj = res.Resources[0]
      else currentObj = {}
    } else if (Array.isArray(res) && res.length === 1) currentObj = res[0]
    else if (res && typeof (res) === 'object' && Object.keys(res).length > 0) currentObj = res
    else currentObj = {}

    if (typeof (currentObj) !== 'object' || Object.keys(currentObj).length === 0) {
      ctx.status = 404
      const err = new Error(`put using method ${handle.getMethod} error: ${handle.description.toLowerCase()} id=${id} does not exist`)
      const [e, customErrorCode] = jsonErr(config.scim.version, pluginName, ctx.status, err)
      if (customErrorCode) ctx.status = customErrorCode
      ctx.body = e
      return
    }

    const activeExists = Object.prototype.hasOwnProperty.call(obj, 'active')
    let objGroups
    if (obj.groups) {
      if (!config.scim.groupMemberOfUser && !config.scim.usePutGroupMemberOfUser) { // usePutGroupMemberOfUser is legacy
        objGroups = utils.copyObj(obj.groups)
        delete obj.groups
      }
    }

    // merge obj with currentObj as cleared
    utils.extendObjClear(obj, currentObj, usePutSoftSync)
    delete obj.id
    delete obj.schemas
    delete obj.meta
    if (!activeExists && !usePutSoftSync) delete obj.active
    // remove from obj what match currentObj
    utils.deltaObj(obj, currentObj)
    // userName/displayName should not be set to blank
    if (!obj.userName) delete obj.userName
    if (!obj.displayName && handle.modifyMethod === 'modifyGroup') delete obj.displayName

    const [scimdata, err] = ScimGateway.prototype.convertedScim(obj)
    if (err) throw err

    // update object
    if (Object.keys(scimdata).length > 0) {
      logger.debug(`${gwName}[${pluginName}] calling "${handle.modifyMethod}" and awaiting result`)
      await this[handle.modifyMethod](ctx.params.baseEntity, id, scimdata, ctx.passThrough)
    }

    // add/remove groups
    if (!config.scim.groupMemberOfUser && !config.scim.usePutGroupMemberOfUser) { // default user member of group, usePutGroupMemberOfUser is legacy
      if (objGroups && Array.isArray(objGroups)) { // only if groups included, { "groups": [] } will remove all existing
        if (typeof this[handler.groups.getMethod] !== 'function' || typeof this[handler.groups.modifyMethod] !== 'function') {
          throw new Error('replaceUser error: put operation can not be fully completed for the user`s groups, methods like getGroups() and modifyGroup() are not implemented')
        }
        let currentGroups
        if (currentObj.groups && Array.isArray(currentObj.groups)) currentGroups = currentObj.groups
        else { // try to get current groups the standard way
          let res
          try {
            res = await this[handler.groups.getMethod](ctx.params.baseEntity, { attribute: 'members.value', operator: 'eq', value: decodeURIComponent(id) }, ['id', 'displayName'], ctx.passThrough)
          } catch (err) {} // method may be implemented but throwing error like groups not supported/implemented
          currentGroups = []
          if (res && res.Resources && Array.isArray(res.Resources) && res.Resources.length > 0) {
            for (let i = 0; i < res.Resources.length; i++) {
              if (!res.Resources[i].id) continue
              const el = {}
              el.value = res.Resources[i].id
              if (res.Resources[i].displayName) el.display = res.Resources[i].displayName
              currentGroups.push(el) // { "value": "Admins", "display": "Admins"}
            }
          }
        }
        currentGroups = currentGroups.map((el) => {
          if (el.value) {
            el.value = decodeURIComponent(el.value)
          }
          return el
        })

        const addGrps = []
        const removeGrps = []
        // add
        for (let i = 0; i < objGroups.length; i++) {
          if (!objGroups[i].value) continue
          objGroups[i].value = decodeURIComponent(objGroups[i].value)
          let found = false
          for (let j = 0; j < currentGroups.length; j++) {
            if (objGroups[i].value === currentGroups[j].value) {
              found = true
              break
            }
          }
          if (!found && objGroups[i].value) addGrps.push(objGroups[i].value)
        }
        // remove
        for (let i = 0; i < currentGroups.length; i++) {
          let found = false
          for (let j = 0; j < objGroups.length; j++) {
            if (!objGroups[j].value) continue
            objGroups[j].value = decodeURIComponent(objGroups[j].value)
            if (currentGroups[i].value === objGroups[j].value) {
              found = true
              break
            }
          }
          if (!found && currentGroups[i].value) removeGrps.push(currentGroups[i].value)
        }

        const assignGroupMember = async (grpId) => {
          return await this[handler.groups.modifyMethod](ctx.params.baseEntity, grpId, { members: [{ value: id }] }, ctx.passThrough)
        }

        const revokeGroupMember = async (grpId) => {
          return await this[handler.groups.modifyMethod](ctx.params.baseEntity, grpId, { members: [{ operation: 'delete', value: id }] }, ctx.passThrough)
        }

        let errRevoke = []
        if (!usePutSoftSync) { // default will remove any existing groups not included, usePutSoftSync=true prevents removing existing groups (only add groups)
          const res = await Promise.allSettled(removeGrps.map((grpId) => revokeGroupMember(grpId)))
          errRevoke = res.filter(result => result.status === 'rejected').map(result => result.reason.message)
        }

        const res = await Promise.allSettled(addGrps.map((grpId) => assignGroupMember(grpId)))
        const errAssign = res.filter(result => result.status === 'rejected').map(result => result.reason.message)

        let errMsg = ''
        if (errRevoke.length > 0) errMsg = `revokeGroupMember errors: ${errRevoke.join(', ')}`
        if (errAssign.length > 0) errMsg += `${errMsg ? ' ' : ''}assignGroupMember errors: ${errAssign.join(', ')}`
        if (errMsg) throw new Error(errMsg)
      }
    }
    ctx.request.body = requestBody // preserve inbound info log
    return null
  }
  this.replaceUsrGrp = replaceUsrGrp

  router.put([`/(|scim/)(!${undefined}|Users|Groups|servicePlans)/:id`,
    `/:baseEntity/(|scim/)(!${undefined}|Users|Groups|servicePlans)/:id`], async (ctx) => {
    const originalUrl = ctx.request.originalUrl
    if (config.stream.publisher.enabled) {
      const streamObj = {
        handle: 'replaceUsrGrp',
        baseEntity: ctx.params.baseEntity,
        originalUrl,
        id: ctx.params.id,
        obj: ctx.request.body,
        ctxPassThrough: ctx.passThrough
      }
      logger.debug(`${gwName}[${pluginName}] publishing replaceUsrGrp to SCIM Stream and awaiting result`)
      await this.publish(streamObj)
    } else {
      await replaceUsrGrp(ctx, config.scim.usePutSoftSync)
    }
    ctx.request.originalUrl = originalUrl
    return await getById(ctx)
  })

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
    const apiObj = ctx.request.body
    const strBody = JSON.stringify(apiObj)
    if (strBody === '{}') {
      const err = new Error('Not accepting empty or none JSON formatted POST requests')
      ctx.status = 500
      ctx.body = apiErr(pluginName, err)
    } else {
      try {
        let result
        if (config.stream.publisher.enabled) {
          const streamObj = {
            handle: 'postApi',
            baseEntity: ctx.params.baseEntity,
            obj: apiObj,
            ctxPassThrough: ctx.passThrough
          }
          logger.debug(`${gwName}[${pluginName}] publishing "postApi" to SCIM Stream and awaiting result`)
          result = await this.publish(streamObj)
        } else {
          logger.debug(`${gwName}[${pluginName}] calling "postApi" and awaiting result`)
          result = await this.postApi(ctx.params.baseEntity, apiObj, ctx.passThrough)
        }
        if (result) {
          if (typeof result === 'object') result = { result }
          else {
            try {
              result = { result: JSON.parse(result) }
            } catch (err) {
              result = { result }
            }
          }
        } else result = {}
        if (!result.meta) result.meta = {}
        result.meta.result = 'success'
        if (!config.scim.skipMetaLocation) {
          const location = ctx.request.origin + ctx.path
          result.meta.location = location
        }
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
    const id = ctx?.params?.id
    logger.debug(`${gwName}[${pluginName}] [PUT api ] id=${id}`)
    const apiObj = ctx.request.body
    const strBody = JSON.stringify(apiObj)
    if (strBody === '{}') {
      const err = new Error('Not accepting empty or none JSON formatted PUT requests')
      ctx.status = 500
      ctx.body = apiErr(pluginName, err)
    } else {
      try {
        let result
        if (config.stream.publisher.enabled) {
          const streamObj = {
            handle: 'putApi',
            baseEntity: ctx.params.baseEntity,
            id,
            obj: apiObj,
            ctxPassThrough: ctx.passThrough
          }
          logger.debug(`${gwName}[${pluginName}] publishing "putApi" to SCIM Stream and awaiting result`)
          result = await this.publish(streamObj)
        } else {
          logger.debug(`${gwName}[${pluginName}] calling "putApi" and awaiting result`)
          result = await this.putApi(ctx.params.baseEntity, id, apiObj, ctx.passThrough)
        }
        if (result) {
          if (typeof result === 'object') result = { result }
          else {
            try {
              result = { result: JSON.parse(result) }
            } catch (err) {
              result = { result }
            }
          }
        } else result = {}
        if (!result.meta) result.meta = {}
        result.meta.result = 'success'
        if (!config.scim.skipMetaLocation) {
          const location = ctx.request.origin + ctx.path
          result.meta.location = location
        }
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
    const id = ctx?.params?.id
    logger.debug(`${gwName}[${pluginName}] [PATCH api ] id=${id}`)
    const apiObj = ctx.request.body
    const strBody = JSON.stringify(apiObj)
    if (strBody === '{}') {
      const err = new Error('Not accepting empty or none JSON formatted PATCH requests')
      ctx.status = 500
      ctx.body = apiErr(pluginName, err)
    } else {
      try {
        let result
        if (config.stream.publisher.enabled) {
          const streamObj = {
            handle: 'patchApi',
            baseEntity: ctx.params.baseEntity,
            id,
            obj: apiObj,
            ctxPassThrough: ctx.passThrough
          }
          logger.debug(`${gwName}[${pluginName}] publishing "patchApi" to SCIM Stream and awaiting result`)
          result = await this.publish(streamObj)
        } else {
          logger.debug(`${gwName}[${pluginName}] calling "patchApi" and awaiting result`)
          result = await this.patchApi(ctx.params.baseEntity, id, apiObj, ctx.passThrough)
        }
        if (result) {
          if (typeof result === 'object') result = { result }
          else {
            try {
              result = { result: JSON.parse(result) }
            } catch (err) {
              result = { result }
            }
          }
        } else result = {}
        if (!result.meta) result.meta = {}
        result.meta.result = 'success'
        if (!config.scim.skipMetaLocation) {
          const location = ctx.request.origin + ctx.path
          result.meta.location = location
        }
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
    const id = ctx?.params?.id
    if (id) logger.debug(`${gwName}[${pluginName}] [GET api] id=${id}`)
    else logger.debug(`${gwName}[${pluginName}] [GET api]`)
    let apiObj = ctx.request.body
    const strBody = JSON.stringify(apiObj)
    if (strBody === '{}') apiObj = undefined
    try {
      let result
      if (config.stream.publisher.enabled) {
        const streamObj = {
          handle: 'getApi',
          baseEntity: ctx.params.baseEntity,
          id,
          query: ctx.query,
          obj: apiObj,
          ctxPassThrough: ctx.passThrough
        }
        logger.debug(`${gwName}[${pluginName}] publishing "getApi" to SCIM Stream and awaiting result`)
        result = await this.publish(streamObj)
      } else {
        logger.debug(`${gwName}[${pluginName}] calling "getApi" and awaiting result`)
        result = await this.getApi(ctx.params.baseEntity, id, ctx.query, apiObj, ctx.passThrough)
      }
      if (result) {
        if (typeof result === 'object') result = { result }
        else {
          try {
            result = { result: JSON.parse(result) }
          } catch (err) {
            result = { result }
          }
        }
      } else result = {}
      if (!result.meta) result.meta = {}
      result.meta.result = 'success'
      if (!config.scim.skipMetaLocation) {
        const location = ctx.request.origin + ctx.path
        result.meta.location = location
      }
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
    const id = ctx?.params?.id
    logger.debug(`${gwName}[${pluginName}] [DELETE api ] id=${id}`)
    try {
      let result
      if (config.stream.publisher.enabled) {
        const streamObj = {
          handle: 'deleteApi',
          baseEntity: ctx.params.baseEntity,
          id,
          ctxPassThrough: ctx.passThrough
        }
        logger.debug(`${gwName}[${pluginName}] publishing "deleteApi" to SCIM Stream and awaiting result`)
        result = await this.publish(streamObj)
      } else {
        logger.debug(`${gwName}[${pluginName}] calling "deleteApi" and awaiting result`)
        result = await this.deleteApi(ctx.params.baseEntity, id, ctx.passThrough)
      }
      if (result) {
        if (typeof result === 'object') result = { result }
        else {
          try {
            result = { result: JSON.parse(result) }
          } catch (err) {
            result = { result }
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
  //   GET Application Roles based on groups
  // ==========================================
  //
  //  GET = /AppRoles
  //
  const getAppRoles = require('../lib/scim-stream').getAppRoles
  this.getAppRoles = async (baseEntity, getObj, attributes, ctx) => {
    return await getAppRoles(this, baseEntity, getObj, attributes)
  }

  // get all groups a user is member of
  const getMemberOf = async (baseEntity, id, getMethod, ctxPassThrough) => {
    const groups = []
    if (getMethod !== 'getGroups') return groups
    if (typeof this[handler.groups.getMethod] !== 'function') return groups // method not implemented
    if (config.scim.groupMemberOfUser) return groups // only support user member of group
    let res
    try {
      const ob = { attribute: 'members.value', operator: 'eq', value: decodeURIComponent(id) }
      const attributes = ['id', 'displayName']
      logger.debug(`${gwName}[${pluginName}] calling "${handler.groups.getMethod}" and awaiting result - groups to be included`)
      res = await this[handler.groups.getMethod](baseEntity, ob, attributes, ctxPassThrough)
    } catch (err) {} // ignore errors
    if (res && res.Resources && Array.isArray(res.Resources) && res.Resources.length > 0) {
      for (let i = 0; i < res.Resources.length; i++) {
        if (!res.Resources[i].id) continue
        const el = {}
        el.value = res.Resources[i].id
        if (res.Resources[i].displayName) el.display = res.Resources[i].displayName
        if (isScimv2) el.type = 'direct'
        else el.type = { value: 'direct' }
        groups.push(el) // { "value": "Admins", "display": "Admins", "type": "direct"}
      }
    }
    return groups
  }
  this.getMemberOf = getMemberOf

  // ==========================================
  // Starting up...
  // ==========================================

  for (let i = 0; i < logger.transports.length; i++) { // loglevel=off => turn off logging
    if (logger.transports[i].name === 'file' && config.log.loglevel.file && config.log.loglevel.file.toLowerCase() === 'off') {
      logger.transports[i].silent = true
    } else if (logger.transports[i].name === 'console' && config.log.loglevel.console && config.log.loglevel.console.toLowerCase() === 'off') {
      logger.transports[i].silent = true
    }
  }

  logger.info('===================================================================')

  if (!config.port) {
    logger.info(`${gwName}[${pluginName}] port deactivated, not allowing incoming traffic`)
  } else {
    if (config.localhostonly === true) {
      logger.info(`${gwName}[${pluginName}] denying other clients than localhost (127.0.0.1)`)
      if (config.certificate && config.certificate.key && config.certificate.cert) {
      // SSL
        let keyFile = path.join(configDir, '/certs/', config.certificate.key)
        if (config.certificate.key.startsWith('/') || config.certificate.key.includes('\\')) {
          keyFile = config.certificate.key
        }
        let certFile = path.join(configDir, '/certs/', config.certificate.cert)
        if (config.certificate.cert.startsWith('/') || config.certificate.cert.includes('\\')) {
          certFile = config.certificate.cert
        }
        server = https.createServer({
          key: fs.readFileSync(keyFile),
          cert: fs.readFileSync(certFile)
        }, app.callback()).listen(config.port, 'localhost')
        logger.info(`${gwName}[${pluginName}] now listening SCIM ${config.scim.version} on TLS port ${config.port}...${config.stream.subscriber.enabled ? '' : '\n'}`)
      } else if (config.certificate && config.certificate.pfx && config.certificate.pfx.bundle) {
      // SSL using PFX / PKCS#12
        let pfxFile = path.join(configDir, '/certs/', config.certificate.pfx.bundle)
        if (config.certificate.pfx.bundle.startsWith('/') || config.certificate.pfx.bundle.includes('\\')) {
          pfxFile = config.certificate.pfx.bundle
        }
        server = https.createServer({
          pfx: fs.readFileSync(pfxFile),
          passphrase: pwPfxPassword
        }, app.callback()).listen(config.port, 'localhost')
        logger.info(`${gwName}[${pluginName}] now listening SCIM ${config.scim.version} on TLS port ${config.port}...${config.stream.subscriber.enabled ? '' : '\n'}`)
      } else {
      // none SSL
        server = http.createServer(app.callback()).listen(config.port, 'localhost')
        logger.info(`${gwName}[${pluginName}] now listening SCIM ${config.scim.version} on port ${config.port}...${config.stream.subscriber.enabled ? '' : '\n'}`)
      }
    } else {
      logger.info(`${gwName}[${pluginName}] accepting requests from all clients`)
      if (config.certificate && config.certificate.key && config.certificate.cert) {
      // SSL self signed cert e.g: openssl req -nodes -newkey rsa:2048 -x509 -sha256 -days 3650 -keyout key.pem -out cert.pem -subj "/O=NodeJS/OU=Testing/CN=<FQDN>"
        let keyFile = path.join(configDir, '/certs/', config.certificate.key)
        if (config.certificate.key.startsWith('/') || config.certificate.key.includes('\\')) {
          keyFile = config.certificate.key
        }
        let certFile = path.join(configDir, '/certs/', config.certificate.cert)
        if (config.certificate.cert.startsWith('/') || config.certificate.cert.includes('\\')) {
          certFile = config.certificate.cert
        }
        let caFile
        if (config.certificate.ca) {
          caFile = path.join(configDir, '/certs/', config.certificate.ca)
          if (config.certificate.ca.startsWith('/') || config.certificate.ca.includes('\\')) {
            caFile = config.certificate.ca
          }
        }
        server = https.createServer({
          key: fs.readFileSync(keyFile),
          cert: fs.readFileSync(certFile),
          ca: (config.certificate.ca) ? fs.readFileSync(caFile) : null
        }, app.callback()).listen(config.port)
        logger.info(`${gwName}[${pluginName}] now listening SCIM ${config.scim.version} on TLS port ${config.port}...${config.stream.subscriber.enabled ? '' : '\n'}`)
      } else if (config.certificate && config.certificate.pfx && config.certificate.pfx.bundle) {
      // SSL using PFX / PKCS#12
        let pfxFile = path.join(configDir, '/certs/', config.certificate.pfx.bundle)
        if (config.certificate.pfx.bundle.startsWith('/') || config.certificate.pfx.bundle.includes('\\')) {
          pfxFile = config.certificate.pfx.bundle
        }
        server = https.createServer({
          pfx: fs.readFileSync(pfxFile),
          passphrase: pwPfxPassword
        }, app.callback()).listen(config.port)
        logger.info(`${gwName}[${pluginName}] now listening SCIM ${config.scim.version} on TLS port ${config.port}...${config.stream.subscriber.enabled ? '' : '\n'}`)
      } else {
      // none SSL
        server = http.createServer(app.callback()).listen(config.port)
        logger.info(`${gwName}[${pluginName}] now listening SCIM ${config.scim.version} on port ${config.port}...${config.stream.subscriber.enabled ? '' : '\n'}`)
      }
    }
  }

  // starting SCIM Stream subscribers
  if (config.stream.subscriber.enabled && config.stream.subscriber.entity && Object.keys(config.stream.subscriber.entity).length > 0) {
    logger.info(`${gwName}[${pluginName}] starting SCIM Stream subscribers...`)
    const sub = new Subscriber(this)
    for (const baseEntity in config.stream.subscriber.entity) {
      const cfgSub = utils.copyObj(config.stream.subscriber.entity[baseEntity])
      cfgSub.baseUrls = config.stream.baseUrls
      cfgSub.certificate = config.stream.certificate
      cfgSub.usePutSoftSync = config.scim.usePutSoftSync
      sub.add(baseEntity, cfgSub)
    }
  }

  // starting SCIM Stream publisher
  if (config.stream.publisher.enabled && config.stream.publisher.entity && Object.keys(config.stream.publisher.entity).length > 0) {
    logger.info(`${gwName}[${pluginName}] starting SCIM Stream publishers...`)
    const pub = new Publisher(this)
    for (const baseEntity in config.stream.publisher.entity) {
      const cfgPub = utils.copyObj(config.stream.publisher.entity[baseEntity])
      cfgPub.baseUrls = config.stream.baseUrls
      cfgPub.certificate = config.stream.certificate
      pub.add(baseEntity, cfgPub)
    }
    this.publish = pub.publish
  }

  function onSignal () {
    logger.info('server is starting cleanup')
    return Promise.all([
      // your clean logic, like closing database connections
    ])
  }

  function onShutdown () {
    logger.info('cleanup finished, server is shutting down')
  }

  function beforeShutdown () {
    return new Promise(resolve => {
      setTimeout(resolve, config.kubernetes.shutdownTimeout || 15000)
    })
  }

  function healthCheck () {
    return Promise.resolve(
      // optionally include a resolve value to be included as
      // info in the health check response
    )
  }
  const options = {
    // health check options
    healthChecks: {
      '/healthcheck': healthCheck, // a function returning a promise indicating service health,
      verbatim: true // [optional = false] use object returned from /healthcheck verbatim in response
    },

    // cleanup options
    timeout: config.kubernetes.forceExitTimeout || 1000, // [optional = 1000] number of milliseconds before forceful exiting
    beforeShutdown, // [optional] called before the HTTP server starts its shutdown
    onSignal, // [optional] cleanup function, returning a promise (used to be onSigterm)
    onShutdown // [optional] called right before exiting
  }

  if (config.kubernetes.enabled) createTerminus(server, options)

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
    if (server) {
      server.close(function () {
        setTimeout(function () { // plugins may also use SIGTERM/SIGINT
          process.exit(0)
        }, 0.5 * 1000)
      })
    }
    setTimeout(function () { // problem closing server connections in time due to keep-alive sessions (active browser connection?), now forcing exit
      process.exit(1)
    }, 2 * 1000)
  }

  process.on('unhandledRejection', (err) => { // older versions of V8, unhandled promise rejections are silently dropped
    logger.error(`${gwName}[${pluginName}] Async function with unhandledRejection: ${err.stack}`)
  })
  process.once('SIGTERM', gracefulShutdown) // kill (windows subsystem lacks signaling support for process.kill)
  process.once('SIGINT', gracefulShutdown) // Ctrl+C

  //
  // exported methods inside ScimGateway because of local defined variable multiValueTypes
  //
  ScimGateway.prototype.isMultiValueTypes = function isMultiValueTypes (attr) { // emails
    return multiValueTypes.includes(attr)
  }

  // Multi-value attributes are customized from array to object based on type
  // except: groups, members and roles
  // e.g "emails":[{"value":"bjensen@example.com","type":"work"}] => {"emails": {"work": {"value":"bjensen@example.com","type":"work"}}}
  // Cleared values are set as user attributes with blank value ""
  // e.g {meta:{attributes:['name.givenName','title']}} => {"name": {"givenName": ""}), "title": ""}
  ScimGateway.prototype.convertedScim = function convertedScim (obj) {
    let err = null
    const scimdata = utils.copyObj(obj)
    if (scimdata.schemas) delete scimdata.schemas
    const newMulti = {}
    for (const key in scimdata) {
      if (Array.isArray(scimdata[key]) && (scimdata[key].length > 0)) {
        if (key === 'groups' || key === 'members' || key === 'roles') {
          scimdata[key].forEach(function (element, index) {
            if (element.value) scimdata[key][index].value = decodeURIComponent(element.value)
          })
        } else if (multiValueTypes.includes(key)) { // "type converted object" // groups, roles, member and scim.excludeTypeConvert are not included
          const tmpAddr = []
          scimdata[key].forEach(function (element, index) {
            if (!element.type) element.type = 'undefined' // "none-type"
            if (element.operation && element.operation === 'delete') { // add as delete if same type not included as none delete
              const arr = scimdata[key].filter(obj => obj.type && obj.type === element.type && !obj.operation)
              if (arr.length < 1) {
                if (!newMulti[key]) newMulti[key] = {}
                if (newMulti[key][element.type]) {
                  if (['addresses'].includes(key)) { // not checking type, but the others have to be unique
                    for (const i in element) {
                      if (i !== 'type') {
                        if (tmpAddr.includes(i)) {
                          err = new Error(`'type converted object' ${key} - includes more than one element having same ${i}, or ${i} is blank on more than one element - note, setting configuration scim.skipTypeConvert=true will disable this logic/check`)
                        }
                        tmpAddr.push(i)
                      }
                    }
                  } else {
                    err = new Error(`'type converted object' ${key} - includes more than one element having same type, or type is blank on more than one element - note, setting configuration scim.skipTypeConvert=true will disable this logic/check`)
                  }
                }
                newMulti[key][element.type] = {}
                for (const i in element) {
                  newMulti[key][element.type][i] = element[i]
                }
                newMulti[key][element.type].value = '' // delete
              }
            } else {
              if (!newMulti[key]) newMulti[key] = {}
              if (newMulti[key][element.type]) {
                if (['addresses'].includes(key)) { // not checking type, but the others have to be unique
                  for (const i in element) {
                    if (i !== 'type') {
                      if (tmpAddr.includes(i)) {
                        err = new Error(`'type converted object' ${key} - includes more than one element having same ${i}, or ${i} is blank on more than one element - note, setting configuration scim.skipTypeConvert=true will disable this logic/check`)
                      }
                      tmpAddr.push(i)
                    }
                  }
                } else {
                  err = new Error(`'type converted object' ${key} - includes more than one element having same type, or type is blank on more than one element - note, setting configuration scim.skipTypeConvert=true will disable this logic/check`)
                }
              }
              newMulti[key][element.type] = {}
              for (const i in element) {
                newMulti[key][element.type][i] = element[i]
              }
            }
          })
          delete scimdata[key]
        }
      }
    }
    if (scimdata.active && typeof scimdata.active === 'string') {
      const lcase = scimdata.active.toLowerCase()
      if (lcase === 'true') scimdata.active = true
      else if (lcase === 'false') scimdata.active = false
    }
    if (scimdata.meta) { // cleared attributes e.g { meta: { attributes: [ 'name.givenName', 'title' ] } }
      if (Array.isArray(scimdata.meta.attributes)) {
        scimdata.meta.attributes.forEach(el => {
          let rootKey
          let subKey
          if (el.startsWith('urn:')) { // can't use dot.str on key having dot e.g. urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department
            const i = el.lastIndexOf(':')
            subKey = el.substring(i + 1)
            if (subKey === 'User' || subKey === 'Group') rootKey = el
            else rootKey = el.substring(0, i)
          }
          if (rootKey) {
            if (!scimdata[rootKey]) scimdata[rootKey] = {}
            dot.str(subKey, '', scimdata[rootKey])
          } else {
            dot.str(el, '', scimdata)
          }
        })
      }
      delete scimdata.meta
    }
    for (const key in newMulti) {
      dot.copy(key, key, newMulti, scimdata)
    }
    return [scimdata, err]
  }
} // scimgateway

//
// exported methods
//
ScimGateway.prototype.countries = countries

ScimGateway.prototype.publish = () => {
  return ScimGateway.publisher.publish() // utils.getPassword('scimgateway.password', './config/plugin-testmode.json');
}

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

/*
ScimGateway.prototype.isMultiValueTypes = function isMultiValueTypes (attr) { // emails
  return multiValueTypes.includes(attr)
}
*/

//
// getMultivalueTypes returns an array of mulitvalue attributes allowing type e.g [emails,addresses,...]
// objName should be 'User' or 'Group'
//
const getMultivalueTypes = (objName, scimDef) => { // objName = 'User' or 'Group'
  if (!objName) return []

  const obj = scimDef.Schemas.Resources.find(el => {
    return (el.name === objName)
  })
  if (!obj) return []

  return obj.attributes
    .filter(el => {
      return (el.multiValued === true && el.subAttributes &&
        el.subAttributes
          .find(function (subel) {
            return (subel.name === 'type')
          })
      )
    })
    .map(obj => obj.name)
}

// config can be set based on environment variables
// config can be set based on correspondig json-content in external file (supports also dot notation)
// syntax environment = "process.env.<ENVIRONMENT>" e.g. config.port could have value "process.env.PORT", then using environment variable PORT
// syntax file = "process.file.<PATH>" e.g. config.password could have value "process.file./tmp/myconf.json"
ScimGateway.prototype.processExtConfig = function processExtConfig (pluginName, config, isMain) {
  const processEnv = 'process.env.'
  const processFile = 'process.file.'
  const processText = 'process.text.'
  const dotConfig = dot.dot(config)
  const processTexts = new Map()
  const processFiles = new Map()

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
    } else if (value && value.constructor === String && value.includes(processText)) {
      const filePath = value.substring(processText.length)
      try {
        if (!processTexts.has(filePath)) { // avoid reading previous file
          processTexts.set(filePath, fs.readFileSync(filePath, 'utf8'))
        }
        value = processTexts.get(filePath) // directly a string
      } catch (err) {
        value = undefined
        throw new Error(`configuration failed - can't read text from external file: "${filePath}"`)
      }
      dotConfig[key] = value
    } else if (value && value.constructor === String && value.includes(processFile)) {
      const filePath = value.substring(processFile.length)
      try {
        if (!processFiles.has(filePath)) { // avoid reading previous file
          processFiles.set(filePath, JSON.parse(fs.readFileSync(filePath, 'utf8')))
        }
        try {
          const jContent = processFiles.get(filePath) // json or json-dot-notation formatting is supported
          const dotContent = dot.dot(dot.object(jContent))
          let newKey = null
          if (isMain) newKey = `${pluginName}.scimgateway.${key}`
          else newKey = `${pluginName}.endpoint.${key}`
          value = dotContent[newKey]
          if (value === undefined) {
            if (dotContent[newKey + '.0']) { // check if array
              let i = 0
              do {
                dotConfig[key + '.' + i] = dotContent[newKey + '.' + i]
                i += 1
              } while (dotContent[newKey + '.' + i])
            } else {
              const newErr = new Error(`configuration failed - external JSON file "${filePath}" does not contain key: "${newKey}"`)
              newErr.name = 'processExtConfig'
              throw newErr
            }
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
  processTexts.clear()
  processFiles.clear()
  return dot.object(dotConfig)
}

// SCIM/CustomScim <=> endpoint attribute parsing used by plugins
// returns [object/string, err]
// TO-DO: rewrite and simplify...
ScimGateway.prototype.endpointMapper = function endpointMapper (direction, parseObj, mapObj) {
  const dotMap = dot.dot(mapObj)
  let str = ''
  let isObj = false
  let noneCore = false
  const arrUnsupported = []
  const inboundArrCheck = []
  const complexArr = []
  const complexObj = {
    addresses: {},
    emails: {},
    phoneNumbers: {},
    entitlements: {},
    ims: {},
    photos: {}
    // roles: {} using array
  }
  let dotParse = null
  const dotNewObj = {}

  if (parseObj.constructor === String || parseObj.constructor === Array) str = parseObj // parseObj is attributes list e.g. 'userName,id' or ['userName', 'id']
  else {
    isObj = true
    if (parseObj['@odata.context']) delete parseObj['@odata.context'] // AAD cleanup
    if (parseObj.controls) delete parseObj.controls // Active Directory cleanup
    dotParse = dot.dot(parseObj) // {"name": {"givenName": "myName"}} => {"name.givenName": "myName"}

    // deletion of complex entry => set to blank
    const arrDelete = []
    for (const key in dotParse) {
      if (key.endsWith('.operation')) {
        const arr = key.split('.') // addresses.work.operation
        if (arr.length > 2 && complexObj[arr[0]] && dotParse[key] === 'delete') {
          arrDelete.push(`${arr[0]}.${arr[1]}.`) // addresses.work.
          delete dotParse[key]
        }
      }
    }
    for (let i = 0; i < arrDelete.length; i++) {
      for (const key in dotParse) {
        if (key.startsWith(arrDelete[i])) dotParse[key] = '' // Active Directory: if country included, no logic on country codes cleanup - c (shortname) and countryCode
      }
    }
  }

  switch (direction) {
    case 'outbound':
      if (isObj) { // body (patch/put)
        for (let key in dotParse) {
          let found = false
          let arrIndex = null
          const arr = key.split('.') // multivalue/array - servicePlan.0.value
          const keyOrg = key
          if (arr.length > 1 && arr[arr.length - 1] === 'value') {
            const secondLast = arr.length - 2
            if (!isNaN(arr[secondLast])) { // servicePlan.0.value => servicePlan.0
              for (let i = 0; i < (secondLast); i++) {
                if (i === 0) key = arr[i]
                else key += `.${arr[i]}`
              }
              arrIndex = arr[secondLast]
            } else if (arr[secondLast].slice(-1) === ']') { // groups[0].value => groups.value
              const prefix = arr.slice(0, -1).join('.')
              const startPos = prefix.indexOf('[')
              if (startPos > 0) {
                key = prefix.substring(0, startPos) + '.value' // groups.value
                arrIndex = prefix.substring(startPos + 1, prefix.length - 1) // 1
              }
            }
          }
          for (const key2 in dotMap) {
            if (!key2.endsWith('.mapTo')) continue
            if (dotMap[key2].split(',').map(item => item.trim().toLowerCase()).includes(key.toLowerCase())) {
              found = true
              const keyRoot = key2.split('.').slice(0, -1).join('.') // xx.yy.mapTo => xx.yy
              if (dotMap[`${keyRoot}.type`] === 'array' && arrIndex && arrIndex >= 0) {
                dotNewObj[`${keyRoot}.${arrIndex}`] = dotParse[keyOrg] // servicePlan.0.value => servicePlan.0 and groups[0].value => memberOf.0
              }
              dotNewObj[keyRoot] = dotParse[key] // {"accountEnabled": {"mapTo": "active"} => str.replace("accountEnabled", "active")
              break
            }
          }
          if (!found) arrUnsupported.push(key)
        }
      } else { // string (get)
        const resArr = []
        let strArr = []
        if (Array.isArray(str)) {
          for (let i = 0; i < str.length; i++) {
            strArr = strArr.concat(str[i].split(',').map(item => item.trim())) // supports "id,userName" e.g. {"mapTo": "id,userName"}
          }
        } else strArr = str.split(',').map(item => item.trim())
        for (let i = 0; i < strArr.length; i++) {
          const attr = strArr[i]
          let found = false
          for (const key in dotMap) {
            if (!key.endsWith('.mapTo')) continue
            const keyNotDot = key.substring(0, key.indexOf('.mapTo'))
            if (dotMap[key].split(',').map(item => item.trim()).includes(attr)) { // supports { "mapTo": "userName,id" }
              found = true
              if (!resArr.includes(keyNotDot)) resArr.push(keyNotDot)
              break
            } else if (attr === 'roles' && dotMap[key] === 'roles.value') { // allow get using attribute roles - convert to correct roles.value
              found = true
              resArr.push(keyNotDot)
              break
            } else {
              if (dotMap[key].startsWith(attr + '.')) { // e.g. emails - complex definition
                if (complexObj[attr]) {
                  found = true
                  resArr.push(keyNotDot)
                // don't break - check for multiple complex definitions
                }
              }
            }
          }
          if (!found) {
            arrUnsupported.push(attr) // comment out? - let caller decide if not to handle unsupported on GET requests (string)
          }
        }
        if (Array.isArray(str)) str = resArr
        else str = resArr.toString()
      }
      break

    case 'inbound':
      for (let key in dotParse) {
        if (Array.isArray(dotParse[key]) && dotParse[key].length < 1) continue // avoid including 'value' in empty array if mapTo xx.value
        if (key.startsWith('lastLogon') && !isNaN(dotParse[key])) { // Active Directory date convert e.g. 132340394347050132 => "2020-05-15 20:03:54"
          const ll = new Date(parseInt(dotParse[key], 10) / 10000 - 11644473600000)
          dotParse[key] = ll.getFullYear() + '-' +
            ('00' + (ll.getMonth() + 1)).slice(-2) + '-' +
            ('00' + ll.getDate()).slice(-2) + ' ' +
            ('00' + (ll.getHours())).slice(-2) + ':' +
            ('00' + ll.getMinutes()).slice(-2) + ':' +
            ('00' + ll.getSeconds()).slice(-2)
        }

        // first element array gives xxx[0] instead of xxx.0
        let keyArr = key.split('.')
        if (keyArr[0].slice(-1) === ']') { // last character=]
          let newStr = keyArr[0]
          newStr = newStr.replace('[', '.')
          newStr = newStr.replace(']', '') // member[0] => member.0
          dotParse[newStr] = dotParse[key]
          key = newStr // will be handled below
        }

        let dotArrIndex = null
        keyArr = key.split('.')
        if (keyArr.length > 1 && !isNaN(keyArr[1])) { // array
          key = keyArr[0] // "proxyAddresses.0" => "proxyAddresses"
          dotArrIndex = keyArr[1]
        }

        let mapTo = dotMap[`${key}.mapTo`]
        if (!mapTo) continue
        if (mapTo.startsWith('urn:')) { // dot workaround for none core (e.g. enterprise and custom schema attributes) having dot in key e.g "2.0": urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.department
          mapTo = mapTo.replace('.', '##') // only first occurence
          noneCore = true
        }

        if (dotMap[`${key}.type`] === 'array') {
          let newStr = mapTo
          if (newStr === 'roles') { // {"mapTo": "roles"} should be {"mapTo": "roles.value"}
            arrUnsupported.push('roles.value')
          }
          let multiValue = true
          if (newStr.indexOf('.value') > 0) newStr = newStr.substring(0, newStr.indexOf('.value')) // multivalue back to ScimGateway - remove .value if defined
          else multiValue = false
          if (dotArrIndex !== null) { // array e.g proxyAddresses.value mapTo proxyAddresses converts proxyAddresses.0 => proxyAddresses.0.value
            if (multiValue) dotNewObj[`${newStr}.${dotArrIndex}.value`] = dotParse[`${key}.${dotArrIndex}`]
            else {
              if (dotMap[`${key}.typeInbound`] && dotMap[`${key}.typeInbound`] === 'string') {
                if (!dotNewObj[newStr]) dotNewObj[newStr] = dotParse[`${key}.${dotArrIndex}`]
                else dotNewObj[newStr] = `${dotParse[`${key}.${dotArrIndex}`]},${dotNewObj[newStr]}`
              } else dotNewObj[`${newStr}.${dotArrIndex}`] = dotParse[`${key}.${dotArrIndex}`]
            }
          } else { // type=array but element is not array
            if (multiValue) dotNewObj[`${newStr}.0.value`] = dotParse[key]
            else dotNewObj[newStr] = dotParse[key]
            if (!dotMap[`${key}.typeInbound`] || dotMap[`${key}.typeInbound`] !== 'string') {
              if (!inboundArrCheck.includes(newStr)) inboundArrCheck.push(newStr) // will be checked
            }
          }
        } else { // none array
          const arrMapTo = mapTo.split(',').map(item => item.trim()) // supports {"mapTo": "id,userName"}
          for (let i = 0; i < arrMapTo.length; i++) {
            dotNewObj[arrMapTo[i]] = dotParse[key] // {"active": {"mapTo": "accountEnabled"} => str.replace("accountEnabled", "active")
          }
        }
        const arr = mapTo.split('.') // addresses.work.postalCode
        if (arr.length > 2 && complexObj[arr[0]]) complexArr.push(arr[0]) // addresses
      }
      break

    default:
      this.logger.error('Plugin using endpointMapper(direction, parseObj, mapObj) with incorrect direction - direction must be set to \'outbound\' or \'inbound\'')
      str = parseObj
  }

  // error handling (only outbound, not inbound)
  let err = null
  const arrErr = []
  for (let i = 0; i < arrUnsupported.length; i++) {
    const arr = arrUnsupported[i].split('.')
    if (arr.length > 2 && complexObj[arr[0]]) continue // no error on complex
    else if (arr.length === 2 && arr[0].startsWith('roles')) {
      if (arr[1] === 'operation') err = new Error('endpointMapper: roles cannot include operation - telling to be deleted - roles needs proper preprocessing when used by endpointMapper')
      else if (arr[1] !== 'value') continue // no error on roles.display, roles.primary
    }
    arrErr.push(arrUnsupported[i])
  }
  if (!err && arrErr.length > 0) {
    err = new Error(`endpointMapper: skipping - no mapping found for attributes: ${arrErr.toString()}`)
  }

  if (isObj) {
    let newObj = dot.object(dotNewObj) // from dot to normal

    if (noneCore) { // revert back dot workaround
      const tmpObj = {}
      for (const key in newObj) {
        if (key.startsWith('urn:') && key.includes('##')) {
          const newKey = key.replace('##', '.')
          tmpObj[newKey] = newObj[key]
        } else tmpObj[key] = newObj[key]
      }
      newObj = tmpObj
    }

    if (arrUnsupported.length > 0) { // delete from newObj when not included in map
      for (const i in arrUnsupported) {
        const arr = arrUnsupported[i].split('.') // emails.work.type
        dot.delete(arrUnsupported[i], newObj) // delete leaf
        for (let i = arr.length - 2; i > -1; i--) { // delete above if not empty
          let oStr = arr[0]
          for (let j = 1; j <= i; j++) {
            oStr += `.${arr[j]}`
          }
          const sub = dot.pick(oStr, newObj)
          if (!sub || JSON.stringify(sub) === '{}') {
            dot.delete(oStr, newObj)
          }
        }
      }
    }

    const recursiveStrMap = function (obj, dotPath) { // converts inbound/outbound regarding endpointMap type of attribute
      for (const key in obj) {
        if (obj[key] && obj[key].constructor === Object) recursiveStrMap(obj[key], (dotPath ? `${dotPath}.${key}` : key))
        let dotKey = ''
        if (!dotPath) dotKey = key
        else dotKey = `${dotPath}.${key}`
        if (direction === 'outbound') { // outbound
          if (dotMap[`${dotKey}.type`]) {
            const type = dotMap[`${dotKey}.type`].toLowerCase()
            if (type === 'boolean' && obj[key].constructor === String) {
              if ((obj[key]).toLowerCase() === 'true') obj[key] = true
              else if ((obj[key]).toLowerCase() === 'false') obj[key] = false
            } else if (type === 'array') {
              if (!Array.isArray(obj[key])) {
                if (!obj[key]) obj[key] = []
                else obj[key] = obj[key].split(',').map(item => item.trim())
              }
            } else if (dotMap.sAMAccountName) { // Active Directory
              if (dotMap[`${dotKey}.mapTo`].startsWith('addresses.') && dotMap[`${dotKey}.mapTo`].endsWith('.country')) {
                const arr = countries.codes.filter(el => obj[key] && el.name === obj[key].toUpperCase())
                if (arr.length === 1) { // country name found in countries, include corresponding c (shortname) and countryCode
                  obj.c = arr[0]['alpha-2']
                  obj.countryCode = arr[0]['country-code']
                }
              }
            }
          }
        } else { // inbound - convert all values to string unless array or boolean
          if (obj[key] === null) delete obj[key] // or set to ''
          else if (obj[key] || obj[key] === false) {
            if (key === 'id') {
              obj[key] = encodeURIComponent(obj[key]) // escaping in case idp don't e.g. Symantec/Broadcom/CA
            }
            if (Array.isArray(obj[key])) { // array
              if (key === 'members' || key === 'groups') {
                for (const el in obj[key]) {
                  if (obj[key][el].value) {
                    obj[key][el].value = encodeURIComponent(obj[key][el].value) // escaping values because id have also been escaped
                  }
                }
              }
            } else if (obj[key].constructor !== Object) {
              if (obj[key].constructor !== Boolean) obj[key] = obj[key].toString() // might have integer that also should be SCIM integer?
            }
          }
        }
      }
    }

    recursiveStrMap(newObj, null)

    if (direction === 'inbound' && newObj.constructor === Object) { // convert any multivalue object syntax to array
      //
      // map config e.g.:
      // "postalCode": {
      //  "mapTo": "addresses.work.postalCode",
      //  "type": "string"
      // }
      //
      if (complexArr.length > 0) {
        const tmpObj = {}
        for (let i = 0; i < complexArr.length; i++) { // e.g. ['emails', 'addresses', 'phoneNumbers', 'ims', 'photos']
          const el = complexArr[i]
          if (newObj[el]) { // { work: { postalCode: '1733' }, work: { streetAddress: 'Roteveien 10' } }
            const tmp = {}
            for (const key in newObj[el]) {
              if (newObj[el][key].constructor === Object) { // { postalCode: '1733' }
                if (!tmp[key]) tmp[key] = [{ type: key }]
                const o = tmp[key][0]
                for (const k in newObj[el][key]) { // merge into one object
                  o[k] = newObj[el][key][k]
                }
                tmp[key][0] = o // { addresses: [ { type: 'work', postalCode: '1733', streetAddress: 'Roteveien 10'} ] } - !isNaN because of push
              }
            }
            delete newObj[el]
            tmpObj[el] = []
            for (const key in tmp) {
              tmpObj[el].push(tmp[key][0])
            }
          }
        }
        utils.extendObj(newObj, tmpObj)
      }

      // make sure inboundArrCheck elements are array
      // e.g. AD group "member" could be string if one, and array if more than one
      for (const i in inboundArrCheck) {
        const el = inboundArrCheck[i]
        if (newObj[el] && !Array.isArray(newObj[el])) {
          newObj[el] = [newObj[el]]
        }
      }
    }

    return [newObj, err]
  } else return [str, err]
}

module.exports = ScimGateway // plugins can now use ScimGateway

const addResources = (data, startIndex, sortBy, sortOrder) => {
  if (!data || JSON.stringify(data) === '{}') data = [] // no user/group found
  const res = { Resources: [] }
  if (Array.isArray(data)) res.Resources = data
  else if (data.Resources) {
    res.Resources = data.Resources
    res.totalResults = data.totalResults
  } else res.Resources.push(data)

  // pagination
  if (!res.totalResults) res.totalResults = res.Resources.length // Specifies the total number of results matching the Consumer query
  res.itemsPerPage = res.Resources.length // Specifies the number of search results returned in a query response page
  res.startIndex = parseInt(startIndex) // The 1-based index of the first result in the current set of search results
  if (!res.startIndex) res.startIndex = 1
  if (res.startIndex > res.totalResults) { // invalid paging request
    res.Resources = []
    res.itemsPerPage = 0
  }

  if (sortBy) res.Resources.sort(utils.sortByKey(sortBy, sortOrder))
  return res
}

const addSchemas = (data, type, isScimv2, location) => {
  if (!type) {
    if (isScimv2) data.schemas = ['urn:ietf:params:scim:api:messages:2.0:ListResponse']
    else data.schemas = ['urn:scim:schemas:core:1.0']
    return data
  }

  if (data.Resources) {
    if (isScimv2) data.schemas = ['urn:ietf:params:scim:api:messages:2.0:ListResponse']
    else data.schemas = ['urn:scim:schemas:core:1.0']
    for (let i = 0; i < data.Resources.length; i++) {
      if (isScimv2) { // scim v2 add schemas/resourceType on each element
        if (type === 'User') {
          const val = 'urn:ietf:params:scim:schemas:core:2.0:User'
          if (!data.Resources[i].schemas) data.Resources[i].schemas = [val]
          else if (!data.Resources[i].schemas.includes(val)) data.Resources[i].schemas.push(val)
          if (!data.Resources[i].meta) data.Resources[i].meta = {}
          data.Resources[i].meta.resourceType = type
          if (location && data.Resources[i].id) data.Resources[i].meta.location = `${location}/${data.Resources[i].id}`
        } else if (type === 'Group') {
          const val = 'urn:ietf:params:scim:schemas:core:2.0:Group'
          if (!data.Resources[i].schemas) data.Resources[i].schemas = [val]
          else if (!data.Resources[i].schemas.includes(val)) data.Resources[i].schemas.push(val)
          if (!data.Resources[i].meta) data.Resources[i].meta = {}
          data.Resources[i].meta.resourceType = 'Group'
        }
      }
      if (location && data.Resources[i].id) {
        if (!data.Resources[i].meta) data.Resources[i].meta = {}
        data.Resources[i].meta.location = `${location}/${data.Resources[i].id}`
      }
      for (const key in data.Resources[i]) {
        if (key.startsWith('urn:')) {
          if (key.includes(':1.0')) {
            if (!data.schemas) data.schemas = []
            if (!data.schemas.includes(key)) data.schemas.push(key)
          } else { // scim v2 add none core schemas on each element
            if (!data.Resources[i].schemas) data.Resources[i].schemas = []
            if (!data.Resources[i].schemas.includes(key)) data.Resources[i].schemas.push(key)
          }
        } else if (key === 'password') delete data.Resources[i].password // exclude password, null and empty object/array
        else if (data.Resources[i][key] === null) delete data.Resources[i][key]
        else if (JSON.stringify(data.Resources[i][key]) === '{}') delete data.Resources[i][key]
        else if (Array.isArray(data.Resources[i][key]) && data.Resources[i][key].length < 1) delete data.Resources[i][key]
      }
      if (Object.keys(data.Resources[i]).length === 0) {
        data.Resources.splice(i, 1) // delete
        i -= 1
      }
    }
  } else {
    if (isScimv2) {
      if (type === 'User') {
        const val = 'urn:ietf:params:scim:schemas:core:2.0:User'
        if (!data.schemas) data.schemas = [val]
        else if (!data.schemas.includes(val)) data.schemas.push(val)
        if (!data.meta) data.meta = {}
        data.meta.resourceType = type
      } else if (type === 'Group') {
        const val = 'urn:ietf:params:scim:schemas:core:2.0:Group'
        if (!data.schemas) data.schemas = [val]
        else if (!data.schemas.includes(val)) data.schemas.push(val)
        if (!data.meta) data.meta = {}
        data.meta.resourceType = type
      }
    } else {
      const val = 'urn:scim:schemas:core:1.0'
      if (!data.schemas) data.schemas = [val]
      else if (!data.schemas.includes(val)) data.schemas.push(val)
    }
    for (const key in data) {
      if (key.startsWith('urn:')) { // add none core schema e.g. urn:ietf:params:scim:schemas:extension:enterprise:2.0:User
        if (!data.schemas) data.schemas = [key]
        else if (!data.schemas.includes(key)) data.schemas.push(key)
      } else if (key === 'password') delete data.password // exclude password, null and empty object/array
      else if (data[key] === null) delete data[key]
      else if (JSON.stringify(data[key]) === '{}') delete data[key]
      else if (Array.isArray(data[key]) && data[key].length < 1) delete data[key]
    }
  }

  return data
}

// addPrimaryAttrs cheks for primary attributes (only for roles) and add them as standalone attributes
// some IdP's may check for these e.g. Azure
// e.g. {roles: [{value: "val1", primary: "True"}]}
// gives:
// { roles: [{value: "val1", primary: "True"}],
//   roles[primary eq "True"].value: "val1",
//   roles[primary eq "True"].primary: "True"}]
// }
const addPrimaryAttrs = (obj) => {
  const key = 'roles'
  if (!obj || typeof obj !== 'object') return obj
  if (!obj[key] || !Array.isArray(obj[key])) return obj
  const o = utils.copyObj(obj)
  const index = o[key].findIndex(el => (el.primary === true || (typeof el.primary === 'string' && el.primary.toLowerCase() === 'true')))
  if (index >= 0) {
    const prim = o[key][index]
    for (const k in prim) {
      const primKey = `${key}[primary eq ${typeof prim.primary === 'string' ? `"${prim.primary}"` : prim.primary}].${k}` // roles[primary eq true].value / roles[primary eq "True"].value``
      o[primKey] = prim[k] // { roles[primary eq true].value : "some-value" }
    }
  }
  return o
}

//
// legacy, check and return none supported attributes
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
// convertedScim20 convert SCIM 2.0 patch request to SCIM 1.1 and calls convertedScim() for "type converted Object" and blank deleted values
//
// Scim 2.0:
// {"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"name.givenName","value":"Rocky"},{"op":"Remove","path":"name.formatted","value":"Rocky Balboa"},{"op":"Add","path":"emails","value":[{"value":"user@compay.com","type":"work"}]}]}
//
// Scim 1.1
// {"name":{"givenName":"Rocky","formatted":"Rocky Balboa"},"meta":{"attributes":["name.formatted"]},"emails":[{"value":"user@compay.com","type":"work"}]}
//
// "type converted object" and blank deleted values
// {"name":{"givenName":"Rocky",formatted:""},"emails":{"work":{"value":"user@company.com","type":"work"}}}
//
ScimGateway.prototype.convertedScim20 = function convertedScim20 (obj) {
  let scimdata = {}
  if (!obj.Operations || !Array.isArray(obj.Operations)) return scimdata
  const o = utils.copyObj(obj)
  const arrPrimaryDone = []
  const primaryOrgType = {}

  for (let i = 0; i < o.Operations.length; i++) {
    const element = o.Operations[i]
    let type = null
    let typeElement = null
    let path = null
    let pathRoot = null
    let rePattern = /^.*\[(.*) eq (.*)\].*$/
    let arrMatches = null
    let primaryValue = null

    if (element.op) element.op = element.op.toLowerCase()

    if (element.path) {
      arrMatches = element.path.match(rePattern)

      if (Array.isArray(arrMatches) && arrMatches.length === 3) { // [type eq "work"]
        if (arrMatches[1] === 'primary') {
          type = 'primary'
          primaryValue = arrMatches[2].replace(/"/g, '') // True
        } else type = arrMatches[2].replace(/"/g, '') // work
      }

      rePattern = /^(.*)\[(type|primary) eq .*\]\.(.*)$/ // "path":"addresses[type eq \"work\"].streetAddress" - "path":"roles[primary eq \"True\"].streetAddress"
      arrMatches = element.path.match(rePattern)
      if (Array.isArray(arrMatches)) {
        if (arrMatches.length === 2) {
          if (type) path = `${arrMatches[1]}.${type}`
          else path = arrMatches[1]
          pathRoot = arrMatches[1]
        } else if (arrMatches.length === 4) {
          if (type) {
            path = `${arrMatches[1]}.${type}.${arrMatches[3]}`
            typeElement = arrMatches[3] // streetAddress

            if (type === 'primary' && !arrPrimaryDone.includes(arrMatches[1])) { // make sure primary is included
              const pObj = utils.copyObj(element)
              pObj.path = pObj.path.substring(0, pObj.path.lastIndexOf('.')) + '.primary'
              pObj.value = primaryValue
              o.Operations.push(pObj)
              arrPrimaryDone.push(arrMatches[1])
              primaryOrgType[arrMatches[1]] = 'primary'
            }
          } else path = `${arrMatches[1]}.${arrMatches[3]}` // NA
          pathRoot = arrMatches[1]
        }
      } else {
        rePattern = /^(.*)\[type eq .*\]$/ // "path":"addresses[type eq \"work\"]"
        arrMatches = element.path.match(rePattern)
        if (Array.isArray(arrMatches) && arrMatches.length === 2) {
          if (type) path = `${arrMatches[1]}.${type}`
          else path = arrMatches[1]
          pathRoot = arrMatches[1]
        }
      }

      rePattern = /^(.*)\[value eq (.*)\]$/ // "path":"members[value eq \"bjensen\"]"
      arrMatches = element.path.match(rePattern)
      if (Array.isArray(arrMatches) && arrMatches.length === 3) {
        // eslint-disable-next-line no-unused-vars
        path = arrMatches[1]
        pathRoot = arrMatches[1]
        const val = arrMatches[2].replace(/"/g, '') // "bjensen" => bjensen
        element.value = val
        typeElement = 'value'
      }

      if (element.value && Array.isArray(element.value)) {
        element.value.forEach(function (el, i) { // {"value": [{ "value": "jsmith" }]}
          if (el.value) {
            if (typeof el.value === 'object') { // "value": [{"value": {"id":"c20e145e-5459-4a6c-a074-b942bbd4cfe1","value":"admin","displayName":"Administrator"}}]
              element.value[i] = el.value
            } else if (typeof el.value === 'string' && el.value.substring(0, 1) === '{') { // "value": [{"value":"{\"id\":\"c20e145e-5459-4a6c-a074-b942bbd4cfe1\",\"value\":\"admin\",\"displayName\":\"Administrator\"}"}}]
              try {
                element.value[i] = JSON.parse(el.value)
              } catch (err) {}
            }
          }
        })
      }

      if (element.value && element.value.value && typeof element.value.value === 'string') { // "value": { "value": "new_email@testing.org" }
        const el = {}
        el.value = element.value.value
        if (element.op && element.op === 'remove') el.operation = 'delete'
        element.value = []
        element.value.push(el)
      }

      if (pathRoot) { // pathRoot = emails and path = emails.work.value (we may also have path = pathRoot)
        if (!scimdata[pathRoot]) scimdata[pathRoot] = []
        const index = scimdata[pathRoot].findIndex(el => el.type === type)
        if (index < 0) {
          if (typeof element.value === 'object') { // e.g. addresses with no typeElement - value includes object having all attributes
            if (element.op && element.op === 'remove') element.value.operation = 'delete'
            scimdata[pathRoot].push(element.value)
          } else {
            const el = {}
            if (element.op && element.op === 'remove') el.operation = 'delete'
            if (type) el.type = type // members no type
            if (element.value) el[typeElement] = element.value // {"value": "some-value"} or {"steetAddress": "some-address"}
            scimdata[pathRoot].push(el)
          }
        } else {
          if (typeElement === 'value' && scimdata[pathRoot][index].value) { // type exist for value index => duplicate type => push new - duplicates handled by last step confertedScim() if needed
            const el = {}
            if (element.op && element.op === 'remove') el.operation = 'delete'
            if (type) el.type = type
            el[typeElement] = element.value
            scimdata[pathRoot].push(el)
          } else {
            if (type === 'primary' && typeElement === 'type') { // type=primary, don't change but store and correct to original type later
              primaryOrgType[pathRoot] = element.value
            } else scimdata[pathRoot][index][typeElement] = element.value
            if (element.op && element.op === 'remove') scimdata[pathRoot][index].operation = 'delete'
          }
        }
      } else { // use element.path e.g name.familyName and members
        if (Array.isArray(element.value)) {
          if (element.op === 'replace' && element.value.length === 0) { // members:[]
            scimdata[element.path] = []
          }
          for (let i = 0; i < element.value.length; i++) {
            if (!scimdata[element.path]) scimdata[element.path] = []
            if (element.op && element.op === 'remove') {
              if (typeof element.value[i] === 'object') element.value[i].operation = 'delete'
            }
            scimdata[element.path].push(element.value[i])
          }
        } else { // add to operations loop without path => handled by "no path"
          const obj = {}
          obj.op = element.op
          obj.value = {}
          obj.value[element.path] = element.value
          o.Operations.push(obj)
        }
      }
    } else { // no path
      for (const key in element.value) {
        if (Array.isArray(element.value[key])) {
          if (element.op === 'replace' && element.value[key].length === 0) { // members:[]
            scimdata[key] = []
          }
          element.value[key].forEach(function (el, i) {
            if (element.op && element.op === 'remove') el.operation = 'delete'
            if (!scimdata[key]) scimdata[key] = []
            scimdata[key].push(el)
          })
        } else {
          let value = element.value[key]
          if (element.op && element.op === 'remove') {
            if (!scimdata.meta) scimdata.meta = {}
            if (!scimdata.meta.attributes) scimdata.meta.attributes = []
            scimdata.meta.attributes.push(key)
          }
          if (key.startsWith('urn:')) { // can't use dot.str on key having dot e.g. urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department
            const i = key.lastIndexOf(':')
            let k = key.substring(i + 1) // User, Group or <parentAttribute>.<childAttribute> - <URN>:<parentAttribute>.<childAttribute> e.g. :User:manager.value
            let rootKey
            if (k === 'User' || k === 'Group') rootKey = key
            else rootKey = key.substring(0, i) // urn:ietf:params:scim:schemas:extension:enterprise:2.0:User
            if (k === 'User' || k === 'Group') { // value is object
              const o = {}
              o[rootKey] = value
              scimdata = utils.extendObj(scimdata, o)
            } else {
              if (!scimdata[rootKey]) scimdata[rootKey] = {}
              if (k === 'manager' && typeof value !== 'object') { // fix Azure bug sending manager instead of manager.value
                k = 'manager.value'
              }
              if (!element.op || element.op !== 'remove') { // remove handled by general logic above
                dot.str(k, value, scimdata[rootKey])
              }
            }
          } else {
            if (typeof value === 'object') {
              for (const k in element.value[key]) {
                if (element.op && element.op === 'remove') {
                  if (!scimdata.meta) scimdata.meta = {}
                  if (!scimdata.meta.attributes) scimdata.meta.attributes = []
                  scimdata.meta.attributes.push(`${key}.${k}`)
                } else {
                  value = element.value[key][k]
                  dot.str(`${key}.${k}`, value, scimdata)
                }
              }
            } else dot.str(key, value, scimdata)
          }
        }
      }
    }
  }

  for (const key in primaryOrgType) { // revert back to original type when included
    if (scimdata[key]) {
      const index = scimdata[key].findIndex(el => el.type === 'primary')
      if (index >= 0) {
        if (primaryOrgType[key] === 'primary') delete scimdata[key][index].type // temp have not been changed - remove
        else scimdata[key][index].type = primaryOrgType[key]
      }
    }
  }

  // scimdata now SCIM 1.1 formatted, using convertedScim to get "type converted Object" and blank deleted values
  return ScimGateway.prototype.convertedScim(scimdata)
}

//
// SCIM error formatting
//
const jsonErr = (scimVersion, pluginName, htmlErrCode, err) => {
  let errJson = {}
  let customErrCode = null
  let scimType = 'invalidSyntax'
  let msg = `scimgateway[${pluginName}] `
  if (err.constructor === Error) {
    if (err.name) { // customErrCode can be set by including suffix "#<number>" e.g., "<scimType>#404"
      const arr = err.name.split('#')
      if (arr.length > 1 && !isNaN(arr[arr.length - 1])) {
        customErrCode = arr[arr.length - 1]
        const code = parseInt(customErrCode)
        if (code < 300 && code > 199) customErrCode = null
        arr.splice(-1)
        err.name = arr.join('#') // back to original having customErrCode removed
      } else if (err.name === 'uniqueness') customErrCode = '409' // legacy support
      scimType = err.name
      if (scimType === 'Error') scimType = 'invalidSyntax' // default err.name used
      if (customErrCode === 409) scimType = 'uniqueness'
    }
    msg += err.message
  } else {
    msg += err
  }

  if (scimVersion !== '2.0' && scimVersion !== 2) { // v1.1
    errJson =
    {
      Errors: [
        {
          description: msg,
          code: customErrCode || htmlErrCode
        }
      ]
    }
  } else { // v2.0
    errJson =
    {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      scimType,
      detail: msg,
      status: customErrCode || htmlErrCode
    }
  }

  if (customErrCode) customErrCode = parseInt(customErrCode)
  return [errJson, customErrCode]
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
