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

  if (config.scimversion == 2.0) scimDef = require('../lib/scimdef-v2')
  else scimDef = require('../lib/scimdef-v1')
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
        results.forEach(function (element) {
          if (element === true) isAuthenticated = true
        })
        if (!err && !isAuthenticated) {
          if (!req.token) err = new Error(`request without authentication information`)
          else {
            err = new Error(`request with unsupported authorization bearer or missing plugin configuration`)
            logger.debug(`${gwName} request bearer token = ${req.token}`)
            logger.debug(`${gwName} request bearer token jwt payload = ${JSON.stringify(jwt.decode(req.token))}`)
          }
        }
        if (!isAuthenticated) {
          res.setHeader('WWW-Authenticate', 'Basic realm=""')
          res.status(401).end('Access denied')
          if (err) logger.error(`${gwName} ${err.message}`)
          else logger.error(`${gwName} request not authorized`)
        } else {
          res.setHeader('Content-Type', 'application/json; charset=utf-8')
          return next()
        }
      }
      ) // async
  })

  // Initial connection, step #1: GET /ServiceProviderConfigs
  // If not included => Provisioning will always use GET /Users without any paramenters
  app.get('(|/:baseEntity)(|/scim)/ServiceProviderConfigs', function (req, res) {
    let tx = scimDef.ServiceProviderConfigs // obfuscator friendly
    res.send(tx)
    logger.debug(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(tx)}`)
  })

  // Initial connection, step #2: GET /Schemas
  app.get('(|/:baseEntity)(|/scim)/Schemas', function (req, res) {
    let tx = scimDef.Schemas
    res.send(tx)
    logger.debug(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(tx)}`)
  })

  app.get('(|/:baseEntity)(|/scim)/Schemas/Users', function (req, res) {
    let tx = scimDef.Schemas.Resources[0]
    res.send(tx)
    logger.debug(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(tx)}`)
  })

  app.get('(|/:baseEntity)(|/scim)/Schemas/Groups', function (req, res) {
    let tx = scimDef.Schemas.Resources[1]
    res.send(tx)
    logger.debug(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(tx)}`)
  })

  app.get('(|/:baseEntity)(|/scim)/Users/:id', (req, res) => {
    let id = require('path').basename(req.params.id, '.json') // supports <id>.json
    logger.debug(`${gwName} [Get User] id=${id}`)
    logger.debug(`${gwName} emitting event "getUser" and awaiting result`)
    this.emit('getUser', req.params.baseEntity, id, null, function (err, data) {
      if (err) {
        err = jsonErr(config.scimversion, pluginName, '404', err)
        res.status(404).send(err)
        logger.error(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
      } else {
        let protocol = 'http'
        if (req.socket._tlsOptions) protocol = 'https'
        let location = `${protocol}://${req.headers.host}${req.originalUrl}`
        data.schemas = scimDef.Response.user.schemas
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

  app.get('(|/:baseEntity)(|/scim)/Users', (req, res) => {
    if (req.query.attributes === 'userName' && !req.query.filter) {
      // ==========================================
      //             EXPLORE USERS
      // ==========================================
      //
      // GET /Users?attributes=userName&startIndex=1&count=100
      //
      logger.debug(`${gwName} [Explore Users]`)
      let scimdata = new scimDef.ScimResource()
      logger.debug(`${gwName} emitting event "exploreUsers" and awaiting result`)
      this.emit('exploreUsers', req.params.baseEntity, parseInt(req.query.startIndex), parseInt(req.query.count), function (err, data) {
        if (err) {
          err = jsonErr(config.scimversion, pluginName, '500', err)
          res.status(500).send(err)
          logger.error(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
        } else {
          if (data) scimdata = data
          scimdata = addPagination(scimdata, req.query.startIndex)
          res.send(scimdata)
          logger.debug(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(scimdata)}`)
        }
      })
    } else if (req.query.filter) {
      // ==========================================
      //             GET USER
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
      //   ---- Azure AD SCIM ----
      // Azure AD:
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
      //  ---- retreive all users for a spesific group ----
      //
      // "user member of group" => CA IM default scim endpoint config - Group having multivalue attribute members containing userName
      // GET = /Users?filter=id eq "jsmith"&attributes=id,userName
      //
      // "group member of user" => User having multivalue attribute groups containing value=GroupName
      // GET = /Users?filter=groups.value eq "UserGroup-1"&attributes=groups.value,userName
      //
      //
      let arrFilter = req.query.filter.split(' ') // userName eq "bjensen"
      if (arrFilter.length > 2) {
        if ((arrFilter[0] === 'userName' || arrFilter[0] === 'id' || arrFilter[0] === 'externalId') && arrFilter[1] === 'eq') {
          let userName = req.query.filter.substring(req.query.filter.indexOf('"')).replace(/"/g, '') // bjensen
          logger.debug(`${gwName} [Get User] userName=${userName}`)
          let scimdata = new scimDef.ScimResource()
          logger.debug(`${gwName} emitting event "getUser" and awaiting result`)
          this.emit('getUser', req.params.baseEntity, userName, req.query.attributes, function (err, data) {
            if (err) {
              err = jsonErr(config.scimversion, pluginName, '404', err)
              res.status(404).send(err)
              logger.error(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
            } else {
              if (data) {
                let protocol = 'http'
                if (req.socket._tlsOptions) protocol = 'https'
                let location = `${protocol}://${req.headers.host}${req.originalUrl.substring(0, req.originalUrl.indexOf('?'))}/${data.userName}`
                if (!data.meta) data.meta = {}
                data.meta.location = location
                scimdata.Resources.push(data)
              }
              scimdata = addPagination(scimdata, req.query.startIndex)
              res.send(scimdata)
              logger.debug(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(scimdata)}`)
            }
          })
        } else if ((arrFilter[0] === 'groups.value') && arrFilter[1] === 'eq') {
          // retreive all users for a spesific group - "group member of user" - using groups attribute on user
          let groupName = req.query.filter.substring(req.query.filter.indexOf('"')).replace(/"/g, '')// UserGroup-1
          logger.debug(`${gwName} [Get User] group=${groupName}`)
          let scimdata = new scimDef.ScimResource()
          logger.debug(`${gwName} emitting event "getGroupUsers" and awaiting result`)
          this.emit('getGroupUsers', req.params.baseEntity, groupName, req.query.attributes, function (err, data) {
            if (err) {
              err = jsonErr(config.scimversion, pluginName, '500', err)
              res.status(500).send(err)
              logger.error(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
            } else {
              // if (data) scimdata.Resources.push(data);
              if (data) scimdata.Resources = data
              scimdata = addPagination(scimdata, req.query.startIndex)
              res.send(scimdata)
              logger.debug(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(scimdata)}`)
            }
          })
        } else {
          let err = 'GET /Users?filter="<Incorrect filter definition>" must include userName (or id) and eq'
          err = jsonErr(config.scimversion, '', '400', err)
          res.status(400).send(err)
          logger.error(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
        }
      } else {
        let err = 'GET /Users?filter="<Incorrect filter definition>'
        err = jsonErr(config.scimversion, '', '400', err)
        res.status(400).send(err)
        logger.error(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
      }
    } else {
      // GET /Users
      let err = `GET ${req.originalUrl} is not supported`
      err = jsonErr(config.scimversion, '', '400', err)
      res.status(400).send(err)
      logger.error(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
    }
  })

  app.get('(|/:baseEntity)(|/scim)/Groups/:id', (req, res) => {
    let id = require('path').basename(req.params.id, '.json') // supports <id>.json
    logger.debug(`${gwName} [Get Group] id=${id}`)
    logger.debug(`${gwName} emitting event "getGroup" and awaiting result`)
    this.emit('getGroup', req.params.baseEntity, id, null, function (err, data) {
      if (err) {
        err = jsonErr(config.scimversion, pluginName, '404', err)
        res.status(404).send(err)
        logger.error(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
      } else {
        let protocol = 'http'
        if (req.socket._tlsOptions) protocol = 'https'
        let location = `${protocol}://${req.headers.host}${req.originalUrl}`
        let i = location.indexOf('?')
        if (i > 0) location = location.substring(0, i)
        data.schemas = scimDef.Response.group.schemas
        if (data.meta) data.meta.location = location
        else {
          data.meta = {}
          data.meta.location = location
        }
        if (req.query.excludedAttributes === 'members' && data.members) delete data.members // Azure AD GET = /scim/Groups/MyGroup?excludedAttributes=members
        res.send(data)
        logger.debug(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(data)}`)
      }
    })
  })

  app.get('(|/:baseEntity)(|/scim)/Groups', (req, res) => {
    let scimdata = new scimDef.ScimResource()
    if (req.query.attributes === 'displayName' && !req.query.filter) {
      // ==========================================
      //             EXPLORE GROUPS
      // ==========================================
      //
      // Explore: GET /Groups?attributes=displayName
      //
      logger.debug(`${gwName} [Explore Groups]`)
      logger.debug(`${gwName} emitting event "exploreGroups" and awaiting result`)
      this.emit('exploreGroups', req.params.baseEntity, parseInt(req.query.startIndex), parseInt(req.query.count), function (err, data) {
        if (err) {
          err = jsonErr(config.scimversion, pluginName, '500', err)
          res.status(500).send(err)
          logger.error(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
        } else {
          if (data) scimdata = data
          scimdata = addPagination(scimdata, req.query.startIndex)
          res.send(scimdata)
          logger.debug(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(scimdata)}`)
        }
      })
    } else if (req.query.filter) {
      // ==========================================
      //         Get group
      //         Get group members
      //           => "user member of group" - CA IM default scim endpoint config
      //               Group having multivalue attribute members containing userName
      //
      // ==========================================
      //
      //   ---- Azure AD SCIM ----
      // Azure AD:
      // Default SCIM attribute for GROUP mapping have:
      //   externalId mapped to displayName (matching precedence #1)
      //   displayName mapped to mailNickname
      //
      // ScimGateway accepts externalId (as matching precedence) instead of displayName, but displayName and externalId must
      // then be mapped to the same AD attribute e.g:
      //
      //   externalId mapped to displayName (matching precedence #1)
      //   displayName mapped to displayName
      //  ------------------------
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
      let arrFilter = req.query.filter.split(' ') // members.value eq "bjensen"...
      if (arrFilter.length > 2) {
        if (arrFilter[0] === 'members.value' && arrFilter[1] === 'eq') {
          // Get user groups
          let userId = req.query.filter.substring(req.query.filter.indexOf('"')).replace(/"/g, '') // bjensen (id and not userName)
          logger.debug(`${gwName} [Get Group Members] user id=${userId}`)
          logger.debug(`${gwName} emitting event "getGroupMembers" and awaiting result`)
          this.emit('getGroupMembers', req.params.baseEntity, userId, req.query.attributes, parseInt(req.query.startIndex), parseInt(req.query.count), function (err, data) {
            if (err) {
              err = jsonErr(config.scimversion, pluginName, '500', err)
              res.status(500).send(err)
              logger.error(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
            } else {
              if (data) scimdata = data
              scimdata = addPagination(scimdata, req.query.startIndex)
              res.send(scimdata)
              logger.debug(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(scimdata)}`)
            }
          })
        } else if ((arrFilter[0] === 'displayName' || arrFilter[0] === 'externalId') && arrFilter[1] === 'eq') {
          let groupDisplayname = req.query.filter.substring(req.query.filter.indexOf('"')).replace(/"/g, '') // Employees (displayName and not id)
          logger.debug(`${gwName} [Get Group] group displayName=${groupDisplayname}`)
          logger.debug(`${gwName} emitting event "getGroup" and awaiting result`)
          this.emit('getGroup', req.params.baseEntity, groupDisplayname, req.query.attributes, function (err, data) {
            if (err) {
              err = jsonErr(config.scimversion, pluginName, '404', err)
              res.status(404).send(err)
              logger.error(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
            } else {
              if (data) scimdata.Resources.push(data)
              scimdata = addPagination(scimdata, req.query.startIndex)
              res.send(scimdata)
              logger.debug(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(scimdata)}`)
            }
          })
        } // displayName (group members)
      }
    } else {
      // GET /Groups
      let err = `GET ${req.originalUrl} is not supported`
      err = jsonErr(config.scimversion, '', '400', err)
      res.status(400).send(err)
      logger.error(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
    }
  }) // app.get

  // ==========================================
  //           CREATE USER
  // ==========================================
  //
  // POST = /Users
  // Body contains user attributes including userName (userID)
  // Body example:
  // {"active":true,"name":{"familyName":"Elshaug","givenName":"Jarle"},"schemas":["urn:scim:schemas:core:1.0"],"userName":"jael01"}
  //
  app.post('(|/:baseEntity)(|/scim)/Users(|.json)(|.xml)', (req, res) => {
    logger.debug(`${gwName} [Create User]`)
    let strBody = ''

    req.on('data', function (data) { // Get body
      strBody += data
    })

    req.on('end', () => {
      let userObj = null
      try {
        userObj = JSON.parse(strBody)
      } catch (err) { }
      if (userObj === null) {
        let err = new Error('Accepting only JSON formatted requests')
        logger.error(`${gwName} ${err.message}`)
        res.status(500).send(`${gwName}[${pluginName}] ${err.message}`)
      } else {
        logger.debug(`${gwName} POST = ${req.originalUrl} Body = ${strBody}`)
        userObj = ScimGateway.prototype.convertedScim(userObj)
        logger.debug(`${gwName} convertedBody = ${JSON.stringify(userObj)}`)
        logger.debug(`${gwName} emitting event "createUser" and awaiting result`)
        this.emit('createUser', req.params.baseEntity, userObj, function (err) {
          if (err) {
            err = jsonErr(config.scimversion, pluginName, '500', err)
            res.status(500).send(err)
            logger.error(`${gwName}[${pluginName}] POST = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
          } else {
            let scimdata = JSON.parse(strBody)
            let protocol = 'http'
            if (req.socket._tlsOptions) protocol = 'https'
            let location = `${protocol}://${req.headers.host}${req.originalUrl}/${scimdata.userName}`
            if (!scimdata.meta) scimdata.meta = {}
            scimdata.meta.location = location
            scimdata.id = scimdata.userName
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
  //          MODIFY USER
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
  app.patch('(|/:baseEntity)(|/scim)/Users/:id', (req, res) => {
    let id = req.params.id
    logger.debug(`${gwName} [Modify User] id=${id}`)
    let strBody = ''

    req.on('data', function (data) { // get body
      strBody += data
    })

    req.on('end', () => {
      logger.debug(`${gwName} PATCH = ${req.originalUrl} Body = ${strBody}`)
      let scimdata = JSON.parse(strBody)
      if (scimdata.Operations) scimdata = convertedScim20(scimdata) // SCIM 2.0
      else scimdata = ScimGateway.prototype.convertedScim(scimdata) // SCIM 1.1
      logger.debug(`${gwName} convertedBody = ${JSON.stringify(scimdata)}`)
      logger.debug(`${gwName} emitting event "modifyUser" and awaiting result`)
      this.emit('modifyUser', req.params.baseEntity, id, scimdata, function (err) {
        if (err) {
          err = jsonErr(config.scimversion, pluginName, '500', err)
          res.status(500).send(err)
          logger.error(`${gwName}[${pluginName}] PATCH = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
        } else {
          let scimdata = JSON.parse(strBody)
          let protocol = 'http'
          if (req.socket._tlsOptions) protocol = 'https'
          let location = `${protocol}://${req.headers.host}${req.originalUrl}`
          res.setHeader('Location', `${location}`)
          res.status(200).send(scimdata)
          logger.debug(`${gwName}[${pluginName}] PATCH = ${req.originalUrl} Response = 200  ${JSON.stringify(scimdata)}`)
        }
      })
    })
  }) // patch

  // ==========================================
  //           CREATE GROUP
  // ==========================================
  //
  // POST = /Groups
  // Body contains user attributes including displayName (group name)
  // Body example:
  // {"displayName":"MyGroup","externalId":"MyExternal","schemas":["urn:scim:schemas:core:1.0"]}
  //
  app.post('(|/:baseEntity)(|/scim)/Groups(|.json)(|.xml)', (req, res) => {
    logger.debug(`${gwName} [Create Group]`)
    let strBody = ''

    req.on('data', function (data) { // Get body
      strBody += data
    })

    req.on('end', () => {
      let groupObj = null
      try {
        groupObj = JSON.parse(strBody)
      } catch (err) { }
      if (groupObj === null) {
        let err = new Error('Accepting only JSON formatted requests')
        logger.error(`${gwName} ${err.message}`)
        res.status(500).send(`${gwName}[${pluginName}] ${err.message}`)
      } else {
        if (groupObj.schemas) delete groupObj['schemas']
        if (!groupObj.id && groupObj.externalId) groupObj.id = groupObj.externalId
        logger.debug(`${gwName} POST = ${req.originalUrl} Body = ${strBody}`)
        logger.debug(`${gwName} emitting event "createGroup" and awaiting result`)

        this.emit('createGroup', req.params.baseEntity, groupObj, function (err) {
          if (err) {
            err = jsonErr(config.scimversion, pluginName, '500', err)
            res.status(500).send(err)
            logger.error(`${gwName}[${pluginName}] POST = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
          } else {
            let scimdata = JSON.parse(strBody)
            let protocol = 'http'
            if (req.socket._tlsOptions) protocol = 'https'
            let location = `${protocol}://${req.headers.host}${req.originalUrl}/${scimdata.displayName}`
            if (!scimdata.meta) scimdata.meta = {}
            scimdata.meta.location = location
            scimdata.id = scimdata.displayName
            res.setHeader('Location', `${location}`)
            res.status(201).send(scimdata)
            logger.debug(`${gwName}[${pluginName}] POST = ${req.originalUrl} Response = ${JSON.stringify(scimdata)}`)
          }
        })
      }
    })
  }) // post

  // ==========================================
  //          MODIFY GROUP MEMBERS
  //
  // PATCH = /Groups/<id>
  // example: PATCH = /Groups/Employees
  //
  // Body contains user attributes to be updated
  // example: {"members":[{"value":"bjensen"}],"schemas":["urn:scim:schemas:core:1.0"]}
  // ==========================================
  app.patch('(|/:baseEntity)(|/scim)/Groups/:id', (req, res) => {
    let id = req.params.id
    logger.debug(`${gwName} [Modify Group Members] group id=${id}`)
    let strBody = ''

    req.on('data', function (data) { // Get body
      strBody += data
    })

    req.on('end', () => {
      logger.debug(`${gwName} PATCH = ${req.originalUrl} Body = ${strBody}`)
      let scimdata = JSON.parse(strBody)
      if (scimdata.Operations) {
        scimdata = convertedScim20(scimdata) // scim version 2.0 => convert to 1.1 standard
        logger.debug(`${gwName} convertedBody = ${JSON.stringify(scimdata)}`)
      }
      logger.debug(`${gwName} emitting event "modifyGroupMembers" and awaiting result`)
      this.emit('modifyGroupMembers', req.params.baseEntity, id, scimdata.members, function (err) {
        if (err) {
          err = jsonErr(config.scimversion, pluginName, '500', err)
          res.status(500).send(err)
          logger.error(`${gwName}[${pluginName}] PATCH = ${req.originalUrl} Response = ${JSON.stringify(err)}`)
        } else {
          let protocol = 'http'
          if (req.socket._tlsOptions) protocol = 'https'
          let location = `${protocol}://${req.headers.host}${req.originalUrl}`
          res.setHeader('Location', `${location}`)
          res.status(200).send(scimdata)
          logger.debug(`${gwName}[${pluginName}] PATCH = ${req.originalUrl} Response = 200  ${JSON.stringify(scimdata)}`)
        }
      })
    })
  })

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
} // scimgateway

// methods
ScimGateway.prototype.getPassword = function (pwEntity, configFile) {
  return utils.getPassword(pwEntity, configFile) // utils.getPassword('scimgateway.password', './config/plugin-testmode.json');
}

ScimGateway.prototype.timestamp = function () {
  return utils.timestamp()
}

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
    if (Array.isArray(scimdata[key]) && scimdata[key][0].type) { // exclude "none type" multivalue attributes (e.g groups and x509Certificates)
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

util.inherits(ScimGateway, EventEmitter)
module.exports = ScimGateway

function addPagination (data, startIndex) {
  // If plugin not using pagination, setting totalResults = itemsPerPage
  if (!data.totalResults) data.totalResults = data.Resources.length // Specifies the total number of results matching the Consumer query
  data.itemsPerPage = data.Resources.length                         // Specifies the number of search results returned in a query response page
  data.startIndex = parseInt(startIndex)                            // The 1-based index of the first result in the current set of search results
  if (!data.startIndex) data.startIndex = 1
  if (data.startIndex > data.totalResults) { // invalid request
    data.Resources = []
    data.itemsPerPage = 0
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
  if (scimVersion != 2.0) { // v1.1
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
