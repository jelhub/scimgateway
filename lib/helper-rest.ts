// =================================================================================
// File:    helper-rest.ts
//
// Author:  Jarle Elshaug
//
// Purpose: HelperRest class for executing REST calls supporting various auth types
//          Plugins may use this class: import { HelperRest } from 'scimgateway'
// =================================================================================

import { HttpsProxyAgent } from 'https-proxy-agent'
import { URL } from 'url'
import { Buffer } from 'node:buffer'
import { createPublicKey, createPrivateKey, createHash } from 'node:crypto'
import { samlAssertion } from './samlAssertion.ts'
import fs from 'node:fs'
import querystring from 'querystring'
import * as jose from 'jose'
import * as utils from './utils.ts'

/**
 * HelperRest includes function doRequest() for executing REST calls
 */
export class HelperRest {
  private lock = new utils.Lock()
  private _serviceClient: Record<string, any> = {}
  private config_entity: any
  private scimgateway: any
  private idleTimeout: number
  private graphUrl = 'https://graph.microsoft.com/beta' // beta instead of 'v1.0' gives all user attributes when no $select
  private googleUrl = 'https://www.googleapis.com'

  constructor(scimgateway: any, optionalEntities?: Record<string, any>) {
    if (!scimgateway || !scimgateway.gwName) throw new Error('HelperRest initialization error: argument scimgateway is not of type ScimGateway')
    this.scimgateway = scimgateway
    this.idleTimeout = (scimgateway as any)?.config?.scimgateway.idleTimeout || 120
    this.idleTimeout = this.idleTimeout - 1
    if (optionalEntities && optionalEntities.entity) this.config_entity = utils.copyObj(optionalEntities.entity) ?? {}
    else this.config_entity = utils.copyObj(scimgateway.getConfig())?.entity ?? {}

    for (const baseEntity in this.config_entity) {
      const connectionObj = this.config_entity[baseEntity]?.connection
      if (connectionObj) {
        const type = connectionObj.auth?.type
        if (type === 'oauthJwtBearer' || type === 'oauth') {
          // set default baseUrls for Entra ID and Google if not already defined
          if (connectionObj.auth?.options?.azureTenantId) { // Entra ID, setting baseUrls to graph
            if (!connectionObj.baseUrls) {
              connectionObj.baseUrls = [this.graphUrl]
            } else if (connectionObj.baseUrls?.length < 1) {
              connectionObj.baseUrls = [this.graphUrl]
            }
          } else if (connectionObj.auth?.options?.serviceAccountKeyFile) { // Google, setting baseUrls to googleapis
            if (!connectionObj.baseUrls) {
              connectionObj.baseUrls = [this.googleUrl]
            } else if (connectionObj.baseUrls?.length < 1) {
              connectionObj.baseUrls = [this.googleUrl]
            }
          }
        }
      }
    }
  }

  /**
   * getAccessToken returns oauth accesstoken object
   * @param baseEntity 
   * @param connectionObj endpoint.entity.baseEntity.connection
   * @param ctx 
   * @returns { access_token: 'xxx', token_type: 'Bearer/Basic', validTo: 'xxx' }
   */
  public async getAccessToken(baseEntity: string, connectionObj: Record<string, any>, ctx?: Record<string, any> | undefined) { // public in case token is needed for other logic e.g. sending mail
    await this.lock.acquire()
    const d = Math.floor(Date.now() / 1000) // seconds (unix time)
    if (this._serviceClient[baseEntity]?.accessToken?.validTo >= d + 30) { // avoid simultaneously token requests
      this.lock.release()
      return this._serviceClient[baseEntity].accessToken
    }

    const action = 'getAccessToken'
    if (typeof connectionObj !== 'object' || connectionObj === null) connectionObj = {}
    const serviceAccountKeyFile = connectionObj.auth?.options?.serviceAccountKeyFile
    const azureTenantId = connectionObj.auth?.options?.azureTenantId
    let tokenUrl: string
    let form: Record<string, any>
    let resource = ''

    try {
      const urlObj = new URL(connectionObj.baseUrls[0])
      resource = urlObj.origin
    } catch (err) { void 0 }
    if (azureTenantId) {
      tokenUrl = `https://login.microsoftonline.com/${azureTenantId}/oauth2/v2.0/token`
      if (resource) connectionObj.auth.options.scope = resource + '/.default' // "https://graph.microsoft.com/.default"
    } else tokenUrl = connectionObj.auth?.options?.tokenUrl

    try {
      switch (connectionObj.auth?.type) {
        case 'basic':
          if (!connectionObj.auth?.options?.username || !connectionObj.auth?.options?.password) {
            const err = new Error(`auth.type 'basic' - missing connection configuration: auth.options.username/password`)
            throw err
          }
          this.lock.release()
          return {
            access_token: Buffer.from(`${connectionObj.auth.options.username}:${connectionObj.auth.options.password}`).toString('base64'),
            token_type: 'Basic',
          }
        case 'oauth':
          if (!connectionObj.auth?.options?.clientId || !connectionObj.auth?.options?.clientSecret) {
            const err = new Error(`auth.type 'oauth' - missing connection configuration: auth.options.clientId/clientSecret`)
            throw err
          }
          form = {
            grant_type: 'client_credentials',
            client_id: connectionObj.auth.options.clientId,
            client_secret: connectionObj.auth.options.clientSecret,
          }
          if (connectionObj.auth.options.scope) form.scope = connectionObj.auth.options.scope // required using Entra ID /oauth2/v2.0/token
          if (connectionObj.auth.options.resource) resource = connectionObj.auth.options.resource // required using Entra ID /oauth2/token

          break

        case 'token':
          if (!connectionObj.auth?.options?.tokenUrl || !connectionObj.auth?.options?.password) {
            const err = new Error(`missing connection configuration: auth.options.tokenUrl/password`)
            throw err
          }
          tokenUrl = connectionObj.auth.options.tokenUrl
          form = { // example username/password in body
            username: connectionObj.auth.options.username,
            password: connectionObj.auth.options.password,
          }
          break

        case 'bearer':
          if (!connectionObj.auth?.options?.token) {
            const err = new Error(`missing connection configuration: auth.options.token`)
            throw err
          }
          this.lock.release()
          return {
            access_token: Buffer.from(connectionObj.auth.options.token).toString('base64'),
            token_type: 'Bearer',
          }

        case 'oauthSamlBearer':
          if (!connectionObj.auth?.options?.samlPayload?.clientId || !connectionObj.auth?.options?.samlPayload?.companyId
            || !connectionObj.auth?.options?.tls?.key) {
            const err = new Error(`auth.type 'oauthSamlBearer' - missing connection configuration: auth.options.tls and/or options.samlPayload.clientId/companyId`)
            throw err
          }
          tokenUrl = connectionObj.auth.options.tokenUrl
          const context = null
          const cert = fs.readFileSync(connectionObj.auth.options.tls.cert).toString()
          const key = fs.readFileSync(connectionObj.auth.options.tls.key).toString()

          const tokenEndpoint = tokenUrl
          const delay = 1

          // mandatory: clientId, companyId and nameId
          const clientId = connectionObj.auth.options.samlPayload.clientId
          const companyId = connectionObj.auth.options.samlPayload.companyId
          const nameId = connectionObj.auth.options.samlPayload.nameId
          const userIdentifierFormat = connectionObj.auth.options.samlPayload.userIdentifierFormat || 'userName'
          const lifetime = connectionObj.auth.options.samlPayload.lifetime || 3600
          const issuer = connectionObj.auth.options.samlPayload.clientId || `https://scimgateway.${this.scimgateway.pluginName}.com`
          const audience = connectionObj.auth.options.samlPayload.audience || `scimgateway/${this.scimgateway.pluginName}`

          form = {
            token_url: tokenUrl,
            grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
            client_id: clientId,
            company_id: companyId,
            new_token: true,
            assertion: await samlAssertion.run(context, cert, key, issuer, lifetime, clientId, nameId, userIdentifierFormat, tokenEndpoint, audience, delay),
          }
          break

        case 'oauthJwtBearer':
          // auth.options.azureTenantId => Microsoft Entra ID
          // auth.options.serviceAccountKeyFile => Google Service Account
          // also support custom using tokenUrl/jwtPayload
          let jwtClaims: jose.JWTPayload | Record<string, any>
          let jwtHeaders: jose.JWTHeaderParameters

          if (azureTenantId) { // Microsoft Entra ID
            if (connectionObj.auth?.options?.fedCred?.issuer) { // federated credentials
              const now = Date.now()
              const jwtPayload: jose.JWTPayload = {
                iss: connectionObj.auth?.options?.fedCred?.issuer, // entra id federated credentials issuer - scimgateway base URL, e.g. https://scimgateway.my-company.com
                sub: connectionObj.auth?.options?.fedCred?.subject, // entra id application object id - client id
                name: connectionObj.auth?.options?.fedCred?.name, // entra id federated credentials unique name e.g. plugin-entra-id
                aud: 'api://AzureADTokenExchange', // entra id federated credentials audience
                // below is not used by entra id federated credentials token-generation - could be skipped
                iat: Math.floor(now / 1000) - 60,
                exp: Math.floor(now / 1000) + 3600,
                jti: crypto.randomUUID(),
                nbf: Math.floor(now / 1000) - 60,
              }
              jwtClaims = {
                ...jwtPayload,
              }

              const { publicKey, privateKey } = await jose.generateKeyPair('RS256')
              const jwk = await jose.exportJWK(publicKey)
              const kid = createHash('sha256') // kid required for JWKS
                .update(JSON.stringify(jwk))
                .digest('base64url')

              jwtHeaders = {
                alg: 'RS256',
                typ: 'JWT',
                kid,
              }

              form = {
                grant_type: 'client_credentials',
                scope: connectionObj.auth.options.scope, // "https://graph.microsoft.com/.default"
                client_id: connectionObj.auth?.options?.fedCred?.subject,
                client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                client_assertion: await new jose.SignJWT(jwtClaims)
                  .setProtectedHeader(jwtHeaders)
                  .sign(privateKey),
              }

              // keep JWK for 5 minutes, will be regenerated on next token request
              // entra id only lookup well-known uri and corresponding jwks_uri on token request validation if kid not found in entra cached JWKS
              if (!this.scimgateway.jwk) this.scimgateway.jwk = {}
              if (!this.scimgateway.jwk[kid]) {
                this.scimgateway.jwk[kid] = { publicKey, privateKey }
                const ttl = 5 * 60
                ;(async () => {
                  setTimeout(async () => {
                    delete this.scimgateway.jwk[kid]
                  }, ttl * 1000)
                })()
              }
              this.scimgateway.jwk.issuer = connectionObj.auth?.options?.fedCred?.issuer // all baseEntities should use same issuer
            } else { // standard certificate
              if (!connectionObj.auth?.options?.tls?.cert) {
                throw new Error(`auth type '${connectionObj.auth?.type}' - missing options.tls.key/cert configuration`)
              }
              let privateKey = connectionObj.auth?.options?.tls?._key || ''
              let cert = connectionObj.auth?.options?.tls?._cert || ''
              let certPem = connectionObj.auth?.options?.tls?._certPem || ''
              if (!privateKey || !cert) {
                const privateKeyPem = fs.readFileSync(connectionObj.auth.options.tls.key, 'utf-8') || ''
                certPem = fs.readFileSync(connectionObj.auth.options.tls.cert, 'utf-8') || ''
                if (privateKeyPem) {
                  privateKey = createPrivateKey(privateKeyPem) // PEM => KeyObject
                  connectionObj.auth.options.tls._key = privateKey
                }
                if (certPem) {
                  cert = createPublicKey(certPem)
                  connectionObj.auth.options.tls._cert = cert
                  connectionObj.auth.options.tls._certPem = certPem
                }
              }
              if (!privateKey || !cert) {
                throw new Error(`auth type '${connectionObj.auth?.type}' - missing options.tls.key/cert file content`)
              }

              const jwtPayload: jose.JWTPayload = {
                iss: connectionObj.auth?.options?.clientId,
                sub: connectionObj.auth?.options?.clientId,
                aud: `https://login.microsoftonline.com/${azureTenantId}/v2.0`,
                iat: Math.floor(Date.now() / 1000) - 60,
                exp: Math.floor(Date.now() / 1000) + 3600,
                jti: crypto.randomUUID(),
                nbf: Math.floor(Date.now() / 1000) - 60,
              }
              jwtClaims = {
                ...jwtPayload,
              }

              const base64Thumbprint = utils.getBase64CertificateThumbprint(certPem, 'sha256') // x5t=>sha1, x5t#S256=>sha256
              jwtHeaders = {
                'alg': 'RS256',
                'typ': 'JWT',
                'x5t#S256': base64Thumbprint, // Microsoft recommend modern x5t#S256 over x5t
              }

              form = {
                grant_type: 'client_credentials',
                scope: connectionObj.auth.options.scope, // "https://graph.microsoft.com/.default"
                client_id: connectionObj.auth?.options?.clientId,
                client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                client_assertion: await new jose.SignJWT(jwtClaims)
                  .setProtectedHeader(jwtHeaders)
                  .sign(privateKey),
              }
            }
          } else if (serviceAccountKeyFile) { // Google - using Service Account key json-file
            if (!connectionObj.auth?.options?.jwtPayload?.scope || !connectionObj.auth?.options?.jwtPayload?.subject) {
              const err = new Error(`auth type '${connectionObj.auth?.type}' - using auth.options 'serviceAccountKeyFile' requires mandatory configuration entity.${baseEntity}.connection.auth.options.jwtPayload.scope/subject`)
              throw err
            }
            let gkey: Record<string, any> = connectionObj.auth?.options?._gkey
            if (!gkey) {
              gkey = await (async () => {
                try {
                  const jsonObject = await import(serviceAccountKeyFile, { assert: { type: 'json' } })
                  return jsonObject.default // access the object via the `default` property
                } catch (err: any) {
                  throw new Error(`auth type '${connectionObj.auth?.type}' - serviceAccountKeyFile error: ${err.message}`)
                }
              })()
              connectionObj.auth.options._gkey = gkey
            }

            tokenUrl = gkey.token_uri // https://oauth2.googleapis.com/token
            const privateKey = createPrivateKey(gkey.private_key) // PEM => KeyObject
            const jwtPayload: jose.JWTPayload = {
              iss: gkey.client_email, // service account email/user
              sub: connectionObj.auth?.options?.jwtPayload?.subject, // gmail sender mail-address: noreply@mycompany.com
              aud: gkey.token_uri,
              iat: Math.floor(Date.now() / 1000) - 60, // issued at
              exp: Math.floor(Date.now() / 1000) + 3600, // expiration time
            }
            jwtClaims = {
              ...jwtPayload,
              scope: connectionObj.auth?.options?.jwtPayload?.scope, // https://www.googleapis.com/auth/gmail.send
            }
            jwtHeaders = {
              alg: 'RS256',
              typ: 'JWT',
              kid: gkey.client_id,
            }

            form = {
              grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
              assertion: await new jose.SignJWT(jwtClaims)
                .setProtectedHeader(jwtHeaders)
                .sign(privateKey),
            }
          } else {
            // standard JWT - requires all configuation: tokenUrl, jwtPayload and tls.key
            if (!connectionObj.auth?.options?.tokenUrl
              || !connectionObj.auth?.options?.jwtPayload
              || typeof connectionObj.auth?.options?.jwtPayload !== 'object') {
              throw new Error(`auth.type '${connectionObj.auth?.type}' (no azureTenantId/serviceAccountKeyFile using raw) - missing connection configuration: auth.options.tokenUrl/jwtPayload`)
            }
            if (!connectionObj.auth?.options?.tls?.key) {
              throw new Error(`auth type '${connectionObj.auth?.type}' (no azureTenantId/serviceAccountKeyFile using raw) - missing options.tls.key configuration`)
            }
            tokenUrl = connectionObj.auth.options.tokenUrl
            let privateKey = connectionObj.auth?.options?.tls?._key || ''
            if (!privateKey) {
              privateKey = fs.readFileSync(connectionObj.auth.options.tls.key, 'utf-8') || ''
              if (privateKey) {
                privateKey = createPrivateKey(privateKey)
                connectionObj.auth.options.tls._key = privateKey
              }
            }

            let jwtPayload: jose.JWTPayload = connectionObj.auth.options.jwtPayload
            if (!jwtPayload.iat) jwtPayload.iat = Math.floor(Date.now() / 1000) - 60
            if (!jwtPayload.exp) jwtPayload.exp = Math.floor(Date.now() / 1000) + 3600

            jwtClaims = {
              ...jwtPayload,
            }
            jwtHeaders = {
              alg: 'RS256',
              typ: 'JWT',
            }

            form = {
              grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
              assertion: await new jose.SignJWT(jwtClaims)
                .setProtectedHeader(jwtHeaders)
                .sign(privateKey),
            }
          }

          break

        default:
          // no auth or PassTrough
          return {}
      }

      if (!tokenUrl) {
        throw new Error(`auth type '${connectionObj.auth?.type}' - missing tokenUrl`)
      }

      this.scimgateway.logDebug(baseEntity, `${action}: Retrieving accesstoken`)
      const method = 'POST'
      let connOpt: any = {}
      if (connectionObj.options && typeof connectionObj.options === 'object') {
        connOpt = utils.copyObj(connectionObj.options)
      }
      if (!connOpt.headers) connOpt.headers = {}
      connOpt.headers['Content-Type'] = 'application/x-www-form-urlencoded' // body must be query string formatted (no JSON)

      const response = await this.doRequest(baseEntity, method, tokenUrl, form, ctx, connOpt)
      if (!response.body) {
        const err = new Error(`[${action}] No data retrieved from: ${method} ${tokenUrl}`)
        throw (err)
      }
      const jbody = response.body
      if (jbody.error) {
        const err = new Error(`[${action}] Error message: ${jbody.error_description}`)
        throw (err)
      }
      if (connectionObj.auth?.type === 'token') { // in case response using token instead of access_token
        if (jbody.token) jbody.access_token = jbody.token
        else if (jbody.accessToken) jbody.access_token = jbody.accessToken
      }
      if (!jbody.access_token) {
        const err = new Error(`[${action}] Error message: Retrieved invalid token response`)
        throw (err)
      }

      const d = Math.floor(Date.now() / 1000) // seconds (unix time)
      jbody.validTo = d + parseInt(jbody.expires_in) // instead of using expires_on (clock may not be in sync with NTP, AAD default expires_in = 3600 seconds)
      jbody.token_type = jbody.token_type || 'Bearer'

      this.lock.release()
      return jbody
    } catch (err) {
      this.lock.release()
      throw (err)
    }
  }

  /**
   * getServiceClient creates and return client.options on first call, successive calls returns already existing client.options
   * @param baseEntity baseEntity
   * @param method GET/PATCH/PUT/DELETE
   * @param path e.g., /Users having baseUrl from configuration added, or full url e.g. https://mycompany.com/Users
   * @param opt optional, connection options
   * @param ctx optional, ctx included if using Auth PassThrough
   * @returns client.options needed for connect
   */
  private async getServiceClient(baseEntity: string, connectionObj: Record<string, any>, method: string, path: string, opt?: any, ctx?: any) {
    const action = 'getServiceClient'
    if (typeof connectionObj !== 'object' || connectionObj === null) connectionObj = {}
    let urlObj: any
    if (!path) path = ''
    try {
      urlObj = new URL(path)
    } catch (err) {
      //
      // path (no url) - default approach and client will be cached based on config
      //
      if (this._serviceClient[baseEntity]) { // serviceClient already exist - token specific
        this.scimgateway.logDebug(baseEntity, `${action}: Using existing client`)
        if (this._serviceClient[baseEntity].accessToken?.validTo) {
          // check if token refresh is needed when using oauth
          const d = Math.floor(Date.now() / 1000) // seconds (unix time)
          if (this._serviceClient[baseEntity].accessToken.validTo < d + 30) { // less than 30 sec before token expiration
            this.scimgateway.logDebug(baseEntity, `${action}: Accesstoken about to expire in ${this._serviceClient[baseEntity].accessToken.validTo - d} seconds`)
            try {
              const accessToken = await this.getAccessToken(baseEntity, connectionObj, ctx)
              this._serviceClient[baseEntity].accessToken = accessToken
              this._serviceClient[baseEntity].options.headers['Authorization'] = `${accessToken.token_type} ${accessToken.access_token}`
            } catch (err) {
              delete this._serviceClient[baseEntity]
              const newErr = err
              throw newErr
            }
          }
        }
      } else {
        this.scimgateway.logDebug(baseEntity, `${action}: Client have to be created`)
        let client = null
        if (this.config_entity && this.config_entity[baseEntity]) client = this.config_entity[baseEntity]
        if (!client) {
          const err = new Error(`unsupported baseEntity: ${baseEntity}`)
          throw err
        }
        if (!connectionObj.baseUrls || !Array.isArray(connectionObj.baseUrls) || connectionObj.baseUrls.length < 1) {
          const err = new Error(`missing connection configuration: baseUrls`)
          throw err
        }
        urlObj = new URL(connectionObj.baseUrls[0])
        const param: any = {
          baseUrl: connectionObj.baseUrls[0],
          options: {
            json: true, // json-object response instead of string
            headers: {
              Accept: 'application/json',
            },
            host: urlObj.hostname,
            port: urlObj.port, // null if https and 443 defined in url
            protocol: urlObj.protocol, // http: or https:
            // 'method' and 'path' added at the end
          },
        }

        // Support  no auth, header based auth (e.g., config {"options":{"headers":{"APIkey":"123"}}}),
        // basicAuth, bearerAuth, oauth, tokenAuth, oauthSamlBearer, oauthJwtBearer and auth PassTrough using request header authorization

        let orgConnection: any
        if (opt?.connection) { // allow overriding/extending configuration connection by caller argument opt.connection
          let org = connectionObj
          orgConnection = utils.copyObj(org)
          if (!org) org = {}
          org = utils.extendObj(org, opt.connection)
        }

        // may use configuration type='oauth' and auto corrected to 'oauthJwtBearer'
        if (connectionObj.auth?.type == 'oauth') {
          if (connectionObj.auth?.options?.azureTenantId) {
            if (connectionObj.auth.options?.tls?.cert
              && connectionObj.auth.options?.tls?.key
              && connectionObj.auth.options.clientId
            ) connectionObj.auth.type = 'oauthJwtBearer'
          } else if (connectionObj.auth?.options?.serviceAccountKeyFile) {
            connectionObj.auth.type = 'oauthJwtBearer'
          }
        }

        param.accessToken = await this.getAccessToken(baseEntity, connectionObj, ctx)
        if (param.accessToken?.access_token && param.accessToken?.token_type) {
          param.options.headers['Authorization'] = `${param.accessToken.token_type} ${param.accessToken.access_token}`
        } else { // no auth or PassTrough
          delete param.accessToken
        }

        if (orgConnection) {
          connectionObj = orgConnection // reset back to original
          if (opt?.connection) delete opt.connection
        }

        // proxy
        if (connectionObj.proxy?.host) {
          const agent = new HttpsProxyAgent(connectionObj.proxy.host)
          param.options.agent = agent // proxy
          if (connectionObj.proxy.username && connectionObj.proxy.password) {
            param.options.headers['Proxy-Authorization'] = 'Basic ' + Buffer.from(`${connectionObj.proxy.username}:${connectionObj.proxy.password}`).toString('base64') // using proxy with auth
          }
        }

        if (connectionObj.options) { // http connect options
          const connOpt: any = utils.copyObj(connectionObj.options)
          try {
            // using fs.readFileSync().toString() instead of Bun.file().text() for nodejs compability
            if (connOpt?.tls?.key) connOpt.tls.key = fs.readFileSync(connOpt.tls.key).toString()
            if (connOpt?.tls?.cert) connOpt.tls.cert = fs.readFileSync(connOpt.tls.cert).toString()
            if (connOpt?.tls?.ca) connOpt.tls.ca = [fs.readFileSync(connOpt.tls.ca).toString()]
          } catch (err: any) {
            throw new Error(`tls configuration error: ${err.message}`)
          }
          if (connOpt.tls && Object.prototype.hasOwnProperty.call(connOpt.tls, 'rejectUnauthorized')) {
            if (connOpt.tls.rejectUnauthorized !== false && connOpt.tls.rejectUnauthorized !== true) {
              delete connOpt.tls.rejectUnauthorized
            }
          }
          // currently nodejs do not support fetch using tls options
          // connOpt.agent = new Agent({key/cert/ca/rejectUnauthorized: <>})
          // for tls and nodejs, environment must instead be used and set before started, e.g.,:
          //   export NODE_EXTRA_CA_CERTS=/plugin-path/config/certs/ca.pem
          //   export NODE_TLS_REJECT_UNAUTHORIZED=0
          param.options = utils.extendObj(param.options, connOpt)
        }

        if (!this._serviceClient[baseEntity]) this._serviceClient[baseEntity] = {}
        this._serviceClient[baseEntity] = param // serviceClient created

        // OData support
        this._serviceClient[baseEntity].nextLink = {} // OData pagination (Entra ID)
        this._serviceClient[baseEntity].nextLink.users = null
        this._serviceClient[baseEntity].nextLink.groups = null
      }

      if (ctx?.headers?.get) { // Auth PassThrough using ctx header
        this._serviceClient[baseEntity].options.headers['Authorization'] = ctx.headers.get('authorization')
      }
      const cli: any = utils.copyObj(this._serviceClient[baseEntity]) // client ready

      // failover support
      path = this._serviceClient[baseEntity].baseUrl + path
      urlObj = new URL(path)
      cli.options.host = urlObj.hostname
      cli.options.port = urlObj.port
      cli.options.protocol = urlObj.protocol

      // adding none static
      cli.options.method = method
      cli.options.path = `${urlObj.pathname}${urlObj.search}`
      if (opt) {
        if (opt?.connection) delete opt.connection // only used for internal connection options
        cli.options = utils.extendObj(cli.options, opt) // merge with argument options
      }

      return cli // final client
    }
    //
    // url path - none config based (enpoint.entity) and used as is (no cache)
    //
    this.scimgateway.logDebug(baseEntity, `${action}: Using raw client`)
    let options: any = {
      json: true,
      headers: {
        Accept: 'application/json',
      },
      host: urlObj.hostname,
      port: urlObj.port,
      protocol: urlObj.protocol,
      method: method,
      path: urlObj.pathname + urlObj.search,
    }

    // proxy
    if (connectionObj.proxy?.host) {
      const agent = new HttpsProxyAgent(connectionObj.proxy.host)
      options.agent = agent // proxy
      if (connectionObj.proxy.username && connectionObj.proxy.password) {
        options.headers['Proxy-Authorization'] = 'Basic ' + Buffer.from(`${connectionObj.proxy.username}:${connectionObj.proxy.password}`).toString('base64') // using proxy with auth
      }
    }

    // merge any argument options - basic auth header is supported through {auth:{type:"basic",options:{username:"username",password:"password"}}}
    if (opt) {
      const o: any = utils.copyObj(opt)
      if (o?.auth?.type === 'basic') {
        options.headers['Authorization'] = 'Basic ' + Buffer.from(`${o.auth?.options?.username}:${o.auth?.options?.password}`).toString('base64')
        delete o.auth
      }
      options = utils.extendObj(options, o)
    }

    const cli: any = {}
    cli.options = options
    return cli // final client
  }

  /**
   * updateServiceClient merges obj with _serviceClient
   * @param baseEntity 
   * @param obj 
   */
  private updateServiceClient(baseEntity: string, obj: any) {
    if (this._serviceClient[baseEntity]) this._serviceClient[baseEntity] = utils.extendObj(this._serviceClient[baseEntity], obj)
  }

  /**
  * doRequestHandler executes REST request and returns response  
  * started by public doRequest() and includes param retryCount
  * @param baseEntity baseEntity
  * @param method GET, PATCH, PUT, DELETE
  * @param path path e.g., /Users (baseUrls configuration will automatically be included) or use full url e.g., https://my-company.com/Users 
  * @param body optional, body
  * @param ctx coptional, ctx when using Auth PassThrough
  * @param opt optional, web-standard fetch client options, e.g., using custom options not defined as general options in configuration file
  * @param retryCount internal use only - internal counter for retry and failover logic to other baseUrls defined
  **/
  private async doRequestHandler(baseEntity: string, method: string, path: string, body?: any, ctx?: any, opt?: any, retryCount?: number): Promise<any> {
    const connectionObj = this.config_entity[baseEntity]?.connection ?? {}
    let retryAfter = 0
    try {
      const controller = new AbortController()
      const signal = controller.signal
      const cli = await this.getServiceClient(baseEntity, connectionObj, method, path, opt, ctx)
      const options = cli.options
      const timeout = setTimeout(() => controller.abort(), options.abortTimeout ? options.abortTimeout * 1000 : this.idleTimeout * 1000) // 120 seconds default abort timeout
      options.signal = signal

      try {
        let dataString = ''
        if (body) {
          if (options.headers['Content-Type']) {
            const type: string = options.headers['Content-Type'].toLowerCase().trim()
            if (type.startsWith('application/x-www-form-urlencoded')) {
              if (typeof body === 'string') dataString = body
              else dataString = querystring.stringify(body) // JSON to query string syntax + URL encoded
            } else {
              if (typeof body === 'string') dataString = body
              else dataString = JSON.stringify(body)
            }
          } else {
            options.headers['Content-Type'] = 'application/json; charset=utf-8'
            if (typeof body === 'string') dataString = body
            else dataString = JSON.stringify(body)
          }
          options.headers['Content-Length'] = Buffer.byteLength(dataString, 'utf8')
          options.body = dataString
        } else if (options.headers) delete options.headers['Content-Type']

        const url = `${options.protocol}//${options.host}${options.port ? ':' + options.port : ''}${options.path}`

        // execute request
        const f = await fetch(url, options)
        if (!f.status) throw new Error('Response missing status code')

        const result: any = {
          statusCode: f.status,
          statusMessage: f.statusText,
          body: null,
        }

        const contentType = f.headers.get('content-type')
        if (contentType?.includes('json')) {
          result.body = await f.json().catch(() => f.text())
        } else {
          const bodyText = await f.text()
          try { result.body = JSON.parse(bodyText) } catch (err) { result.body = bodyText }
        }

        if (f.status > 399) {
          if (f.status === 429) { // throttle
            const v = f.headers.get('retry-after')
            if (v) retryAfter = parseInt(v, 10) + 1
            else retryAfter = 10
          }
          throw new Error(JSON.stringify(result))
        }
        this.scimgateway.logDebug(baseEntity, `doRequest ${method} ${options.protocol}//${options.host}${(options.port ? `:${options.port}` : '')}${options.path} Body = ${JSON.stringify(body)} Response = ${JSON.stringify(result)}`)
        if (result.body && typeof result.body === 'object' && result.body['@odata.nextLink']) { // {"@odata.nextLink": "https://graph.microsoft.com/beta/users?$top=100&$skiptoken=xxx"}
          // OData paging
          const nextUrl = result.body['@odata.nextLink'].split('?')[1] // keep search query
          const arr = result['@odata.nextLink'].split('?')[0].split('/')
          const objType = (arr[arr.length - 1]) // users
          let startIndexNext = ''
          if (this._serviceClient[baseEntity].nextLink[objType]) {
            for (const k in this._serviceClient[baseEntity].nextLink[objType]) {
              if (this._serviceClient[baseEntity].nextLink[objType][k] === nextUrl) return result // repetive startIndex=1
              startIndexNext = k
              break
            }
          }
          const a = result.body['@odata.nextLink'].split('top=')
          let top = '0'
          if (a.length > 1) {
            top = a[1].split('&')[0]
          }
          if (!startIndexNext) startIndexNext = (Number(top) + 1).toString()
          else startIndexNext = (Number(startIndexNext) + Number(top) + 1).toString()
          // reset and set new nextLink
          this._serviceClient[baseEntity].nextLink[objType] = {}
          this._serviceClient[baseEntity].nextLink[objType][startIndexNext] = nextUrl
        }
        return result
      } finally {
        clearTimeout(timeout)
      }
    } catch (err: any) { // includes failover/retry logic based on config baseUrls array
      let statusCode
      try { statusCode = JSON.parse(err.message).statusCode } catch (e) { void 0 }
      if (err.message.includes('ratelimit')) { // have seen throttling not follow standard 429/retry-after, but instead using 500 and error message only
        if (!retryAfter) retryAfter = 60
      }
      if (!retryCount) retryCount = 0
      let urlObj
      try { urlObj = new URL(path) } catch (err) { void 0 }
      let isServiceClient = !urlObj && this._serviceClient[baseEntity] && !this.lock.isLocked() // !isLocked to avoid retry ongoing doRequest with failing getAccessToken()
      let oAuthTokeErr = statusCode === 401 && connectionObj?.auth?.type && connectionObj.auth.type.startsWith('oauth')

      if (isServiceClient && (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || err.code === 'ABORT_ERR' || err.code === 'ETIMEDOUT' || statusCode === 504 || oAuthTokeErr || retryAfter)) {
        this.scimgateway.logDebug(baseEntity, `doRequest ${method} ${path} Body = ${JSON.stringify(body)} Error Response = ${err.message}`)
        if (retryAfter) {
          this.scimgateway.logDebug(baseEntity, `doRequest ${method} ${path} throttle/ratelimit error - awaiting ${retryAfter} seconds before automatic retry`)
          await new Promise(resolve => setTimeout(function () {
            resolve(null)
          }, retryAfter * 1000))
        }
        if (retryCount < connectionObj.baseUrls.length) {
          retryCount++
          if (isServiceClient) {
            this.updateServiceClient(baseEntity, { baseUrl: connectionObj.baseUrls[retryCount - 1] })
            this.scimgateway.logDebug(baseEntity, `${(connectionObj.baseUrls.length > 1) ? 'failover ' : ''}retry[${retryCount}] using baseUrl = ${this._serviceClient[baseEntity].baseUrl}`)
          }
          if (oAuthTokeErr) {
            delete this._serviceClient[baseEntity] // ensure new getAccessToken request - token used should not have been expired, but rejected for other reason e.g. token server restart and no persistent token store?
          }
          const ret = await this.doRequestHandler(baseEntity, method, path, body, ctx, opt, retryCount) // retry
          return ret // problem fixed
        } else {
          if (statusCode === 404) { // not logged as error e.g. getUser-manager
            this.scimgateway.logDebug(baseEntity, `doRequest ${method} ${path} Body = ${JSON.stringify(body)} Error Response = ${err.message}`)
          } else this.scimgateway.logError(baseEntity, `doRequest ${method} ${path} Body = ${JSON.stringify(body)} Error Response = ${err.message}`)
          throw err
        }
      } else {
        if (statusCode === 404) { // not logged as error e.g. getUser-manager
          this.scimgateway.logDebug(baseEntity, `doRequest ${method} ${path} Body = ${JSON.stringify(body)} Error Response = ${err.message}`)
        } else this.scimgateway.logError(baseEntity, `doRequest ${method} ${path} Body = ${JSON.stringify(body)} Error Response = ${err.message}`)
        if (statusCode === 401) delete this._serviceClient[baseEntity]
        throw err
      }
    }
  }

  /**
  * doRequest executes REST request and return response 
  * @param baseEntity baseEntity
  * @param method GET, PATCH, PUT, DELETE
  * @param path path e.g., /Users (baseUrls configuration will be used), optional use full url e.g., https://my-company.com/Users 
  * @param body optional, body
  * @param ctx optional, ctx when using Auth PassThrough
  * @param opt optional, web-standard fetch client options, e.g., using custom options not defined as general options in configuration file
  * @remarks
  * configuration file description  
  * ```
  * {
  *   "scimgateway": { ... }
  *   "endpoint": {
  *     "entity": {
  *       "undefined": {
  *         "connection": {
  *           "baseUrls": [  // ignored when using option azureTenantId
  *             "<baseUrl>", // "https://host1.company.com:8880",
  *             "<baseUrl2>" // optional using several baseUrls for failover
  *           ],
  *          "auth": {
  *            "type": "<type>",
  *            "options": { <auth.options> }
  *           },
  *           "options": { <connection.options> }
  *           "proxy": {
  *             "host": "<host>", // http://proxy-host:1234
  *             "username": "<username>", // username if authentication is required
  *             "password": "<password>" // password if authentication is required
  *           }
  *         }
  *       }
  *     }
  *   }
  * }
  * ```
  * type defines authentication being used  
  * if type not defined, no authentication used  
  * valid type is: `basic`, `oauth`, `token`, `bearer`, `oauthSamlBearer` or `oauthJwtBearer`  
  * 
  * for each valid type there are different auth.options  
  * 
  * type=**"basic"** having auth.options:
  * ```
  * {
  *   "type": "basic",
  *   "options": {
  *      "username": "<username>",
  *      "password": "<password>"
  *    }
  * }
  * ```
  * 
  * type=**"oauth"** having auth.options:
  * ```
  * {
  *   "type": "oauth",
  *   "options": {
  *     "azureTenantId": "<Entra ID azureTenantId", // Entra ID authentication - if baseUrls not defined, baseUrls automatically set to [https://graph.microsoft.com/beta]
  *     "tokenUrl": "<tokenUrl>", // must be set if not using azureTenantId
  *     "clientId": "<clientId>",
  *     "clientSecret": "<clientSecret>"
  *   }
  * }
  * ```
  * 
  * type=**"token"** having auth.options:
  * ```
  * {
  *   "type": "token",
  *   "options": {
  *     "tokenUrl": "<url for requesting token">
  *     "username": "<user name for token request>"
  *     "password": "<password for token request>"
  *   }
  * }
  * ```
  * 
  * type=**"bearer"** having auth.options:
  * ```
  * {
  *   "type": "bearer",
  *   "options": {
  *     "token": "<bearer token to be used">
  *   }
  * }
  * ```
  * 
  * type=**"oauthSamlBearer"** having auth.options:
  * ```
  * {
  *   "type": "oauthSamlBearer",
  *   "options": {
  *     "tokenUrl": "<tokenUrl>",
  *     "samlPayload": {
  *       "clientId": "<clientId>",
  *       "companyId": "<companyId>",
  *       "nameId": "<nameId>",
  *       "lifetime": "<optional>"
  *       "issuer": "<optional>",
  *       "userIdentifierFormat": "<optional>",
  *       "audience": "<optional>"
  *     },
  *     "tls": {
  *       "key": "<key-file-name>", // location: config/certs
  *       "cert": "<cert-file-name>", // location: config/certs
  *     }
  *   }
  * }
  * ```
  * 
  * type=**"oauthJwtBearer"** having auth.options:
  * ```
  * // Microsoft Entra ID - using certificate
  * {
  *   "type": "oauthJwtBearer",
  *   "options": {
  *     "azureTenantId": "<Entra ID azureTenantId", // Entra ID authentication, if baseUrls not defined, baseUrls automatically set to [https://graph.microsoft.com/beta]
  *     "clientId": "<clientId>",
  *     "tls": { // files located in ./config/certs
  *       "key": "key.pem",
  *       "cert": "cert.pem"
  *     }
  *   }
  * }
  * 
  * // Microsoft Entra ID - using Federated credentials
  * // Note, fedCred configuration must match corresponding configuration in Entra ID Application - Certificates & Secrets - Federated credentials - scenario "Other issuer"
  * {
  *   "type": "oauthJwtBearer",
  *   "options": {
  *     "azureTenantId": "<Entra ID azureTenantId",
  *     "fedCred": {
  *       "issuer": "<https://FQDN-scimgateway", // scimgateway base URL, e.g. https://scimgateway.my-company.com
  *       "subject": "<entra id application object id - client id>",
  *       "name": "<entra id federated credentials unique name>" // e.g. plugin-entra-id
  *     }
  *   }
  * }
  * 
  * // Google Cloud Platform - GCP
  * {
  *   "type": "oauthJwtBearer",
  *   "options": {
  *     "serviceAccountKeyFile": "<Google Service Account key file name>", // located in ./config/certs. If baseUrls not defined, baseUrls automatically set to [https://www.googleapis.com]
  *     "scope": "<jwt-scope>",
  *     "subject": "<jwt-subject>
  *   }
  * }
  * 
  * // General JWT API
  * {
  *   "type": "oauthJwtBearer",
  *   "options": {
  *     "tokenUrl":  "<tokenUrl",
  *     "tls": {
  *       "key": "<signing-key-file-name>" // key.pem file located in ./config/certs
  *      },
  *     "jwtPayload": {
  *       "sub": "<subject>",
  *       "iss": "<issuer>",
  *       "aud": "<audience>",
  *       ...
  *     }
  *   }
  * }
  * ```
  * 
  * **connection.options** can be set according to web-standard fetch client options  
  * examples:  
  * ```
  * {
  *   "options": {
  *     "tls": {
  *       "key": "<key-file-name>", // location: config/certs
  *       "cert": "<cert-file-name>", // location: config/certs
  *       "ca": "<ca-file-name>", // location: config/certs
  *       "rejectUnauthorized": <true/false>
  *      },
  *     "headers": {
  *       "<header1>", "<key1>",
  *       "<header2>", "<key2>"
  *      }
  *   }
  * }
  * ```
  * 
  **/
  public async doRequest(baseEntity: string, method: string, path: string, body?: any, ctx?: any, opt?: any) {
    return await this.doRequestHandler(baseEntity, method, path, body, ctx, opt)
  }

  /**
  * nextLinkPaging returns paging url when using OData e.g., Entra ID 
  * @param baseEntity baseEntity
  * @param objType e.g., 'users' or 'groups', a type that corresponds with what's being used by endpoint url request
  * @param startIndex SCIM startIndex paramenter
  * @returns paging url to be used
  **/
  public nextLinkPaging(baseEntity: string, objType: string, startIndex: number) {
    objType = objType.toLowerCase() // users or groups
    let nextPath = ''
    if (!startIndex || !this._serviceClient[baseEntity]) return ''
    if (startIndex < 2) {
      if (this._serviceClient[baseEntity].nextLink[objType]) {
        this._serviceClient[baseEntity].nextLink[objType] = null
      }
      return ''
    }
    if (this._serviceClient[baseEntity].nextLink[objType]) {
      if (this._serviceClient[baseEntity].nextLink[objType][startIndex]) {
        nextPath = `/users?${this._serviceClient[baseEntity].nextLink[objType][startIndex]}`
      } else {
        this._serviceClient[baseEntity].nextLink[objType] = null
        return ''
      }
    } else {
      return ''
    }
    return nextPath
  }

  /**
  * getGraphUrl returns Microsoft Graph API url used for Entra ID 
  * @returns Microsoft Graph API url
  **/
  public getGraphUrl(): string {
    return this.graphUrl
  }
} // class HelperRest
