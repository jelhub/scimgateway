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
import { samlAssertion } from './samlAssertion.ts'
import * as jsonwebtoken from 'jsonwebtoken'
import fs from 'node:fs'
import querystring from 'querystring'
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
    if (optionalEntities && optionalEntities.entity) this.config_entity = utils.copyObj(optionalEntities.entity)
    else this.config_entity = utils.copyObj(scimgateway.getConfig())?.entity
    let entityFound = false
    let connectionFound = false
    for (const baseEntity in this.config_entity) {
      entityFound = true
      if (this.config_entity[baseEntity]?.connection) {
        connectionFound = true
        const type = this.config_entity[baseEntity].connection?.auth?.type
        if (type === 'oauthJwtBearer' || type === 'oauth') {
          // set default baseUrls for Entra ID and Google if not already defined
          if (this.config_entity[baseEntity]?.connection?.auth?.options?.tenantIdGUID) { // Entra ID, setting baseUrls to graph
            if (!this.config_entity[baseEntity].connection.baseUrls) {
              this.config_entity[baseEntity].connection.baseUrls = [this.graphUrl]
            } else if (this.config_entity[baseEntity].connection.baseUrls?.length < 1) {
              this.config_entity[baseEntity].connection.baseUrls = [this.graphUrl]
            }
          } else if (this.config_entity[baseEntity]?.connection?.auth?.options?.serviceAccountKeyFile) { // Google, setting baseUrls to googleapis
            if (!this.config_entity[baseEntity].connection.baseUrls) {
              this.config_entity[baseEntity].connection.baseUrls = [this.googleUrl]
            } else if (this.config_entity[baseEntity].connection.baseUrls?.length < 1) {
              this.config_entity[baseEntity].connection.baseUrls = [this.googleUrl]
            }
          }
        }
      }
    }
    let errMsg = ''
    if (!entityFound) errMsg = 'HelperRest initialization error: missing configuration \'endpoint.entity.<name>\''
    else if (!connectionFound) errMsg = 'HelperRest initialization error: missing configuration \'endpoint.entity.<name>.connection\''
    if (errMsg) this.scimgateway.logError('undefined', errMsg)
  }

  /**
   * getAccessToken returns oauth accesstoken object
   * @param baseEntity 
   * @param ctx 
   * @returns oauth accesstoken object
   */
  public async getAccessToken(baseEntity: string, ctx?: Record<string, any> | undefined) { // public in case token is needed for other logic e.g. sending mail
    await this.lock.acquire()
    const d = Math.floor(Date.now() / 1000) // seconds (unix time)
    if (this._serviceClient[baseEntity] && this._serviceClient[baseEntity].accessToken
      && (this._serviceClient[baseEntity].accessToken.validTo >= d + 30)) { // avoid simultaneously token requests
      this.lock.release()
      return this._serviceClient[baseEntity].accessToken
    }

    const action = 'getAccessToken'

    const serviceAccountKeyFile = this.config_entity[baseEntity]?.connection?.auth?.options?.serviceAccountKeyFile
    const tenantIdGUID = this.config_entity[baseEntity]?.connection?.auth?.options?.tenantIdGUID
    let tokenUrl: string
    let form: Record<string, any>
    let resource = ''

    try {
      const urlObj = new URL(this.config_entity[baseEntity].connection.baseUrls[0])
      resource = urlObj.origin
    } catch (err) { void 0 }
    if (tenantIdGUID) {
      tokenUrl = `https://login.microsoftonline.com/${tenantIdGUID}/oauth2/v2.0/token`
      if (resource) this.config_entity[baseEntity].connection.auth.options.scope = resource + '/.default' // "https://graph.microsoft.com/.default"
    } else tokenUrl = this.config_entity[baseEntity].connection.auth.options.tokenUrl

    try {
      switch (this.config_entity[baseEntity]?.connection?.auth?.type) {
        case 'oauth':
          form = {
            grant_type: 'client_credentials',
            client_id: this.config_entity[baseEntity].connection.auth.options.clientId,
            client_secret: this.config_entity[baseEntity].connection.auth.options.clientSecret,
          }
          if (this.config_entity[baseEntity].connection.auth.options.scope) form.scope = this.config_entity[baseEntity].connection.auth.options.scope // required using Entra ID /oauth2/v2.0/token
          if (this.config_entity[baseEntity].connection.auth.options.resource) resource = this.config_entity[baseEntity].connection.auth.options.resource // required using Entra ID /oauth2/token

          break

        case 'token':
          tokenUrl = this.config_entity[baseEntity].connection.auth.options.tokenUrl
          form = { // example username/password in body
            username: this.config_entity[baseEntity].connection.auth.options.username,
            password: this.config_entity[baseEntity].connection.auth.options.password,
          }
          break

        case 'oauthSamlBearer':
          tokenUrl = this.config_entity[baseEntity].connection.auth.options.tokenUrl
          const context = null
          const cert = fs.readFileSync(this.config_entity[baseEntity].connection.auth.options.certificate.cert).toString()
          const key = fs.readFileSync(this.config_entity[baseEntity].connection.auth.options.certificate.key).toString()

          const tokenEndpoint = tokenUrl
          const delay = 1

          // mandatory: clientId, companyId and userId (nameId)
          const clientId = this.config_entity[baseEntity].connection.auth.options.samlPayload.clientId
          const companyId = this.config_entity[baseEntity].connection.auth.options.samlPayload.companyId
          const userId = this.config_entity[baseEntity].connection.auth.options.samlPayload.userId
          const userIdentifierFormat = this.config_entity[baseEntity].connection.auth.options.samlPayload.userIdentifierFormat || 'userName'
          const lifetime = this.config_entity[baseEntity].connection.auth.options.samlPayload.lifetime || 3600
          const issuer = this.config_entity[baseEntity].connection.auth.options.samlPayload.clientId || `https://scimgateway.${this.scimgateway.pluginName}.com`
          const audience = this.config_entity[baseEntity].connection.auth.options.samlPayload.audience || `scimgateway/${this.scimgateway.pluginName}`

          form = {
            token_url: tokenUrl,
            grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
            client_id: clientId,
            company_id: companyId,
            assertion: await samlAssertion.run(context, cert, key, issuer, lifetime, clientId, userId, userIdentifierFormat, tokenEndpoint, audience, delay),
          }
          break

        case 'oauthJwtBearer':
          let jwtClaims: jsonwebtoken.JwtPayload | Record<string, any> = {}
          let jwtOpts: jsonwebtoken.SignOptions = {}

          if (tenantIdGUID) { // Microsoft Entra ID
            if (!this.config_entity[baseEntity]?.connection?.auth?.options?.certificate?.key || !this.config_entity[baseEntity]?.connection?.auth?.options?.certificate?.cert) {
              throw new Error(`auth type '${this.config_entity[baseEntity]?.connection?.auth?.type}' - missing options.certificate.key/cert configuration`)
            }
            let privateKey = this.config_entity[baseEntity]?.connection?.auth?.options?.certificate?._key || ''
            let cert = this.config_entity[baseEntity]?.connection?.auth?.options?.certificate?._cert || ''
            if (!privateKey || !cert) {
              privateKey = fs.readFileSync(this.config_entity[baseEntity].connection.auth.options.certificate.key, 'utf-8') || ''
              cert = fs.readFileSync(this.config_entity[baseEntity].connection.auth.options.certificate.cert, 'utf-8') || ''
              if (privateKey) this.config_entity[baseEntity].connection.auth.options.certificate._key = privateKey
              if (cert) this.config_entity[baseEntity].connection.auth.options.certificate._cert = cert
            }
            if (!privateKey || !cert) {
              throw new Error(`auth type '${this.config_entity[baseEntity]?.connection?.auth?.type}' - missing options.certificate.key/cert file content`)
            }

            const jwtPayload: jsonwebtoken.JwtPayload = {
              sub: this.config_entity[baseEntity]?.connection?.auth?.options?.clientId,
              iss: this.config_entity[baseEntity]?.connection?.auth?.options?.clientId,
              aud: `https://login.microsoftonline.com/${tenantIdGUID}/v2.0`,
              iat: Math.floor(Date.now() / 1000) - 60,
              exp: Math.floor(Date.now() / 1000) + 3600,
              jti: crypto.randomUUID(),
              nbf: Math.floor(Date.now() / 1000) - 60,
            }
            jwtClaims = {
              ...jwtPayload,
            }

            const base64Thumbprint = utils.getBase64CertificateThumbprint(cert, 'sha1') // xt5=>sha1, x5t#S256=>sha256
            jwtOpts = {
              algorithm: 'RS256',
              header: {
                typ: 'JWT',
                alg: 'RS256',
                x5t: base64Thumbprint,
              },
            }

            /* Microsoft recommended modern x5t#S256 does not work using self-signed certificate
            const base64Thumbprint = utils.getBase64CertificateThumbprint(cert, 'sha256')
            jwtOpts = {
              algorithm: 'PS256',
              header: {
                'typ': 'JWT',
                'alg': 'PS256',
                'x5t#S256': base64Thumbprint,
              },
            }
            */

            form = {
              grant_type: 'client_credentials',
              scope: this.config_entity[baseEntity].connection.auth.options.scope, // "https://graph.microsoft.com/.default"
              client_id: this.config_entity[baseEntity]?.connection?.auth?.options?.clientId,
              client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
              client_assertion: jsonwebtoken.sign(jwtClaims, privateKey, jwtOpts),
            }
          } else if (serviceAccountKeyFile) { // Google - using Service Account key json-file
            if (!this.config_entity[baseEntity]?.connection?.auth?.options?.jwtPayload?.scope || !this.config_entity[baseEntity]?.connection?.auth?.options?.jwtPayload?.subject) {
              const err = new Error(`auth type '${this.config_entity[baseEntity]?.connection?.auth?.type}' - using auth.options 'serviceAccountKeyFile' requires mandatory configuration entity.${baseEntity}.connection.auth.options.jwtPayload.scope/subject`)
              throw err
            }
            let gkey: Record<string, any> = this.config_entity[baseEntity]?.connection?.auth?.options?._gkey
            if (!gkey) {
              gkey = await (async () => {
                try {
                  const jsonObject = await import(serviceAccountKeyFile, { assert: { type: 'json' } })
                  return jsonObject.default // access the object via the `default` property
                } catch (err: any) {
                  throw new Error(`auth type '${this.config_entity[baseEntity]?.connection?.auth?.type}' - serviceAccountKeyFile error: ${err.message}`)
                }
              })()
              this.config_entity[baseEntity].connection.auth.options._gkey = gkey
            }

            tokenUrl = gkey.token_uri // https://oauth2.googleapis.com/token
            const privateKey = gkey.private_key
            const jwtPayload: jsonwebtoken.JwtPayload = {
              sub: this.config_entity[baseEntity]?.connection?.auth?.options?.jwtPayload?.subject, // gmail sender mail-address: noreply@mycompany.com
              iss: gkey.client_email, // service account email/user
              aud: gkey.token_uri,
              iat: Math.floor(Date.now() / 1000) - 60, // issued at
              exp: Math.floor(Date.now() / 1000) + 3600, // expiration time
            }
            jwtClaims = {
              ...jwtPayload,
              scope: this.config_entity[baseEntity]?.connection?.auth?.options?.jwtPayload?.scope, // https://www.googleapis.com/auth/gmail.send
            }
            jwtOpts = {
              algorithm: 'RS256',
              header: {
                typ: 'JWT',
                alg: 'RS256',
                kid: gkey.client_id,
              },
            }
            form = {
              grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
              assertion: jsonwebtoken.sign(jwtClaims, privateKey, jwtOpts),
            }
          } else {
            // standard JWT - requires all configuation: tokenUrl, jwtPayload and certificate.key
            if (!this.config_entity[baseEntity]?.connection?.auth?.options?.tokenUrl
              || !this.config_entity[baseEntity]?.connection?.auth?.options?.jwtPayload
              || typeof this.config_entity[baseEntity]?.connection?.auth?.options?.jwtPayload !== 'object') {
              throw new Error(`auth.type '${this.config_entity[baseEntity]?.connection?.auth?.type}' (no tenantIdGUID/serviceAccountKeyFile using raw) - missing configuration entity.${baseEntity}.connection.auth.options.tokenUrl/jwtPayload`)
            }
            if (!this.config_entity[baseEntity]?.connection?.auth?.options?.certificate?.key) {
              throw new Error(`auth type '${this.config_entity[baseEntity]?.connection?.auth?.type}' (no tenantIdGUID/serviceAccountKeyFile using raw) - missing options.certificate.key configuration`)
            }
            tokenUrl = this.config_entity[baseEntity].connection.auth.options.tokenUrl
            let privateKey = this.config_entity[baseEntity]?.connection?.auth?.options?.certificate?._key || ''
            if (!privateKey) {
              privateKey = fs.readFileSync(this.config_entity[baseEntity].connection.auth.options.certificate.key, 'utf-8') || ''
              if (privateKey) this.config_entity[baseEntity].connection.auth.options.certificate._key = privateKey
            }

            let jwtPayload = this.config_entity[baseEntity].connection.auth.options.jwtPayload
            if (!jwtPayload.iat) jwtPayload.iat = Math.floor(Date.now() / 1000) - 60
            if (!jwtPayload.exp) jwtPayload.exp = Math.floor(Date.now() / 1000) + 3600

            jwtClaims = {
              ...jwtPayload,
            }
            jwtOpts = {
              algorithm: 'RS256',
              header: {
                typ: 'JWT',
                alg: 'RS256',
              },
            }

            form = {
              grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
              assertion: jsonwebtoken.sign(jwtClaims, privateKey, jwtOpts),
            }
          }

          break

        default:
          throw new Error(`getAccessToken() none supported entity.${baseEntity}.connection.auth.type: '${this.config_entity[baseEntity]?.connection?.auth?.type}'`)
      }

      if (!tokenUrl) {
        throw new Error(`auth type '${this.config_entity[baseEntity]?.connection?.auth?.type}' - missing tokenUrl`)
      }

      this.scimgateway.logDebug(baseEntity, `${action}: Retrieving accesstoken`)
      const method = 'POST'
      let connOpt: any = {}
      if (this.config_entity[baseEntity].connection.options && typeof this.config_entity[baseEntity].connection.options === 'object') {
        connOpt = utils.copyObj(this.config_entity[baseEntity].connection.options)
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
      if (this.config_entity[baseEntity]?.connection?.auth?.type === 'token') { // in case response using token instead of access_token
        if (jbody.token) jbody.access_token = jbody.token
        else if (jbody.accessToken) jbody.access_token = jbody.accessToken
      }
      if (!jbody.access_token) {
        const err = new Error(`[${action}] Error message: Retrieved invalid token response`)
        throw (err)
      }

      const d = Math.floor(Date.now() / 1000) // seconds (unix time)
      jbody.validTo = d + parseInt(jbody.expires_in) // instead of using expires_on (clock may not be in sync with NTP, AAD default expires_in = 3600 seconds)

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
  private async getServiceClient(baseEntity: string, method: string, path: string, opt?: any, ctx?: any) {
    const action = 'getServiceClient'

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
        if (this._serviceClient[baseEntity].accessToken) {
          // check if token refresh is needed when using oauth
          const d = Math.floor(Date.now() / 1000) // seconds (unix time)
          if (this._serviceClient[baseEntity].accessToken.validTo < d + 30) { // less than 30 sec before token expiration
            this.scimgateway.logDebug(baseEntity, `${action}: Accesstoken about to expire in ${this._serviceClient[baseEntity].accessToken.validTo - d} seconds`)
            try {
              const accessToken = await this.getAccessToken(baseEntity, ctx)
              this._serviceClient[baseEntity].accessToken = accessToken
              this._serviceClient[baseEntity].options.headers['Authorization'] = ` Bearer ${accessToken.access_token}`
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
        if (!this.config_entity[baseEntity]?.connection?.baseUrls || !Array.isArray(this.config_entity[baseEntity].connection.baseUrls) || this.config_entity[baseEntity].connection.baseUrls.length < 1) {
          const err = new Error(`missing configuration entity.${baseEntity}.connection.baseUrls`)
          throw err
        }
        urlObj = new URL(this.config_entity[baseEntity].connection.baseUrls[0])
        const param: any = {
          baseUrl: this.config_entity[baseEntity].connection.baseUrls[0],
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
          let org = this.config_entity[baseEntity]?.connection
          orgConnection = utils.copyObj(org)
          if (!org) org = {}
          org = utils.extendObj(org, opt.connection)
        }

        // may use configuration type='oauth' and auto corrected to 'oauthJwtBearer'
        if (this.config_entity[baseEntity]?.connection?.auth?.type == 'oauth') {
          if (this.config_entity[baseEntity].connection.auth?.options?.tenantIdGUID) {
            if (this.config_entity[baseEntity].connection.auth.options?.certificate?.cert
              && this.config_entity[baseEntity].connection.auth.options?.certificate?.key
              && this.config_entity[baseEntity].connection.auth.options.clientId
            ) this.config_entity[baseEntity].connection.auth.type = 'oauthJwtBearer'
          } else if (this.config_entity[baseEntity]?.connection?.auth?.options?.serviceAccountKeyFile) {
            this.config_entity[baseEntity].connection.auth.type = 'oauthJwtBearer'
          }
        }

        switch (this.config_entity[baseEntity]?.connection?.auth?.type) {
          case 'basic':
            if (!this.config_entity[baseEntity]?.connection?.auth?.options?.username || !this.config_entity[baseEntity]?.connection?.auth?.options?.password) {
              const err = new Error(`auth.type 'basic' - missing configuration entity.${baseEntity}.connection.auth.options.username/password`)
              throw err
            }
            param.options.headers['Authorization'] = 'Basic ' + Buffer.from(`${this.config_entity[baseEntity].connection.auth.options.username}:${this.config_entity[baseEntity].connection.auth.options.password}`).toString('base64')
            break
          case 'oauth':
            if (!this.config_entity[baseEntity]?.connection?.auth?.options?.clientId || !this.config_entity[baseEntity]?.connection?.auth?.options?.clientSecret) {
              const err = new Error(`auth.type 'oauth' - missing configuration entity.${baseEntity}.connection.auth.options.clientId/clientSecret`)
              throw err
            }
            param.accessToken = await this.getAccessToken(baseEntity, ctx)
            param.options.headers['Authorization'] = `Bearer ${param.accessToken.access_token}`
            break
          case 'token':
            if (!this.config_entity[baseEntity]?.connection?.auth?.options?.tokenUrl || !this.config_entity[baseEntity]?.connection?.auth?.options?.password) {
              const err = new Error(`missing configuration entity.${baseEntity}.connection.auth.options.tokenUrl/password`)
              throw err
            }
            param.accessToken = await this.getAccessToken(baseEntity, ctx)
            param.options.headers['Authorization'] = `Bearer ${param.accessToken.access_token}`
            break
          case 'bearer':
            if (!this.config_entity[baseEntity]?.connection?.auth?.options?.token) {
              const err = new Error(`missing configuration entity.${baseEntity}.connection.auth.options.token`)
              throw err
            }
            param.options.headers['Authorization'] = 'Bearer ' + Buffer.from(this.config_entity[baseEntity].connection.auth.options.token).toString('base64')
            break
          case 'oauthSamlBearer':
            if (!this.config_entity[baseEntity]?.connection?.auth?.options?.samlPayload?.clientId || !this.config_entity[baseEntity]?.connection?.auth?.options?.samlPayload?.companyId
              || !this.config_entity[baseEntity]?.connection?.auth?.options?.certificate?.key) {
              const err = new Error(`auth.type 'oauthSamlBearer' - missing configuration entity.${baseEntity}.connection.auth.options.certificate and/or options.samlPayload.clientId/companyId`)
              throw err
            }
            param.accessToken = await this.getAccessToken(baseEntity, ctx)
            param.options.headers['Authorization'] = `Bearer ${param.accessToken.access_token}`
            break
          case 'oauthJwtBearer':
            // auth.options.tenantIdGUID => Microsoft Entra ID
            // auth.options.serviceAccountKeyFile => Google Service Account
            // also support custom using tokenUrl/jwtPayload
            param.accessToken = await this.getAccessToken(baseEntity, ctx)
            param.options.headers['Authorization'] = `Bearer ${param.accessToken.access_token}`
            break

          default:
            // no auth or PassTrough
        }

        if (orgConnection) {
          this.config_entity[baseEntity].connection = orgConnection // reset back to original
          if (opt?.connection) delete opt.connection
        }

        // proxy
        if (this.config_entity[baseEntity]?.connection?.proxy?.host) {
          const agent = new HttpsProxyAgent(this.config_entity[baseEntity].connection.proxy.host)
          param.options.agent = agent // proxy
          if (this.config_entity[baseEntity].connection.proxy.username && this.config_entity[baseEntity].connection.proxy.password) {
            param.options.headers['Proxy-Authorization'] = 'Basic ' + Buffer.from(`${this.config_entity[baseEntity].connection.proxy.username}:${this.config_entity[baseEntity].connection.proxy.password}`).toString('base64') // using proxy with auth
          }
        }

        if (this.config_entity[baseEntity]?.connection?.options) { // http connect options
          const connOpt: any = utils.copyObj(this.config_entity[baseEntity].connection.options)
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
    if (this.config_entity[baseEntity]?.connection?.proxy?.host) {
      const agent = new HttpsProxyAgent(this.config_entity[baseEntity].connection.proxy.host)
      options.agent = agent // proxy
      if (this.config_entity[baseEntity].connection.proxy.username && this.config_entity[baseEntity].connection.proxy.password) {
        options.headers['Proxy-Authorization'] = 'Basic ' + Buffer.from(`${this.config_entity[baseEntity].connection.proxy.username}:${this.config_entity[baseEntity].connection.proxy.password}`).toString('base64') // using proxy with auth
      }
    }

    // merge any argument options - support basic auth using {auth: {username: "username", password: "password"} }
    if (opt) {
      const o: any = utils.copyObj(opt)
      if (o.auth) {
        options.headers['Authorization'] = 'Basic ' + Buffer.from(`${o.auth.username}:${o.auth.password}`).toString('base64')
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
  * @param body body
  * @param ctx ctx when using Auth PassThrough
  * @param opt web-standard fetch client options, e.g., options not defined as general options in configuration file
  * @param retryCount internal use only - internal counter for retry and failover logic to other baseUrls defined
  **/
  private async doRequestHandler(baseEntity: string, method: string, path: string, body?: any, ctx?: any, opt?: any, retryCount?: number): Promise<any> {
    let retryAfter = 0
    try {
      const cli = await this.getServiceClient(baseEntity, method, path, opt, ctx)
      const options = cli.options
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
      } else delete options.headers['Content-Type']
      const controller = new AbortController()
      const signal = controller.signal
      const timeout = setTimeout(() => controller.abort(), options.abortTimeout ? options.abortTimeout * 1000 : this.idleTimeout * 1000) // 120 seconds default abort timeout
      options.signal = signal
      const url = `${options.protocol}//${options.host}${options.port ? ':' + options.port : ''}${options.path}`
      // execute request
      const f = await fetch(url, options)
      clearTimeout(timeout)
      if (!f.status) throw new Error('response missing statusCode header')
      const result: any = {
        statusCode: f.status,
        statusMessage: f.statusText,
        body: null,
      }
      const contentType = f.headers.get('content-type')
      if (contentType) {
        if (contentType.includes('json')) result.body = await f.json()
        else {
          result.body = await f.text()
          try {
            result.body = JSON.parse(result)
          } catch (err) { void 0 }
        }
      }
      if (f.status < 200 || f.status > 299) {
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
      let oAuthTokeErr = statusCode === 401 && this.config_entity[baseEntity].connection?.auth?.type && this.config_entity[baseEntity].connection.auth.type.startsWith('oauth')
      if (isServiceClient && (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || err.code === 'ABORT_ERR' || err.code === 'ETIMEDOUT' || oAuthTokeErr || retryAfter)) {
        this.scimgateway.logDebug(baseEntity, `doRequest ${method} ${path} Body = ${JSON.stringify(body)} Error Response = ${err.message}`)
        if (retryAfter) {
          this.scimgateway.logDebug(baseEntity, `doRequest ${method} ${path} throttle/ratelimit error - awaiting ${retryAfter} seconds before automatic retry`)
          await new Promise(resolve => setTimeout(function () {
            resolve(null)
          }, retryAfter * 1000))
        }
        if (retryCount < this.config_entity[baseEntity].connection.baseUrls.length) {
          retryCount++
          this.updateServiceClient(baseEntity, { baseUrl: this.config_entity[baseEntity].connection.baseUrls[retryCount - 1] })
          this.scimgateway.logDebug(baseEntity, `${(this.config_entity[baseEntity].connection.baseUrls.length > 1) ? 'failover ' : ''}retry[${retryCount}] using baseUrl = ${this._serviceClient[baseEntity].baseUrl}`)
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
  *           "baseUrls": [  // ignored when using option tenantIdGUID
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
  * valid type is: `basic`, `oauth`, `token`, `bearer` or `oauthSamlBearer`  
  * 
  * for each valid type there are different auth.options  
  * 
  * type=**"basic"** having auth.options:
  * ```
  * {
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
  *   "options": {
  *     "tenantIdGUID": "<Entra ID tenantIdGUID", // Entra ID authentication - if baseUrls not defined, baseUrls automatically set to [https://graph.microsoft.com/beta]
  *     "tokenUrl": "<tokenUrl>", // must be set if not using tenantIdGUID
  *     "clientId": "<clientId>",
  *     "clientSecret": "<clientSecret>"
  *   }
  * }
  * ```
  * 
  * type=**"token"** having auth.options:
  * ```
  * {
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
  *   "options": {
  *     "token": "<bearer token to be used">
  *   }
  * }
  * ```
  * 
  * type=**"oauthSamlBearer"** having auth.options:
  * ```
  * {
  *   "options": {
  *     "tokenUrl": "<tokenUrl>",
  *     "samlPayload": {
  *       "clientId": "<clientId>",
  *       "companyId": "<companyId>",
  *       "userId": "<userId>",  // nameId
  *       "lifetime": "<optional>"
  *       "issuer": "<optional>",
  *       "userIdentifierFormat": "<optional>",
  *       "audience": "<optional>"
  *     },
  *     "certificate": {
  *       "key": "<key-file-name>", // location: config/certs
  *       "cert": "<cert-file-name>", // location: config/certs
  *     }
  *   }
  * }
  * ```
  * 
  * type=**"oauthJwtBearer"** having auth.options:
  * ```
  * // Microsoft Entra ID
  * {
  *   "options": {
  *     "tenantIdGUID": "<Entra ID tenantIdGUID", // Entra ID authentication, if baseUrls not defined, baseUrls automatically set to [https://graph.microsoft.com/beta]
  *     "clientId": "<clientId>",
  *     "certificate": { // files located in ./config/certs
  *       "key": "key.pem",
  *       "cert": "cert.pem"
  *     }
  *   }
  * }
  * 
  * // Google Cloud Platform - GCP
  * {
  *   "options": {
  *     "serviceAccountKeyFile": "<Google Service Account key file name>", // located in ./config/certs. If baseUrls not defined, baseUrls automatically set to [https://www.googleapis.com]
  *     "scope": "<jwt-scope>",
  *     "subject": "<jwt-subject>
  *   }
  * }
  * 
  * // General JWT API
  * {
  *   "options": {
  *     "tokenUrl":  "<tokenUrl",
  *     "certificate": {
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
