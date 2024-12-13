import { HttpsProxyAgent } from 'https-proxy-agent'
import { URL } from 'url'
import { Buffer } from 'node:buffer'
import fs from 'node:fs'
import querystring from 'querystring'
import * as utils from './utils.ts'
import ScimGateway from 'scimgateway'

/**
 * HelperRest includes function doRequest() for doing REST calls
 */
export class HelperRest {
  private lock = new utils.Lock()
  private _serviceClient: Record<string, any> = {}
  private config_entity: any
  private scimgateway: ScimGateway
  private idleTimeout: number
  private graphUrl = 'https://graph.microsoft.com/beta' // beta instead of 'v1.0' gives all user attributes when no $select

  constructor(scimgateway: ScimGateway, optionalEntities?: Record<string, any>) {
    if (!(scimgateway instanceof ScimGateway)) throw new Error('HelperRest initialization error: argument scimgateway is not of type ScimGateway')
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
        if (this.config_entity[baseEntity]?.connection?.auth?.options?.tenantIdGUID) { // Entra ID, setting baseUrls to graph
          if (this.config_entity[baseEntity]?.connection?.auth?.type === 'oauth') {
            this.config_entity[baseEntity].connection.baseUrls = [this.graphUrl]
          }
        }
        connectionFound = true
      }
    }
    let errMsg = ''
    if (!entityFound) errMsg = 'HelperRest initialization error: missing configuration \'endpoint.entity.<name>\''
    else if (!connectionFound) errMsg = 'HelperRest initialization error: missing configuration \'endpoint.entity.<name>.connection\''
    if (errMsg) this.scimgateway.logError('undefined', errMsg)
  }

  /**
  * getClientIdentifier returns a unique client identifier having format user_secret
  * @param ctx having format { autorization: "<type>:xxxxx" }
  * @returns user_secret
  **/
  private getClientIdentifier(ctx: Record<string, any> | undefined): string {
    if (!ctx?.headers?.authorization) return 'undefined'
    const [user, secret] = this.getCtxAuth(ctx)
    return `${encodeURIComponent(user)}_${encodeURIComponent(secret)}` // user_password or undefined_password
  }

  /**
  * getCtxAuth returns [username, secret] based on Auth PassThrough autorization header included in ctx
  * @param ctx includes Auth PassThrough having format {headers:{autorization:"<type>:xxxxx"}}
  * @returns [username, secret]
  **/
  private getCtxAuth(ctx: Record<string, any> | undefined): any[] {
    if (!ctx?.headers?.authorization) return []
    const [authType, authToken] = (ctx.headers.authorization || '').split(' ') // [0] = 'Basic' or 'Bearer'
    let username, password
    if (authType === 'Basic') [username, password] = (Buffer.from(authToken, 'base64').toString() || '').split(':')
    if (username) return [username, password] // basic auth
    else return [undefined, authToken] // bearer auth
  }

  /**
   * getAccessToken returns oauth accesstoken object
   * @param baseEntity 
   * @param ctx 
   * @returns oauth accesstoken object
   */
  public async getAccessToken(baseEntity: string, ctx?: Record<string, any> | undefined) { // public in case token is needed for other logic e.g. sending mail
    await this.lock.acquire()
    const clientIdentifier = this.getClientIdentifier(ctx)
    const d = Math.floor(Date.now() / 1000) // seconds (unix time)
    if (this._serviceClient[baseEntity] && this._serviceClient[baseEntity][clientIdentifier] && this._serviceClient[baseEntity][clientIdentifier].accessToken
      && (this._serviceClient[baseEntity][clientIdentifier].accessToken.validTo >= d + 30)) { // avoid simultaneously token requests
      this.lock.release()
      return this._serviceClient[baseEntity][clientIdentifier].accessToken
    }

    const action = 'getAccessToken'

    let tokenUrl: string
    let form: object
    let resource = ''

    switch (this.config_entity[baseEntity]?.connection?.auth?.type) {
      case 'oauth':
        try {
          const urlObj = new URL(this.config_entity[baseEntity].connection.baseUrls[0])
          resource = urlObj.origin
        } catch (err) { void 0 }
        if (this.config_entity[baseEntity].connection.auth?.options?.tenantIdGUID) { // Azure
          tokenUrl = `https://login.microsoftonline.com/${this.config_entity[baseEntity].connection.auth.options.tenantIdGUID}/oauth2/token`
        } else {
          tokenUrl = this.config_entity[baseEntity].connection.auth.options.tokenUrl
        }
        form = {
          grant_type: 'client_credentials',
          client_id: this.config_entity[baseEntity].connection.auth.options.clientId,
          client_secret: this.config_entity[baseEntity].connection.auth.options.clientSecret,
          scope: this.config_entity[baseEntity].connection.auth.options.scope || null,
          resource: resource || null, // "https://graph.microsoft.com"
        }
        break

      case 'token':
        tokenUrl = this.config_entity[baseEntity].connection.auth.options.tokenUrl
        form = { // example username/password in body
          username: this.config_entity[baseEntity].connection.auth.options.username,
          password: this.config_entity[baseEntity].connection.auth.options.password,
        }
        break

      default:
        this.lock.release()
        throw new Error(`getAccessToken() none supported entity.${baseEntity}.connection.auth.type: '${this.config_entity[baseEntity]?.connection?.auth?.type}'`)
    }

    if (!tokenUrl) {
      this.lock.release()
      throw new Error(`auth type '${this.config_entity[baseEntity]?.connection?.auth?.type}' - missing tokenUrl or tenantIdGUID configuration`)
    }

    this.scimgateway.logDebug(baseEntity, `${action}: Retrieving accesstoken`)
    const method = 'POST'
    let connOpt: any = {}
    if (this.config_entity[baseEntity].connection.options && typeof this.config_entity[baseEntity].connection.options === 'object') {
      connOpt = utils.copyObj(this.config_entity[baseEntity].connection.options)
    }
    if (!connOpt.headers) connOpt.headers = {}
    connOpt.headers['Content-Type'] = 'application/x-www-form-urlencoded' // body must be query string formatted (no JSON)

    try {
      const response = await this.doRequest(baseEntity, method, tokenUrl, form, ctx, connOpt)
      if (!response.body) {
        const err = new Error(`[${action}] No data retrieved from: ${method} ${tokenUrl}`)
        this.lock.release()
        throw (err)
      }
      const jbody = response.body
      if (jbody.error) {
        const err = new Error(`[${action}] Error message: ${jbody.error_description}`)
        this.lock.release()
        throw (err)
      }
      if (this.config_entity[baseEntity]?.connection?.auth?.type === 'token') { // in case response using token instead of access_token
        if (jbody.token) jbody.access_token = jbody.token
        else if (jbody.accessToken) jbody.access_token = jbody.accessToken
      }
      if (!jbody.access_token) {
        this.lock.release()
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
   * @param opt optional, connection optios
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
      const clientIdentifier = this.getClientIdentifier(ctx)
      if (this._serviceClient[baseEntity] && this._serviceClient[baseEntity][clientIdentifier]) { // serviceClient already exist - token specific
        this.scimgateway.logDebug(baseEntity, `${action}: Using existing client`)
        if (this._serviceClient[baseEntity][clientIdentifier].accessToken) {
          // check if token refresh is needed when using oauth
          const d = Math.floor(Date.now() / 1000) // seconds (unix time)
          if (this._serviceClient[baseEntity][clientIdentifier].accessToken.validTo < d + 30) { // less than 30 sec before token expiration
            this.scimgateway.logDebug(baseEntity, `${action}: Accesstoken about to expire in ${this._serviceClient[baseEntity][clientIdentifier].accessToken.validTo - d} seconds`)
            try {
              const accessToken = await this.getAccessToken(baseEntity, ctx)
              this._serviceClient[baseEntity][clientIdentifier].accessToken = accessToken
              this._serviceClient[baseEntity][clientIdentifier].options.headers['Authorization'] = ` Bearer ${accessToken.access_token}`
            } catch (err) {
              delete this._serviceClient[baseEntity][clientIdentifier]
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

        // Supporting  no auth, header based auth (e.g., config {"options":{"headers":{"APIkey":"123"}}}),
        // basicAuth, bearerAuth, oauth, tokenAuth and auth PassTrough using request header authorization
        if (ctx?.headers?.authorization) { // Auth PassThrough using ctx header
          param.options.headers['Authorization'] = ctx.headers.authorization
        } else {
          switch (this.config_entity[baseEntity]?.connection?.auth?.type) {
            case 'basic':
              if (!this.config_entity[baseEntity]?.connection?.auth?.options?.username || !this.config_entity[baseEntity]?.connection?.auth?.options?.password) {
                const err = new Error(`auth type 'basic' - missing configuration entity.${baseEntity}.connection.auth.options.username/password`)
                throw err
              }
              param.options.headers['Authorization'] = 'Basic ' + Buffer.from(`${this.config_entity[baseEntity].connection.auth.options.username}:${this.config_entity[baseEntity].connection.auth.options.password}`).toString('base64')
              break
            case 'oauth':
              if (!this.config_entity[baseEntity]?.connection?.auth?.options?.clientId || !this.config_entity[baseEntity]?.connection?.auth?.options?.clientSecret) {
                const err = new Error(`auth type 'oauth' - missing configuration entity.${baseEntity}.connection.auth.options.clientId/clientSecret`)
                throw err
              }
              param.accessToken = await this.getAccessToken(baseEntity, ctx) // support Auth PassThrough
              param.options.headers['Authorization'] = `Bearer ${param.accessToken.access_token}`
              break
            case 'token':
              if (!this.config_entity[baseEntity]?.connection?.auth?.options?.tokenUrl || !this.config_entity[baseEntity]?.connection?.auth?.options?.password) {
                const err = new Error(`missing configuration entity.${baseEntity}.connection.auth.options.tokenUrl/password`)
                throw err
              }
              param.accessToken = await this.getAccessToken(baseEntity, ctx) // support Auth PassThrough
              param.options.headers['Authorization'] = `Bearer ${param.accessToken.access_token}`
              break
            case 'bearer':
              if (!this.config_entity[baseEntity]?.connection?.auth?.options?.token) {
                const err = new Error(`missing configuration entity.${baseEntity}.connection.auth.options.token`)
                throw err
              }
              param.options.headers['Authorization'] = 'Bearer ' + Buffer.from(this.config_entity[baseEntity].connection.auth.options.token).toString('base64')
              break
            default:
            // no auth
          }
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
        if (!this._serviceClient[baseEntity][clientIdentifier]) this._serviceClient[baseEntity][clientIdentifier] = {}
        this._serviceClient[baseEntity][clientIdentifier] = param // serviceClient created

        // OData support - note, not using [clientIdentifier]
        this._serviceClient[baseEntity].nextLink = {} // OData pagination (Entra ID)
        this._serviceClient[baseEntity].nextLink.users = null
        this._serviceClient[baseEntity].nextLink.groups = null
      }

      const cli: any = utils.copyObj(this._serviceClient[baseEntity][clientIdentifier]) // client ready

      // failover support
      path = this._serviceClient[baseEntity][clientIdentifier].baseUrl + path
      urlObj = new URL(path)
      cli.options.host = urlObj.hostname
      cli.options.port = urlObj.port
      cli.options.protocol = urlObj.protocol

      // adding none static
      cli.options.method = method
      cli.options.path = `${urlObj.pathname}${urlObj.search}`
      if (opt) cli.options = utils.extendObj(cli.options, opt) // merge with argument options

      return cli // final client
    }
    //
    // url path - none config based and used as is (no cache)
    //
    this.scimgateway.logDebug(baseEntity, `${action}: Using none config based client`)
    let options: any = {
      json: true,
      headers: {
        Accept: 'application/json',
      },
      host: urlObj.hostname,
      port: urlObj.port,
      protocol: urlObj.protocol,
      method: method,
      path: urlObj.pathname,
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
   * @param clientIdentifier 
   * @param obj 
   */
  private updateServiceClient(baseEntity: string, clientIdentifier: string, obj: any) {
    if (this._serviceClient[baseEntity] && this._serviceClient[baseEntity][clientIdentifier]) this._serviceClient[baseEntity][clientIdentifier] = utils.extendObj(this._serviceClient[baseEntity][clientIdentifier], obj)
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
      if (statusCode === 404) { // not logged as error, let caller decide e.g. getUser-manager
        this.scimgateway.logDebug(baseEntity, `doRequest ${method} ${path} Body = ${JSON.stringify(body)} Error Response = ${err.message}`)
      } else this.scimgateway.logError(baseEntity, `doRequest ${method} ${path} Body = ${JSON.stringify(body)} Error Response = ${err.message}`)
      const clientIdentifier = this.getClientIdentifier(ctx)
      if (err.message.includes('ratelimit')) { // have seen throttling not follow standard 429/retry-after, but instead using 500 and error message only
        if (!retryAfter) retryAfter = 60
      }
      if (!retryCount) retryCount = 0
      let urlObj
      try { urlObj = new URL(path) } catch (err) { void 0 }
      if (!urlObj && (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || err.code === 'ABORT_ERR' || err.code === 'ETIMEDOUT' || retryAfter)) {
        if (retryAfter) {
          this.scimgateway.logDebug(baseEntity, `doRequest ${method} ${path} throttle/ratelimit error - awaiting ${retryAfter} seconds before automatic retry`)
          await new Promise(resolve => setTimeout(function () {
            resolve(null)
          }, retryAfter * 1000))
        }
        if (retryCount < this.config_entity[baseEntity].connection.baseUrls.length) {
          retryCount++
          this.updateServiceClient(baseEntity, clientIdentifier, { baseUrl: this.config_entity[baseEntity].connection.baseUrls[retryCount - 1] })
          this.scimgateway.logDebug(baseEntity, `${(this.config_entity[baseEntity].connection.baseUrls.length > 1) ? 'failover ' : ''}retry[${retryCount}] using baseUrl = ${this._serviceClient[baseEntity].baseUrl}`)
          const ret = await this.doRequestHandler(baseEntity, method, path, body, ctx, opt, retryCount) // retry
          return ret // problem fixed
        } else {
          throw err
        }
      } else {
        if (statusCode === 401 && this._serviceClient[baseEntity]) {
          delete this._serviceClient[baseEntity][clientIdentifier]
        }
        throw err // CA IM retries getUser failure once (retry 6 times on ECONNREFUSED)
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
  *           "baseUrls": [
  *             "<baseUrl>", // "https://host1.company.com:8880",
  *             "<baseUrl2>" // optional using several baseUrls for failover
  *           ],
  *          "auth": {
  *            "type": "<type>"",
  *            "options": { <auth.options> }
  *           },
  *           "options": { <connection.options> }
  *         }
  *       }
  *     }
  *   }
  * }
  * ```
  * type defines authentication being used  
  * if type not defined, no authentication used  
  * valid type is: `basic`, `oauth`, `token` or `bearer`   
  * 
  * for each valid type there are different auth.options  
  * 
  * type=**basic**, auth.options:
  * ```
  * {
  *   "options": {
  *      "username": "<username>",
  *      "password": "<password>"
  *    }
  * }
  * ```
  * 
  * type=**oauth**, auth.options:
  * ```
  * {
  *   "options": {
  *     "tenantIdGUID": "<Entra ID tenantIdGUID", // only defined when using Entra ID
  *     "tokenUrl": "<tokenUrl>", // not used when tenantIdGUID defined
  *     "clientId": "<clientId",
  *     "clientSecret": "<clientSecret>"
  *   }
  * }
  * ```
  * 
  * type=**token**, auth.options:
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
  * type=**bearer**, auth.options:
  * ```
  * {
  *   "options": {
  *     "token": "<bearer token to be used">
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
