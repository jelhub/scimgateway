// =================================================================================
// File:    scimgateway.ts
//
// Author:  Jarle Elshaug
//
// Purpose: Started by endpoint plugin
//          Listens and replies on incoming SCIM requests
//          Optional SCIM Stream subscriber/publisher
// =================================================================================

import { createServer as httpCreateServer } from 'node:http'
import { createServer as httpsCreateServer } from 'node:https'
import { type IncomingMessage, type ServerResponse } from 'node:http'
import { createPublicKey } from 'node:crypto'
import { createChecker } from 'is-in-subnet'
import { fileURLToPath } from 'node:url'
import { Logger } from './logger.ts'
import { HelperRest } from './helper-rest.ts'
import dot from 'dot-object'
import nodemailer from 'nodemailer'
import fs from 'node:fs'
import path from 'node:path'
import * as jose from 'jose'
import * as utils from './utils.ts'
import * as utilsScim from './utils-scim.ts'
import * as stream from './scim-stream.js'
export * from './helper-rest.ts'
// @ts-expect-error: cannot find declaration
import hycoPkg from 'hyco-https'

export class ScimGateway {
  private config: any
  private logger: any
  private gwName: string
  private scimDef: any
  private jwk: any
  private multiValueTypes: any
  private getMemberOf: any
  private getAppRoles: any
  private pub: any
  // @ts-expect-error: has no initializer
  private helperRest: HelperRest
  /** pluginName is the name of plugin e.g., plugin-loki */
  readonly pluginName: string
  /** configDir is full path to plugin ./config directory */
  readonly configDir: string
  /** configFile is full path to plugin configuration file */
  readonly configFile: string
  /** 
  * authPassThroughAllowed can be set by plugin for enabling Auth PassThrough  
  * Set to true will allow plugin to pass the ctx.request.headers.authorization as authorization 
  * header in the communication with endpoint
  */
  authPassThroughAllowed: boolean
  //
  // plugin methods
  //

  /**
   * getUsers method is defined at the plugin and should return users from endpoint according to getObj (rawFilter) and attributes parameter - if getObj.operator and getObj.rawFilter not defined, all users should be returned  
   * @param baseEntity used for multi tenant or multi endpoint support, either "undefined" or set by request url e.g., http://localhost:8880/loki2/Users gives baseEntity=loki2
   * @param getObj
   * ```
   * {
   *   "attribute": "<>",
   *   "operator": "<>",
   *   "value": "<>",
   *   "rawFilter": "<>",
   *   "startIndex": <undefined | number>,
   *   "count": <undefined | number>
   * }
   * ```
   * **attribute**, **operator** and **value** are included when using "simpel filtering", e.g.: `{ "attribute": "userName", "operator": "eq", "value": "bjensen" }`  
   * **rawFilter** is original query filter e.g., `{ "rawFilter": "userName eq \"bjensen\"" }`  
   * **startIndex** paging, is the beginning index and count for the resources on the page  
   * **count** paging, is the desired maximum number of query results per page  
   * @param attributes array of attributes to be returned - if empty, all supported attributes should be returned. All attributes may also be returned regardless of attributes parameter, scimgateway will do final filtering
   * @param ctx if plugin authPassThroughAllowed is set to true, ctx contains authorization header `{ "headers": { "authorization": "<value>" } }` that can be used in the communication with endpoint, something that is included when using HelperRest
   * @returns
   * ```
   * {  
   *   Resources: [<list of user objects>],  
   *   totalResults: <null | number> // number is total number of endpoint objects when using paging (startIndex/count) - if unknown, we might set a high number to ensure getting new paging request (scimgateway have logic for final page) 
   * }
   * ```
   * could return all supported attributes having **id** and **userName** as mandatory, scimgateway will do final filtering e.g.:  
   * ```
   * {  
   *   Resources: [
   *     {"id": "bjensen", "userName": "bjensen"},
   *     {"id":"jsmith", "userName":"jsmith"}
   *   ]
   * }
   * ```
   *  @remarks if all attributes are supposed to be returned (or should include groups) and returned result do not include user groups, 
   * scimgateway will do additional getGroups() request for each user object for including groups. If groups are not supported or we do 
   * not want getGroups() requests, user object should include `{ "groups": [] }`
   *  @remarks the value of returned 'id' will be used as 'id' in modifyUser and deleteUser
   */
  getUsers!: (baseEntity: string, getObj: Record<string, any>, attributes: string[], ctx?: undefined | Record<string, any>) => any
  /**
   * createUser method is defined at the plugin and should create user at endpoint  
   * @param baseEntity used for multi tenant or multi endpoint support, either "undefined" or set by request url e.g., http://localhost:8880/loki2/Users gives baseEntity=loki2
   * @param userObj
   *   
   * ```
   * {
   *   "userName": "<unique on both IdP and endpoint>", // userName or externalId always included
   *   "<attribute>": <value>,
   *   ...
   * }
   * ```
   * @param ctx if plugin authPassThroughAllowed is set to true, ctx contains authorization header `{ "headers": { "authorization": "<value>" } }` that can be used in the communication with endpoint, something that is included when using HelperRest
   * @returns
   * {  
   *   "id": "<unique endpoint id>" // if id not included or not returning an object, scimgateway will do an additional getUsers() for retrieving user's id
   * }
   * ```
   *  @remarks
   * ```js
   * catch (err: any) {
   *   const newErr = new Error(`${action} error: ${err.message}`)
   *   if (err.message && err.message.startsWith('Duplicate key')) {
   *     newErr.name += '#409' // customErrorCode
   *   }
   *   throw newErr
   * }
   * ```
   *  if user already exist, an error should be thrown that includes suffix `#<code>` to the err.name having `<code>` set to 409 that indicates duplicate key
   */
  createUser!: (baseEntity: string, userObj: Record<string, any>, ctx?: undefined | Record<string, any>) => any
  /**
   * deleteUser method is defined at the plugin and should delete user at endpoint  
   * @param baseEntity used for multi tenant or multi endpoint support, either "undefined" or set by request url e.g., http://localhost:8880/loki2/Users gives baseEntity=loki2
   * @param id unique user id at endpoint
   * @param ctx if plugin authPassThroughAllowed is set to true, ctx contains authorization header `{ "headers": { "authorization": "<value>" } }` that can be used in the communication with endpoint, something that is included when using HelperRest
   * @returns null | throw error
   */
  deleteUser!: (baseEntity: string, id: string, ctx?: undefined | Record<string, any>) => any
  /**
   * modifyUser method is defined at the plugin and should modify user at endpoint based on attrObj parameter  
   * @param baseEntity used for multi tenant or multi endpoint support, either "undefined" or set by request url e.g., http://localhost:8880/loki2/Users gives baseEntity=loki2
   * @param id unique user id at endpoint
   * @param attrObj object having user attributes to be modified
   * @param ctx if plugin authPassThroughAllowed is set to true, ctx contains authorization header `{ "headers": { "authorization": "<value>" } }` that can be used in the communication with endpoint, something that is included when using HelperRest
   * @returns null | throw error
   */
  modifyUser!: (baseEntity: string, id: string, attrObj: Record<string, any>, ctx?: undefined | Record<string, any>) => any
  /**
   * getGroups method is defined at the plugin and should return groups from endpoint according to getObj (rawFilter) and attributes parameter - if getObj.operator and getObj.rawFilter not defined, all groups should be returned  
   * @param baseEntity used for multi tenant or multi endpoint support, either "undefined" or set by request url e.g., http://localhost:8880/loki2/Groups gives baseEntity=loki2
   * @param getObj
   * ```
   * {
   *   "attribute": "<>",
   *   "operator": "<>",
   *   "value": "<>",
   *   "rawFilter": "<>",
   *   "startIndex": <undefined | number>,
   *   "count": <undefined | number>
   * }
   * ```
   * **attribute**, **operator** and **value** are included when using "simpel filtering", e.g.: `{ "attribute": "displayName", "operator": "eq", "value": "Admins" }`  
   * **rawFilter** is original query filter e.g., `{ "rawFilter": "displayName eq \"Admins\"" }`  
   * **startIndex** paging, is the beginning index and count for the resources on the page  
   * **count** paging, is the desired maximum number of query results per page  
   * @param attributes array of attributes to be returned - if empty, all supported attributes should be returned. All attributes may also be returned regardless of attributes parameter, scimgateway will do final filtering
   * @param ctx if plugin authPassThroughAllowed is set to true, ctx contains authorization header `{ "headers": { "authorization": "<value>" } }` that can be used in the communication with endpoint, something that is included when using HelperRest
   * @returns
   * ```
   * {  
   *   Resources: [<list of group objects>],  
   *   totalResults: <null | number> // number is total number of endpoint objects when using paging (startIndex/count) - if unknown, we might set a high number to ensure getting new paging request (scimgateway have logic for final page) 
   * }
   * ```
   * could return all supported attributes having **id** and **displayName** as mandatory, scimgateway will do final filtering e.g.:  
   * ```
   * {  
   *   Resources: [
   *     {"id": "Admins", "displayName": "Admins","members":[{"value":"bjensen"}]},
   *     {"id":"Employees", "userName":"Employees","members":[{"value":"jsmith"}]}
   *   ]
   * }
   * ```
   *  @remarks the value of returned 'id' will be used as 'id' in modifyGroup and deleteGroup
   */
  getGroups!: (baseEntity: string, getObj: Record<string, any>, attributes: string[], ctx?: undefined | Record<string, any>) => any
  /**
   * createGroup method is defined at the plugin and should create group at endpoint  
   * @param baseEntity used for multi tenant or multi endpoint support, either "undefined" or set by request url e.g., http://localhost:8880/loki2/Users gives baseEntity=loki2
   * @param userObj
   *   
   * ```
   * {
   *   "displayName": "<unique on both IdP and endpoint>", // displayName always included
   *   "<attribute>": <value>,
   *   ...
   * }
   * ```
   * @param ctx if plugin authPassThroughAllowed is set to true, ctx contains authorization header `{ "headers": { "authorization": "<value>" } }` that can be used in the communication with endpoint, something that is included when using HelperRest
   * @returns
   * {  
   *   "id": "<unique endpoint id>" // if id not included or not returning an object, scimgateway will do an additional getGroups() for retrieving group id
   * }
   * ```
   *  @remarks
   * ```js
   * catch (err: any) {
   *   const newErr = new Error(`${action} error: ${err.message}`)
   *   if (err.message && err.message.startsWith('Duplicate key')) {
   *     newErr.name += '#409' // customErrorCode
   *   }
   *   throw newErr
   * }
   * ```
   *  if group already exist, an error should be thrown that includes suffix `#<code>` to the err.name having `<code>` set to 409 that indicates duplicate key
   */
  createGroup!: (baseEntity: string, groupObj: Record<string, any>, ctx?: undefined | Record<string, any>) => any
  /**
   * deleteGroup method is defined at the plugin and should should delete group at endpoint  
   * @param baseEntity used for multi tenant or multi endpoint support, either "undefined" or set by request url e.g., http://localhost:8880/loki2/Users gives baseEntity=loki2
   * @param id unique group id at endpoint
   * @param ctx if plugin authPassThroughAllowed is set to true, ctx contains authorization header `{ "headers": { "authorization": "<value>" } }` that can be used in the communication with endpoint, something that is included when using HelperRest
   * @returns null | throw error
   */
  deleteGroup!: (baseEntity: string, id: string, ctx?: undefined | Record<string, any>) => any
  /**
  * modifyGroup method is defined at the plugin and should modify group at endpoint based on attrObj parameter  
  * @param baseEntity used for multi tenant or multi endpoint support, either "undefined" or set by request url e.g., http://localhost:8880/loki2/Users gives baseEntity=loki2
  * @param id unique user id at endpoint
  * @param attrObj 
  * ```
  * {
  *   "members": [
  *     { "value": "jsmith" }, // user having id=jsmith should be assigned to group
  *     {"operation":"delete","value":"bjensen"} // user having id=bjensen shoud be revoked from group
  *   ]
  * }
  * ```
  * attrObj contains group attributes to be modified  
  * @param ctx if plugin authPassThroughAllowed is set to true, ctx contains authorization header `{ "headers": { "authorization": "<value>" } }` that can be used in the communication with endpoint, something that is included when using HelperRest
  * @returns null | throw error
  */
  modifyGroup!: (baseEntity: string, id: string, attrObj: Record<string, any>, ctx?: undefined | Record<string, any>) => any

  /** getServicePlans is used by plugin-entra for retrieving Entra ID license plans */
  getServicePlans!: (baseEntity: string, getObj: Record<string, any>, attributes: Array<string>, ctx?: undefined | Record<string, any>) => any

  /**
  * postApi method is defined at the plugin and should handle incoming `"POST /api"` for creating an object and should be used according to your needs  
  * @param baseEntity used for multi tenant or multi endpoint support, either "undefined" or set by request url e.g., http://localhost:8880/loki2/Users gives baseEntity=loki2
  * @param body is POST body and contains object to be created
  * @param ctx if plugin authPassThroughAllowed is set to true, ctx contains authorization header `{ "headers": { "authorization": "<value>" } }` that can be used in the communication with endpoint, something that is included when using HelperRest
  * @returns according to your needs
  * @example
  * POST http://localhost:8890/api  
  * body = {"title":"BMW X5","price":58}
  */
  postApi!: (baseEntity: string, body: any, ctx?: undefined | Record<string, any>) => any
  /**
  * putApi method is defined at the plugin and should handle incoming `"PUT /api/<id>"` for replacing an object and should be used according to your needs  
  * @param baseEntity used for multi tenant or multi endpoint support, either "undefined" or set by request url e.g., http://localhost:8880/loki2/Users gives baseEntity=loki2
  * @param id unique object id
  * @param body is PUT body and contains the new replaced object
  * @param ctx if plugin authPassThroughAllowed is set to true, ctx contains authorization header `{ "headers": { "authorization": "<value>" } }` that can be used in the communication with endpoint, something that is included when using HelperRest
  * @returns according to your needs
  * @example
  * PUT http://localhost:8890/api/100  
  * body = {"title":"BMW X1","price":21}  
  */
  putApi!: (baseEntity: string, id: string, body: any, ctx?: undefined | Record<string, any>) => any
  /**
  * patchApi method is defined at the plugin and should handle incoming `"PATCH /api/<id>"` for modifying an object and should be used according to your needs  
  * @param baseEntity used for multi tenant or multi endpoint support, either "undefined" or set by request url e.g., http://localhost:8880/loki2/Users gives baseEntity=loki2
  * @param id unique object id
  * @param body is PATCH body and contains attributes to be modified
  * @param ctx if plugin authPassThroughAllowed is set to true, ctx contains authorization header `{ "headers": { "authorization": "<value>" } }` that can be used in the communication with endpoint, something that is included when using HelperRest
  * @returns according to your needs
  * @example
  * PATCH http://localhost:8890/api/100  
  * body = {"title":"BMW X3"}
  */
  patchApi!: (baseEntity: string, id: string, body: any, ctx?: undefined | Record<string, any>) => any
  /**
  * getApi method is defined at the plugin and should handle incoming `"GET /api/<query>"` for retrieving one or more objects and should be used according to your needs  
  * @param baseEntity used for multi tenant or multi endpoint support, either "undefined" or set by request url e.g., http://localhost:8880/loki2/Users gives baseEntity=loki2
  * @param id <undefined | unique object id> // if undefined all objects should be retrived
  * @param query is url querystring
  * @param ctx if plugin authPassThroughAllowed is set to true, ctx contains authorization header `{ "headers": { "authorization": "<value>" } }` that can be used in the communication with endpoint, something that is included when using HelperRest
  * @returns according to your needs
  * @examples
  * GET http://localhost:8890/api  
  * GET http://localhost:8890/api/100  
  */
  getApi!: (baseEntity: string, id: string, query: Record<string, any> | undefined, ctx?: undefined | Record<string, any>) => any
  /**
  * deleteApi method is defined at the plugin and should handle incoming `"DELETE /api/<id>"` for deleting an objects and should be used according to your needs  
  * @param baseEntity used for multi tenant or multi endpoint support, either "undefined" or set by request url e.g., http://localhost:8880/loki2/Users gives baseEntity=loki2
  * @param id unique object id
  * @param ctx if plugin authPassThroughAllowed is set to true, ctx contains authorization header `{ "headers": { "authorization": "<value>" } }` that can be used in the communication with endpoint, something that is included when using HelperRest
  * @returns according to your needs
  * @example
  * DELETE http://localhost:8890/api/100
  */
  deleteApi!: (baseEntity: string, id: string, ctx?: undefined | Record<string, any>) => any
  /**
  * publicApi method is defined at the plugin and should handle all incoming methods for the public path `/pub/api` - note, there are no authentication for this path
  * @param baseEntity will always be `pub`
  * @param method GET/POST/PATCH/PUT/DELETE
  * @param id unique object id for methods having id else undefined
  * @param query query object if exists else undefined
  * @param apiObj body
  * @returns according to your needs
  * @example
  * PATCH http://localhost:8890/pub/api/100  
  * body = {"title":"BMW X3"}
  */
  publicApi!: (baseEntity: string, method: string, id: string | undefined, query: Record<string, any> | undefined, apiObj: any, ctx?: undefined | Record<string, any>) => any

  constructor() {
    const funcHandler: any = {}
    let requester: string = ''
    {
      let _prepareStackTrace = Error.prepareStackTrace
      Error.prepareStackTrace = (_, stack) => {
        return stack.map((callSite) => {
          return callSite.getFileName()
        })
      }
      const e = new Error()
      requester = e.stack?.[1] ?? ''
      try { // node.js using url-path win: file:///path - linux: file://path
        requester = fileURLToPath(requester)
      } catch (err) { void 0 }
      Error.prepareStackTrace = _prepareStackTrace
    }
    let pluginName = path.basename(requester)
    pluginName = pluginName.substring(0, pluginName.lastIndexOf('.')) || pluginName
    let pluginDir = path.dirname(requester)
    let configDir = path.join(pluginDir, '..', 'config')
    let gwName = path.basename(fileURLToPath(import.meta.url)).split('.')[0] // prefix of current file - using fileURLToPath because using "__filename" is not supported by nodejs typescript
    if (pluginDir.includes('$bunfs/root')) {
      // running compiled binary - binary prefix name must match the config prefix name located in the config folder in the same directory as the binary.
      // bun build --compile ./lib/plugin-xxx.ts --target=bun-darwin-arm64 --outfile ./build/plugin-xxx
      pluginDir = '.' // only support running binary in current directory
      configDir = './config'
      gwName = 'scimgateway'
    }
    const configFile = path.join(configDir, `${pluginName}.json`) // config name prefix same as pluging name prefix

    this.config = {}
    // exposed outside class
    this.gwName = gwName
    this.pluginName = pluginName
    this.configDir = configDir
    this.configFile = configFile
    this.authPassThroughAllowed = false // set to true by plugin if using Auth PassThrough

    let found: Record<string, any> = {}
    let configErr: any
    try {
      this.config = JSON.parse(fs.readFileSync(configFile, 'utf-8'))
      found = this.processConfig()
    } catch (err) { configErr = err }

    let logDir: string
    if (pluginDir === '.') logDir = 'logs' // running bun compiled binary
    else logDir = this.config?.scimgateway?.log?.logDirectory || path.join(pluginDir, '..', 'logs')

    const logger = new Logger(
      pluginName,
      {
        type: 'console',
        level: 'info', // will be set according to config during startup
        customMasking: this.config?.scimgateway?.log?.customMasking,
        colorize: this.config?.scimgateway?.log?.colorize,
      },
      {
        type: 'file',
        level: this.config?.scimgateway?.log?.loglevel?.file,
        customMasking: this.config?.scimgateway?.log?.customMasking,
        logDir,
        logFileName: pluginName + '.log',
        maxSize: this.config?.scimgateway?.log?.maxSize,
        maxFiles: this.config?.scimgateway?.log?.maxFiles,
      },
    )

    if (configErr) {
      logger.error(`${gwName} ${configErr.message}`)
      logger.error(`${gwName} stopping...`)
      throw (new Error('Using exception to stop further asynchronous code execution (ensure synchronous logger flush to logfile and exit program), please ignore this one...'))
    }
    this.logger = logger

    const oAuthTokenExpire = 3600 // seconds
    let pwErrCount = 0
    let isMailLock = false
    let ipAllowListChecker: any
    let server: any

    if (!this.config) this.config = {}
    if (!this.config.scimgateway.scim) this.config.scimgateway.scim = {}
    if (!this.config.scimgateway.log) this.config.scimgateway.log = {}
    if (!this.config.scimgateway.log.loglevel) this.config.scimgateway.log.loglevel = {}
    if (!this.config.scimgateway.auth) this.config.scimgateway.auth = {}
    if (!this.config.scimgateway.auth.basic) this.config.scimgateway.auth.basic = []
    if (!this.config.scimgateway.auth.bearerToken) this.config.scimgateway.auth.bearerToken = []
    if (!this.config.scimgateway.auth.bearerJwt) this.config.scimgateway.auth.bearerJwt = []
    if (!this.config.scimgateway.auth.bearerOAuth) this.config.scimgateway.auth.bearerOAuth = []
    if (!this.config.scimgateway.auth.passThrough) this.config.scimgateway.auth.passThrough = {}
    this.config.scimgateway.auth.oauthTokenStore = {}
    if (!this.config.scimgateway.certificate) this.config.scimgateway.certificate = {}
    if (!this.config.scimgateway.certificate.pfx) this.config.scimgateway.certificate.pfx = {}

    if (!this.config.scimgateway.email) this.config.scimgateway.email = {}
    if (!this.config.scimgateway.email.auth) this.config.scimgateway.email.auth = {}
    if (!this.config.scimgateway.email.auth.options) this.config.scimgateway.email.auth.options = {}
    if (!this.config.scimgateway.email.emailOnError) this.config.scimgateway.email.emailOnError = {}
    if (!this.config.scimgateway.email.emailOnError) this.config.scimgateway.email.proxy = {}

    if (!this.config.scimgateway.azureRelay) this.config.scimgateway.azureRelay = {}
    if (!this.config.scimgateway.stream) this.config.scimgateway.stream = {}
    if (!this.config.scimgateway.stream.subscriber) this.config.scimgateway.stream.subscriber = {}
    if (!this.config.scimgateway.stream.publisher) this.config.scimgateway.stream.publisher = {}

    // start - legacy support
    if (this.config.scimgateway?.emailOnError?.smtp?.host) {
      this.config.scimgateway.email.auth.options.host = this.config.scimgateway.emailOnError.smtp.host
    }
    if (this.config.scimgateway?.emailOnError?.smtp?.port) {
      this.config.scimgateway.email.auth.options.port = this.config.scimgateway.emailOnError.smtp.port
    }
    if (this.config.scimgateway?.emailOnError?.smtp?.proxy) {
      this.config.scimgateway.email.proxy = this.config.scimgateway.emailOnError.smtp.proxy
    }
    if (this.config.scimgateway?.emailOnError?.smtp?.username) {
      this.config.scimgateway.email.emailOnError.from = this.config.scimgateway.emailOnError.smtp.username
      this.config.scimgateway.email.auth.options.username = this.config.scimgateway.emailOnError.smtp.username
    }
    if (this.config.scimgateway?.emailOnError?.smtp?.password) {
      this.config.scimgateway.email.auth.options.password = this.config.scimgateway.emailOnError.smtp.password
      this.config.scimgateway.email.auth.type = 'smtp'
    }
    if (this.config.scimgateway?.emailOnError?.smtp?.enabled) {
      this.config.scimgateway.email.emailOnError.enabled = this.config.scimgateway.emailOnError.smtp.enabled
    }
    if (this.config.scimgateway?.emailOnError?.smtp?.sendInterval) {
      this.config.scimgateway.email.emailOnError.sendInterval = this.config.scimgateway.emailOnError.smtp.sendInterval
    }
    if (this.config.scimgateway?.emailOnError?.smtp?.subject) {
      this.config.scimgateway.email.emailOnError.subject = this.config.scimgateway.emailOnError.smtp.subject
    }
    if (this.config.scimgateway?.emailOnError?.smtp?.to) {
      this.config.scimgateway.email.emailOnError.to = this.config.scimgateway.emailOnError.smtp.to
    }
    if (this.config.scimgateway?.emailOnError?.smtp?.cc) {
      this.config.scimgateway.email.emailOnError.cc = this.config.scimgateway.emailOnError.smtp.cc
    }
    // end - legacy support

    if (this.config.scimgateway.ipAllowList && Array.isArray(this.config.scimgateway.ipAllowList) && this.config.scimgateway.ipAllowList.length > 0) {
      ipAllowListChecker = createChecker(this.config.scimgateway.ipAllowList)
    }

    const handler: { [key: string]: any } = {}
    handler.Users = handler.users = {
      description: 'User',
      getMethod: 'getUsers',
      modifyMethod: 'modifyUser',
      createMethod: 'createUser',
      deleteMethod: 'deleteUser',
    }
    handler.Groups = handler.groups = {
      description: 'Group',
      getMethod: 'getGroups',
      modifyMethod: 'modifyGroup',
      createMethod: 'createGroup',
      deleteMethod: 'deleteGroup',
    }
    handler.servicePlans = handler.serviceplans = { // plugin-entra
      description: 'ServicePlan',
      getMethod: 'getServicePlans',
    }
    handler.AppRoles = handler.approles = { // scim-stream
      description: 'AppRoles',
      getMethod: 'getAppRoles',
    }
    /** handlers supported url paths */
    const handlers = ['users', 'groups', 'bulk', 'serviceplans', 'approles', 'api', 'schemas', 'resourcetypes', 'serviceproviderconfig', 'serviceproviderconfigs', 'oauth', '.well-known', 'logger']

    try {
      if (!fs.existsSync(configDir + '/wsdls')) fs.mkdirSync(configDir + '/wsdls')
      if (!fs.existsSync(configDir + '/certs')) fs.mkdirSync(configDir + '/certs')
      if (!fs.existsSync(configDir + '/schemas')) fs.mkdirSync(configDir + '/schemas')
    } catch (err) { void 0 }

    let isScimv2 = false
    if (this.config.scimgateway.scim.version === '2.0' || this.config.scimgateway.scim.version === 2) {
      this.scimDef = utilsScim.loadScimDef('2.0', pluginDir)
      isScimv2 = true
    } else {
      this.scimDef = utilsScim.loadScimDef('1.1', pluginDir)
    }
    const isScimv2Initial = isScimv2

    // multiValueTypes array contains attributes that will be used by "type converted objects" logic
    // groups, roles, and members are excluded
    // default: ['emails','phoneNumbers','ims','photos','addresses','entitlements','x509Certificates']
    // configuration skipTypeConvert = true disables logic by empty multiValueTypes array
    if (this.config.scimgateway.scim.skipTypeConvert === true) this.multiValueTypes = []
    else {
      this.multiValueTypes = utilsScim.getMultivalueTypes('User', this.scimDef) // not icluding 'Group' => 'members' are excluded
      for (let i = 0; i < this.multiValueTypes.length; i++) {
        if (this.multiValueTypes[i] === 'groups' || this.multiValueTypes[i] === 'roles' || this.multiValueTypes[i] === 'members') {
          this.multiValueTypes.splice(i, 1) // delete
          i -= 1
        }
      }
    }

    const logResult = async (ctx: Context) => {
      if (ctx.path === '/ping' || ctx.path === '/favicon.ico' || ctx.path.startsWith('/apple-touch-icon')) return
      const ellapsed = performance.now() - ctx.perfStart
      let userName
      const [authType, authToken] = (ctx.request.headers.get('authorization') ?? '').split(' ') // [0] = 'Basic' or 'Bearer'
      if (authType === 'Basic') [userName] = (Buffer.from(authToken, 'base64').toString() ?? '').split(':')
      if (!userName && authType === 'Bearer') userName = 'token'
      let outbound = ctx.response.body

      if (typeof outbound === 'string' && outbound.includes('"Resources":') && outbound.length > 1500) {
        try {
          const o = JSON.parse(outbound)
          if (o?.Resources?.length > 1) {
            o.Resources = [o.Resources[0]]
            o.Resources.push({ loggerComment: '===OBJECTS TRUNCATED BECAUSE OF LOG LENGTH===' })
            outbound = JSON.stringify(o)
          }
        } catch (err) { }
      }

      const logEvent = {
        baseEntity: ctx?.routeObj?.baseEntity,
        durationMs: ellapsed,
        clientIp: ctx.ip,
        issuer: userName,
        target: ctx.target, // userName/displayName
        status: ctx.response.status,
        method: ctx.request.method,
        url: ctx.request.url,
        requestBody: JSON.stringify(ctx.request.body),
        responseBody: outbound,
      }
      let msg = utils.statusText(logEvent.status)

      if (ctx.response.status && ctx.response.status > 399) {
        try {
          const o = JSON.parse(ctx.response.body as string ?? '')
          if (o.detail) msg = o.detail
          else if (o.Errors && Array.isArray(o.Errors) && o.Errors[0]?.description) msg = o.Errors[0].description
        } catch (err) { }
        if (ctx.response.status === 401 && !ctx.request.headers.has('authorization')) {
          logger.warn(msg, logEvent)
        } else if (ctx.response.status === 404) {
          logger.warn(msg, logEvent)
        } else if (ctx.response.status === 412) {
          logger.info(msg, logEvent)
        } else logger.error(msg, logEvent)
      } else {
        logger.info(msg, logEvent)
      }
    }

    // start auth methods - used by auth
    const basic = async (baseEntity: string, method: string, authType: string, authToken: string): Promise<boolean> => {
      return await new Promise((resolve, reject) => { // basic auth
        if (!found.Basic) return resolve(false)
        if (authType !== 'Basic' || !authToken) return resolve(false)
        const [userName, userPassword] = (Buffer.from(authToken, 'base64').toString() ?? '').split(':')
        if (!userName || !userPassword) return resolve(false)
        const arr = this.config.scimgateway.auth.basic
        for (let i = 0; i < arr.length; i++) {
          if (arr[i].username === userName && arr[i].password === userPassword) { // authentication OK
            if (arr[i].baseEntities) {
              if (Array.isArray(arr[i].baseEntities) && arr[i].baseEntities.length > 0) {
                if (!arr[i].baseEntities.includes(baseEntity)) return reject(new Error(`baseEntity=${baseEntity} not allowed for user ${arr[i].username} according to basic configuration baseEntitites=${arr[i].baseEntities}`))
              }
            }
            if (arr[i].readOnly === true && method !== 'GET') return reject(new Error(`only allowing readOnly for user ${arr[i].username} according to basic configuration readOnly=true`))
            return resolve(true)
          }
        }
        resolve(false)
      })
    }

    const bearerToken = async (baseEntity: string, method: string, authType: string, authToken: string): Promise<boolean> => {
      return await new Promise((resolve, reject) => { // bearer token
        if (!found.BearerToken) return resolve(false)
        if (authType !== 'Bearer' || !authToken) return resolve(false)
        const arr = this.config.scimgateway.auth.bearerToken
        for (let i = 0; i < arr.length; i++) {
          if (arr[i].token === authToken) { // authentication OK
            if (arr[i].baseEntities) {
              if (Array.isArray(arr[i].baseEntities) && arr[i].baseEntities.length > 0) {
                if (!arr[i].baseEntities.includes(baseEntity)) return reject(new Error(`baseEntity=${baseEntity} not allowed for this bearerToken according to bearerToken configuration baseEntitites=${arr[i].baseEntities}`))
              }
            }
            if (arr[i].readOnly === true && method !== 'GET') return reject(new Error('only allowing readOnly for this bearerToken according to bearerToken configuration readOnly=true'))
            return resolve(true)
          }
        }
        resolve(false)
      })
    }

    const jwtVerify = async (baseEntity: string, method: string, el: Record<string, any>, authToken: string): Promise<boolean> => { // used by bearerJwt
      try {
        if (el.azureTenantId) {
          el.wellKnownUri = `https://login.microsoftonline.com/${el.azureTenantId}/.well-known/openid-configuration`
          el.customOptions = {
            tid: el.azureTenantId,
            appid: '00000014-0000-0000-c000-000000000000', // Well known appid: Microsoft.Azure.SyncFabric
            aud: [
              // Appid used for SCIM provisioning for non-gallery applications. See changes introduced, in reverse cronological order:
              // - https://github.com/MicrosoftDocs/azure-docs/commit/f6997c0952d2ad4f33ce7f5339eeb83c21b51f1e
              // - https://github.com/MicrosoftDocs/azure-docs/commit/64525fea0675a73b2e6b8fe42fbd03ee568cadfc
              '8adf8e6e-67b2-4cf2-a259-e3dc5476c621',
              // Well known appid: Issued for accessing Windows Azure Active Directory Graph Webservice
              '00000002-0000-0000-c000-000000000000',
            ],
          }
        }
        if (el.wellKnownUri) {
          if (!el.jwks) {
            if (!this.helperRest) this.helperRest = this.newHelperRest()
            let res
            try { // get issuer and jwks_uri from well-knonw uri
              res = await this.helperRest.doRequest('undefined', 'GET', el.wellKnownUri)
            } catch (err: any) {
              throw new Error(`JWKS wellKnownUri=${el.wellKnownUri} error: ${err.message}`)
            }
            if (!res?.body) throw new Error(`JWKS wellKnownUri=${el.wellKnownUri} error: response missing data`)
            const issuer = res.body.issuer
            const jwks_uri = res.body.jwks_uri
            if (!issuer || !jwks_uri) {
              throw new Error(`JWKS wellKnownUri=${el.wellKnownUri} error: found issuer=${issuer} and jwks_uri=${jwks_uri} - both should be found`)
            }
            if (!el.options) el.options = {}
            el.options.issuer = issuer
            el.jwks = jose.createRemoteJWKSet(new URL(jwks_uri)) // will automatically reload the JWKS when verification fails due to an unknown kid
          }
          const { payload } = await jose.jwtVerify(authToken, el.jwks, el.options)
          if (!payload || Object.keys(payload).length < 1) throw new Error('incorrect verification response')
          if (el.customOptions) { // verify non-standard JWT claims
            for (const key in el.customOptions) {
              if (!el.customOptions[key]) continue
              if (Array.isArray(el.customOptions[key])) {
                if (!el.customOptions[key].includes(payload[key])) throw new Error(`${el.azureTenantId ? 'azureTenantId ' : ''}verification of claim '${key}' failed`)
              } else {
                if (payload[key] !== el.customOptions[key]) throw new Error(`${el.azureTenantId ? 'azureTenantId ' : ''}verification of claim '${key}' failed`)
              }
            }
          }
        } else {
          if (el.secret && !el.secretEncoded) {
            el.secretEncoded = new TextEncoder().encode(el.secret)
            if (!el.options) el.options = {}
            el.options.algorithms = ['HS256', 'HS384', 'HS512'] // symmetric algorithms when using secret
          }
          await jose.jwtVerify(authToken, (el.secretEncoded) ? el.secretEncoded : el.publicKeyObj, el.options)
        }
        if (Array.isArray(el?.baseEntities) && el.baseEntities.length > 0) {
          if (!el.baseEntities.includes(baseEntity)) return false
        }
        if (el.readOnly === true && method !== 'GET') return false
        return true // authorization OK
      } catch (err: any) {
        throw new Error(`JWT error: ${err.message}`)
      }
    }

    const bearerJwt = async (baseEntity: string, method: string, authType: string, authToken: string): Promise<boolean> => {
      if (!found.BearerJwt) return false
      if (authType !== 'Bearer' || !authToken) return false
      let payload
      try {
        payload = jose.decodeJwt(authToken)
        if (!payload) return false
      } catch (err: any) {
        return false
      }
      if (found.BearerOAuth) {
        const a = this.config.scimgateway.auth.bearerOAuth
        const confObjs = a.filter((o: any) => o.clientId === payload.aud)
        if (confObjs.length > 0) return false // jwt handled by bearerOauth
      }
      const errs: Array<string> = []
      const arr = this.config.scimgateway.auth.bearerJwt
      for (let i = 0; i < arr.length; i++) {
        try {
          if (await jwtVerify(baseEntity, method, arr[i], authToken) === true) return true
        } catch (err: any) {
          errs.push(err.message)
        }
      }
      if (errs.length > 0) throw new Error(errs.join(' == NextConfigValidation ==> '))
      return false
    }

    const bearerOAuth = async (baseEntity: string, method: string, authType: string, authToken: string): Promise<boolean> => {
      return await new Promise(async (resolve, reject) => { // bearer token
        if (!found.BearerOAuth) return resolve(false)
        if (authType !== 'Bearer' || !authToken) return resolve(false)
        // this.config.scimgateway.auth.oauthTokenStore is autmatically generated by token create having syntax:
        // { this.config.scimgateway.auth.oauthTokenStore: <token>: { expireDate: <timestamp>, readOnly: <copy-from-config>, baseEntities: [ <copy-from-config> ], isTokenRequested: true }}
        let payload
        try {
          payload = jose.decodeJwt(authToken)
          if (!payload || payload.iss !== 'SCIM Gateway' || !payload.aud || !payload.sub) return resolve(false)
        } catch (err: any) {
          return resolve(false)
        }

        const arr = this.config.scimgateway.auth.bearerOAuth
        const confObjs = arr.filter((o: any) => o.clientId === payload.aud)
        if (confObjs.length !== 1) return resolve(false)
        try {
          await jose.jwtVerify(authToken, new TextEncoder().encode(confObjs[0].clientSecret), { algorithms: ['HS256'] })
          authToken = payload.sub
        } catch (err: any) {
          return resolve(false)
        }

        if (this.config.scimgateway.auth.oauthTokenStore[authToken]) { // authentication OK
          const tokenObj = this.config.scimgateway.auth.oauthTokenStore[authToken]
          if (Date.now() > tokenObj.expireDate) {
            delete this.config.scimgateway.auth.oauthTokenStore[authToken]
            const err = new Error('OAuth access token expired')
            err.name = 'invalid_token'
            return reject(err)
          }
          if (tokenObj.baseEntities) {
            if (Array.isArray(tokenObj.baseEntities) && tokenObj.baseEntities.length > 0) {
              if (!tokenObj.baseEntities.includes(baseEntity)) return reject(new Error(`baseEntity=${baseEntity} not allowed according to bearerOAuth configuration baseEntitites=${tokenObj.baseEntities}`))
            }
          }
          if (tokenObj.readOnly === true && method !== 'GET') return reject(new Error('only allowing readOnly according to bearerOAuth configuration readOnly=true'))
          return resolve(true)
        } else {
          for (let i = 0; i < arr.length; i++) { // resolve if token memory store have been cleared because of a gateway restart
            if (arr[i].isTokenRequested || !arr[i].clientSecret) continue
            if (arr[i].baseEntities && Array.isArray(arr[i].baseEntities) && arr[i].baseEntities.length > 0) {
              if (!arr[i].baseEntities.includes(baseEntity)) continue
            }
            if (utils.getEncrypted(authToken, arr[i].clientSecret) === arr[i].clientSecret) {
              arr[i].isTokenRequested = true // flagged as true to not allow repeated resolvements because token will also be cleared when expired
              const baseEntities = utils.copyObj(arr[i].baseEntities)
              let expires
              let readOnly = false
              if (arr[i].readOnly && arr[i].readOnly === true) readOnly = true
              if (arr[i].expires_in && !isNaN(arr[i].expires_in)) expires = arr[i].expires_in
              else expires = oAuthTokenExpire
              this.config.scimgateway.auth.oauthTokenStore[authToken] = {
                expireDate: Date.now() + expires * 1000,
                readOnly,
                baseEntities,
              }
              return resolve(true)
            }
          }
        }
        resolve(false)
      })
    }

    const authPassThrough = async (baseEntity: string, method: string, authType: string, authToken: string, path: string): Promise<boolean> => {
      if (!found.PassThrough || !this.authPassThroughAllowed || path.endsWith('/logger')) return false
      if (!authToken) return false
      if (authType === 'Basic') {
        const [userName, userPassword] = (Buffer.from(authToken, 'base64').toString() ?? '').split(':')
        if (!userName || !userPassword) return false
      }
      const obj = this.config.scimgateway.auth.passThrough
      if (obj.baseEntities) {
        if (Array.isArray(obj.baseEntities) && obj.baseEntities.length > 0) {
          if (!obj.baseEntities.includes(baseEntity)) throw new Error(`baseEntity=${baseEntity} not allowed for passThrough according to passThrough configuration baseEntitites=${obj.baseEntities}`)
        }
      }
      if (obj.readOnly === true && method !== 'GET') throw new Error('only allowing readOnly for passThrough according to passThrough configuration readOnly=true')
      return true
    }

    // end auth methods - used by auth

    const isAuthorized = async (ctx: Context): Promise<boolean> => { // authentication/authorization
      const [authType, authToken] = (ctx.request.headers.get('authorization') ?? '').split(' ') // [0] = 'Basic' or 'Bearer'
      let arrResolve: boolean[] = []
      try {
        // authenticate
        arrResolve = await Promise.all([
          basic(ctx.routeObj.baseEntity, ctx.request.method, authType, authToken),
          bearerToken(ctx.routeObj.baseEntity, ctx.request.method, authType, authToken),
          bearerJwt(ctx.routeObj.baseEntity, ctx.request.method, authType, authToken),
          bearerOAuth(ctx.routeObj.baseEntity, ctx.request.method, authType, authToken),
          authPassThrough(ctx.routeObj.baseEntity, ctx.request.method, authType, authToken, ctx.path),
        ])
      } catch (err: any) {
        if (authType === 'Bearer') {
          let str = 'realm=""'
          if (err?.name === 'invalid_token') {
            str += `, error="${err.name}"`
            if (err.message) {
              str += `, error_description="${err.message}"`
              const errMsg = {
                error: err.name,
                error_description: err.message,
              }
              ctx.response.body = JSON.stringify(errMsg)
            }
          }
          ctx.response.headers.set('www-authenticate', `Bearer ${str}`)
        } else ctx.response.headers.set('www-authenticate', 'Basic realm=""')
        logger.error(`${gwName} ${err.message}`)
        return false
      }
      for (const i in arrResolve) {
        if (arrResolve[i] === true) return true // auth OK - continue with routes
      }
      // all auth validations failed
      if (!authToken) {
        if (found.Basic && ctx.request.headers.has('sec-fetch-dest')) ctx.response.headers.set('www-authenticate', 'Basic realm=""')
        return false
      }
      if (authType === 'Bearer') ctx.response.headers.set('www-authenticate', 'Bearer realm=""')
      else ctx.response.headers.set('www-authenticate', 'Basic realm=""')
      if (pwErrCount < 3) pwErrCount += 1
      else { // delay brute force attempts
        const delay = (this.config.scimgateway.idleTimeout || 120) - 5
        logger.error(`${gwName} ${ctx.request.url} => max authentication failures reached, delaying response with ${delay} seconds to prevent brute force`, { baseEntity: ctx?.routeObj?.baseEntity })
        await new Promise((resolve) => {
          setTimeout(() => { resolve(null) }, 1000 * delay)
        })
      }
      return false
    }

    const ipAllowList = (ipAddr: string): boolean => {
      if (ipAllowListChecker === undefined) return true
      if (ipAllowListChecker(ipAddr) === true) return true // if proxy, prereq: request includes header X-Forwarded-For
      return false
    }

    const getHandlerSchemas = async (ctx: Context) => {
      let tx = this.scimDef.Schemas
      tx = utilsScim.addResources(tx, undefined, undefined, undefined)
      tx = utilsScim.addSchemas(tx, isScimv2, undefined, undefined)
      ctx.response.body = JSON.stringify(tx)
    }
    funcHandler.getHandlerSchemas = getHandlerSchemas

    // scimv2 GET /ResourceTypes, scimv1 not used
    const getHandlerResourceTypes = async (ctx: Context) => {
      const tx = this.scimDef.ResourceType
      if (!this.config.scimgateway.scim.skipMetaLocation) {
        const location = ctx.origin + ctx.path
        if (tx.meta) tx.meta.location = location
        else {
          tx.meta = {}
          tx.meta.location = location
        }
      }
      ctx.response.body = JSON.stringify(tx)
    }
    funcHandler.getHandlerResourceTypes = getHandlerResourceTypes

    // scimv1 = GET /ServiceProviderConfigs, scimv2 GET /ServiceProviderConfig
    const getHandlerServiceProviderConfig = async (ctx: Context) => {
      const tx = this.scimDef.ServiceProviderConfigs
      if (!this.config.scimgateway.scim.skipMetaLocation) {
        const location = ctx.origin + ctx.path
        if (tx.meta) tx.meta.location = location
        else {
          tx.meta = {}
          tx.meta.location = location
        }
      }
      ctx.response.body = JSON.stringify(tx)
    }
    funcHandler.getHandlerServiceProviderConfig = getHandlerServiceProviderConfig

    // getHandlerLogger implements SSE based online publisher for log events
    const getHandlerLoggerSSE = async (ctx: Context) => {
      const levelInt = logger.levelToInt(this.config?.scimgateway?.log?.loglevel?.push || 'info')
      const encoder = new TextEncoder()
      logger.info(`${gwName} remote logger connected from ip address ${ctx.ip}`, { baseEntity: ctx?.routeObj?.baseEntity })

      return new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(encoder.encode(`: keep-alive\n\n`))

            const sub = async (msgObj: Record<string, any>) => {
              if (logger.levelToInt(msgObj.level) < levelInt) return
              if (ctx?.routeObj?.baseEntity !== 'undefined') { // if using baseEntity e.g. <host>/company1/logger, only include corresponding baseEntity logentries
                if (ctx?.routeObj?.baseEntity !== msgObj.baseEntity) return
              }
              controller.enqueue(encoder.encode(`data: ${JSON.stringify(msgObj)}\n\n`))
            }
            logger.subscribe(sub)

            const keepAliveInterval = setInterval(() => {
              controller.enqueue(encoder.encode(`: keep-alive\n\n`))
            }, 10000)

            const cleanup = () => {
              clearInterval(keepAliveInterval)
              logger.unsubscribe(sub)
              controller.close()
              logger.info(`${gwName} remote logger disconnected from ip address ${ctx.ip}`, { baseEntity: ctx?.routeObj?.baseEntity })
            }

            ctx.request.signal.onabort = cleanup // Bun
            ctx.request?.raw?.socket?.on('close', cleanup) // Node detect when the client disconnects
          },
        }),
        {
          status: 200,
          headers: {
            'Connection': 'keep-alive',
            'Content-Type': 'text/event-stream;charset=utf-8',
            'Cache-Control': 'no-cache, no-transform',
            'X-Accel-Buffering': 'no',
            'Content-Encoding': 'identity',
          },
        },
      )
    }

    // oauth well-known: /.well-known/openid-configuration
    // this.jwk is managed by helper-rest oauthJwtBearer - Entra ID Federated Identity
    // { issuer: <scimgateway-baseUrl>, kid: { privateKey, publicKey } }
    // example issuer: https://scimgateway.my-company.com
    const getHandlerOauthWellKnown = async (ctx: Context) => {
      logger.debug(`${gwName} [oauth] .well-known request`)
      if (!this.jwk || (Object.keys(this.jwk).length < 1)) {
        ctx.response.body = '{}'
        ctx.response.status = 200
        return ctx
      }
      const issuer = this.jwk.issuer
      let body = {
        issuer,
        jwks_uri: issuer + '/.well-known/jwks.json',
      }
      ctx.response.body = JSON.stringify(body)
      ctx.response.status = 200
    }

    // oauth JWKS: /.well-known/jwks.json
    // this.jwk is managed by helper-rest oauthJwtBearer - Entra ID Federated Identity
    // { issuer: <scimgateway-baseUrl>, kid: { privateKey, publicKey } }
    const getHandlerOauthJwks = async (ctx: Context) => {
      logger.debug(`${gwName} [oauth] jwks_uri request`)
      if (!this.jwk || (Object.keys(this.jwk).length < 1)) {
        ctx.response.body = '{"keys":[]}'
        ctx.response.status = 200
        return ctx
      }
      const keys: Array<Record<string, any>> = []
      for (const kid in this.jwk) {
        const keyObj = this.jwk[kid]
        if (typeof keyObj !== 'object' || keyObj === null) continue
        const jwk = await jose.exportJWK(this.jwk[kid].publicKey)
        jwk.kid = kid // needed for JWKS
        keys.push(jwk)
      }
      let body = {
        keys,
      }
      ctx.response.body = JSON.stringify(body)
      ctx.response.status = 200
    }

    // oauth token request, POST /oauth/token
    const postHandlerOauthToken = async (ctx: Context) => {
      const baseEntity = ctx.routeObj.baseEntity
      logger.debug(`${gwName} [oauth] token request`)
      if (!found.BearerOAuth) {
        logger.error(`${gwName} [oauth] token request, but plugin is missing auth.bearerOAuth configuration`)
        ctx.response.status = 500
        return
      }
      let jsonBody = ctx.request.body
      try {
        if (!jsonBody) throw new Error('missing body')
        if (typeof jsonBody !== 'object') { // might have application/x-www-form-urlencoded or multipart/form-data body, but incorrect Content-Type header
          logger.debug(`${gwName} [oauth] continue request validation even though incorrect body vs header Content-Type: ${ctx.request.headers.get('content-type')}`)
          let body = utils.formUrlEncodedToJSON(jsonBody)
          if (Object.keys(body).length < 1) {
            body = utils.formDataMultipartToJSON(jsonBody)
            if (Object.keys(body).length < 1) throw new Error('body is not JSON, application/x-www-form-urlencoded nor multipart/form-data')
          }
          ctx.request.body = body // now json - ensure final info log will be masked
          jsonBody = body
        }
        jsonBody = utils.copyObj(jsonBody) // no changes to original
      } catch (err: any) {
        logger.error(`${gwName} [oauth] token request error: ${err.message}`)
        ctx.response.status = 401
        return
      }
      const [authType, authToken] = (ctx.request.headers.get('authorization') ?? '').split(' ') // [0] = 'Basic'
      if (authType === 'Basic') { // id and secret may be in authorization header if not already included in body
        const [id, secret] = (Buffer.from(authToken, 'base64').toString() ?? '').split(':')
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
        const arr = this.config.scimgateway.auth.bearerOAuth
        for (let i = 0; i < arr.length; i++) {
          if (!arr[i].clientId || !arr[i].clientSecret) continue
          if (arr[i].clientId === jsonBody.client_id && arr[i].clientSecret === jsonBody.client_secret) { // authentication OK
            if (Array.isArray(arr[i].baseEntities) && arr[i].baseEntities.length > 0) {
              if (!arr[i].baseEntities.includes(baseEntity)) continue
            }
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
          errDescr = 'incorrect or missing client_id/client_secret or baseEntity'
          if (pwErrCount < 3) {
            pwErrCount += 1
          } else { // delay brute force attempts
            const delay = (this.config.scimgateway.idleTimeout || 120) - 5
            logger.error(`${gwName} [oauth] ${ctx.origin + ctx.path} ${errDescr} => delaying response with ${delay} seconds to prevent brute force`)
            await new Promise((resolve) => {
              setTimeout(() => {
                resolve(ctx)
              }, 1000 * delay)
            })
            ctx.response.status = 401
            return
          }
        }
      }

      if (err) {
        logger.error(`${gwName} [oauth] token request client_id: ${jsonBody ? jsonBody.client_id : ''} error: ${errDescr}`, { baseEntity: ctx?.routeObj?.baseEntity })
        ctx.response.status = 401
        const errMsg = {
          error: err,
          error_description: errDescr,
        }
        ctx.response.body = JSON.stringify(errMsg)
        return
      }

      const dtNow = Date.now()
      for (const i in this.config.scimgateway.auth.oauthTokenStore) { // cleanup any expired tokens
        const tokenObj = this.config.scimgateway.auth.oauthTokenStore[i]
        if (dtNow > tokenObj.expireDate) {
          delete this.config.scimgateway.auth.oauthTokenStore[i]
        }
      }

      this.config.scimgateway.auth.oauthTokenStore[token] = { // update token store
        expireDate: dtNow + expires * 1000, // 1 hour
        readOnly,
        baseEntities,
      }

      const jwtPayload: jose.JWTPayload = {
        iss: 'SCIM Gateway',
        aud: jsonBody.client_id,
        sub: token,
        iat: Math.floor(Date.now() / 1000) - 60,
        exp: Math.floor(Date.now() / 1000) + expires,
      }
      const jwtHeaders = {
        alg: 'HS256',
        typ: 'JWT',
      }
      const jwt = await new jose.SignJWT(jwtPayload)
        .setProtectedHeader(jwtHeaders)
        .sign(new TextEncoder().encode(jsonBody.client_secret))

      const tx = {
        access_token: jwt,
        token_type: 'Bearer',
        expires_in: expires,
        refresh_token: jwt, // ignored by scimgateway, but maybe used by client
      }

      ctx.response.headers.set('Cache-Control', 'no-store')
      ctx.response.body = JSON.stringify(tx)
      ctx.response.status = 200
    }

    // ==========================================
    //           getUser by id
    //           getGroup by id
    // ==========================================
    const getHandlerId = async (ctx: Context) => {
      const handle = handler[ctx.routeObj.handle]
      const baseEntity = ctx.routeObj.baseEntity
      const id = decodeURIComponent(path.basename(ctx.routeObj.id ?? '', '.json')) // supports <id>.json

      if (!id) {
        const err = new Error('missing id')
        const [e, statusCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, 500, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
        return
      }
      if (ctx.query.attributes) ctx.query.attributes = ctx.query.attributes.split(',').filter(Boolean).map((item: string) => item.trim()).join()
      if (ctx.query.excludedAttributes) ctx.query.excludedAttributes = ctx.query.excludedAttributes.split(',').filter(Boolean).map((item: string) => item.trim()).join()

      const getObj = {
        attribute: 'id',
        operator: 'eq',
        value: id,
      }

      logger.debug(`${gwName} [Get ${handle.description}] ${getObj.attribute}=${getObj.value}`, { baseEntity: ctx?.routeObj?.baseEntity })

      try {
        const ob = utils.copyObj(getObj)
        const attributes: string[] = ctx.query.attributes ? ctx.query.attributes.split(',').map((item: string) => item.trim()) : []
        if (attributes.length > 0 && !attributes.includes('id')) attributes.push('id')
        logger.debug(`${gwName} calling ${handle.getMethod}`, { baseEntity: ctx?.routeObj?.baseEntity })
        let res = await (this as any)[handle.getMethod](baseEntity, ob, attributes, ctx.passThrough)

        let scimdata: { [key: string]: any } = {
          Resources: [],
          totalResults: null,
        }
        if (res) {
          if (res.Resources && Array.isArray(res.Resources)) {
            scimdata.Resources = res.Resources
            scimdata.totalResults = res.totalResults
          } else if (Array.isArray(res)) scimdata.Resources = res
          else if (typeof (res) === 'object' && Object.keys(res).length > 0) scimdata.Resources[0] = res
        }

        if (scimdata.Resources.length !== 1) {
          const err = new Error(`${handle.description} ${getObj.value} not found`)
          const [e, statusCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, 404, err)
          ctx.response.status = statusCode
          ctx.response.body = JSON.stringify(e)
          return
        }
        const obj = scimdata.Resources[0]
        const eTag = utils.getEtag(obj)

        const eTagIfMatch = ctx.request.headers.get('if-match')?.split(',').map((item: string) => item.trim()).filter(Boolean)
        const eTagIfNoneMatch = ctx.request.headers.get('if-none-match')?.split(',').map((item: string) => item.trim()).filter(Boolean)

        if (obj.userName) ctx.target = obj.userName
        else if (obj.externalId) ctx.target = obj.externalId
        else if (obj.displayName) ctx.target = obj.displayName

        if (eTag) {
          if (eTagIfMatch && !eTagIfMatch.includes(eTag) && !eTagIfMatch.includes('*')) {
            ctx.response.headers.set('ETag', eTag)
            ctx.response.status = 412 // Precondition Failed
            const err = new Error(`ETag If-Match mismatch: ${eTagIfMatch} != ${eTag}`)
            const [e] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
            ctx.response.body = JSON.stringify(e)
            return
          } else if (eTagIfNoneMatch && (eTagIfNoneMatch.includes(eTag) || eTagIfNoneMatch.includes('*'))) {
            ctx.response.headers.set('ETag', eTag)
            ctx.response.status = 304 // Not Modified
            return
          }
        }

        // check for user attribute groups and include if needed
        if (handle.getMethod === handler.users.getMethod && Object.keys(obj).length > 0) {
          if (attributes.length === 0 || attributes.includes('groups')) { // include groups
            if (!obj.groups && obj.id) {
              obj.groups = await getMemberOf(baseEntity, obj.id, handler.groups.getMethod, ctx.passThrough)
            }
          }
        }

        scimdata = utils.stripObj(obj, ctx.query.attributes, ctx.query.excludedAttributes)
        scimdata = utilsScim.addSchemas(scimdata, isScimv2, handle.description, undefined)

        if (!this.config.scimgateway.scim.skipMetaLocation) {
          const location = ctx.origin + ctx.path
          if (scimdata.meta) scimdata.meta.location = location
          else {
            scimdata.meta = {}
            scimdata.meta.location = location
          }
        }
        ctx.response.body = JSON.stringify(scimdata)
        if (eTag) ctx.response.headers.set('ETag', eTag)
        if (scimdata?.meta?.location) ctx.response.headers.set('Location', scimdata.meta.location)
      } catch (err: any) {
        const [e, statusCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, 404, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
      }
    }
    funcHandler.getHandlerId = getHandlerId

    // ==========================================
    //           getUsers
    //           getGroups
    // ==========================================
    const getHandler = async (ctx: Context) => {
      const handle = handler[ctx.routeObj.handle]
      const baseEntity = ctx.routeObj.baseEntity
      if (ctx.query.attributes) ctx.query.attributes = ctx.query.attributes.split(',').filter(Boolean).map((item: string) => item.trim()).join()
      if (ctx.query.excludedAttributes) ctx.query.excludedAttributes = ctx.query.excludedAttributes.split(',').filter(Boolean).map((item: string) => item.trim()).join()

      const getObj: any = {
        attribute: undefined,
        operator: undefined,
        value: undefined,
        rawFilter: ctx.query.filter, // included for advanced filtering
        startIndex: undefined,
        count: undefined,
      }

      if (ctx.query.filter) {
        ctx.query.filter = ctx.query.filter.trim()
        const arrFilter = ctx.query.filter.split(' ')
        if (arrFilter.length === 3 || (arrFilter.length > 2 && arrFilter[2].startsWith('"') && arrFilter[arrFilter.length - 1].endsWith('"'))) {
          getObj.attribute = arrFilter[0] // userName
          getObj.operator = arrFilter[1].toLowerCase() // eq
          const value = arrFilter.slice(2).join(' ').replace(/"/g, '')
          try {
            getObj.value = decodeURIComponent(value) // bjensen
          } catch (err) { // e.g., character '%' in string - 'name%test' 
            getObj.value = value
          }
        }
      }

      let err
      if (getObj.attribute) {
        if (this.multiValueTypes.includes(getObj.attribute) || getObj.attribute === 'roles') {
          getObj.attribute = `${getObj.attribute}.value` // emails => emails.value
        } else if (getObj.attribute.includes('[')) { // e.g. rawFilter = emails[type eq "work"]
          const rePattern = /^(.*)\[(.*) (.*) (.*)\]$/
          const arrMatches = ctx.query?.filter?.match(rePattern)
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
        if (isScimv2) ctx.response.status = 400
        else ctx.response.status = 500
        const [e, statusCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
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
      // ---- no filtering - simpel filtering - advanced filtering ----
      // GET /Users
      // GET /Groups
      // GET /Users?attributes=userName&startIndex=1&count=100
      // GET /Groups?attributes=displayName
      // GET /Users?filter=meta.created ge "2010-01-01T00:00:00Z"&attributes=userName,id,name.familyName,meta.created
      // GET /Users?filter=emails.value co "@example.com"&attributes=userName,name.familyName,emails&sortBy=name.familyName&sortOrder=descending

      let info = ''
      if (getObj.operator === 'eq' && ['id', 'userName', 'externalId', 'displayName', 'members.value'].includes(getObj.attribute)) info = ` ${getObj.attribute}=${getObj.value}`
      logger.debug(`${gwName} [Get ${handle.description}s]${info}`, { baseEntity: ctx?.routeObj?.baseEntity })
      try {
        getObj.startIndex = ctx.query.startIndex ? parseInt(ctx.query.startIndex) : undefined
        getObj.count = ctx.query.count ? parseInt(ctx.query.count) : undefined
        if (getObj.startIndex && !getObj.count) getObj.count = 200 // defaults to 200 (plugin may override)
        if (getObj.count && !getObj.startIndex) getObj.startIndex = 1

        let res: any
        const obj: any = utils.copyObj(getObj)
        const attributes: string[] = ctx.query.attributes ? ctx.query.attributes.split(',').map((item: string) => item.trim()) : []
        if (attributes.length > 0 && !attributes.includes('id')) attributes.push('id')
        if (!obj.operator && obj.rawFilter && obj.rawFilter.includes(' or ')) {
          // advanced filtering using or logic - used by One Identity Manager
          // e.g.: (id eq "bjensen") or (id eq "jsmith")
          // handled by scimgateway instead of plugins if supported operator being used
          const arr = obj.rawFilter.split(' or ')
          let getObjArr: object[] = []
          for (let i = 0; i < arr.length; i++) {
            arr[i] = arr[i].replace(/\(/g, '').replace(/\)/g, '').trim()
            const arrFilter = arr[i].split(' ')
            if (arrFilter.length === 3 || (arrFilter.length > 2 && arrFilter[2].startsWith('"') && arrFilter[arrFilter.length - 1].endsWith('"'))) {
              const o: any = {}
              o.attribute = arrFilter[0] // id
              o.operator = arrFilter[1].toLowerCase() // eq
              o.value = decodeURIComponent(arrFilter.slice(2).join(' ').replace(/"/g, '')) // bjensen
              getObjArr.push(o)
            } else {
              getObjArr = []
              break
            }
          }
          if (getObjArr.length > 0) {
            const getObj = async (o: Record<string, any>) => {
              return await (this as any)[handle.getMethod](baseEntity, o, attributes, ctx.passThrough)
            }
            const chunk = 5
            const chunkRes: Record<string, any>[] = []
            logger.debug(`${gwName} calling ${handle.getMethod} with chunks`, { baseEntity: ctx?.routeObj?.baseEntity })
            do {
              const arrChunk = getObjArr.splice(0, chunk)
              const results = await Promise.allSettled(arrChunk.map(o => getObj(o))) as { status: 'fulfilled' | 'rejected', reason: any, value: any }[] // processing max chunk async              
              const errors = results.filter(result => result.status === 'rejected').map(result => result.reason.message)
              if (errors.length > 0) {
                const errMsg = `${handle.getMethod} with chunks returned errors: ${errors.join(', ')}`
                throw new Error(errMsg)
              }
              const arrArr = results.map(result => result?.value?.Resources)
              for (let i = 0; i < arrArr.length; i++) {
                Array.prototype.push.apply(chunkRes, arrArr[i])
              }
            } while (getObjArr.length > 0)
            res = { Resources: chunkRes }
          }
        }

        if (!res) { // standard
          logger.debug(`${gwName} calling ${handle.getMethod}`, { baseEntity: ctx?.routeObj?.baseEntity })
          res = await (this as any)[handle.getMethod](baseEntity, obj, attributes, ctx.passThrough)
        }
        // check for user attribute groups and include if needed
        if (Array.isArray(res?.Resources)) {
          if (handle.getMethod === handler.users.getMethod) {
            if (attributes.length === 0 || attributes.includes('groups')) { // include groups
              for (let i = 0; i < res.Resources.length; i++) {
                const userObj = res.Resources[i]
                if (!userObj.id) break
                if (userObj.groups) break
                userObj.groups = await getMemberOf(baseEntity, userObj.id, handler.groups.getMethod, ctx.passThrough)
              }
            }
          }
        }
        let scimdata: { [key: string]: any } = {
          Resources: [],
          totalResults: null,
        }
        if (res) {
          if (res.Resources && Array.isArray(res.Resources)) {
            scimdata.Resources = res.Resources
            scimdata.totalResults = res.totalResults
          } else if (Array.isArray(res)) scimdata.Resources = res
          else if (typeof (res) === 'object' && Object.keys(res).length > 0) scimdata.Resources[0] = res
        }

        if (scimdata.Resources.length === 1) {
          const obj = scimdata.Resources[0]
          if (obj.userName) ctx.target = obj.userName
          else if (obj.externalId) ctx.target = obj.externalId
          else if (obj.displayName) ctx.target = obj.displayName
        }

        let location: string | undefined = ctx.origin + ctx.path
        if (this.config.scimgateway.scim.skipMetaLocation) location = undefined
        else if (ctx.query.excludedAttributes && ctx.query.excludedAttributes.includes('meta')) location = undefined
        for (let i = 0; i < scimdata.Resources.length; i++) {
          utils.getEtag(scimdata.Resources[i])
          scimdata.Resources[i] = utils.stripObj(scimdata.Resources[i], ctx.query.attributes, ctx.query.excludedAttributes)
        }
        scimdata = utilsScim.addResources(scimdata, ctx.query.startIndex, ctx.query.sortBy, ctx.query.sortOrder)
        scimdata = utilsScim.addSchemas(scimdata, isScimv2, handle.description, location)

        ctx.response.body = JSON.stringify(scimdata)
      } catch (err: any) {
        if (isScimv2) ctx.response.status = 400
        else ctx.response.status = 500
        const [e, statusCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
      }
    }
    funcHandler.getHandler = getHandler

    // ==========================================
    //           createUser
    //           createGroup
    // ==========================================
    //
    // POST = /Users
    // POST = /Groups
    // Body contains user/group object
    // Body example:
    // {"active":true,"name":{"familyName":"Elshaug","givenName":"Jarle"},"schemas":["urn:scim:schemas:core:1.0"],"userName":"jael01"}
    // {"displayName":"MyGroup","externalId":"MyExternal","schemas":["urn:scim:schemas:core:1.0"]}
    //
    const postHandler = async (ctx: Context) => {
      const handle = handler[ctx.routeObj.handle]
      const baseEntity = ctx.routeObj.baseEntity
      logger.debug(`${gwName} [Create ${handle.description}]`, { baseEntity: ctx?.routeObj?.baseEntity })
      let jsonBody = ctx.request.body
      try {
        if (!jsonBody) throw new Error('missing body')
        if (typeof jsonBody !== 'object' || jsonBody === null) throw new Error('body is not JSON')
        jsonBody = utils.copyObj(jsonBody) // no changes to original
      } catch (err: any) {
        const [e, statusCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, 500, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
        return
      }

      if (jsonBody.userName) ctx.target = jsonBody.userName
      else if (jsonBody.externalId) ctx.target = jsonBody.externalId
      else if (jsonBody.displayName) ctx.target = jsonBody.displayName

      if (handle.createMethod === 'createUser' && !jsonBody.userName && !jsonBody.externalId) {
        const err = new Error('userName or externalId is mandatory')
        const [e, statusCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, 500, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
        return
      } else if (handle.createMethod === 'createGroup' && !jsonBody.displayName && !jsonBody.externalId) {
        const err = new Error('displayName or externalId is mandatory')
        const [e, statusCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, 500, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
        return
      }

      logger.debug(`${gwName} POST ${ctx.origin + ctx.path} body=${JSON.stringify(jsonBody)}`, { baseEntity: ctx?.routeObj?.baseEntity })
      const [scimdata, err] = utilsScim.convertedScim(jsonBody, this.multiValueTypes)
      logger.debug(`${gwName} convertedBody=${JSON.stringify(scimdata)}`, { baseEntity: ctx?.routeObj?.baseEntity })
      if (err) {
        const [e, statusCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, 500, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
        return
      }
      delete jsonBody.id // in case included in request
      const addGrps: any = []
      try {
        if (scimdata.groups && Array.isArray(scimdata.groups) && handle.createMethod === 'createUser') {
          if (!this.config.scimgateway.scim.groupMemberOfUser) {
            for (let i = 0; i < scimdata.groups.length; i++) {
              if (!scimdata.groups[i].value) continue
              addGrps.push(decodeURIComponent(scimdata.groups[i].value))
            }
            delete scimdata.groups
          }
        }
        logger.debug(`${gwName} calling ${handle.createMethod}`, { baseEntity: ctx?.routeObj?.baseEntity })
        const res = await (this as any)[handle.createMethod](baseEntity, scimdata, ctx.passThrough)
        for (const key in res) { // merge any result e.g: {'id': 'xxxx'}
          jsonBody[key] = res[key]
        }

        if (!jsonBody.id) { // retrieve all attributes including id
          let res: any
          let obj: any
          try {
            if (handle.createMethod === 'createUser') {
              const attributes: string[] = []
              if (jsonBody.userName) obj = { attribute: 'userName', operator: 'eq', value: jsonBody.userName }
              else if (jsonBody.externalId) obj = { attribute: 'externalId', operator: 'eq', value: jsonBody.externalId }
              res = await (this as any)[handle.getMethod](baseEntity, obj, attributes, ctx.passThrough)
            } else if (handle.createMethod === 'createGroup') {
              const attributes: string[] = []
              if (jsonBody.externalId) obj = { attribute: 'externalId', operator: 'eq', value: jsonBody.externalId }
              else if (jsonBody.displayName) obj = { attribute: 'displayName', operator: 'eq', value: jsonBody.displayName }
              res = await (this as any)[handle.getMethod](baseEntity, obj, attributes, ctx.passThrough)
            }
          } catch (err: any) {
            logger.warn(`${gwName} ${handle.createMethod} succeeded, but corresponding ${handle.getMethod} ${obj?.value} failed with error: ${err.message}`, { baseEntity: ctx?.routeObj?.baseEntity })
          }
          if (res?.Resources && Array.isArray(res.Resources) && res.Resources.length === 1) {
            if (res.Resources[0]?.id) jsonBody = res.Resources[0] // id found, using returned object
          }
        }

        const eTag = utils.getEtag(jsonBody)
        if (addGrps.length > 0 && handle.createMethod === 'createUser') { // add group membership
          const addGroups = async (groupId: string) => {
            return await (this as any)[handler.groups.modifyMethod](baseEntity, groupId, { members: [{ value: jsonBody.id }] }, ctx.passThrough)
          }
          const res = await Promise.allSettled(addGrps.map((groupId: string) => addGroups(groupId)))
          const errAdd = res.filter(result => result.status === 'rejected').map(result => result.reason.message)
          if (errAdd.length > 0) {
            const errMsg = `user created, but there are group membership errors: ${errAdd.join(', ')}`
            throw new Error(errMsg)
          }
          jsonBody.groups = []
          addGrps.forEach((el: any) => {
            jsonBody.groups.push({ value: el, type: 'direct' })
          })
        }

        if (!this.config.scimgateway.scim.skipMetaLocation) {
          const location = ctx.origin + `${ctx.path}/${encodeURIComponent(decodeURIComponent(jsonBody.id))}`
          if (!jsonBody.meta) jsonBody.meta = {}
          jsonBody.meta.location = location
        }
        jsonBody = utilsScim.addSchemas(jsonBody, isScimv2, handle.description, undefined)
        if (eTag) ctx.response.headers.set('ETag', eTag)
        if (jsonBody?.meta?.location) ctx.response.headers.set('Location', jsonBody.meta.location)
        ctx.response.status = 201
        ctx.response.body = JSON.stringify(jsonBody)
      } catch (err: any) {
        if (isScimv2) ctx.response.status = 400
        else ctx.response.status = 500
        const [e, statusCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
      }
    } // post
    funcHandler.postHandler = postHandler

    // ==========================================
    //           deleteUser
    //           deleteGroup
    // ==========================================
    //
    // DELETE /Users/<id>
    // DELETE /Groups/<id>
    //
    const deleteHandler = async (ctx: Context) => {
      const handle = handler[ctx.routeObj.handle] // h = Users/Groups
      const baseEntity = ctx.routeObj.baseEntity
      const id = decodeURIComponent(ctx.routeObj.id ?? '')
      if (!id || id.includes('/')) {
        const err = new Error('missing id')
        const [e, statusCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, 500, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
        return
      }
      logger.debug(`${gwName} [Delete ${handle.description}] id=${id}`, { baseEntity: ctx?.routeObj?.baseEntity })

      if (handle.getMethod === handler.users.getMethod || handle.getMethod === handler.groups.getMethod) { // getUsers/getGroups implemented
        // get userName/displayName for logging purposes
        const obj = { attribute: 'id', operator: 'eq', value: id }
        let res: any
        try {
          res = await (this as any)[handle.getMethod](baseEntity, obj, [], ctx.passThrough)
          if (res?.Resources?.length === 1) {
            const obj = res.Resources[0]
            logger.debug(`${gwName} ${handle.description?.toLowerCase()} to be deleted: ${JSON.stringify(obj)}`, { baseEntity: ctx?.routeObj?.baseEntity })
            if (obj.userName) ctx.target = obj.userName
            else if (obj.externalId) ctx.target = obj.externalId
            else if (obj.displayName) ctx.target = obj.displayName
          }
        } catch (err) { }
      }

      try {
        if (handle.deleteMethod === 'deleteUser') {
          // remove user from groups before deleting user
          const groups = await getMemberOf(baseEntity, id, handler.groups.getMethod, ctx.passThrough)
          if (Array.isArray(groups) && groups.length > 0) {
            const revokeGroupMember = async (grpId: string) => {
              return await (this as any)[handler.groups.modifyMethod](baseEntity, grpId, { members: [{ operation: 'delete', value: id }] }, ctx.passThrough)
            }
            await Promise.allSettled(groups.map((grp: any) => {
              if (grp.value) return revokeGroupMember(grp.value)
              return Promise.resolve()
            })) // result not handled - ignore any failures
          }
        }

        logger.debug(`${gwName} calling ${handle.deleteMethod}`, { baseEntity: ctx?.routeObj?.baseEntity })
        await (this as any)[handle.deleteMethod](baseEntity, id, ctx.passThrough)
        ctx.response.status = 204
      } catch (err: any) {
        const [e, statusCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, 500, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
      }
    }
    funcHandler.deleteHandler = deleteHandler

    // ==========================================
    //          modifyUser
    //          modifyGroup
    // ==========================================
    //
    // PATCH = /Users/<id>
    // PATCH = /Groups/<id>
    // Body contains groups attributes to be updated
    // example: {"members":[{"value":"bjensen"}],"schemas":["urn:scim:schemas:core:1.0"]}
    //
    const patchHandler = async (ctx: Context) => {
      if (ctx.query.attributes) ctx.query.attributes = ctx.query.attributes.split(',').filter(Boolean).map((item: string) => item.trim()).join()
      if (ctx.query.excludedAttributes) ctx.query.excludedAttributes = ctx.query.excludedAttributes.split(',').filter(Boolean).map((item: any) => item.trim()).join()
      const handle = handler[ctx.routeObj.handle]
      const baseEntity = ctx.routeObj.baseEntity
      const id = ctx.routeObj.id ? decodeURIComponent(ctx.routeObj.id) : ctx.routeObj.id

      const jsonBody = ctx.request.body
      try {
        if (!jsonBody) throw new Error('missing body')
        if (typeof jsonBody !== 'object' || jsonBody === null) throw new Error('body is not JSON')
        if (!id || id.includes('/')) throw new Error('missing id')
      } catch (err: any) {
        const [e, statusCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, 500, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
        return
      }

      logger.debug(`${gwName} [Modify ${handle.description}] id=${id}`, { baseEntity: ctx?.routeObj?.baseEntity })

      const eTagIfMatch = ctx.request.headers.get('if-match')?.split(',').map((item: string) => item.trim()).filter(Boolean)
      const eTagIfNoneMatch = ctx.request.headers.get('if-none-match')?.split(',').map((item: string) => item.trim()).filter(Boolean)
      if (eTagIfMatch || eTagIfNoneMatch) {
        let eTag = ''
        if (handle.getMethod === handler.users.getMethod || handle.getMethod === handler.groups.getMethod) { // getUsers or getGroups implemented
          const ob = { attribute: 'id', operator: 'eq', value: id }
          logger.debug(`${gwName} calling ${handle.getMethod}`, { baseEntity: ctx?.routeObj?.baseEntity })
          const res = await (this as any)[handle.getMethod](baseEntity, ob, [], ctx.passThrough)
          if (res) {
            let obj: any
            if (res.Resources && Array.isArray(res.Resources)) {
              if (res.Resources.length === 1) {
                obj = res.Resources[0]
              }
            } else if (Array.isArray(res)) {
              if (res.length === 1) {
                obj = res[0]
              }
            } else if (typeof (res) === 'object' && res !== null) obj = res[0]
            if (obj) {
              eTag = utils.getEtag(obj)
              if (obj.userName) ctx.target = obj.userName
              else if (obj.externalId) ctx.target = obj.externalId
              else if (obj.displayName) ctx.target = obj.displayName
            }
          }
        }
        if (eTag)
          if (eTagIfMatch && !eTagIfMatch.includes(eTag) && !eTagIfMatch.includes('*')) {
            ctx.response.headers.set('ETag', eTag)
            ctx.response.status = 412 // Precondition Failed
            const err = new Error(`ETag If-Match mismatch: ${eTagIfMatch} != ${eTag}`)
            const [e] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
            ctx.response.body = JSON.stringify(e)
            return
          } else if (eTagIfNoneMatch && (eTagIfNoneMatch.includes(eTag) || eTagIfNoneMatch.includes('*'))) {
            ctx.response.headers.set('ETag', eTag)
            ctx.response.status = 412 // Precondition Failed
            return
          }
      }

      let scimdata: any, err: any
      if (jsonBody.Operations) [scimdata, err] = utilsScim.convertedScim20(jsonBody, this.multiValueTypes) // v2.0
      else [scimdata, err] = utilsScim.convertedScim(jsonBody, this.multiValueTypes) // v1.1
      logger.debug(`${gwName} convertedBody=${JSON.stringify(scimdata)}`, { baseEntity: ctx?.routeObj?.baseEntity })
      if (err) {
        const [e, statusCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, 500, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
        return
      }
      delete scimdata.id
      const groups: any = []
      if (scimdata.groups && Array.isArray(scimdata.groups) && handle.modifyMethod === 'modifyUser') {
        if (!this.config.scimgateway.scim.groupMemberOfUser) {
          for (let i = 0; i < scimdata.groups.length; i++) {
            if (!scimdata.groups[i].value) continue
            const obj: any = utils.copyObj(scimdata.groups[i])
            obj.value = decodeURIComponent(obj.value)
            groups.push(obj)
          }
          delete scimdata.groups
        }
      }
      try {
        let res: any
        if (Array.isArray(scimdata.members) && scimdata.members.length === 0 && handle.modifyMethod === 'modifyGroup') {
          res = await replaceUsrGrp(ctx.routeObj.handle, baseEntity, id, scimdata, this.config.scimgateway.scim.usePutSoftSync, ctx.passThrough, undefined)
        } else {
          logger.debug(`${gwName} calling ${handle.modifyMethod}`, { baseEntity: ctx?.routeObj?.baseEntity })
          res = await (this as any)[handle.modifyMethod](baseEntity, id, scimdata, ctx.passThrough)
        }

        if (groups.length > 0 && handle.modifyMethod === 'modifyUser') { // modify user includes groups, add/remove group membership
          const updateGroup = async (groupsObj: Record<string, any>) => {
            const groupId = groupsObj.value
            const memberObj: any = { value: id }
            if (groupsObj.operation) memberObj.operation = groupsObj.operation
            return await (this as any)[handler.groups.modifyMethod](baseEntity, groupId, { members: [memberObj] }, ctx.passThrough)
          }
          const res = await Promise.allSettled(groups.map((groupsObj: Record<string, any>) => updateGroup(groupsObj)))
          const errRes = res.filter(result => result.status === 'rejected').map(result => result.reason.message)
          if (errRes.length > 0) {
            const errMsg = `modify user group membership error: ${errRes.join(', ')}`
            throw new Error(errMsg)
          }
        }

        if (!res) { // include full object in response, TODO: include groups
          if (handle.getMethod !== handler.users.getMethod && handle.getMethod !== handler.groups.getMethod) { // getUsers or getGroups not implemented
            ctx.response.status = 204
            return
          }
          const ob = { attribute: 'id', operator: 'eq', value: id }
          logger.debug(`${gwName} calling ${handle.getMethod}`, { baseEntity: ctx?.routeObj?.baseEntity })
          res = await (this as any)[handle.getMethod](baseEntity, ob, [], ctx.passThrough)
        }

        scimdata = {
          Resources: [],
        }
        if (res) {
          if (res.Resources && Array.isArray(res.Resources)) {
            scimdata.Resources = res.Resources
          } else if (Array.isArray(res)) scimdata.Resources = res
          else if (typeof (res) === 'object') scimdata.Resources[0] = res
          else scimdata.Resources = []
          if (scimdata.Resources.length === 1) {
            const obj = scimdata.Resources[0]
            if (obj.userName) ctx.target = obj.userName
            else if (obj.externalId) ctx.target = obj.externalId
            else if (obj.displayName) ctx.target = obj.displayName
          }
        } else scimdata.Resources = []
        if (scimdata.Resources.length === 0 || scimdata.Resources.length > 1) {
          ctx.response.status = 204
          return
        }

        const userObj = scimdata.Resources[0]
        const eTag = utils.getEtag(userObj)
        if (!this.config.scimgateway.scim.skipMetaLocation) {
          const location = ctx.origin + ctx.path
          if (!userObj.meta) userObj.meta = {}
          userObj.meta.location = location
        }

        scimdata = utils.stripObj(userObj, ctx.query.attributes, ctx.query.excludedAttributes)
        scimdata = utilsScim.addSchemas(scimdata, isScimv2, handle.description, undefined)
        if (eTag) ctx.response.headers.set('ETag', eTag)
        if (scimdata?.meta?.location) ctx.response.headers.set('Location', scimdata.meta.location)
        ctx.response.status = 200
        ctx.response.body = JSON.stringify(scimdata)
      } catch (err: any) {
        const [e, statusCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, 500, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
      }
    } // patch
    funcHandler.patchHandler = patchHandler

    // ==========================================
    //          Replace User
    //          Replace Group
    // ==========================================
    const replaceUsrGrp = async (h: string, baseEntity: string, id: string | undefined, obj: Record<string, any>, usePutSoftSync: boolean | undefined, ctxPassThrough: Record<string, any> | undefined, headers: Headers | undefined) => {
      const handle = handler[h] // h = Users/Groups
      if (!id) throw new Error('missing id')
      id = decodeURIComponent(id)

      // get current object
      logger.debug(`${gwName} calling ${handle.getMethod}`, { baseEntity })
      const res = await (this as any)[handle.getMethod](baseEntity, { attribute: 'id', operator: 'eq', value: id }, [], ctxPassThrough)
      logger.debug(`${gwName} "${handle.getMethod}" result: ${res ? JSON.stringify(res) : ''}`, { baseEntity })
      let currentObj
      if (res && res.Resources && Array.isArray(res.Resources)) {
        if (res.Resources.length === 1) currentObj = res.Resources[0]
        else currentObj = {}
      } else if (Array.isArray(res) && res.length === 1) currentObj = res[0]
      else if (res && typeof (res) === 'object' && Object.keys(res).length > 0) currentObj = res
      else currentObj = {}

      if (typeof (currentObj) !== 'object' || Object.keys(currentObj).length === 0) {
        const err = new Error(`put using method ${handle.getMethod} error: ${handle.description.toLowerCase()} id=${id} does not exist`)
        err.name += '#404'
        throw err
      }

      const eTagIfMatch = headers ? headers.get('if-match')?.split(',').map((item: string) => item.trim()).filter(Boolean) : undefined
      const eTagIfNoneMatch = headers ? headers.get('if-none-match')?.split(',').map((item: string) => item.trim()).filter(Boolean) : undefined
      if (eTagIfMatch || eTagIfNoneMatch) {
        const eTag = utils.getEtag(currentObj)
        if (eTag) {
          if (eTagIfMatch && !eTagIfMatch.includes(eTag) && !eTagIfMatch.includes('*')) {
            const err = new Error(`put using method ${handle.getMethod} error: ETag If-Match mismatch: ${eTagIfMatch} != ${eTag}`)
            err.name += '#412' // Precondition Failed
            throw err
          } else if (eTagIfNoneMatch && (eTagIfNoneMatch.includes(eTag) || eTagIfNoneMatch.includes('*'))) {
            const err = new Error(`put using method ${handle.getMethod} error: ETag If-None-Match mismatch: ${eTagIfNoneMatch} = ${eTag}`)
            err.name += '#412' // Precondition Failed
            throw err
          }
        }
      }

      const activeExists = Object.prototype.hasOwnProperty.call(obj, 'active')
      let objGroups: any
      if (obj.groups) {
        if (!this.config.scimgateway.scim.groupMemberOfUser) {
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

      const [scimdata, err] = utilsScim.convertedScim(obj, this.multiValueTypes)
      if (err) throw err

      // update object
      if (Object.keys(scimdata).length > 0) {
        logger.debug(`${gwName} calling ${handle.modifyMethod}`, { baseEntity })
        await (this as any)[handle.modifyMethod](baseEntity, id, scimdata, ctxPassThrough)
      }

      // add/remove groups
      if (!this.config.scimgateway.scim.groupMemberOfUser) {
        if (objGroups && Array.isArray(objGroups) && !(usePutSoftSync && objGroups.length < 1)) { // only if groups included, { "groups": [] } will remove all existing
          if (typeof (this as any)[handler.groups.getMethod] !== 'function' || typeof (this as any)[handler.groups.modifyMethod] !== 'function') {
            throw new Error('replaceUser error: put operation can not be fully completed for the user`s groups, methods like getGroups() and modifyGroup() are not implemented')
          }
          let currentGroups
          if (currentObj.groups && Array.isArray(currentObj.groups)) currentGroups = currentObj.groups
          else { // try to get current groups the standard way
            let res: any
            try {
              res = await (this as any)[handler.groups.getMethod](baseEntity, { attribute: 'members.value', operator: 'eq', value: decodeURIComponent(id) }, ['id', 'displayName'], ctxPassThrough)
              logger.debug(`${gwName} "${handler.groups.getMethod}" result: ${res ? JSON.stringify(res) : ''}`, { baseEntity })
            } catch (err) { void 0 } // method may be implemented, but throwing error like groups not supported/implemented
            currentGroups = []
            if (res && res.Resources && Array.isArray(res.Resources) && res.Resources.length > 0) {
              for (let i = 0; i < res.Resources.length; i++) {
                if (!res.Resources[i].id) continue
                const el: { [key: string]: any } = {}
                el.value = res.Resources[i].id
                if (res.Resources[i].displayName) el.display = res.Resources[i].displayName
                currentGroups.push(el) // { "value": "Admins", "display": "Admins"}
              }
            }
          }
          currentGroups = currentGroups.map((el: Record<string, any>) => {
            if (el.value) {
              el.value = decodeURIComponent(el.value)
            }
            return el
          })

          const addGrps: string[] = []
          const removeGrps: string[] = []
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

          const assignGroupMember = async (grpId: string) => {
            return await (this as any)[handler.groups.modifyMethod](baseEntity, grpId, { members: [{ value: id }] }, ctxPassThrough)
          }

          const revokeGroupMember = async (grpId: string) => {
            return await (this as any)[handler.groups.modifyMethod](baseEntity, grpId, { members: [{ operation: 'delete', value: id }] }, ctxPassThrough)
          }

          let errRevoke: string[] = []
          if (!usePutSoftSync) { // default will remove any existing groups not included, usePutSoftSync=true prevents removing existing groups (only add groups)
            const res: { [key: string]: any } = await Promise.allSettled(removeGrps.map(async grpId => revokeGroupMember(grpId)))
            errRevoke = res.filter((result: Record<string, any>) => result.status === 'rejected').map((result: Record<string, any>) => result.reason.message)
          }

          const res: { [key: string]: any } = await Promise.allSettled(addGrps.map(async grpId => assignGroupMember(grpId)))
          const errAssign: string[] = res.filter((result: Record<string, any>) => result.status === 'rejected').map((result: Record<string, any>) => result.reason.message)

          let errMsg = ''
          if (errRevoke.length > 0) errMsg = `revokeGroupMember errors: ${errRevoke.join(', ')}`
          if (errAssign.length > 0) errMsg += `${errMsg ? ' ' : ''}assignGroupMember errors: ${errAssign.join(', ')}`
          if (errMsg) throw new Error(errMsg)
        }
      }
    } // replaceUsrGrp
    funcHandler.replaceUsrGrp = replaceUsrGrp

    const putHandler = async (ctx: Context) => {
      const handle = ctx.routeObj.handle // Users/Groups
      const baseEntity = ctx.routeObj.baseEntity
      const id = ctx.routeObj.id ? decodeURIComponent(ctx.routeObj.id) : ctx.routeObj.id
      const obj = ctx.request.body

      logger.debug(`${gwName} [PUT ${handle[0].toUpperCase() + handle.slice(1)}] id=${id} body=${JSON.stringify(obj)}`, { baseEntity: ctx?.routeObj?.baseEntity })
      try {
        if (!obj) throw new Error('missing body')
        if (typeof obj !== 'object') throw new Error('body is not JSON')
        const headers = ctx.request.headers
        await replaceUsrGrp(handle, baseEntity, id, obj, this.config.scimgateway.scim.usePutSoftSync, ctx.passThrough, headers)
        ctx.request.headers.delete('if-match')
        ctx.request.headers.delete('if-none-match')
        await getHandlerId(ctx) // ctx.response.body now updated with userObject to be returned
        if (ctx.response.status && ctx.response.status !== 200) { // clear any get error
          ctx.response.status = 204
        }
      } catch (err: any) {
        const [e, statusCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, 500, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
      }
    }
    funcHandler.putHandler = putHandler

    // ==========================================
    //          Bulk Operations
    // ==========================================
    //
    // POST = /Bulk + body
    // Body example:
    // {"failOnErrors":1,"Operations":[{"method":"POST","path":"/Users","data":{"userName":"Alice"}},{...},{...}]}

    type SCIMBulkOperation = {
      method: string
      path: string
      bulkId?: string
      version?: string
      data?: any
    }

    type SCIMBulkRequest = {
      schemas: string[]
      failOnErrors?: number
      Operations: SCIMBulkOperation[]
    }

    type SCIMBulkResponse = {
      schemas: string[]
      Operations: {
        method: string
        path: string
        bulkId?: string
        location?: string
        status?: number
        version?: string
      }[]
    }

    const postBulkHandler = async (ctx: Context) => {
      const baseEntity = ctx.routeObj.baseEntity
      logger.debug(`${gwName} [Bulk Operations]`, { baseEntity: ctx?.routeObj?.baseEntity })
      const bulkBody: SCIMBulkRequest = utils.copyObj(ctx.request.body)
      try {
        if (!bulkBody) throw new Error('missing body')
        if (typeof bulkBody !== 'object') throw new Error('body is not JSON')
        if (!bulkBody.Operations || !Array.isArray(bulkBody.Operations)) throw new Error('missing Operations array')
        if (bulkBody.Operations.length > this.scimDef.ServiceProviderConfigs.bulk.maxOperations) {
          const err = new Error(`the number of bulk operations exceeds the maxOperations (${this.scimDef.ServiceProviderConfigs.bulk.maxOperations})`)
          err.name += '#413'
          throw err
        }

        const operations = bulkBody.Operations
        const bulkIdMap = new Map<string, any>()
        const responseList: SCIMBulkResponse['Operations'] = []
        const depGraph = utilsScim.bulkBuildDependencyGraph(operations)
        const sortedOps = utilsScim.bulkTopologicalSort(depGraph)
        if (!sortedOps) {
          const err = new Error('Bulk circular dependency detected')
          err.name += '#409'
          throw err
        }

        let errCount = 0
        for (const op of sortedOps) {
          let resolvedData: any
          let resolvedErr: any
          try {
            resolvedData = utilsScim.bulkResolveIdReferences(op.data, bulkIdMap)
          } catch (err: any) {
            resolvedErr = err
          }
          const path = decodeURIComponent(op.path ?? '')
          const bulkReq = new Request(new URL(ctx.origin + `${baseEntity === 'undefined' ? path : '/' + baseEntity + path}`), {
            method: op?.method,
            headers: new Headers(ctx.request.headers as any),
            signal: ctx.request.signal,
            body: JSON.stringify(resolvedData),
          }) as Request & { raw: IncomingMessage }
          if (op.version) bulkReq.headers.set('if-match', op.version)

          const bulkCtx = await onBeforeHandle(bulkReq, ctx.ip)

          if (!resolvedErr) {
            if (!op.method || !op.path) {
              resolvedErr = new Error('missing method or path')
            } else if (!op.data && op.method.toUpperCase() !== 'DELETE') resolvedErr = new Error('missing data')
            else {
              const p = op.path?.toLowerCase()
              if (!p?.startsWith('/users') && !p?.startsWith('/groups')) {
                resolvedErr = new Error(`unsupported path: ${op.path}`)
              }
            }
          }

          if (resolvedErr) {
            bulkCtx.response.status = 404
            const [e] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, bulkCtx.response.status, resolvedErr)
            bulkCtx.response.body = JSON.stringify(e)
          } else {
            switch (op.method.toUpperCase()) {
              case 'POST':
                await postHandler(bulkCtx)
                break
              case 'PUT':
                await putHandler(bulkCtx)
                break
              case 'PATCH':
                if (isScimv2) {
                  if (Array.isArray(bulkCtx.request.body)) {
                    bulkCtx.request.body = {
                      Operations: bulkCtx.request.body,
                    }
                  } else {
                    bulkCtx.request.body = {
                      Operations: [bulkCtx.request.body],
                    }
                  }
                }
                await patchHandler(bulkCtx)
                break
              case 'DELETE':
                await deleteHandler(bulkCtx)
                break
              default:
                const err = Error(`Unsupported method: ${op.method}`)
                bulkCtx.response.status = 405
                const [e] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, bulkCtx.response.status, err)
                bulkCtx.response.body = JSON.stringify(e)
            }
          }

          let body: any
          if (bulkCtx.response.body) {
            body = JSON.parse(bulkCtx.response.body as string)
            if (op.bulkId && body.id) bulkIdMap.set(op.bulkId, body.id)
          }

          let errResponse
          if (body && bulkCtx.response.status && bulkCtx.response.status > 399) {
            errCount++
            if (body?.Errors && Array.isArray(body.Errors)) { // scim v1
              errResponse = body.Errors[0]
            } else errResponse = body
          }
          const response: any = {
            method: op.method,
            bulkId: op.bulkId,
            path: op.path,
            status: { code: bulkCtx.response.status?.toString() || '200' },
            location: body?.meta?.location,
            version: body?.meta?.version,
            response: errResponse,
          }
          if (!response.response) delete response.response
          if (!response.location) delete response.location
          if (!response.version) delete response.version
          responseList.push(response)

          if (bulkBody.failOnErrors && errCount >= bulkBody.failOnErrors) {
            break
          }
        }
        const res = {
          schemas: ['urn:ietf:params:scim:api:messages:2.0:BulkResponse'],
          Operations: responseList,
        }
        if (!isScimv2) {
          res.schemas = ['urn:ietf:params:scim:api:messages:1.0:BulkResponse']
        }
        ctx.response.status = 200
        ctx.response.body = JSON.stringify(res)
      } catch (err: any) {
        const [e, statusCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, 500, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
      }
    }

    // ==========================================
    //           API POST (no SCIM)
    // ==========================================
    //
    // POST = /api + body
    // Send body "as is" to plugin-api
    // Body example:
    // {"eventName":"AsignAccessRoleEvent","subjectName":"RACF_System-B","userID":"peter01"}
    //
    const postApiHandler = async (ctx: Context) => {
      const baseEntity = ctx.routeObj.baseEntity
      const obj = ctx.request.body
      logger.debug(`${gwName} [POST ${ctx.routeObj.handle}]`, { baseEntity: ctx?.routeObj?.baseEntity })

      if (!obj) {
        const err = new Error('missing body')
        const [e, statusCode] = utilsScim.jsonErr('1.1', pluginName, 500, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
        ctx.response.headers.set('content-type', 'application/json; charset=utf-8')
        return
      }
      try {
        logger.debug(`${gwName} calling postApi`, { baseEntity: ctx?.routeObj?.baseEntity })
        const result = await this.postApi(baseEntity, obj, ctx.passThrough)
        if (result) {
          if (typeof result === 'string') {
            const r = result.trim()
            if (r.startsWith('<') && r.endsWith('>')) {
              ctx.response.headers.set('content-type', 'text/html; charset=utf-8')
            } else ctx.response.headers.set('content-type', 'text/plain; charset=utf-8')
            ctx.response.body = result
            return
          }
          try {
            ctx.response.body = JSON.stringify(result)
          } catch (err) {
            ctx.response.body = result.toString()
          }
          ctx.response.status = 201
        } else ctx.response.status = 204
        ctx.response.headers.set('content-type', 'application/json; charset=utf-8')
      } catch (err: any) {
        const [e, statusCode] = utilsScim.jsonErr('1.1', pluginName, 500, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
        ctx.response.headers.set('content-type', 'application/json; charset=utf-8')
      }
    }
    funcHandler.postApiHandler = postApiHandler

    // ==========================================
    //           API PUT (no SCIM)
    // ==========================================
    //
    // PUT = /api/{id} + body
    // Send body "as is" to plugin-api
    // Body example:
    // {"eventName":"AsignAccessRoleEvent","subjectName":"RACF_System-B","userID":"peter01"}
    //
    const putApiHandler = async (ctx: Context) => {
      const baseEntity = ctx.routeObj.baseEntity
      const id = ctx.routeObj.id
      const obj = ctx.request.body
      logger.debug(`${gwName} [PUT ${ctx.routeObj.handle}] id=${id}`, { baseEntity: ctx?.routeObj?.baseEntity })

      try {
        if (!obj) throw new Error('missing body')
        if (!id) throw new Error('missing id')
      } catch (err: any) {
        const [e, statusCode] = utilsScim.jsonErr('1.1', pluginName, 500, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
        ctx.response.headers.set('content-type', 'application/json; charset=utf-8')
        return
      }

      try {
        logger.debug(`${gwName} calling putApi`, { baseEntity: ctx?.routeObj?.baseEntity })
        let result = await this.putApi(baseEntity, id, obj, ctx.passThrough)
        if (result) {
          if (typeof result === 'string') {
            const r = result.trim()
            if (r.startsWith('<') && r.endsWith('>')) {
              ctx.response.headers.set('content-type', 'text/html; charset=utf-8')
            } else ctx.response.headers.set('content-type', 'text/plain; charset=utf-8')
            ctx.response.body = result
            return
          }
          try {
            ctx.response.body = JSON.stringify(result)
          } catch (err) {
            ctx.response.body = result.toString()
          }
          ctx.response.status = 200
        } else ctx.response.status = 204
        ctx.response.headers.set('content-type', 'application/json; charset=utf-8')
      } catch (err: any) {
        const [e, statusCode] = utilsScim.jsonErr('1.1', pluginName, 500, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
        ctx.response.headers.set('content-type', 'application/json; charset=utf-8')
      }
    }
    funcHandler.putApiHandler = putApiHandler

    // ==========================================
    //           API PATCH (no SCIM)
    // ==========================================
    //
    // PATCH = /api/{id} + body
    // Send body "as is" to plugin-api
    // Body example:
    // {"eventName":"AsignAccessRoleEvent","subjectName":"RACF_System-B","userID":"peter01"}
    //
    const patchApiHandler = async (ctx: Context) => {
      const handle = ctx.routeObj.handle
      const baseEntity = ctx.routeObj.baseEntity
      const id = ctx.routeObj.id as string
      const body = ctx.request.body

      logger.debug(`${gwName} [PATCH ${handle} ] id=${id}`, { baseEntity: ctx?.routeObj?.baseEntity })

      if (!body) {
        const err = new Error('missing body')
        const [e, statusCode] = utilsScim.jsonErr('1.1', pluginName, 500, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
        ctx.response.headers.set('content-type', 'application/json; charset=utf-8')
        return
      } else {
        try {
          logger.debug(`${gwName} calling patchApi`, { baseEntity: ctx?.routeObj?.baseEntity })
          let result = await this.patchApi(baseEntity, id, body, ctx.passThrough)
          if (result) {
            if (typeof result === 'string') {
              const r = result.trim()
              if (r.startsWith('<') && r.endsWith('>')) {
                ctx.response.headers.set('content-type', 'text/html; charset=utf-8')
              } else ctx.response.headers.set('content-type', 'text/plain; charset=utf-8')
              ctx.response.body = result
              return
            }
            try {
              ctx.response.body = JSON.stringify(result)
            } catch (err) {
              ctx.response.body = result.toString()
            }
            ctx.response.status = 200
          } else ctx.response.status = 204
          ctx.response.headers.set('content-type', 'application/json; charset=utf-8')
        } catch (err: any) {
          const [e, statusCode] = utilsScim.jsonErr('1.1', pluginName, 500, err)
          ctx.response.status = statusCode
          ctx.response.body = JSON.stringify(e)
          ctx.response.headers.set('content-type', 'application/json; charset=utf-8')
        }
      }
    }
    funcHandler.patchApiHandler = patchApiHandler

    // ==========================================
    //           API GET (no SCIM)
    // ==========================================
    //
    //  GET = /api
    //  GET = /api?queries
    //  GET = /api/{id}
    //
    const getApiHandler = async (ctx: Context) => {
      const handle = ctx.routeObj.handle
      const baseEntity = ctx.routeObj.baseEntity
      const id = ctx.routeObj.id as string

      if (id) logger.debug(`${gwName} [GET ${handle}] id=${id}`, { baseEntity: ctx?.routeObj?.baseEntity })
      else logger.debug(`${gwName} [GET ${handle}]`)

      try {
        logger.debug(`${gwName} calling getApi`, { baseEntity: ctx?.routeObj?.baseEntity })
        let result = await this.getApi(baseEntity, id, ctx.query, ctx.passThrough)
        if (result) {
          if (result instanceof ReadableStream) { // support long-running tasks
            ctx.response.body = result
            return
          }
          if (typeof result === 'string') {
            const r = result.trim()
            if (r.startsWith('<') && r.endsWith('>')) {
              ctx.response.headers.set('content-type', 'text/html; charset=utf-8')
            } else ctx.response.headers.set('content-type', 'text/plain; charset=utf-8')
            ctx.response.body = result
            return
          }
          try {
            ctx.response.body = JSON.stringify(result)
          } catch (err) {
            ctx.response.body = result.toString()
          }
        }
        ctx.response.status = 200
        ctx.response.headers.set('content-type', 'application/json; charset=utf-8')
      } catch (err: any) {
        const [e, statusCode] = utilsScim.jsonErr('1.1', pluginName, 404, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
        ctx.response.headers.set('content-type', 'application/json; charset=utf-8')
      }
    }
    funcHandler.getApiHandler = getApiHandler

    // ==========================================
    //           API DELETE (no SCIM)
    // ==========================================
    //
    //  DELETE = /api/{id}
    //
    const deleteApiHandler = async (ctx: Context) => {
      const baseEntity = ctx.routeObj.baseEntity
      const id = ctx.routeObj.id
      logger.debug(`${gwName} [DELETE ${ctx.routeObj.handle}] id=${id}`, { baseEntity: ctx?.routeObj?.baseEntity })
      try {
        if (!id || id.includes('/')) throw new Error('missing id')
        logger.debug(`${gwName} calling deleteApi`, { baseEntity: ctx?.routeObj?.baseEntity })
        let result = await this.deleteApi(baseEntity, id, ctx.passThrough)
        if (result) {
          if (typeof result === 'string') {
            const r = result.trim()
            if (r.startsWith('<') && r.endsWith('>')) {
              ctx.response.headers.set('content-type', 'text/html; charset=utf-8')
            } else ctx.response.headers.set('content-type', 'text/plain; charset=utf-8')
            ctx.response.body = result
            return
          }
          try {
            ctx.response.body = JSON.stringify(result)
          } catch (err) {
            ctx.response.body = result.toString()
          }
          ctx.response.status = 200
        } else ctx.response.status = 204
        ctx.response.headers.set('content-type', 'application/json; charset=utf-8')
      } catch (err: any) {
        const [e, statusCode] = utilsScim.jsonErr('1.1', pluginName, 500, err)
        ctx.response.status = statusCode
        ctx.response.body = JSON.stringify(e)
        ctx.response.headers.set('content-type', 'application/json; charset=utf-8')
      }
    }
    funcHandler.deleteApiHandler = deleteApiHandler

    // ========================================================================
    //           API PUBLIC (no SCIM, public available - no authentication)
    // ========================================================================
    //
    //  GET/POST/PATCH/PUT/DELETE: '/pub/api'
    //
    const publicApiHandler = async (ctx: Context) => {
      if (typeof this.publicApi !== 'function') { // plugin method not implemented
        ctx.response.status = 404
        return
      }
      const handle = ctx.routeObj.handle
      const baseEntity = ctx.routeObj.baseEntity = 'undefined'
      const method = ctx.request.method
      const id = ctx.routeObj.id || undefined
      const query = Object.keys(ctx.query).length > 0 ? ctx.query : undefined
      const body = ctx.request.body

      logger.debug(`${gwName} [${method} public ${handle}] id=${id} query=${query ? JSON.stringify(query) : query}`, { baseEntity: ctx?.routeObj?.baseEntity })

      try {
        logger.debug(`${gwName} calling publicApi`, { baseEntity: ctx?.routeObj?.baseEntity })
        let result = await this.publicApi(baseEntity, method, id, query, body, ctx.passThrough)
        if (result) {
          if (typeof result === 'string') {
            const r = result.trim()
            if (r.startsWith('<') && r.endsWith('>')) {
              ctx.response.headers.set('content-type', 'text/html; charset=utf-8')
            } else ctx.response.headers.set('content-type', 'text/plain; charset=utf-8')
            ctx.response.body = result
            return
          }
          try {
            ctx.response.body = JSON.stringify(result)
          } catch (err) {
            ctx.response.body = result.toString()
          }
          if (method === 'POST') ctx.response.status = 201
          else ctx.response.status = 200
        } else ctx.response.status = 204
        ctx.response.headers.set('content-type', 'application/json; charset=utf-8')
      } catch (err: any) {
        const [e, statusCode] = utilsScim.jsonErr('1.1', pluginName, 500, err)
        ctx.response.status = statusCode
        if (err.message) { // may use err.name (xxx#<code>) and no message to avoid returning standard error formatted body e.g., const err=new Error(); err.name=err.name +='#404'; throw err
          ctx.response.body = JSON.stringify(e)
          ctx.response.headers.set('content-type', 'application/json; charset=utf-8')
        }
      }
    }
    funcHandler.publicApiHandler = publicApiHandler

    // ==========================================
    //   GET Application Roles based on groups
    // ==========================================
    //
    //  GET = /AppRoles
    //
    this.getAppRoles = async (baseEntity: string) => {
      return await stream.getAppRoles(this, baseEntity)
    }

    // get all groups a user is member of
    const getMemberOf = async (baseEntity: string, id: string, getMethod: string, ctxPassThrough: any) => {
      const groups: object[] = []
      if (getMethod !== 'getGroups') return groups
      if (typeof (this as any)[handler.groups.getMethod] !== 'function') return groups // method not implemented
      if (this.config.scimgateway.scim.groupMemberOfUser) return groups // only support user member of group
      let res: any
      try {
        const ob = { attribute: 'members.value', operator: 'eq', value: decodeURIComponent(id) }
        const attributes = ['id', 'displayName']
        logger.debug(`${gwName} calling ${handler.groups.getMethod} - groups to be included`, { baseEntity })
        res = await (this as any)[handler.groups.getMethod](baseEntity, ob, attributes, ctxPassThrough)
      } catch (err) { void 0 }
      if (res && res.Resources && Array.isArray(res.Resources) && res.Resources.length > 0) {
        for (let i = 0; i < res.Resources.length; i++) {
          if (!res.Resources[i].id) continue
          const el: any = {}
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
    // Route helpers
    // ==========================================

    type RouteObj = {
      method: string
      baseEntity: string
      handle: string
      id: string | undefined
    }

    type Context = {
      request: {
        method: string
        url: string
        signal: AbortSignal
        raw?: IncomingMessage
        headers: Headers
        body: any
      }
      response: {
        headers: Headers // HeadersInit
        status?: number
        body?: string | ReadableStream<any>
      }
      routeObj: RouteObj
      perfStart: number
      path: string
      query: Record<string, any>
      ip: string
      origin: string
      passThrough: Record<string, any> | undefined
      target?: string | undefined
    }

    const ipHeaders: string[] = [
      'x-real-ip', // Nginx proxy/FastCGI
      'x-client-ip', // Apache https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html#page-header
      'cf-connecting-ip', // Cloudflare
      'fastly-client-ip', // Fastly
      'x-cluster-client-ip', // GCP
      'x-forwarded', // General Forwarded
      'forwarded-for', // RFC 7239
      'forwarded', // RFC 7239
      'x-forwarded', // RFC 7239
      'appengine-user-ip', // GCP
      'true-client-ip', // Akamai and Cloudflare
      'cf-pseudo-ipv4', // Cloudflare
    ]

    /**
    * getIpFromHeader returns client ip-address if found in existing headers else null
    * @param headers request headers
    * @returns ip-address or null 
    */
    const getIpFromHeader = (headers: Headers): string | null | undefined => {
      let clientIP: string | undefined | null = null
      // X-Forwarded-For is the de-facto standard header
      if (headers.get('x-forwarded-for')) clientIP = headers.get('x-forwarded-for')?.split(',')[0]
      if (!clientIP) {
        for (const header of ipHeaders) {
          clientIP = headers.get(header)
          if (clientIP) break
        }
      }
      return clientIP
    }

    /**
    * getOriginFromHeader returns origin (https://FQDN/path) based on header
    * @param headers request headers
    * @returns origin or null 
    */
    const getOriginFromHeader = (headers: Headers): string | null => {
      if (headers.get('origin')) return headers.get('origin')
      const xfHost = headers.get('x-forwarded-host')
      if (xfHost) {
        const xfProto = headers.get('x-forwarded-proto')
        const xfPort = headers.get('x-forwarded-port')
        return `${xfProto ? xfProto + '://' : ''}${xfHost}${xfPort ? ':' + xfPort : ''}`
      }
      return null
    }

    const onBeforeHandle = async (request: Request & { raw: IncomingMessage }, directIp: string): Promise<Context> => {
      const method = request.method
      const url = new URL(request.url)
      let leadingPath = ''
      let pathname = url.pathname
      if (url.hostname.endsWith('.servicebus.windows.net')) { // Azure Relay - remove the first path segment - "/<hybrid-connection-name>/xxx
        const parts = pathname.split('/')
        leadingPath = '/' + parts[1]
        parts.splice(1, 1)
        pathname = parts.join('/') || '/'
      }

      const match = pathname.match(/.*\/v(1|2)(\/.*)/)
      if (match) {
        if (match[1] === '2' && !isScimv2) {
          this.scimDef = utilsScim.loadScimDef('2.0', pluginDir)
          isScimv2 = true
        } else if (match[1] === '1' && isScimv2) {
          this.scimDef = utilsScim.loadScimDef('1.1', pluginDir)
          isScimv2 = false
        }
        leadingPath = pathname.substring(0, pathname.indexOf(match[2]))
        pathname = match[2] // the part after /v1 or /v2
      } else if (isScimv2 !== isScimv2Initial) {
        // scim version have previously been changed by above v1/v2 path, but now not using v1/v2 and version must be reset to original
        isScimv2 = isScimv2Initial
        if (isScimv2) this.scimDef = utilsScim.loadScimDef('2.0', pluginDir)
        else this.scimDef = utilsScim.loadScimDef('1.1', pluginDir)
      }

      let [baseEntity, handle, id, rest]: string[] = pathname.split('/').filter(Boolean)
      if (baseEntity && handlers.includes(baseEntity.toLowerCase())) {
        rest = id
        id = handle
        handle = baseEntity
        baseEntity = 'undefined'
      }
      if (handle) handle = handle.toLowerCase()
      if (!handlers.includes(handle)) {
        baseEntity = ''
        handle = ''
        id = ''
        rest = ''
      } else if (rest) { // too many path elements - keep baseEntity only
        handle = ''
        id = ''
        rest = ''
      }

      // bodyParser
      let body: any
      const bodyString = await request.text()
      try {
        body = JSON.parse(bodyString)
      } catch (err: any) {
        const contentType = request.headers.get('content-type')
        if (contentType && contentType.toLowerCase().startsWith('application/x-www-form-urlencoded')) {
          body = utils.formUrlEncodedToJSON(bodyString)
        } else if (contentType && contentType.toLowerCase().startsWith('multipart/form-data')) {
          body = utils.formDataMultipartToJSON(bodyString)
        } else if (bodyString) body = bodyString
      }

      let path = pathname
      if (path.slice(-1) === '/' && path.length > 1) path = path.slice(0, -1)

      const ctx: Context = {
        request: { // not using request as-is becuase body is stream and read once
          method: request.method,
          url: request.url,
          signal: request.signal,
          raw: request.raw,
          headers: request.headers,
          body: body,
        },
        response: {
          status: undefined,
          headers: new Headers(),
          body: undefined,
        },
        routeObj: {
          method: method,
          baseEntity: baseEntity,
          handle: handle,
          id: id,
        },
        perfStart: performance.now(),
        path,
        query: {},
        ip: getIpFromHeader(request.headers) || directIp,
        origin: getOriginFromHeader(request.headers) || url.origin,
        passThrough: (found.PassThrough && this.authPassThroughAllowed) ? { headers: request.headers } : undefined,
      }

      if (leadingPath) {
        ctx.origin += leadingPath // using origin as placeholder for leading path that have been removed from ctx.path
        if (ctx.origin.includes('.servicebus.windows.net')) {
          ctx.origin = ctx.origin.replace('http:', 'https:')
        }
      }

      url.searchParams.forEach((value, key) => {
        ctx.query[key] = value
      })

      // no validation
      if (ctx.path === '/ping') {
        ctx.response.status = 200
        ctx.response.body = 'hello'
        ctx.response.headers.set('content-type', 'text/plain')
        return ctx
      }
      if (ctx.path === '/_ah/start' || ctx.path === '/_ah/stop') {
        // Google App Engine B-class instance start/stop request
        const ver = process.env.GAE_VERSION
        if (ctx.ip === '0.1.0.3' && ver && ctx.origin.includes(`.${ver}.`)) { // origin = http://<instance>.<version>.<project-id>.<region>.r.appspot.com
          ctx.response.status = 200 // request coming from GCP App Engine
          return ctx
        }
      }
      if (ctx.request.method === 'GET' && ctx.path.endsWith('/.well-known/openid-configuration')) {
        await getHandlerOauthWellKnown(ctx)
        if (!ctx.response.status) ctx.response.status = 404
        return ctx
      }
      if (ctx.request.method === 'GET' && ctx.path.endsWith('/.well-known/jwks.json')) {
        await getHandlerOauthJwks(ctx)
        if (!ctx.response.status) ctx.response.status = 404
        return ctx
      }
      if (ctx.path.startsWith('/pub/api')) { // public api methods
        await publicApiHandler(ctx)
        if (!ctx.response.status) ctx.response.status = 200
        return ctx
      }

      // validation
      if (ctx.request.method === 'POST' && ctx.path.endsWith('/oauth/token')) {
        await postHandlerOauthToken(ctx)
        if (!ctx.response.status) ctx.response.status = 401 // Unauthorized
      } else if (!ctx.routeObj.handle) {
        ctx.response.status = 404 // NOT_FOUND
      } else if (!ipAllowList(ctx.ip)) {
        logger.debug(`${gwName} client ip ${ctx.ip} not in ipAllowList`, { baseEntity: ctx?.routeObj?.baseEntity })
        ctx.response.status = 401
      } else if (!await isAuthorized(ctx)) {
        ctx.response.status = 401
      }
      return ctx
    }

    /** 
     * onChainingHandler - chain request to another SCIM Gateway, like a reverse proxy
     * @param ctx original Context - ctx.response will become updated based on chain response
    **/
    const onChainingHandler = async (ctx: Context) => {
      const chainingBaseUrl = this.config.scimgateway.chainingBaseUrl // http(s)://<host>:<port>
      if (!chainingBaseUrl) {
        ctx.response.status = 500
        logger.error(`${gwName} onChainingHandler error: configuration scimgateway.chainingBaseUrl missing`, { baseEntity: ctx?.routeObj?.baseEntity })
        return
      }
      try {
        new URL(chainingBaseUrl)
      } catch (err: any) {
        ctx.response.status = 500
        logger.error(`${gwName} onChainingHandler error: configuration scimgateway.chainingBaseUrl must use correct syntax 'http(s)://host:port' error: ${err.message}`, { baseEntity: ctx?.routeObj?.baseEntity })
        return
      }
      try {
        if (!this.helperRest) this.helperRest = this.newHelperRest()
        const url = new URL(ctx.request.url)
        const method = ctx.request.method
        const chainUrl = ctx.request.url.replace(url.origin, chainingBaseUrl)
        const body = ctx.request.body
        const options = { headers: { Authorization: ctx.request.headers.get('authorization') } }
        const result = await this.helperRest.doRequest('undefined', method, chainUrl, body, undefined, options)
        ctx.response.status = result.statusCode
        try {
          ctx.response.body = JSON.stringify(result.body)
        } catch (err) {
          ctx.response.body = result.body
          ctx.response.headers.set('content-type', 'text/plain')
        }
      } catch (err: any) {
        try {
          const jBody = JSON.parse(err.message) // check for SCIM error response
          ctx.response.status = jBody?.body?.status || jBody?.statusCode || 500
          ctx.response.body = jBody.body ? JSON.stringify(jBody.body) : err.message
        } catch (parseErr) {
          ctx.response.status = 500
          logger.error(`${gwName} onChainingHandler error: ${err.message}`, { baseEntity: ctx?.routeObj?.baseEntity })
        }
      }
    }

    const onPublisherHandler = async (ctx: Context) => {
      if (!this.pub) {
        ctx.response.status = 500
        logger.error(`${gwName} onPublisherHandler error: publisher not initialized`, { baseEntity: ctx?.routeObj?.baseEntity })
        return
      }
      try {
        ctx.response = await this.pub.publish({ ctx })
      } catch (err: any) {
        ctx.response.status = 500
        logger.error(`${gwName} onPublisherHandler error: ${err.message}`, { baseEntity: ctx?.routeObj?.baseEntity })
        return
      }
    }

    const onAfterHandle = async (ctx: Context): Promise<Response> => {
      if (ctx.response.body instanceof ReadableStream && !ctx.response.headers.get('Content-Type')?.includes('text/event-stream')) {
        // This handles long-running tasks from plugins that return a ReadableStream.
        // Currently available by getApiHandler() - GET /api
        // ReadableStream body gives header "Transfer-Encoding: chunked" keeping connection open until last chunk and stream is closed
        // In addition implementing heartbeat for preventing proxy/loadbalancer closing connection
        //
        // corresponding plugin example code:
        /*
          const { readable, writable } = new TransformStream()
            // process the original stream in the background
            ; (async () => {
              const writer = writable.getWriter()
              try {
                const options = { abortTimeout: 5 * 60 } // 5 minutes
                const data = await helper.doRequest(,,,,,options)
                await writer.write(new TextEncoder().encode(data.body ?? ''))
              } catch (err: any) {
                await writer.write(new TextEncoder().encode(`error: ${err.message}`))
              } finally {
                await writer.close()
              } 
            })()
          return readable // return the readable part immediately
        */
        const originalStream = ctx.response.body
        const originalHeaders = new Headers(ctx.response.headers)
        let originalStatus = ctx.response.status || 200

        const { readable, writable } = new TransformStream()

        const processStream = async () => {
          const reader = originalStream.getReader()
          const writer = writable.getWriter()

          // Heartbeat to keep the connection alive for long-running tasks
          const heartbeat = setInterval(() => {
            if (writer.desiredSize && writer.desiredSize > 0) {
              writer.write(new Uint8Array([32])).catch(() => {}) // space
            }
          }, 15000)

          try {
            const { done, value } = await reader.read()
            if (!done) {
              const firstChunkText = new TextDecoder().decode(value).trim()
              if (firstChunkText.startsWith('<') && firstChunkText.endsWith('>')) {
                originalHeaders.set('content-type', 'text/html; charset=utf-8')
              } else if (firstChunkText.startsWith('{') || firstChunkText.startsWith('[')) {
                originalHeaders.set('content-type', 'application/json; charset=utf-8')
              } else {
                originalHeaders.set('content-type', 'text/plain; charset=utf-8')
              }

              if (firstChunkText.startsWith('error: ')) {
                originalStatus = 500
              }
              ctx.response.body = firstChunkText

              // Write the first chunk and then pipe the rest
              await writer.write(value)
              while (true) {
                const { done, value } = await reader.read()
                if (done) break
                await writer.write(value)
              }
            }
          } catch (err: any) {
            logger.error(`${gwName} onAfterHandle streaming error: ${err.message}`)
            await writer.abort(err).catch(() => {})
          } finally {
            clearInterval(heartbeat)
            await writer.close().catch(() => {})
            reader.releaseLock()
          }
        }
        processStream()

        const response = new Response(readable, { status: originalStatus, headers: originalHeaders })
        ctx.response.status = response.status
        ctx.response.headers = response.headers
        logResult(ctx)
        return response
      }

      // default non-streaming responses
      if (!ctx.response.status) ctx.response.status = 200
      if (ctx.response.status === 401) {
        // 401 - do not return scim formatted error message e.g., using PassThrough
        ctx.response.body = utils.statusText(ctx.response.status)
        ctx.response.headers.set('content-type', 'text/plain')
      }
      let body = ctx.response.body
      if (body === '') body = undefined
      if (body && !ctx.response.headers.has('content-type')) {
        ctx.response.headers.set('content-type', 'application/scim+json; charset=utf-8')
      }
      const response = new Response(body, { status: ctx.response.status, headers: ctx.response.headers })
      logResult(ctx)
      return response
    }

    // ==========================================
    // Starting up...
    // ==========================================

    logger.info('===================================================================')

    if (!this.config.scimgateway.port && this.config.scimgateway.azureRelay?.enabled !== true) {
      logger.info(`${gwName} port deactivated, not allowing incoming traffic`)
    } else {
      let hostname: string | undefined = undefined // '0.0.0.0'
      const tls: any = { // TlsOptions
        key: undefined,
        cert: undefined,
        ca: undefined,
        pfx: undefined,
        passphrase: undefined,
      }
      if (this.config.scimgateway.localhostonly === true) {
        hostname = 'localhost'
      }
      try {
        // using fs.readFileSync() instead of Bun.file() for nodejs compatibility
        if (this.config.scimgateway?.certificate?.key && this.config.scimgateway?.certificate?.cert) {
          // TLS
          tls.key = this.config.scimgateway.certificate.key ? fs.readFileSync(this.config.scimgateway.certificate.key) : undefined
          tls.cert = this.config.scimgateway.certificate.cert ? fs.readFileSync(this.config.scimgateway.certificate.cert) : undefined
          if (this.config.scimgateway?.certificate?.ca) {
            if (Array.isArray(this.config.scimgateway.certificate.ca)) {
              for (let i = 0; i < this.config.scimgateway.certificate.ca.length; i++) {
                this.config.scimgateway.certificate.ca[i] = fs.readFileSync(this.config.scimgateway.certificate.ca[i])
              }
            } else tls.ca = fs.readFileSync(this.config.scimgateway.certificate.ca)
          }
        } else if (this.config.scimgateway?.certificate?.pfx && this.config.scimgateway?.certificate?.pfx?.bundle) {
          // TODO: PFX/PKC#12 currently not supported by Bun
          tls.pfx = this.config.scimgateway.certificate.pfx.bundle ? fs.readFileSync(this.config.scimgateway.certificate.pfx.bundle) : undefined
          tls.passphrase = this.config.scimgateway.certificate.pfx.password ? utils.getSecret('scimgateway.certificate.pfx.password', this.configFile) : undefined
        }
      } catch (err: any) {
        const msg = `tls/certificate configuration error: ${err.message}`
        logger.error(`${gwName} startup error: ${msg}`)
        throw new Error(msg)
      }

      const isPublisherEnabled = this.config.scimgateway.stream.publisher.enabled
      const isChainingEnabled = this.config.scimgateway.chainingBaseUrl

      const sseInit = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          html, body {
            height: 100%;
            margin: 0;
            padding: 0;
          }
          body {
            display: flex;
            flex-direction: column;
            height: 100vh;
            margin-left: 8px;
          }
          .header-flex {
            display: flex;
            align-items: center;
            gap: 16px;
            flex-shrink: 0;
            margin-top: 2px;
            margin-bottom: 2px;
          }
          #log {
            flex: 1 1 auto;
            width: 100%;
            overflow: auto;
            white-space: pre;
            margin: 0;
            min-height: 0;
            height: auto;
            box-sizing: border-box;
          }
          #stopBtn {
            padding: 4px 18px;
            font-size: 12px;
            background: #eee;
            border: 1px solid #888;
            border-radius: 4px;
            color: #222;
            cursor: pointer;
          }
        </style>
      </head>
      <body>
        <div class="header-flex">
          <h3>SCIM Gateway remote logger</h3>
          <button id="stopBtn" type="button">Stop</button>
        </div>
        <pre id="log"></pre>
        <script>
          const stopBtn = document.getElementById('stopBtn')
          const logElem = document.getElementById('log')
          let es = new EventSource(location.pathname)

          es.onmessage = function(event) {
            if (!event.data.trim()) return
            const htmlLine = event.data.replace(
              /(level":"\s*)(debug|info|warn|error)/i,
              function(match, p1, p2) {
                let color = ''
                switch (p2.toLowerCase()) {
                  case 'debug': color = '#888'; break
                  case 'info':  color = 'blue'; break
                  case 'warn':  color = 'orange'; break
                  case 'error': color = 'red'; break
                  default: color = 'black'
                }
                return p1 + '<span style="color:' + color + ';font-weight:bold">' + p2 + '</span>'
              }
            )
            logElem.innerHTML += htmlLine + '<br>'
            logElem.scrollTop = logElem.scrollHeight
          }

          stopBtn.onclick = function() {
            if (es) {
              es.close()
              es = null
              stopBtn.textContent = 'Start'
              stopBtn.onclick = function() { location.reload() }
            }
          }
        </script>
      </body>
      </html>
      `

      const route = async (req: Request & { raw: IncomingMessage }, ip: string): Promise<Response> => {
        const ctx = await onBeforeHandle(req, ip)
        if (ctx.response.status) { // 401/Unauthorized - 404/NOT_FOUND
          return await onAfterHandle(ctx)
        }
        if (isPublisherEnabled) {
          await onPublisherHandler(ctx)
          return await onAfterHandle(ctx)
        }
        if (isChainingEnabled) {
          await onChainingHandler(ctx)
          return await onAfterHandle(ctx)
        }

        const apiEndpoint = `${ctx.routeObj.method} ${ctx.routeObj.handle}`
        switch (apiEndpoint) {
          case 'GET users':
          case 'GET groups':
          case 'GET serviceplans':
            if (ctx.routeObj.id) await getHandlerId(ctx)
            else await getHandler(ctx)
            return await onAfterHandle(ctx)
          case 'GET api':
            await getApiHandler(ctx)
            return await onAfterHandle(ctx)
          case 'GET schemas':
            await getHandlerSchemas(ctx)
            return await onAfterHandle(ctx)
          case 'GET resourcetypes':
            await getHandlerResourceTypes(ctx)
            return await onAfterHandle(ctx)
          case 'GET serviceproviderconfig':
          case 'GET serviceproviderconfigs':
            await getHandlerServiceProviderConfig(ctx)
            return await onAfterHandle(ctx)
          case 'GET logger': // no onAfterHandle
            if (req.headers.has('sec-fetch-dest')) { // client is browser
              if (ctx.request.headers.get('accept')?.includes('text/event-stream')) {
                return await getHandlerLoggerSSE(ctx)
              } else {
                return new Response(sseInit, {
                  status: 200,
                  headers: {
                    'Content-Type': 'text/html; charset=utf-8',
                  },
                })
              }
            } else return await getHandlerLoggerSSE(ctx)
          case 'PATCH users':
          case 'PATCH groups':
            await patchHandler(ctx)
            return await onAfterHandle(ctx)
          case 'PATCH api':
            await patchApiHandler(ctx)
            return await onAfterHandle(ctx)
          case 'PUT users':
          case 'PUT groups':
            await putHandler(ctx)
            return await onAfterHandle(ctx)
          case 'PUT api':
            await putApiHandler(ctx)
            return await onAfterHandle(ctx)
          case 'POST users':
          case 'POST groups':
            await postHandler(ctx)
            return await onAfterHandle(ctx)
          case 'POST bulk':
            await postBulkHandler(ctx)
            return await onAfterHandle(ctx)
          case 'POST api':
            await postApiHandler(ctx)
            return await onAfterHandle(ctx)
          case 'DELETE users':
          case 'DELETE groups':
            await deleteHandler(ctx)
            return await onAfterHandle(ctx)
          case 'DELETE api':
            await deleteApiHandler(ctx)
            return await onAfterHandle(ctx)
          default:
            return new Response('NOT_FOUND', { status: 404 })
        }
      }

      // starting SCIM listeners
      // bun is preferred, but also supporting nodejs: node --experimental-strip-types index.ts
      if (!this.config.scimgateway.azureRelay?.enabled === true && typeof Bun !== 'undefined') {
        // this code will only run when the file is run with Bun
        if (tls.pfx && !tls.key) throw new Error('pfx is not supported for Bun')
        let idleTimeout = this.config.scimgateway.idleTimeout || 120
        if (idleTimeout < 10) idleTimeout = 10
        server = Bun.serve({
          port: this.config.scimgateway.port,
          reusePort: false,
          idleTimeout,
          hostname, // hostname === 'localhost' ? hostname : undefined, // bun defaults to '0.0.0.0', but using '0.0.0.0.' or other ip like '127.0.0.1' becomes extremly slow - bun bug
          tls,
          fetch: async (req, srv) => {
            // start route handlers
            const reqWithRaw = req as Request & { raw: IncomingMessage }
            return await route(reqWithRaw, srv.requestIP(req)?.address ?? '')
          },
        })
      } else {
        // using nodejs server either through Bun compability or Node.js
        // get body from req
        async function getRequestBody(req: any): Promise<Buffer> {
          return new Promise((resolve, reject) => {
            const body: Uint8Array[] = []
            req.on('data', (chunk: Uint8Array) => body.push(chunk)) // Explicitly typing chunk
            req.on('end', () => resolve(Buffer.concat(body)))
            req.on('error', (err: Error) => reject(err))
          })
        }

        // convert ReadableStream to string or Buffer
        async function streamToString(stream: any): Promise<string> {
          const reader = stream.getReader()
          const decoder = new TextDecoder()
          let result = ''
          while (true) {
            const { done, value } = await reader.read()
            if (done) break
            result += decoder.decode(value, { stream: true })
          }
          return result
        }

        async function handleSSEStream(stream: ReadableStream | null, onMessage: (msg: string) => void) {
          if (!stream) return
          const reader = stream.getReader()
          const decoder = new TextDecoder()
          while (true) {
            const { done, value } = await reader.read()
            if (done) break
            const chunck = decoder.decode(value, { stream: true })
            onMessage(chunck)
          }
        }

        // use Fetch API like Bun, start common route() and return a nodejs (http.createServer) formatted response
        async function doFetchApi(req: IncomingMessage, res: ServerResponse) {
          // @ts-expect-error ignore the TypeScript error about 'encrypted' not existing on 'Socket'
          const protocol = req.socket.encrypted ? 'https' : 'http'
          try {
            // convert nodejs req to Fetch API request - using same standard as Bun
            const requestBody = await getRequestBody(req)
            const body = ['GET', 'HEAD'].includes(req.method as string) ? undefined : requestBody.length > 0 ? requestBody : undefined
            // TODO fix below hardcoding
            let request = new Request(new URL(req.url ?? '', `${protocol}://${req.headers.host}`), {
              method: req.method,
              headers: new Headers(req.headers as any),
              // @ts-expect-error ignore incompatible types
              body: body,
              duplex: body ? 'half' : undefined,
            }) as Request & { raw: IncomingMessage }
            request.raw = req

            // start route processing and retrieve response
            const response = await route(request, req.socket.remoteAddress ?? '')

            // convert Fetch API response (Bun standard) to nodejs res
            let headers: any
            if (response.headers instanceof Headers) { // Headers object without entries(), use forEach to convert to an object
              headers = {}
              response.headers.forEach((value, key) => {
                headers[key] = value
              })
            } else if (Array.isArray(response.headers)) { // [string, string][]
              headers = Object.fromEntries(response.headers)
            } else { // Record<string, string>
              headers = response.headers
            }
            res.writeHead(response.status as any, headers) // Set headers and status

            if (response.body && response.body instanceof ReadableStream) {
              if (response.headers.get('content-type')?.includes('text/event-stream')) {
                handleSSEStream(response.body, (msg) => {
                  res.write(msg)
                })
              } else {
                const bodyText = await streamToString(response.body)
                res.end(bodyText)
              }
            } else {
              res.end()
            }
          } catch (err: any) {
            logger.error(`${gwName} internal error: ${err.message}`)
            res.writeHead(500, { 'Content-Type': 'text/plain' })
            res.end('Internal Server Error')
          }
        }

        // create nodejs server and start listen
        if (this.config.scimgateway.azureRelay?.enabled === true) {
          // Azure Relay listener server
          (async () => {
            const hyco = hycoPkg.default || hycoPkg
            let url: URL = {} as URL
            try {
              url = new URL(this.config.scimgateway.azureRelay.connectionUrl) // Azure Relay hybrid connection URL: 'https://<namespace>.servicebus.windows.net/<hybrid-connection-name>'
            } catch (err: any) {
              logger.error(`${gwName} Azure Relay configuration scimgateway.azureRelay.connectionUrl - error: ${err.message}`)
            }

            const ns = url.hostname// <namespace>.servicebus.windows.net
            const path = url?.pathname?.replace(/^[\s\/]+|[\s\/]+$/g, '') // <hybrid-connection-name> - removing any leading/trailing whitespace and '/'  
            const keyrule = this.config.scimgateway.azureRelay.keyRule || 'RootManageSharedAccessKey'
            const key = this.config.scimgateway.azureRelay.apiKey ?? '' // Azure Relay - SAS Primary Key
            const uri = hyco.createRelayListenUri(ns, path) // wss://<namespace>.servicebus.windows.net:443/$hc/<hybrid-connection-name>?sb-hc-action=listen

            server = hyco.createRelayedServer(
              {
                server: uri,
                token: () => hyco.createRelayToken(uri, keyrule, key),
              },
              async (req: IncomingMessage, res: ServerResponse) => {
                doFetchApi(req, res)
              })
            server.listen()

            { // check if Azure Relay listener is working by sending a 5 sec delayed ping request
              let options = {
                connection: {
                  options: {
                    headers: {
                      ServiceBusAuthorization: hyco.createRelayToken(uri, keyrule, key),
                    },
                  },
                },
              }
              setTimeout(async () => {
                try {
                  if (!this.helperRest) this.helperRest = this.newHelperRest()
                  await this.helperRest.doRequest('undefined', 'GET', `${this.config.scimgateway.azureRelay.connectionUrl}/ping`, null, null, options)
                } catch (err: any) {
                  logger.error(`${gwName} Azure Relay listener failed to start - ping test doRequest() returned an error - please verify configuration scimgateway.azureRelay.connectionUrl/apiKey including the Azure Relay setup}`)
                }
              }, 5 * 1000)
            }
          })()
        } else {
          // nodejs server
          if (tls.key) {
            server = httpsCreateServer({
              key: tls.key,
              cert: tls.cert,
              ca: tls.ca,
            },
            async (req, res) => {
              doFetchApi(req, res)
            })
          } else if (tls.pfx) {
            server = httpsCreateServer({
              pfx: tls.pfx,
              passphrase: tls.passphrase,
            },
            async (req, res) => {
              doFetchApi(req, res)
            })
          } else {
            server = httpCreateServer(async (req, res) => {
              doFetchApi(req, res)
            })
          }
          server.listen(this.config.scimgateway.port, hostname)
        }
      }

      // server has been started
      if (this.config.scimgateway.azureRelay?.enabled === true) {
        logger.info(`${gwName} now listening SCIM ${this.config.scimgateway.scim.version} using Azure Relay ${this.config.scimgateway.azureRelay.connectionUrl}...`)
      } else {
        logger.info(`${gwName} now listening SCIM ${this.config.scimgateway.scim.version}${tls.key || tls.pfx ? ' TLS' : ''} at ${hostname || '0.0.0.0'}:${this.config.scimgateway.port}...`)
      }
      if (this.config.scimgateway.chainingBaseUrl) logger.info(`${gwName} using remote gateway ${this.config.scimgateway.chainingBaseUrl}`)
    }

    // starting SCIM Stream subscribers
    if (this.config.scimgateway.stream.subscriber.enabled && this.config.scimgateway.stream.subscriber.entity
      && Object.keys(this.config.scimgateway.stream.subscriber.entity).length > 0) {
      logger.info(`${gwName} starting SCIM Stream subscribers...`)
      const sub: any = new stream.Subscriber(this, funcHandler)
      for (const baseEntity in this.config.scimgateway.stream.subscriber.entity) {
        const cfgSub: any = utils.copyObj(this.config.scimgateway.stream.subscriber.entity[baseEntity])
        cfgSub.baseUrls = this.config.scimgateway.stream.baseUrls
        cfgSub.certificate = this.config.scimgateway.stream.certificate
        cfgSub.usePutSoftSync = this.config.scimgateway.scim.usePutSoftSync
        sub.add(baseEntity, cfgSub)
      }
    }

    // starting SCIM Stream publisher
    if (this.config.scimgateway.stream.publisher.enabled && this.config.scimgateway.stream.publisher.entity
      && Object.keys(this.config.scimgateway.stream.publisher.entity).length > 0) {
      logger.info(`${gwName} starting SCIM Stream publishers...`)
      const pub: any = new stream.Publisher(this)
      for (const baseEntity in this.config.scimgateway.stream.publisher.entity) {
        const cfgPub: any = utils.copyObj(this.config.scimgateway.stream.publisher.entity[baseEntity])
        cfgPub.baseUrls = this.config.scimgateway.stream.baseUrls
        cfgPub.certificate = this.config.scimgateway.stream.certificate
        pub.add(baseEntity, cfgPub)
      }
      this.pub = pub
    }

    logger.setLoglevelConsole(this.config?.scimgateway?.log?.loglevel?.console) // revert temporary info console loglevel, use config

    if (this.config.scimgateway.email.emailOnError.enabled === true) {
      logger.subscribe(async (msgObj: Record<string, any>) => { // emailOnError
        if (msgObj.level !== 'error') return
        if (isMailLock) return null // not sending new mail until lock released
        isMailLock = true

        setTimeout(function () { // release lock after "sendInterval" minutes
          isMailLock = false
        }, (this.config.scimgateway.email.emailOnError.sendInterval || 15) * 1000 * 60)

        const msgHtml = `<html><body><pre style="font-family: monospace; white-space: pre-wrap;">${JSON.stringify(msgObj)}</pre><br/><p>This is an automatically generated email - please do NOT reply to this email</p></body></html>`
        const eObj = {
          from: this.config.scimgateway.email.emailOnError.from,
          to: this.config.scimgateway.email.emailOnError.to,
          cc: this.config.scimgateway.email.emailOnError.cc,
          subject: this.config.scimgateway.email.emailOnError.subject || 'SCIM Gateway error message',
          content: msgHtml,
        }
        this.sendMail(eObj, true)
        logger.debug(`${gwName} emailOnError sent to: ${eObj.to} cc: ${eObj.cc}`)
      })
    }

    const gracefulShutdown = async function () {
      logger.info(`${gwName} now stopping...`)
      await logger.close()
      if (server) {
        if (typeof server.stop === 'function') { // Bun
          server.stop(true)
          await Bun.sleep(400) // give in-flight requests a chance to complete, also plugins may use SIGTERM/SIGINT
          server.stop()
          process.exit(0)
        } else if (typeof server.close === 'function') { // Node.js
          server.close(() => {
            setTimeout(() => { // plugins may use SIGTERM/SIGINT
              process.exit(0)
            }, 0.5 * 1000)
          })
          server?.closeIdleConnections() // allows server.close() to fire sooner
        }
      }
      setTimeout(() => { // safety net
        process.exit(1)
      }, 2 * 1000)
    }

    process.setMaxListeners(Infinity)
    process.on('unhandledRejection', (reason: any, _promise: Promise<any>) => { // older versions of V8, unhandled promise rejections are silently dropped
      if (reason instanceof Error) {
        logger.error(`${gwName} async function with unhandledRejection: ${reason.stack}`)
      } else {
        logger.error(`${gwName} async function with unhandledRejection: ${JSON.stringify(reason)}`)
      }
    })
    process.once('SIGTERM', gracefulShutdown) // kill (windows subsystem lacks signaling support for process.kill)
    process.once('SIGINT', gracefulShutdown) // Ctrl+C
  } // constructor

  /**
  * logDebug logs debug message
  **/
  logDebug(baseEntity: string | undefined, msg: string) {
    this.logger.debug(msg, { baseEntity })
  }

  /**
  * logInfo logs info message
  **/
  logInfo(baseEntity: string | undefined, msg: string) {
    this.logger.info(msg, { baseEntity })
  }

  /**
  * logWarn logs warning message
  **/
  logWarn(baseEntity: string | undefined, msg: string) {
    this.logger.warn(msg, { baseEntity })
  }

  /**
  * logError logs error message
  **/
  logError(baseEntity: string | undefined, msg: string) {
    this.logger.error(msg, { baseEntity })
  }

  /**
  * getConfig returns plugin endpoint configuration "scimgatway.endpoint"   
  * Includes encryption/decryption of any attributes named password, secret, client_secret, token and APIKey  
  * For other custom attribute to be encrypted/decrypted use e.g., config.endpoint.myPasswordKey = scimgateway.getSecret('endpoint.myPasswordKey')
  * 
  * @returns plugin endpoint configuration
  **/
  getConfig(): Record<string, any> {
    if (this.config.endpoint) return this.config.endpoint
    else return {}
  }

  /**
  * isMultiValueTypes returns true if attr is mulitvalue else false
  * @attr scim attribute to check e.g., emails
  * @returns true or false based on attr is multivalue - e.g., emails returns true
  **/
  isMultiValueTypes(attr: string): boolean { // emails
    return this.multiValueTypes.includes(attr)
  }

  /**
  * getSecret returns the clear text secret value from an encrypted attribute in configuration file. If cleartext, configuration file will be updated with encrypted attribute value
  * @param dotNotationAttr dot-notated config file attribute e.g., endpoint.entity.undefined.password
  * @returns clear text secret and updates configuration file if needed with encrypted secret
  **/
  getSecret(dotNotationAttr: string) {
    return utils.getSecret(dotNotationAttr, this.configFile) // utils.getPassword('scimgateway.password', './config/plugin-testmode.json')
  }

  /**
  * @returns scim test user objects: bjensen and jsmith
  **/
  getTestModeUsers(): any[] {
    // used by plugin-loki
    let testmodeusers: any[] = []
    if (this.scimDef.TestmodeUsers && this.scimDef.TestmodeUsers.Resources) {
      testmodeusers = this.scimDef.TestmodeUsers.Resources
    }
    return testmodeusers
  }

  /**
  * @returns scim test group objects: Admins and Employees
  **/
  getTestModeGroups(): any[] {
    // used by plugin-loki
    let testmodegroups: any[] = []
    if (this.scimDef.TestmodeGroups && this.scimDef.TestmodeGroups.Resources) {
      testmodegroups = this.scimDef.TestmodeGroups.Resources
    }
    return testmodegroups
  }

  /**
  * copyObj returns a copy of the object
  * @param obj object to be copied
  * @returns copy of object
  **/
  copyObj(obj: any) {
    return utils.copyObj(obj)
  }

  /**
  * extendObj extends obj with src
  * @param obj object to be extended with src
  * @param src object to be included
  * @returns updated object
  **/
  extendObj(obj: any, src: any) {
    return utils.extendObj(obj, src)
  }

  /**
  * Lock for mutual exclusion
  * - const lock = new scimgateway.Lock()
  * - lock.acquire()
  * - do stuff...
  * - lock.release()
  **/
  Lock = utils.Lock

  /**
  * getArrayObject returns object in element multivalue havint type defined 
  * @param obj `{..., "emails":[{"type":work", "value":"123"}, ...]}`
  * @param element "emails"
  * @param type "work"
  * @returns `{"type":work", "value":"123"}`
  **/
  getArrayObject(obj: any, element: string, type: string): any {
    if (obj[element]) { // element is case sensitive
      return obj[element].find(function (el: Record<string, any>) {
        return (el.type && (el.type).toLowerCase() === type.toLowerCase())
      })
    }
    return null
  }

  /**
  * endpointMapper maps inbound SCIM and outbound endpoint attributes both ways
  * @param direction 'outbound' (to the endpoint) or 'inbound' (SCIM response) 
  * @param parseObj object containing attributes to be mapped
  * @param mapObj map configuration object, often using user or group mapper configuration object defined in the plugin configuration file
  * @returns [mappedObj, err] - errors are often ignored because there might be parseObj attributes not defined in mapObj configuration
  * @example
  * ```
  * const [endpointObj] = scimgateway.endpointMapper('outbound', userObj, config.map.user)
  * using [endpointObj, err] - if err, throw error to catch non supported attributes
  * const [endpointObj] = scimgateway.endpointMapper('outbound', {"userName":"bjensen","name":{"givenName":"Barbara"}}, {"userID":{"mapTo":"userName","type":"string"},"lastName":{"mapTo":"name.givenName","type":"string"}})
  * => returns object having correct endpoint attributes
  * const outAttr = scimgateway.endpointMapper('outbound', 'userName', config.map.user)
  * => returns the mapped outbound attribute for "userName" e.g. "userID"
  * ```
  */
  endpointMapper = utilsScim.endpointMapper

  /**
  * sendMail sends a mail using scimgateway.email configuraration
  * @param msgObj mail object
  * @param isHtml set to true if msgObj.content is HTML encoded, else false for plain text
  * @remarks
  * msgObj example:  
  * ```
  * {
  *   from: 'firstname.lastname@company.com',
  *   to: 'servicedesk@company.com',
  *   cc: 'operators@company.com',
  *   subject: 'SCIM Gateway message',
  *   content: '<html><body><p>Testing <b>HTML encoded</b> message</p></body></html>',
  * }
  * ```
  * email server and authentication being used is defiend in configuration file setting scimgateway.email  
  * example below using **SMTP AUTH**  
  * note, msgObj.from should normally correspond with configuration auth.options.username
  * ```
  * {
  *   "scimgateway": {
  *     "email": {
  *       "host": "<host>", // smtp.gmail.com
  *       "port": <port>, // 587
  *       "auth": {
  *         "type": "basic",
  *         "options": {
  *           "username": "<email address>",
  *           "password": "<password>" // app password
  *         }
  *       },
  *       "proxy": {
  *         "host": null, // http://proxy-host:1234
  *         "username": null,
  *         "password": null
  *        }
  *     },
  *    ...
  *   }
  * }
  * ```
  * example below using recommended **OAuth**  
  * note, Microsoft do not default support SMTP AUTH anymore and OAuth should be used   
  * ```
  * {
  *   "scimgateway": {
  *     "email": {
  *       "host": "<host>", // required when not using azureTenantId (Microsoft)
  *       "port": <port>, // required when not using azureTenantId (Microsoft)
  *       "auth": {
  *         "type": "oauth",
  *         "options": {
  *           "azureTenantId": "<tenantId>", // used for Microsoft Exchange Online
  *           "tokenUrl": "<tokenUrl>",     // required when not using azureTenantId (Microsoft)
  *           "clientId": "<clientId>",
  *           "clientSecret": "<clientSecret>"
  *         }
  *       },
  *       "proxy": {
  *         "host": null, // http://proxy-host:1234
  *         "username": null,
  *         "password": null
  *        }
  *     },
  *    ...
  *   }
  * }
  * ```
  * Some notes when using OAuth and azureTenantId - Microsoft Exchange:  
  * Entra ID application must have application permissions "**Mail.Send**"  
  *   
  * For not allowing send email from all mailboxes, ExO **ApplicationAccessPolicy** must be defined through PowerShell.  
  * First create a mail-enabled security-group that only includes users (mailboxes) the app is allowed to send from  
  * Note, "mail enabled security" cannot be created from portal, only from admin or admin.exchange console  
  * ```
  * ##Connect to Exchange
  * Install-Module -Name ExchangeOnlineManagement
  * Connect-ExchangeOnline
  * 
  * ##Create ApplicationAccessPolicy
  * New-ApplicationAccessPolicy -AppId $AppClientID -PolicyScopeGroupId $MailEnabledSecurityGrpId -AccessRight RestrictAccess -Description "Restrict app to specific mailboxes"
  * ```
  **/
  async sendMail(msgObj: Record<string, any>, isHtml: boolean = false) {
    const gwName = this.gwName
    const logger = this.logger
    const authType = this.config.scimgateway?.email?.auth?.type ? this.config.scimgateway.email.auth.type.toLowerCase() : ''

    if (typeof msgObj !== 'object' || !msgObj.from || !msgObj.to || !msgObj.content) {
      logger.error(`${gwName} sendMail failed: missing or invalid msgObj argument`)
      return
    }
    if (!isHtml) {
      isHtml = true
      msgObj.content = `<html><body><pre style="font-family: monospace; white-space: pre-wrap;">${msgObj.content}</pre></body></html>`
    }
    if (!msgObj.to) msgObj.to = ''
    if (!msgObj.cc) msgObj.cc = ''
    if (!msgObj.subject) msgObj.subject = 'SCIM Gateway message'

    if (authType === 'oauth') {
      if (!this.helperRest) this.helperRest = this.newHelperRest()
      if (this.config.scimgateway.email.auth?.options?.azureTenantId) {
        // Microsoft Exchange Online (ExO) - using Graph API
        const emailMessage: Record<string, any> = {
          message: {
            subject: msgObj.subject,
            body: {
              content: msgObj.content,
              contentType: isHtml ? 'HTML' : 'Text',
            },
            toRecipients: [],
            ccRecipients: [],
          },
          saveToSentItems: 'false',
        }

        if (msgObj.to) {
          let arr = msgObj.to.split(',')
          for (let i = 0; i < arr.length; i++) {
            emailMessage.message.toRecipients.push({
              emailAddress: {
                address: arr[i].trim(),
              },
            })
          }
        }
        if (msgObj.cc) {
          const arr = msgObj.cc.split(',')
          for (let i = 0; i < arr.length; i++) {
            emailMessage.message.ccRecipients.push({
              emailAddress: {
                address: arr[i].trim(),
              },
            })
          }
        }
        if (emailMessage.message.toRecipients.length === 0) delete emailMessage.message.toRecipients
        if (emailMessage.message.ccRecipients.length === 0) delete emailMessage.message.ccRecipients

        const path = `/users/${msgObj.from}/sendMail`
        try {
          await this.helperRest.doRequest('undefined', 'POST', path, emailMessage)
          logger.debug(`${gwName} sendMail subject '${msgObj.subject}' sent to: ${msgObj.to}${(msgObj.cc) ? ',' + msgObj.cc : ''}`)
        } catch (err: any) {
          logger.error(`${gwName} sendMail subject '${msgObj.subject}' sending failed: ${err.message}`)
        }
        return
      } else if (this.config.scimgateway.email.auth?.options?.serviceAccountKeyFile) {
        // Google Workspace Gmail
        let mimeMessage = `From: ${msgObj.from}
To: ${msgObj.to}
Cc: ${msgObj.cc}
Subject: ${msgObj.subject}
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

`
        mimeMessage += msgObj.content
        const encodedMessage = btoa(mimeMessage)
        const emailMessage = { raw: encodedMessage }
        const path = `/gmail/v1/users/${msgObj.from}/messages/send`
        try { // using opt connection argument type=oauthJwtBearer and options scope/subject because we want to keep simplified email.auth.type=oauth and options serviceAccountKeyFile
          await this.helperRest.doRequest('undefined', 'POST', path, emailMessage, null, { connection: { auth: { type: 'oauthJwtBearer', options: { jwtPayload: { scope: 'https://www.googleapis.com/auth/gmail.send', subject: msgObj.from } } } } })
          logger.debug(`${gwName} sendMail subject '${msgObj.subject}' sent to: ${msgObj.to}${(msgObj.cc) ? ',' + msgObj.cc : ''}`)
        } catch (err: any) {
          logger.error(`${gwName} sendMail subject '${msgObj.subject}' sending failed: ${err.message}`)
        }
        return
      }
      logger.error(`${gwName} sendMail error: type oauth supports only ExO (scimgateway.email.auth.options.azureTenantId) or Google Workspace Gmail (scimgateway.email.auth.options.serviceAccountKeyFile)`)
      return
    }

    if (authType !== 'smtp') {
      logger.error(`${gwName} sendMail error: configuration scimgateway.email.auth.type must be set to oauth or smtp`)
      return
    }

    // nodemailer - SMTP Auth
    const smtpConfig: { [key: string]: any } = {
      host: this.config.scimgateway?.email?.auth?.options?.host, // e.g. smtp.office365.com
      port: this.config.scimgateway?.email?.auth?.options?.port || 587,
      secure: (this.config.scimgateway?.email?.auth?.options?.port === 465), // false on 25/587
      tls: { minVersion: 'TLSv1.2' },
      proxy: this.config.scimgateway?.email?.proxy,
    }

    smtpConfig.auth = {}
    smtpConfig.auth.user = this.config.scimgateway?.email?.auth?.options?.username
    smtpConfig.auth.pass = this.config.scimgateway?.email?.auth?.options?.password

    if (!this.config.scimgateway?.email?.auth?.options?.host || !this.config.scimgateway?.email?.auth?.options?.username) {
      logger.error(`${gwName} sendMail subject '${msgObj.subject}' sending error: missing scimgateway.email.options configuration for auth type smtp`)
      return
    }

    const transporter = nodemailer.createTransport(smtpConfig)

    const mailOptions: Record<string, any> = {
      from: msgObj.from, // sender address
      to: msgObj.to, // list of receivers - comma separated
      cc: msgObj.cc,
      subject: msgObj.subject,
    }

    if (isHtml) mailOptions.html = msgObj.content
    else mailOptions.text = msgObj.content

    transporter.sendMail(mailOptions, function (err) {
      if (err != null) logger.error(`${gwName} sendMail subject '${msgObj.subject}' sending failed: ${err.message}`)
      else logger.debug(`${gwName} sendMail subject '${msgObj.subject}' sent to: ${msgObj.to}${(msgObj.cc) ? ',' + msgObj.cc : ''}`)
    })
  }

  // processConfig updates this.config and return found.<auth method>
  // config external process.env/file/text replaced with actual values
  // config encryption/decryption for keys named: 'password', 'secret', 'clientSecret', 'token', 'apikey'
  // certificates updated with full path
  private processConfig() {
    const encryptAttrs = ['password', 'secret', 'clientsecret', 'token', 'apikey'] // lowercase
    const processEnv = 'process.env.'
    const processFile = 'process.file.'
    const processText = 'process.text.'
    const processTexts = new Map()
    const processFiles = new Map()
    const dotConfig = dot.dot(this.config)

    let foundBasic = false
    let foundBearerToken = false
    let foundBearerJwt = false
    let foundBearerOAuth = false
    let foundPassThrough = false

    for (const key in dotConfig) {
      let value = dotConfig[key]
      if (!value || value.constructor !== String) continue
      const arr = key.split('.')
      const lastKey = arr[arr.length - 1]

      // found logic
      if (lastKey === 'password' && key.startsWith('scimgateway.auth.basic')) foundBasic = true
      else if (lastKey === 'token' && key.startsWith('scimgateway.auth.bearerToken')) foundBearerToken = true
      else if ((lastKey === 'publicKey' || lastKey === 'secret' || lastKey === 'wellKnownUri' || 'azureTenantId') && key.startsWith('scimgateway.auth.bearerJwt')) foundBearerJwt = true
      else if (lastKey === 'clientSecret' && key.startsWith('scimgateway.auth.bearerOAuth')) foundBearerOAuth = true

      // certificate full path
      if (key.includes('.certificate.') || key.includes('.tls.')) {
        if (key.endsWith('.key') || key.endsWith('.cert') || key.endsWith('.ca') || key.includes('.ca[') || key.endsWith('.pfx.bundle')) {
          let keyFile = path.join(this.configDir, '/certs/', dotConfig[key])
          if (dotConfig[key].startsWith('/') || dotConfig[key].includes('\\')) {
            keyFile = dotConfig[key]
          }
          dotConfig[key] = keyFile
        }
      } else if (key.startsWith('scimgateway.auth.bearerJwt') && lastKey === 'publicKey') {
        let keyFile = path.join(this.configDir, '/certs/', dotConfig[key])
        if (dotConfig[key].startsWith('/') || dotConfig[key].includes('\\')) {
          keyFile = dotConfig[key]
        }
        dotConfig[key] = keyFile
        const addKey = key.replace(`.${lastKey}`, '.publicKeyObj')
        const pem = fs.readFileSync(keyFile)
        dotConfig[addKey] = createPublicKey(pem)
      } else if (key.endsWith('.serviceAccountKeyFile')) { // Google Service Account Key json-file
        let keyFile = path.join(this.configDir, '/certs/', dotConfig[key])
        if (dotConfig[key].startsWith('/') || dotConfig[key].includes('\\')) {
          keyFile = dotConfig[key]
        }
        dotConfig[key] = keyFile
      }

      // process env, file and text
      if (value.includes(processEnv)) {
        const envKey = value.substring(processEnv.length)
        value = process.env[envKey]
        dotConfig[key] = value
        if (!value) {
          const newErr = new Error(`configuration failed - can't use none existing environment: "${envKey}"`)
          newErr.name = 'processConfig'
          throw newErr
        }
      } else if (value.includes(processText)) {
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
      } else if (value.includes(processFile)) {
        const filePath = value.substring(processFile.length)
        try {
          if (!processFiles.has(filePath)) { // avoid reading previous file
            processFiles.set(filePath, JSON.parse(fs.readFileSync(filePath, 'utf8')))
          }
          try {
            const jContent = processFiles.get(filePath) // json or json-dot-notation formatting is supported
            const dotContent = dot.dot(dot.object(jContent))
            const newKey = `${this.pluginName}.${key}` // plugin-loki.endpoint.password
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
                newErr.name = 'processConfig'
                throw newErr
              }
            }
          } catch (err: any) {
            if (err.name && err.name === 'processConfig') throw err
            else {
              const newErr = new Error(`configuration failed - can't JSON parse external file: "${filePath}"`)
              newErr.name = 'processConfig'
              throw newErr
            }
          }
        } catch (err: any) {
          value = undefined
          if (err.name && err.name === 'processConfig') throw err
          else throw (new Error(`configuration failed - can't read external configuration file: ${err.message}`))
        }
        dotConfig[key] = value
      } else {
        // check for standard encryption/decryption
        if (encryptAttrs.includes(lastKey.toLowerCase())) {
          dotConfig[key] = utils.getSecret(key, this.configFile)
        }
      }
    }

    processTexts.clear()
    processFiles.clear()
    this.config = dot.object(dotConfig) // updated config

    if (!foundBasic) this.config.scimgateway.auth.basic = []
    if (!foundBearerToken) this.config.scimgateway.auth.bearerToken = []
    if (!foundBearerOAuth) this.config.scimgateway.auth.bearerOAuth = []
    if (!foundBearerJwt) this.config.scimgateway.auth.bearerJwt = []
    if (this?.config?.scimgateway?.auth?.passThrough?.enabled === true) foundPassThrough = true

    return { // valid auth methods
      Basic: foundBasic,
      BearerToken: foundBearerToken,
      BearerJwt: foundBearerJwt,
      BearerOAuth: foundBearerOAuth,
      PassThrough: foundPassThrough,
    }
  }

  /** 
   * newHelerRest returns a new HelperRest that includs email connection  
   * This to ensure same instance can be used globally for scimgateway
   */
  private newHelperRest() {
    return new HelperRest(this, { entity: { undefined: { connection: this.config.scimgateway.email } } })
  }
} // class scimgateway

export default ScimGateway
