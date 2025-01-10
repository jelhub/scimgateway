// =================================================================================
// File:    scimgateway.js
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
import { createChecker } from 'is-in-subnet'
import { BearerStrategy, type IBearerStrategyOptionWithRequest } from 'passport-azure-ad'
import { fileURLToPath } from 'url'
import { Log } from './logger.ts'
import passport from 'passport'
import dot from 'dot-object'
import nodemailer from 'nodemailer'
import fs from 'node:fs'
import path from 'node:path'
import * as jwt from 'jsonwebtoken'
import * as utils from './utils.ts'
import * as utilsScim from './utils-scim.ts'
import * as stream from './scim-stream.js'
export * from './helper-rest.ts'
import { HelperRest } from './helper-rest.ts'

export class ScimGateway {
  private config: any
  private logger: any
  private gwName: string
  private scimDef: any
  private countries: any
  private multiValueTypes: any
  private replaceUsrGrp: any
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
  getUsers!: (baseEntity: string, getObj: Record<string, any>, attributes: Array<string>, ctx?: undefined | Record<string, any>) => any
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
  getGroups!: (baseEntity: string, getObj: Record<string, any>, attributes: Array<string>, ctx?: undefined | Record<string, any>) => any
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
  * @param apiObj is POST body and contains object to be created
  * @param ctx if plugin authPassThroughAllowed is set to true, ctx contains authorization header `{ "headers": { "authorization": "<value>" } }` that can be used in the communication with endpoint, something that is included when using HelperRest
  * @returns according to your needs
  * @example
  * POST http://localhost:8890/api  
  * body = {"title":"BMW X5","price":58}
  */
  postApi!: (baseEntity: string, apiObj: any, ctx?: undefined | Record<string, any>) => any
  /**
  * putApi method is defined at the plugin and should handle incoming `"PUT /api/<id>"` for replacing an object and should be used according to your needs  
  * @param baseEntity used for multi tenant or multi endpoint support, either "undefined" or set by request url e.g., http://localhost:8880/loki2/Users gives baseEntity=loki2
  * @param id unique object id
  * @param apiObj is PUT body and contains the new replaced object
  * @param ctx if plugin authPassThroughAllowed is set to true, ctx contains authorization header `{ "headers": { "authorization": "<value>" } }` that can be used in the communication with endpoint, something that is included when using HelperRest
  * @returns according to your needs
  * @example
  * PUT http://localhost:8890/api/100  
  * body = {"title":"BMW X1","price":21}  
  */
  putApi!: (baseEntity: string, id: string, apiObj: any, ctx?: undefined | Record<string, any>) => any
  /**
  * patchApi method is defined at the plugin and should handle incoming `"PATCH /api/<id>"` for modifying an object and should be used according to your needs  
  * @param baseEntity used for multi tenant or multi endpoint support, either "undefined" or set by request url e.g., http://localhost:8880/loki2/Users gives baseEntity=loki2
  * @param id unique object id
  * @param apiObj is PATCH body and contains attributes to be modified
  * @param ctx if plugin authPassThroughAllowed is set to true, ctx contains authorization header `{ "headers": { "authorization": "<value>" } }` that can be used in the communication with endpoint, something that is included when using HelperRest
  * @returns according to your needs
  * @example
  * PATCH http://localhost:8890/api/100  
  * body = {"title":"BMW X3"}
  */
  patchApi!: (baseEntity: string, id: string, apiObj: any, ctx?: undefined | Record<string, any>) => any
  /**
  * getApi method is defined at the plugin and should handle incoming `"GET /api/<query>"` for retrieving one or more objects and should be used according to your needs  
  * @param baseEntity used for multi tenant or multi endpoint support, either "undefined" or set by request url e.g., http://localhost:8880/loki2/Users gives baseEntity=loki2
  * @param id <undefined | unique object id> // if undefined all objects should be retrived
  * @param apiQuery is url querystring
  * @param ctx if plugin authPassThroughAllowed is set to true, ctx contains authorization header `{ "headers": { "authorization": "<value>" } }` that can be used in the communication with endpoint, something that is included when using HelperRest
  * @returns according to your needs
  * @examples
  * GET http://localhost:8890/api  
  * GET http://localhost:8890/api/100  
  */
  getApi!: (baseEntity: string, id: string, apiQuery: any, apiObj: any, ctx?: undefined | Record<string, any>) => any
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

  constructor() {
    const startTime = utils.timestamp()

    // need requester/plugin full path for setting pluginName and configDir
    const originalStackTrace = new Error().stack
    const stackLines = originalStackTrace ? originalStackTrace.split('\n') : ''
    let requester: string = ''
    let callerLine = ''
    for (let i = 0; i < stackLines.length; i++) {
      if (stackLines[i].includes('new ScimGateway') && i < stackLines.length - 1) {
        callerLine = stackLines[i + 1]
        break
      }
    }
    if (callerLine) {
      let match = callerLine.match(/(?:\()([^)]+):\d+:\d+(?:\))/)
      if (match && match[1]) {
        requester = match[1]
      }
      if (!requester) {
        match = callerLine.match(/.*(file:\/\/\/)?([A-Za-z]:[/\\].*?):\d+:\d+(?:\))?/) // nodejs
        if (match && match[2]) {
          requester = match[2]
        }
      }
    }

    let pluginName = path.basename(requester)
    pluginName = pluginName.substring(0, pluginName.lastIndexOf('.')) || pluginName
    let pluginDir = path.dirname(requester)
    let configDir = path.join(pluginDir, '..', 'config')
    if (pluginDir.includes('BUN/root')) {
      // running compiled binary, binary name will be pluginName
      // bun build index.ts --target bun --compile --outfile plugin-xxx
      // we then need: ./plugin-xxx and ./config/plugin-xxx.json
      pluginDir = '.' // only support running binary in current directory (path to binary can't be found)
      configDir = './config'
    }
    const configFile = path.join(`${configDir}`, `${pluginName}.json`) // config name prefix same as pluging name prefix
    const gwName = path.basename(fileURLToPath(import.meta.url)).split('.')[0] // prefix of current file - using fileURLToPath because using "__filename" is not supported by nodejs typescript
    const gwPath = path.dirname(fileURLToPath(import.meta.url))
    const logDir = path.join(pluginDir, '..', 'logs')

    this.config = {}
    // exposed outside class
    this.pluginName = pluginName
    this.configDir = configDir
    this.configFile = configFile
    this.countries = (() => {
      try {
        return JSON.parse(fs.readFileSync(path.join(gwPath, 'countries.json')).toString())
      } catch (err) {
        return []
      }
    })()

    let found: Record<string, any> = {}
    let configErr: any
    try {
      this.config = JSON.parse(fs.readFileSync(configFile, 'utf-8'))
      found = this.processConfig()
    } catch (err) { configErr = err }

    const logger = new Log('info', this.config?.scimgateway?.log?.loglevel?.file, path.join(`${logDir}`, `${pluginName}.log`), pluginName, this.config?.scimgateway?.log?.customMasking)
    if (configErr) {
      logger.error(`${gwName}[${pluginName}] ${configErr.message}`)
      logger.error(`${gwName}[${pluginName}] stopping...\n`)
      throw (new Error('Using exception to stop further asynchronous code execution (ensure synchronous logger flush to logfile and exit program), please ignore this one...'))
    }

    this.logger = logger
    // exposed to plugin
    this.gwName = gwName
    this.pluginName = pluginName
    this.configDir = configDir
    this.configFile = configFile
    this.authPassThroughAllowed = false // set to true by plugin if using Auth PassThrough

    const oAuthTokenExpire = 3600 // seconds
    let pwErrCount = 0
    let requestCounter = 0
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
    if (!this.config.scimgateway.auth.bearerJwtAzure) this.config.scimgateway.auth.bearerJwtAzure = []
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
    const handlers = ['users', 'groups', 'serviceplans', 'approles', 'api', 'schemas', 'serviceproviderconfig', 'serviceproviderconfigs']

    try {
      if (!fs.existsSync(configDir + '/wsdls')) fs.mkdirSync(configDir + '/wsdls')
      if (!fs.existsSync(configDir + '/certs')) fs.mkdirSync(configDir + '/certs')
      if (!fs.existsSync(configDir + '/schemas')) fs.mkdirSync(configDir + '/schemas')
    } catch (err) { void 0 }

    let isScimv2 = false
    if (this.config.scimgateway.scim.version === '2.0' || this.config.scimgateway.scim.version === 2) {
      this.scimDef = (() => {
        try {
          return JSON.parse(fs.readFileSync(path.join(pluginDir, 'scimdef-v2.json')).toString()) // using custom
        } catch (err) {
          return JSON.parse(fs.readFileSync(path.join(gwPath, 'scimdef-v2.json')).toString())
        }
      })()
      isScimv2 = true
    } else {
      this.scimDef = (() => {
        try {
          return JSON.parse(fs.readFileSync(path.join(pluginDir, 'scimdef-v1.json')).toString()) // using custom
        } catch (err) {
          return JSON.parse(fs.readFileSync(path.join(gwPath, 'scimdef-v1.json')).toString())
        }
      })()
    }

    if (this.config.scimgateway.scim.customSchema) { // legacy - merge plugin custom schema extension into core schemas
      let custom
      try {
        custom = JSON.parse(fs.readFileSync(`${configDir}/schemas/${this.config.scimgateway.scim.customSchema}`, 'utf8'))
      } catch (err: any) {
        throw new Error(`failed reading file defined in configuration "scim.customSchema": ${err.message}`)
      }
      if (!Array.isArray(custom)) custom = [custom]
      const schemas = ['User', 'Group']
      let customMerged = false
      for (let i = 0; i < schemas.length; i++) {
        const schema = this.scimDef.Schemas.Resources.find((el: Record<string, any>) => el.name === schemas[i])
        const customSchema = custom.find((el: Record<string, any>) => el.name === schemas[i])
        if (schema && customSchema && Array.isArray(customSchema.attributes)) {
          const arr1 = schema.attributes // core:1.0/2.0 schema
          const arr2 = customSchema.attributes
          schema.attributes = arr2.filter((arr2Obj: Record<string, any>) => { // only merge attributes (objects) having unique name into core schema
            if (!arr1.some((arr1Obj: Record<string, any>) => arr1Obj.name === arr2Obj.name)) {
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
          'Also make sure attribute names in attributes array do not conflict with core:1.0/2.0 SCIM attribute names',
        ].join()
        throw new Error(err)
      }
    }

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
      if (ctx.path === '/ping' || ctx.path === '/favicon.ico') return
      const ellapsed = performance.now() - ctx.perfStart
      let userName
      const [authType, authToken] = (ctx.request.headers.get('authorization') || '').split(' ') // [0] = 'Basic' or 'Bearer'
      if (authType === 'Basic') [userName] = (Buffer.from(authToken, 'base64').toString() || '').split(':')
      if (!userName && authType === 'Bearer') userName = 'token'
      if (ctx.response.status && (ctx.response.status < 200 || ctx.response.status > 299)) {
        logger.error(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] ${ellapsed} ${ctx.ip} ${userName} ${ctx.response.status} ${ctx.request.method} ${ctx.request.url} Inbound=${JSON.stringify(ctx.request.body)} Outbound=${ctx.response.body}${(this.config.scimgateway.log.loglevel.file === 'debug' && ctx.request.url !== '/ping') ? '\n' : ''}`)
      } else logger.info(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] ${ellapsed} ${ctx.ip} ${ctx.response.status} ${userName} ${ctx.request.method} ${ctx.request.url} Inbound=${JSON.stringify(ctx.request.body)} Outbound=${ctx.response.body}${(this.config.scimgateway.log.loglevel.file === 'debug' && ctx.request.url !== '/ping') ? '\n' : ''}`)
      requestCounter += 1 // logged on exit (not win process termination)
    }

    // start auth methods - used by auth
    const basic = async (baseEntity: string, method: string, authType: string, authToken: string): Promise<boolean> => {
      return await new Promise((resolve, reject) => { // basic auth
        if (authType !== 'Basic') resolve(false)
        if (!found.Basic) resolve(false)
        if (found.PassThrough && this.authPassThroughAllowed) resolve(false)
        const [userName, userPassword] = (Buffer.from(authToken, 'base64').toString() || '').split(':')
        if (!userName || !userPassword) {
          return reject(new Error(`authentication failed for user ${userName}`))
        }
        const arr = this.config.scimgateway.auth.basic
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

    const bearerToken = async (baseEntity: string, method: string, authType: string, authToken: string): Promise<boolean> => {
      return await new Promise((resolve, reject) => { // bearer token
        if (authType !== 'Bearer' || !authToken) resolve(false)
        if (!found.BearerToken) resolve(false)
        const arr = this.config.scimgateway.auth.bearerToken
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

    const bearerJwtAzure = async (baseEntity: string, method: string, authType: string, authToken: string): Promise<boolean> => {
      return await new Promise((resolve, reject) => {
        if (authType !== 'Bearer' || !found.BearerJwtAzure) resolve(false) // no azure bearer token
        const jtoken: any = jwt.decode(authToken, { complete: true })
        if (jtoken == null) resolve(false)
        else if (!jtoken.payload['iss']) resolve(false)
        if (jtoken?.payload['iss'].indexOf('https://sts.windows.net') !== 0) resolve(false)
        const req = { headers: { authorization: `${authType} ${authToken}` } } // Node.js http.createServer type IncomingMessage - header supported by passport 
        passport.authenticate('oauth-bearer', { session: false }, (err: any, user: any, info: any) => {
          if (err) { return reject(err) }
          if (user) { // authenticated OK
            const arr = this.config.scimgateway.auth.bearerJwtAzure
            for (let i = 0; i < arr.length; i++) {
              if (arr[i].tenantIdGUID && jtoken?.payload['iss'].includes(arr[i].tenantIdGUID)) {
                if (arr[i].baseEntities) {
                  if (Array.isArray(arr[i].baseEntities) && arr[i].baseEntities.length > 0) {
                    if (!baseEntity) return reject(new Error(`baseEntity=${baseEntity} not allowed for user ${arr[i].tenantIdGUID} according to bearerJwtAzure configuration baseEntitites=${arr[i].baseEntities}`))
                    if (!arr[i].baseEntities.includes(baseEntity)) return reject(new Error(`baseEntity=${baseEntity} not allowed for user ${arr[i].tenantIdGUID} according to bearerJwtAzure configuration baseEntitites=${arr[i].baseEntities}`))
                  }
                }
                if (arr[i].readOnly === true && method !== 'GET') return reject(new Error(`only allowing readOnly for user ${arr[i].tenantIdGUID} according to bearerJwtAzure configuration readOnly=true`))
              }
            }
            resolve(true)
          } else reject(new Error(`Azure JWT authorization failed: ${info}`))
        })(req)
      })
    }

    const jwtVerify = async (baseEntity: string, method: string, el: Record<string, any>, authToken: string) => { // used by bearerJwt
      return await new Promise((resolve) => {
        jwt.verify(authToken, (el.secret) ? el.secret : el.publicKeyContent, el.options, (err) => {
          if (err != null) resolve(false)
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

    const bearerJwt = async (baseEntity: string, method: string, authType: string, authToken: string): Promise<boolean> => {
      if (authType !== 'Bearer' || !found.BearerJwt) return false // no standard jwt bearer token
      const jtoken: any = jwt.decode(authToken, { complete: true })
      if (jtoken == null) return false
      if (jtoken?.payload['iss'] && jtoken?.payload['iss'].indexOf('https://sts.windows.net') === 0) return false // azure - handled by bearerJwtAzure
      const promises: any = []
      const arr = this.config.scimgateway.auth.bearerJwt
      for (let i = 0; i < arr.length; i++) {
        promises.push(jwtVerify(baseEntity, method, arr[i], authToken))
      }
      const arrResolve = await Promise.all(promises).catch((err) => { throw (err) })
      for (const i in arrResolve) {
        if (arrResolve[i]) return true
      }
      throw new Error('JWT authentication failed')
    }

    const bearerOAuth = async (baseEntity: string, method: string, authType: string, authToken: string): Promise<boolean> => {
      return await new Promise((resolve, reject) => { // bearer token
        if (authType !== 'Bearer' || !authToken) resolve(false)
        if (!found.BearerOAuth || !authToken) resolve(false)
        // this.config.scimgateway.auth.oauthTokenStore is autmatically generated by token create having syntax:
        // { this.config.scimgateway.auth.oauthTokenStore: <token>: { expireDate: <timestamp>, readOnly: <copy-from-config>, baseEntities: [ <copy-from-config> ], isTokenRequested: true }}
        const arr = this.config.scimgateway.auth.bearerOAuth
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
              if (!tokenObj.baseEntities.includes(baseEntity)) return reject(new Error(`baseEntity=${baseEntity} not allowed for this bearerOAuth according to bearerOAuth configuration baseEntitites=${tokenObj.baseEntities}`))
            }
          }
          if (tokenObj.readOnly === true && method !== 'GET') return reject(new Error('only allowing readOnly for this bearerOAuth according to bearerOAuth configuration readOnly=true'))
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
        reject(new Error('OAuth authentication failed'))
      })
    }

    const authPassThrough = async (baseEntity: string, method: string, authType: string, authToken: string): Promise<boolean> => {
      if (!found.PassThrough || !this.authPassThroughAllowed) return false
      if (!authToken) return false
      if (authType === 'Basic') {
        const [userName, userPassword] = (Buffer.from(authToken, 'base64').toString() || '').split(':')
        if (!userName || !userPassword) return false
      }
      const obj = this.config.scimgateway.auth.passThrough
      if (obj.baseEntities) {
        if (Array.isArray(obj.baseEntities) && obj.baseEntities.length > 0) {
          if (!baseEntity || !obj.baseEntities.includes(baseEntity)) throw new Error(`baseEntity=${baseEntity} not allowed for passThrough according to passThrough configuration baseEntitites=${obj.baseEntities}`)
        }
      }
      if (obj.readOnly === true && method !== 'GET') throw new Error('only allowing readOnly for passThrough according to passThrough configuration readOnly=true')
      return true
    }

    // end auth methods - used by auth

    const isAuthorized = async (ctx: Context): Promise<boolean> => { // authentication/authorization 
      const [authType, authToken] = (ctx.request.headers.get('authorization') || '').split(' ') // [0] = 'Basic' or 'Bearer'
      try { // authenticate
        const arrResolve = await Promise.all([
          basic(ctx.routeObj.baseEntity, ctx.request.method, authType, authToken),
          bearerToken(ctx.routeObj.baseEntity, ctx.request.method, authType, authToken),
          bearerJwtAzure(ctx.routeObj.baseEntity, ctx.request.method, authType, authToken),
          bearerJwt(ctx.routeObj.baseEntity, ctx.request.method, authType, authToken),
          bearerOAuth(ctx.routeObj.baseEntity, ctx.request.method, authType, authToken),
          authPassThrough(ctx.routeObj.baseEntity, ctx.request.method, authType, authToken),
        ])
          .catch((err) => { throw (err) })
        for (const i in arrResolve) {
          if (arrResolve[i]) return true // auth OK - continue with routes
        }
        // all false - invalid auth method or missing pluging config
        let err: Error
        if (authType.length < 1) err = new Error(`${ctx.request.url} request is missing authentication information`)
        else {
          err = new Error(`${ctx.request.url} request having unsupported authentication or plugin configuration is missing`)
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] request authToken = ${authToken}`)
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] request jwt.decode(authToken) = ${JSON.stringify(jwt.decode(authToken))}`)
        }
        if (authType === 'Bearer') ctx.response.headers.set('WWW-Authenticate', 'Bearer realm=""')
        else if (found.Basic) ctx.response.headers.set('WWW-Authenticate', 'Basic realm=""')
        if (ctx.request.url !== '/favicon.ico') logger.error(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] ${err.message}`)
        return false
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
          ctx.response.headers.set('WWW-Authenticate', `Bearer ${str}`)
        } else ctx.response.headers.set('WWW-Authenticate', 'Basic realm=""')
        if (pwErrCount < 3) {
          pwErrCount += 1
          logger.error(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] ${ctx.request.url} ${err.message}`)
        } else { // delay brute force attempts
          logger.error(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] ${ctx.request.url} ${err.message} => delaying response with 2 minutes to prevent brute force`)
          await new Promise((resolve) => {
            setTimeout(() => { resolve(null) }, 1000 * 60 * 2)
          })
        }
        return false
      }
      return false
    }

    const ipAllowList = (ipAddr: string): boolean => {
      if (ipAllowListChecker === undefined) return true
      if (ipAllowListChecker(ipAddr) === true) return true // if proxy, prereq: request includes header X-Forwarded-For
      logger.debug(`${gwName}[${pluginName}] client ip ${ipAddr} not in ipAllowList`)
      return false
    }

    const getHandlerSchemas = async (ctx: Context) => {
      let tx = this.scimDef.Schemas
      tx = utilsScim.addResources(tx, undefined, undefined, undefined)
      tx = utilsScim.addSchemas(tx, isScimv2, undefined, undefined)
      ctx.response.body = JSON.stringify(tx)
    }

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

    // oauth token request, POST /oauth/token
    const postHandlerOauthToken = async (ctx: Context) => {
      logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] [oauth] token request`)
      if (!found.BearerOAuth) {
        logger.error(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] [oauth] token request, but plugin is missing auth.bearerOAuth configuration`)
        ctx.response.status = 500
        return
      }
      let jsonBody = ctx.request.body
      try {
        if (!jsonBody) throw new Error('missing body')
        if (typeof jsonBody !== 'object') { // might have application/x-www-form-urlencoded or multipart/form-data body, but incorrect Content-Type header
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] [oauth] continue request validation even though incorrect body vs header Content-Type: ${ctx.request.headers.get('content-type')}`)
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
        logger.error(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] [oauth] token request error: ${err.message}`)
        ctx.response.status = 401
        return
      }
      const [authType, authToken] = (ctx.request.headers.get('authorization') || '').split(' ') // [0] = 'Basic'
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
        const arr = this.config.scimgateway.auth.bearerOAuth
        for (let i = 0; i < arr.length; i++) {
          if (!arr[i].clientId || !arr[i].clientSecret) continue
          if (arr[i].clientId === jsonBody.client_id && arr[i].clientSecret === jsonBody.client_secret) { // authentication OK
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
            logger.error(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] [oauth] ${ctx.origin + ctx.path} ${errDescr} => delaying response with 2 minutes to prevent brute force`)
            await new Promise((resolve) => {
              setTimeout(() => {
                resolve(ctx)
              }, 1000 * 60 * 2)
            })
            ctx.response.status = 401
            return
          }
        }
      }

      if (err) {
        logger.error(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] [oauth] token request client_id: ${jsonBody ? jsonBody.client_id : ''} error: ${errDescr}`)
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

      const tx = {
        access_token: token,
        token_type: 'Bearer',
        expires_in: expires,
        refresh_token: token, // ignored by scimgateway, but maybe used by client
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
      const id = decodeURIComponent(path.basename(ctx.routeObj.id || '', '.json')) // supports <id>.json

      if (!id) {
        ctx.response.status = 500
        const err = new Error('missing id')
        const [e, customErrorCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
        if (customErrorCode) ctx.response.status = customErrorCode
        ctx.response.body = JSON.stringify(e)
        return
      }
      if (ctx.query.attributes) ctx.query.attributes = ctx.query.attributes.split(',').map((item: string) => item.trim()).join()
      if (ctx.query.excludedAttributes) ctx.query.excludedAttributes = ctx.query.excludedAttributes.split(',').map((item: string) => item.trim()).join()

      const getObj = {
        attribute: 'id',
        operator: 'eq',
        value: id,
      }

      logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] [Get ${handle.description}s] ${getObj.attribute}=${getObj.value}`)

      let res
      try {
        const ob = utils.copyObj(getObj)
        const attributes = ctx.query.attributes ? ctx.query.attributes.split(',').map((item: string) => item.trim()) : []
        if (this.config.scimgateway.stream.publisher.enabled) {
          const streamObj = {
            func: handle.getMethod,
            baseEntity: baseEntity,
            obj: ob,
            attributes,
            ctxPassThrough: ctx.passThrough,
          }
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] publishing "${handle.getMethod}" to SCIM Stream and awaiting result`)
          res = await this.pub.publish(streamObj)
        } else {
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] calling "${handle.getMethod}" and awaiting result`)
          res = await (this as any)[handle.getMethod](baseEntity, ob, attributes, ctx.passThrough)
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

        if (scimdata.Resources.length !== 1) {
          ctx.response.status = 404
          const err = new Error(`${handle.description} ${getObj.value} not found`)
          const [e, customErrorCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
          if (customErrorCode) ctx.response.status = customErrorCode
          ctx.response.body = JSON.stringify(e)
          return
        }
        let userObj = scimdata.Resources[0]

        // check for user attribute groups and include if needed
        if (handle.getMethod === handler.users.getMethod && Object.keys(userObj).length > 0) {
          let arrAttr: string[] = []
          if (ctx.query.attributes) arrAttr = ctx.query.attributes.split(',')
          if ((!ctx.query.attributes || arrAttr.includes('groups'))) { // include groups
            if (!userObj.groups && userObj.id) {
              userObj.groups = await getMemberOf(baseEntity, userObj.id, handler.groups.getMethod, ctx.passThrough)
            }
          }
        }

        scimdata = utils.stripObj(userObj, ctx.query.attributes, ctx.query.excludedAttributes)
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
      } catch (err: any) {
        ctx.response.status = 404
        const [e, customErrorCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
        if (customErrorCode) ctx.response.status = customErrorCode
        ctx.response.body = JSON.stringify(e)
      }
    }

    // ==========================================
    //           getUsers
    //           getGroups
    // ==========================================
    const getHandler = async (ctx: Context) => {
      const handle = handler[ctx.routeObj.handle]
      const baseEntity = ctx.routeObj.baseEntity
      if (ctx.query.attributes) ctx.query.attributes = ctx.query.attributes.split(',').map((item: string) => item.trim()).join()
      if (ctx.query.excludedAttributes) ctx.query.excludedAttributes = ctx.query.excludedAttributes.split(',').map((item: string) => item.trim()).join()

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
          getObj.value = decodeURIComponent(arrFilter.slice(2).join(' ').replace(/"/g, '')) // bjensen
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
        const [e, customErrorCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
        if (customErrorCode) ctx.response.status = customErrorCode
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
      logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] [Get ${handle.description}]${info}`)
      try {
        getObj.startIndex = ctx.query.startIndex ? parseInt(ctx.query.startIndex) : undefined
        getObj.count = ctx.query.count ? parseInt(ctx.query.count) : undefined
        if (getObj.startIndex && !getObj.count) getObj.count = 200 // defaults to 200 (plugin may override)
        if (getObj.count && !getObj.startIndex) getObj.startIndex = 1

        let res: any
        const obj: any = utils.copyObj(getObj)
        const attributes = ctx.query.attributes ? ctx.query.attributes.split(',').map((item: string) => item.trim()) : []
        if (this.config.scimgateway.stream.publisher.enabled) {
          const streamObj = {
            func: handle.getMethod,
            baseEntity: baseEntity,
            obj,
            attributes,
            ctxPassThrough: ctx.passThrough,
          }
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] publishing "${handle.getMethod}" to SCIM Stream and awaiting result`)
          res = await this.pub.publish(streamObj)
        } else {
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
              logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] calling "${handle.getMethod}" with chunks and awaiting result`)
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
            logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] calling "${handle.getMethod}" and awaiting result`)
            res = await (this as any)[handle.getMethod](baseEntity, obj, attributes, ctx.passThrough)
          }
          // check for user attribute groups and include if needed
          if (Array.isArray(res?.Resources)) {
            if (handle.getMethod === handler.users.getMethod) {
              let arrAttr: string[] = []
              if (ctx.query.attributes) arrAttr = ctx.query.attributes.split(',')
              if ((!ctx.query.attributes || arrAttr.includes('groups'))) { // include groups
                for (let i = 0; i < res.Resources.length; i++) {
                  const userObj = res.Resources[i]
                  if (!userObj.id) break
                  if (userObj.groups) break
                  userObj.groups = await getMemberOf(baseEntity, userObj.id, handler.groups.getMethod, ctx.passThrough)
                }
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

        let location: string | undefined = ctx.origin + ctx.path
        if (this.config.scimgateway.scim.skipMetaLocation) location = undefined
        else if (ctx.query.attributes || (ctx.query.excludedAttributes && ctx.query.excludedAttributes.includes('meta'))) location = undefined
        for (let i = 0; i < scimdata.Resources.length; i++) {
          scimdata.Resources[i] = utils.stripObj(scimdata.Resources[i], ctx.query.attributes, ctx.query.excludedAttributes)
        }
        scimdata = utilsScim.addResources(scimdata, ctx.query.startIndex, ctx.query.sortBy, ctx.query.sortOrder)
        scimdata = utilsScim.addSchemas(scimdata, isScimv2, handle.description, location)

        ctx.response.body = JSON.stringify(scimdata)
      } catch (err: any) {
        if (isScimv2) ctx.response.status = 400
        else ctx.response.status = 500
        const [e, customErrorCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
        if (customErrorCode) ctx.response.status = customErrorCode
        ctx.response.body = JSON.stringify(e)
      }
    }

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
      logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] [Create ${handle.description}]`)
      let jsonBody = ctx.request.body
      try {
        if (!jsonBody) throw new Error('missing body')
        if (typeof jsonBody !== 'object') throw new Error('body is not JSON')
        jsonBody = utils.copyObj(jsonBody) // no changes to original
      } catch (err: any) {
        ctx.response.status = 500
        const [e, customErrorCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
        if (customErrorCode) ctx.response.status = customErrorCode
        ctx.response.body = JSON.stringify(e)
        return
      }

      if (handle.createMethod === 'createUser' && !jsonBody.userName && !jsonBody.externalId) {
        ctx.response.status = 500
        const err = new Error('userName or externalId is mandatory')
        const [e, customErrorCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
        if (customErrorCode) ctx.response.status = customErrorCode
        ctx.response.body = JSON.stringify(e)
        return
      } else if (handle.createMethod === 'createGroup' && !jsonBody.displayName && !jsonBody.externalId) {
        ctx.response.status = 500
        const err = new Error('displayName or externalId is mandatory')
        const [e, customErrorCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
        if (customErrorCode) ctx.response.status = customErrorCode
        ctx.response.body = JSON.stringify(e)
        return
      }

      logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] POST ${ctx.origin + ctx.path} body=${JSON.stringify(jsonBody)}`)
      const [scimdata, err] = utilsScim.convertedScim(jsonBody, this.multiValueTypes)
      logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] convertedBody=${JSON.stringify(scimdata)}`)
      if (err) {
        ctx.response.status = 500
        const [e, customErrorCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
        if (customErrorCode) ctx.response.status = customErrorCode
        ctx.response.body = JSON.stringify(e)
        return
      }
      delete jsonBody.id // in case included in request
      const addGrps: any = []
      try {
        let res
        if (this.config.scimgateway.stream.publisher.enabled) {
          const streamObj = {
            func: handle.createMethod,
            baseEntity: baseEntity,
            obj: scimdata,
            ctxPassThrough: ctx.passThrough,
          }
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] publishing "${handle.createMethod}" to SCIM Stream and awaiting result`)
          res = await this.pub.publish(streamObj)
        } else {
          if (scimdata.groups && Array.isArray(scimdata.groups) && handle.createMethod === 'createUser') {
            if (!this.config.scimgateway.scim.groupMemberOfUser) {
              for (let i = 0; i < scimdata.groups.length; i++) {
                if (!scimdata.groups[i].value) continue
                addGrps.push(decodeURIComponent(scimdata.groups[i].value))
              }
              delete scimdata.groups
            }
          }
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] calling "${handle.createMethod}" and awaiting result`)
          res = await (this as any)[handle.createMethod](baseEntity, scimdata, ctx.passThrough)
        }
        for (const key in res) { // merge any result e.g: {'id': 'xxxx'}
          jsonBody[key] = res[key]
        }

        if (!jsonBody.id) { // retrieve all attributes including id
          let res
          try {
            if (handle.createMethod === 'createUser') {
              let ob = {}
              const attributes: string[] = []
              if (jsonBody.userName) ob = { attribute: 'userName', operator: 'eq', value: jsonBody.userName }
              else if (jsonBody.externalId) ob = { attribute: 'externalId', operator: 'eq', value: jsonBody.externalId }
              if (this.config.scimgateway.stream.publisher.enabled) {
                const streamObj = {
                  func: handle.getMethod,
                  baseEntity: baseEntity,
                  obj: ob,
                  attributes,
                  ctxPassThrough: ctx.passThrough,
                }
                res = await this.pub.publish(streamObj)
              } else {
                res = await (this as any)[handle.getMethod](baseEntity, ob, attributes, ctx.passThrough)
              }
            } else if (handle.createMethod === 'createGroup') {
              let ob = {}
              const attributes: string[] = []
              if (jsonBody.externalId) ob = { attribute: 'externalId', operator: 'eq', value: jsonBody.externalId }
              else if (jsonBody.displayName) ob = { attribute: 'displayName', operator: 'eq', value: jsonBody.displayName }
              if (this.config.scimgateway.stream.publisher.enabled) {
                const streamObj = {
                  func: handle.getMethod,
                  baseEntity: baseEntity,
                  obj: ob,
                  attributes,
                  ctxPassThrough: ctx.passThrough,
                }
                res = await this.pub.publish(streamObj)
              } else {
                res = await (this as any)[handle.getMethod](baseEntity, ob, attributes, ctx.passThrough)
              }
            }
          } catch (err) { void 0 }
          let obj
          if (res.Resources && Array.isArray(res.Resources) && res.Resources.length === 1) {
            obj = res.Resources[0]
          }
          if (obj && obj.id) jsonBody = obj // id found, using returned object
        }

        if (addGrps.length > 0 && handle.createMethod === 'createUser') { // add group membership
          const addGroups = async (groupId: string) => {
            if (this.config.scimgateway.stream.publisher.enabled) {
              const streamObj = {
                func: handler.groups.modifyMethod,
                baseEntity: baseEntity,
                id: groupId,
                obj: { members: [{ value: jsonBody.id }] },
                ctxPassThrough: ctx.passThrough,
              }
              return await this.pub.publish(streamObj)
            } else {
              return await (this as any)[handler.groups.modifyMethod](baseEntity, groupId, { members: [{ value: jsonBody.id }] }, ctx.passThrough)
            }
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
          const location = ctx.origin + `${ctx.path}/${jsonBody.id}`
          if (!jsonBody.meta) jsonBody.meta = {}
          jsonBody.meta.location = location
          ctx.response.headers.set('Location', location)
        }
        delete jsonBody.password
        jsonBody = utilsScim.addSchemas(jsonBody, isScimv2, handle.description, undefined)
        ctx.response.status = 201
        ctx.response.body = JSON.stringify(jsonBody)
      } catch (err: any) {
        if (isScimv2) ctx.response.status = 400
        else ctx.response.status = 500
        const [e, customErrorCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
        if (customErrorCode) ctx.response.status = customErrorCode
        ctx.response.body = JSON.stringify(e)
      }
    } // post

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
      const id = decodeURIComponent(ctx.routeObj.id || '')
      if (!id || id.includes('/')) {
        ctx.response.status = 500
        const err = new Error('missing id')
        const [e, customErrorCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
        if (customErrorCode) ctx.response.status = customErrorCode
        ctx.response.body = JSON.stringify(e)
        return
      }
      logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] [Delete ${handle.description}] id=${id}`)

      try {
        if (this.config.scimgateway.stream.publisher.enabled) {
          const streamObj = {
            func: handle.deleteMethod,
            baseEntity: baseEntity,
            id,
            ctxPassThrough: ctx.passThrough,
          }
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] publishing "${handle.deleteMethod}" to SCIM Stream and awaiting result`)
          await this.pub.publish(streamObj)
        } else {
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
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] calling "${handle.deleteMethod}" and awaiting result`)
          await (this as any)[handle.deleteMethod](baseEntity, id, ctx.passThrough)
        }
        ctx.response.status = 204
      } catch (err: any) {
        ctx.response.status = 500
        const [e, customErrorCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
        if (customErrorCode) ctx.response.status = customErrorCode
        ctx.response.body = JSON.stringify(e)
      }
    } // delete

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
      if (ctx.query.attributes) ctx.query.attributes = ctx.query.attributes.split(',').map((item: string) => item.trim()).join()
      if (ctx.query.excludedAttributes) ctx.query.excludedAttributes = ctx.query.excludedAttributes.split(',').map((item: any) => item.trim()).join()
      const handle = handler[ctx.routeObj.handle]
      const baseEntity = ctx.routeObj.baseEntity
      const id = ctx.routeObj.id ? decodeURIComponent(ctx.routeObj.id) : ctx.routeObj.id

      const jsonBody = ctx.request.body
      try {
        if (!jsonBody) throw new Error('missing body')
        if (typeof jsonBody !== 'object') throw new Error('body is not JSON')
        if (!id || id.includes('/')) throw new Error('missing id')
      } catch (err: any) {
        ctx.response.status = 500
        const [e, customErrorCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
        if (customErrorCode) ctx.response.status = customErrorCode
        ctx.response.body = JSON.stringify(e)
        return
      }

      logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] [Modify ${handle.description}] id=${id}`)
      let scimdata: any, err: any
      if (jsonBody.Operations) [scimdata, err] = utilsScim.convertedScim20(jsonBody, this.multiValueTypes) // v2.0
      else [scimdata, err] = utilsScim.convertedScim(jsonBody, this.multiValueTypes) // v1.1
      logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] convertedBody=${JSON.stringify(scimdata)}`)
      if (err) {
        ctx.response.status = 500
        const [e, customErrorCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
        if (customErrorCode) ctx.response.status = customErrorCode
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
        if (this.config.scimgateway.stream.publisher.enabled) {
          const streamObj: { [key: string]: any } = {
            func: handle.modifyMethod,
            baseEntity: baseEntity,
            id,
            obj: scimdata,
            ctxPassThrough: ctx.passThrough,
          }
          if (Array.isArray(scimdata.members) && scimdata.members.length === 0 && handle.modifyMethod === 'modifyGroup') {
            streamObj.func = 'replaceUsrGrp'
            streamObj.handle = ctx.routeObj.handle
          }
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] publishing "${handle.modifyMethod}" to SCIM Stream and awaiting result`)
          res = await this.pub.publish(streamObj)
        } else {
          if (Array.isArray(scimdata.members) && scimdata.members.length === 0 && handle.modifyMethod === 'modifyGroup') {
            res = await replaceUsrGrp(ctx.routeObj.handle, baseEntity, id, scimdata, this.config.scimgateway.scim.usePutSoftSync, ctx.passThrough)
          } else {
            logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] calling "${handle.modifyMethod}" and awaiting result`)
            res = await (this as any)[handle.modifyMethod](baseEntity, id, scimdata, ctx.passThrough)
          }
        }

        if (groups.length > 0 && handle.modifyMethod === 'modifyUser') { // modify user includes groups, add/remove group membership
          const updateGroup = async (groupsObj: Record<string, any>) => {
            const groupId = groupsObj.value
            const memberObj: any = { value: id }
            if (groupsObj.operation) memberObj.operation = groupsObj.operation
            if (this.config.scimgateway.stream.publisher.enabled) {
              const streamObj = {
                func: handler.groups.modifyMethod,
                baseEntity: baseEntity,
                id: groupId,
                obj: { members: [memberObj] },
                ctxPassThrough: ctx.passThrough,
              }
              return await this.pub.publish(streamObj)
            } else {
              return await (this as any)[handler.groups.modifyMethod](baseEntity, groupId, { members: [memberObj] }, ctx.passThrough)
            }
          }
          const res = await Promise.allSettled(groups.map((groupsObj: Record<string, any>) => updateGroup(groupsObj)))
          const errRes = res.filter(result => result.status === 'rejected').map(result => result.reason.message)
          if (errRes.length > 0) {
            const errMsg = `modify user group membership error: ${errRes.join(', ')}`
            throw new Error(errMsg)
          }
        }

        if (!res) { // include full object in response, TODO: include groups
          if (handle.getMethod !== handler.users.getMethod && handle.getMethod !== handler.groups.getMethod && !this.config.scimgateway.stream.publisher.enabled) { // getUsers or getGroups not implemented
            ctx.response.status = 204
            return
          }
          const ob = { attribute: 'id', operator: 'eq', value: id }
          const attributes = ctx.query.attributes ? ctx.query.attributes.split(',').map((item: string) => item.trim()) : []
          if (this.config.scimgateway.stream.publisher.enabled) {
            const streamObj = {
              func: handle.getMethod,
              baseEntity: baseEntity,
              obj: ob,
              attributes,
              ctxPassThrough: ctx.passThrough,
            }
            logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] publishing "${handle.getMethod}" to SCIM Stream and awaiting result`)
            res = await this.pub.publish(streamObj)
          } else {
            logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] calling "${handle.getMethod}" and awaiting result`)
            res = await (this as any)[handle.getMethod](baseEntity, ob, attributes, ctx.passThrough)
          }
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
        } else scimdata.Resources = []
        if (scimdata.Resources.length === 0 || scimdata.Resources.length > 1) {
          ctx.response.status = 204
          return
        }
        if (!this.config.scimgateway.scim.skipMetaLocation) {
          const location = ctx.origin + ctx.path
          ctx.response.headers.set('Location', location)
        }
        const userObj = scimdata.Resources[0]
        scimdata = utils.stripObj(userObj, ctx.query.attributes, ctx.query.excludedAttributes)
        scimdata = utilsScim.addSchemas(scimdata, isScimv2, handle.description, undefined)
        ctx.response.status = 200
        ctx.response.body = JSON.stringify(scimdata)
      } catch (err: any) {
        ctx.response.status = 500
        const [e, customErrorCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
        if (customErrorCode) ctx.response.status = customErrorCode
        ctx.response.body = JSON.stringify(e)
      }
    } // patch

    // ==========================================
    //          Replace User
    //          Replace Group
    // ==========================================
    const replaceUsrGrp = async (h: string, baseEntity: string, id: string | undefined, obj: Record<string, any>, usePutSoftSync: boolean | undefined, ctxPassThrough: Record<string, any> | undefined) => {
      const handle = handler[h] // h = Users/Groups
      if (!id) throw new Error('missing id')
      id = decodeURIComponent(id)

      // get current object
      logger.debug(`${gwName}[${pluginName}][${baseEntity}] calling "${handle.getMethod}" and awaiting result`)
      const res = await (this as any)[handle.getMethod](baseEntity, { attribute: 'id', operator: 'eq', value: id }, [], ctxPassThrough)
      logger.debug(`${gwName}[${pluginName}][${baseEntity}] "${handle.getMethod}" result: ${res ? JSON.stringify(res) : ''}`)
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
        logger.debug(`${gwName}[${pluginName}][${baseEntity}] calling "${handle.modifyMethod}" and awaiting result`)
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
            let res
            try {
              res = await (this as any)[handler.groups.getMethod](baseEntity, { attribute: 'members.value', operator: 'eq', value: decodeURIComponent(id) }, ['id', 'displayName'], ctxPassThrough)
              logger.debug(`${gwName}[${pluginName}][${baseEntity}] "${handler.groups.getMethod}" result: ${res ? JSON.stringify(res) : ''}`)
            } catch (err) { void 0 } // method may be implemented but throwing error like groups not supported/implemented
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
    this.replaceUsrGrp = replaceUsrGrp

    const putHandler = async (ctx: Context) => {
      const handle = ctx.routeObj.handle // Users/Groups
      const baseEntity = ctx.routeObj.baseEntity
      const id = ctx.routeObj.id ? decodeURIComponent(ctx.routeObj.id) : ctx.routeObj.id
      const obj = ctx.request.body

      logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] [PUT ${handle[0].toUpperCase() + handle.slice(1)}] id=${id} body=${JSON.stringify(obj)}`)
      try {
        if (!obj) throw new Error('missing body')
        if (typeof obj !== 'object') throw new Error('body is not JSON')
        if (this.config.scimgateway.stream.publisher.enabled) {
          const streamObj = {
            func: 'replaceUsrGrp',
            handle: handle,
            baseEntity: baseEntity,
            originalUrl: ctx.origin + ctx.path,
            id: id,
            obj: obj,
            ctxPassThrough: ctx.passThrough,
          }
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] publishing replaceUsrGrp to SCIM Stream and awaiting result`)
          await this.pub.publish(streamObj)
        } else await replaceUsrGrp(handle, baseEntity, id, obj, this.config.scimgateway.scim.usePutSoftSync, ctx.passThrough)
        await getHandlerId(ctx) // ctx.response.body now updated with userObject to be returned
        if (ctx.response.status && ctx.response.status !== 200) { // clear any get error
          ctx.response.body = undefined
          ctx.response.status = 204
        }
      } catch (err: any) {
        ctx.response.status = 500
        const [e, customErrorCode] = utilsScim.jsonErr(this.config.scimgateway.scim.version, pluginName, ctx.response.status, err)
        if (customErrorCode) ctx.response.status = customErrorCode
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
      logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] [POST ${ctx.routeObj.handle}]`)

      if (!obj) {
        const err = new Error('missing body')
        ctx.response.status = 500
        ctx.response.body = JSON.stringify(utilsScim.apiErr(pluginName, err))
        return
      }
      try {
        let result: Record<string, any>
        if (this.config.scimgateway.stream.publisher.enabled) {
          const streamObj = {
            func: 'postApi',
            baseEntity: baseEntity,
            obj: obj,
            ctxPassThrough: ctx.passThrough,
          }
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] publishing "postApi" to SCIM Stream and awaiting result`)
          result = await this.pub.publish(streamObj)
        } else {
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] calling "postApi" and awaiting result`)
          result = await this.postApi(baseEntity, obj, ctx.passThrough)
        }
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
        if (!this.config.scimgateway.scim.skipMetaLocation) {
          const location = ctx.origin + ctx.path
          result.meta.location = location
        }
        ctx.response.status = 201
        ctx.response.body = JSON.stringify(result)
      } catch (err) {
        ctx.response.status = 500
        ctx.response.body = JSON.stringify(utilsScim.apiErr(pluginName, err))
      }
    } // post

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
      logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] [PUT ${ctx.routeObj.handle}] id=${id}`)

      try {
        if (!obj) throw new Error('missing body')
        if (!id) throw new Error('missing id')
      } catch (err) {
        ctx.response.status = 500
        ctx.response.body = JSON.stringify(utilsScim.apiErr(pluginName, err))
        return
      }

      try {
        let result: Record<string, any>
        if (this.config.scimgateway.stream.publisher.enabled) {
          const streamObj = {
            func: 'putApi',
            baseEntity: baseEntity,
            id,
            obj: obj,
            ctxPassThrough: ctx.passThrough,
          }
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] publishing "putApi" to SCIM Stream and awaiting result`)
          result = await this.pub.publish(streamObj)
        } else {
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] calling "putApi" and awaiting result`)
          result = await this.putApi(baseEntity, id, obj, ctx.passThrough)
        }
        if (result) {
          if (typeof result === 'object') result = { result }
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
        if (!this.config.scimgateway.scim.skipMetaLocation) {
          const location = ctx.origin + ctx.path
          result.meta.location = location
        }
        ctx.response.body = JSON.stringify(result)
      } catch (err) {
        ctx.response.status = 500
        ctx.response.body = JSON.stringify(utilsScim.apiErr(pluginName, err))
      }
    } // put

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

      logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] [PATCH ${handle} ] id=${id}`)

      if (!body) {
        const err = new Error('missing body')
        ctx.response.status = 500
        ctx.response.body = JSON.stringify(utilsScim.apiErr(pluginName, err))
        return
      } else {
        try {
          let result: Record<string, any>
          if (this.config.scimgateway.stream.publisher.enabled) {
            const streamObj = {
              func: 'patchApi',
              baseEntity: baseEntity,
              id,
              obj: body,
              ctxPassThrough: ctx.passThrough,
            }
            logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] publishing "patchApi" to SCIM Stream and awaiting result`)
            result = await this.pub.publish(streamObj)
          } else {
            logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] calling "patchApi" and awaiting result`)
            result = await this.patchApi(baseEntity, id, body, ctx.passThrough)
          }
          if (result) {
            if (typeof result === 'object') result = { result }
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
          if (!this.config.scimgateway.scim.skipMetaLocation) {
            const location = ctx.origin + ctx.path
            result.meta.location = location
          }
          ctx.response.body = JSON.stringify(result)
        } catch (err) {
          ctx.response.status = 500
          ctx.response.body = JSON.stringify(utilsScim.apiErr(pluginName, err))
        }
      }
    } // patch

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
      const body = ctx.request.body

      if (id) logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] [GET ${handle}] id=${id}`)
      else logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] [GET ${handle}]`)

      try {
        let result: any
        if (this.config.scimgateway.stream.publisher.enabled) {
          const streamObj = {
            func: 'getApi',
            baseEntity: baseEntity,
            id,
            query: ctx.query,
            obj: body,
            ctxPassThrough: ctx.passThrough,
          }
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] publishing "getApi" to SCIM Stream and awaiting result`)
          result = await this.pub.publish(streamObj)
        } else {
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] calling "getApi" and awaiting result`)
          result = await this.getApi(baseEntity, id, ctx.query, body, ctx.passThrough)
        }
        if (result) {
          if (typeof result === 'object') result = { result }
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
        if (!this.config.scimgateway.scim.skipMetaLocation) {
          const location = ctx.origin + ctx.path
          result.meta.location = location
        }
        ctx.response.body = JSON.stringify(result)
      } catch (err) {
        ctx.response.status = 404
        ctx.response.body = JSON.stringify(utilsScim.apiErr(pluginName, err))
      }
    }

    // ==========================================
    //           API DELETE (no SCIM)
    // ==========================================
    //
    //  DELETE = /api/{id}
    //
    const deleteApiHandler = async (ctx: Context) => {
      const baseEntity = ctx.routeObj.baseEntity
      const id = ctx.routeObj.id
      logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] [DELETE ${ctx.routeObj.handle} ] id=${id}`)
      try {
        if (!id || id.includes('/')) throw new Error('missing id')
        let result: Record<string, any>
        if (this.config.scimgateway.stream.publisher.enabled) {
          const streamObj = {
            func: 'deleteApi',
            baseEntity: baseEntity,
            id,
            ctxPassThrough: ctx.passThrough,
          }
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] publishing "deleteApi" to SCIM Stream and awaiting result`)
          result = await this.pub.publish(streamObj)
        } else {
          logger.debug(`${gwName}[${pluginName}][${ctx?.routeObj?.baseEntity}] calling "deleteApi" and awaiting result`)
          result = await this.deleteApi(baseEntity, id, ctx.passThrough)
        }
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
        ctx.response.body = JSON.stringify(result)
      } catch (err) {
        ctx.response.status = 500
        ctx.response.body = JSON.stringify(utilsScim.apiErr(pluginName, err))
      }
    } // delete

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
        logger.debug(`${gwName}[${pluginName}][${baseEntity}] calling "${handler.groups.getMethod}" and awaiting result - groups to be included`)
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
        headers: Headers
        body: any
      }
      response: {
        headers: Headers // HeadersInit
        status?: number
        body?: string
      }
      routeObj: RouteObj
      perfStart: number
      path: string
      query: Record<string, any>
      ip: string
      origin: string
      passThrough: Record<string, any> | undefined
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

    const onBeforeHandle = async (request: Request, directIp: string): Promise<Context> => {
      const method = request.method
      const url = new URL(request.url)

      let [, baseEntity, handle, id, rest]: string[] = url.pathname.split('/')
      if (baseEntity && handlers.includes(baseEntity.toLowerCase())) {
        rest = id
        id = handle
        handle = baseEntity
        baseEntity = 'undefined'
      }
      if (handle) handle = handle.toLowerCase()
      if (!handlers.includes(handle) || rest) { // rest => too many path elements
        baseEntity = ''
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

      const ctx: Context = {
        request: { // not using request as-is becuase body is stream and read once
          method: request.method,
          url: request.url,
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
        path: url.pathname,
        query: {},
        ip: getIpFromHeader(request.headers) || directIp,
        origin: getOriginFromHeader(request.headers) || url.origin,
        passThrough: (found.PassThrough && this.authPassThroughAllowed) ? { headers: request.headers } : undefined,
      }

      url.searchParams.forEach((value, key) => {
        ctx.query[key] = value
      })

      // no validation
      if (ctx.path === '/ping') {
        ctx.response.status = 200
        ctx.response.body = 'hello'
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

      // validation
      if (ctx.request.method === 'POST' && ctx.path === '/oauth/token') {
        await postHandlerOauthToken(ctx)
        if (!ctx.response.status) ctx.response.status = 401 // Unauthorized
      } else if (!ctx.routeObj.handle) {
        ctx.response.status = 404 // NOT_FOUND
      } else if (!ipAllowList(ctx.ip)) {
        ctx.response.status = 401
      } else if (!await isAuthorized(ctx)) {
        ctx.response.status = 401
      }
      return ctx
    }

    /** 
     * onChainingHandler - chain request to another SCIM Gateway, like a reverse proxy
     * @param ctx original Context - ctx.response will become updated based on chain response
     * @returns true if chainingHandler is used, false if not
    **/
    const onChainingHandler = async (ctx: Context): Promise<boolean> => {
      const chainingBaseUrl = this.config.scimgateway.chainingBaseUrl // http(s)://<host>:<port>
      if (!chainingBaseUrl) return false
      if (!this.helperRest) this.helperRest = this.newHelperRest()
      try {
        new URL(chainingBaseUrl)
      } catch (err: any) {
        ctx.response.status = 500
        logger.error(`${gwName}[${pluginName}] onChainingHandler error: configuration scimgateway.chainingBaseUrl must use correct syntax 'http(s)://host:port' error: ${err.message}`)
        return true
      }
      try {
        const url = new URL(ctx.request.url)
        const method = ctx.request.method
        const chainUrl = ctx.request.url.replace(url.origin, chainingBaseUrl)
        const options = { headers: { Authorization: ctx.request.headers.get('authorization') } }
        const result = await this.helperRest.doRequest('undefined', method, chainUrl, undefined, undefined, options)
        ctx.response.status = result.statusCode
        try {
          ctx.response.body = JSON.stringify(result.body)
        } catch (err) {
          ctx.response.body = result.body
        }
      } catch (err: any) {
        try {
          const jBody = JSON.parse(err.message) // check for SCIM error response
          ctx.response.status = jBody?.body?.statusCode || jBody?.statusCode || 500
          ctx.response.body = err.message
        } catch (parseErr) {
          ctx.response.status = 500
          logger.error(`${gwName}[${pluginName}] onChainingHandler error: ${err.message}`)
        }
      }
      return true
    }

    const onAfterHandle = async (ctx: Context): Promise<Response> => {
      if (!ctx.response.status) ctx.response.status = 200
      switch (ctx.response.status) {
        case 401:
          if (!ctx.response.body) ctx.response.body = 'Unauthorized'
          break
        case 403:
          if (!ctx.response.body) ctx.response.body = 'Forbidden'
          break
        case 404:
          if (!ctx.response.body) ctx.response.body = 'NOT_FOUND'
          break
        case 500:
          if (!ctx.response.body) ctx.response.body = 'Internal Server Error'
          break
      }
      const body = ctx.response.body
      if (body) {
        try {
          JSON.parse(body)
          ctx.response.headers.set('content-type', 'application/scim+json; charset=utf-8')
        } catch (err) { void 0 }
      }
      const response = new Response(body, { status: ctx.response.status, headers: ctx.response.headers })
      logResult(ctx)
      return response
    }

    // ==========================================
    // Starting up...
    // ==========================================

    logger.info('===================================================================')

    if (!this.config.scimgateway.port) {
      logger.info(`${gwName}[${pluginName}] port deactivated, not allowing incoming traffic`)
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
        // using fs.readFileSync() instead of Bun.file() for nodejs compability
        if (this.config.scimgateway?.certificate?.key && this.config.scimgateway?.certificate?.cert) {
          // TLS
          tls.key = this.config.scimgateway.certificate.key ? fs.readFileSync(this.config.scimgateway.certificate.key) : undefined
          tls.cert = this.config.scimgateway.certificate.cert ? fs.readFileSync(this.config.scimgateway.certificate.cert) : undefined
          // loading tls.ca would require client certificates to be used
        } else if (this.config.scimgateway?.certificate?.pfx && this.config.scimgateway?.certificate?.pfx?.bundle) {
          // TLS PFX / PKCS#12
          tls.pfx = this.config.scimgateway.certificate.pfx.bundle ? fs.readFileSync(this.config.scimgateway.certificate.pfx.bundle) : undefined
          tls.passphrase = this.config.scimgateway.certificate.pfx.password ? utils.getSecret('scimgateway.certificate.pfx.password', this.configFile) : undefined
        }
      } catch (err: any) {
        const msg = `tls/certificate configuration error: ${err.message}`
        logger.error(`${gwName}[${pluginName}] startup error: ${msg}`)
        throw new Error(msg)
      }

      async function route(req: Request, ip: string): Promise<Response> {
        const ctx = await onBeforeHandle(req, ip)
        if (ctx.response.status) { // 401/Unauthorized - 404/NOT_FOUND
          return await onAfterHandle(ctx)
        }
        if (await onChainingHandler(ctx)) return await onAfterHandle(ctx)

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
          case 'GET serviceproviderconfig':
          case 'GET serviceproviderconfigs':
            await getHandlerServiceProviderConfig(ctx)
            return await onAfterHandle(ctx)
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
      if (typeof Bun !== 'undefined') {
        // this code will only run when the file is run with Bun
        if (tls.pfx && !tls.key) throw new Error('pfx is not supported for Bun')
        server = Bun.serve({
          port: this.config.scimgateway.port,
          reusePort: false,
          idleTimeout: this.config.scimgateway.idleTimeout || 120,
          hostname, // hostname === 'localhost' ? hostname : undefined, // bun defaults to '0.0.0.0', but using '0.0.0.0.' or other ip like '127.0.0.1' becomes extremly slow - bun bug
          tls,
          async fetch(req, srv) {
            // start route processing and return response
            return await route(req, srv.requestIP(req)?.address || '')
          },
          error(err) {
            logger.error(`${gwName} internal error: ${err.message}`)
            return new Response('Internal Server Error', { status: 500 })
          },
        })
      } else {
        // using nodejs
        // node --experimental-strip-types index.ts

        // return body from req
        async function getRequestBody(req: any): Promise<Buffer> {
          return new Promise((resolve, reject) => {
            const body: Uint8Array[] = []
            req.on('data', (chunk: Uint8Array) => body.push(chunk)) // Explicitly typing chunk
            req.on('end', () => resolve(Buffer.concat(body)))
            req.on('error', (err: Error) => reject(err))
          })
        }

        // convert ReadableStream to string or Buffer
        async function streamToString(stream: any) {
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

        // use Fetch API like Bun, start common route() and return a nodejs (http.createServer) formatted response
        async function doFetchApi(req: IncomingMessage, res: ServerResponse) {
          // @ts-expect-error ignore the TypeScript error about 'encrypted' not existing on 'Socket'
          const protocol = req.socket.encrypted ? 'https' : 'http'
          try {
            // convert nodejs req to Fetch API request - using same standard as Bun
            const requestBody = await getRequestBody(req)
            const body = ['GET', 'HEAD'].includes(req.method as string) ? undefined : requestBody.length > 0 ? requestBody : undefined
            // TODO fix below hardcoding
            const request = new Request(new URL(req.url ?? '', `${protocol}://${req.headers.host}`), {
              method: req.method,
              headers: new Headers(req.headers as any),
              body: body,
              // @ts-expect-error duplex not defined in RequestInit interface
              duplex: body ? 'half' : undefined,
            })

            // start route processing and retrieve response
            const response = await route(request, req.socket.remoteAddress || '')

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

            if (response.body) {
              if (response.body instanceof ReadableStream) {
                const bodyText = await streamToString(response.body)
                res.end(bodyText)
              } else {
                res.end(response.body)
              }
            } else res.end()
          } catch (err: any) {
            logger.error(`${gwName} internal error: ${err.message}`)
            res.writeHead(500, { 'Content-Type': 'text/plain' })
            res.end('Internal Server Error')
          }
        }

        // create nodejs server and start listen
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
      logger.info(`${gwName}[${pluginName}] now listening SCIM ${this.config.scimgateway.scim.version}${tls.key || tls.pfx ? ' TLS' : ''} at ${hostname || '0.0.0.0'}:${this.config.scimgateway.port}...${this.config.scimgateway.stream.subscriber.enabled || this.config.scimgateway.chainingBaseUrl ? '' : '\n'}`)
      if (this.config.scimgateway.chainingBaseUrl) logger.info(`${gwName}[${pluginName}] using remote gateway ${this.config.scimgateway.chainingBaseUrl}\n`)
    }

    // starting SCIM Stream subscribers
    if (this.config.scimgateway.stream.subscriber.enabled && this.config.scimgateway.stream.subscriber.entity
      && Object.keys(this.config.scimgateway.stream.subscriber.entity).length > 0 && !this.config.scimgateway.chainingBaseUrl) {
      logger.info(`${gwName}[${pluginName}] starting SCIM Stream subscribers...`)
      const sub: any = new stream.Subscriber(this)
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
      && Object.keys(this.config.scimgateway.stream.publisher.entity).length > 0 && !this.config.scimgateway.chainingBaseUrl) {
      logger.info(`${gwName}[${pluginName}] starting SCIM Stream publishers...`)
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

    logger.setEmailOnError(async (msg: string) => { // logger sending email on error
      if (!(this.config.scimgateway.email.emailOnError.enabled === true) || isMailLock) return null // not sending mail
      isMailLock = true

      setTimeout(function () { // release lock after "sendInterval" minutes
        isMailLock = false
      }, (this.config.scimgateway.email.emailOnError.sendInterval || 15) * 1000 * 60)

      const msgHtml = `<html><body><pre style="font-family: monospace; white-space: pre-wrap;">${msg}</pre><br/><p><strong>This is an automatically generated email - please do NOT reply to this email or forward to others</strong></p></body></html>`
      const msgObj = {
        from: this.config.scimgateway.email.emailOnError.from,
        to: this.config.scimgateway.email.emailOnError.to,
        cc: this.config.scimgateway.email.emailOnError.cc,
        subject: this.config.scimgateway.email.emailOnError.subject ? this.config.scimgateway.email.emailOnError.subject : 'SCIM Gateway error message',
        content: msgHtml,
      }
      this.sendMail(msgObj, true)
    })

    const gracefulShutdown = async function () {
      if (server) {
        if (typeof Bun !== 'undefined') {
          server.stop(true)
        }
      }
      logger.debug(`${gwName}[${pluginName}] received terminate/kill signal - closing connections and exit`)
      logger.setLoglevelConsole('info')
      logger.setLoglevelFile('info')
      logger.info(`${gwName}[${pluginName}] pheww... ${requestCounter} requests have been processed in the period ${startTime} - ${utils.timestamp()}\n`)
      logger.close()
      if (server) {
        if (typeof Bun !== 'undefined') {
          await Bun.sleep(400) // give in-flight requests a chance to complete, also plugins may use SIGTERM/SIGINT
          server.stop()
          process.exit(0)
        } else {
          server.close(function () {
            setTimeout(function () { // plugins may also use SIGTERM/SIGINT
              process.exit(0)
            }, 0.5 * 1000)
          })
          setTimeout(function () { // problem closing server connections in time due to keep-alive sessions (active browser connection?), now forcing exit
            process.exit(1)
          }, 2 * 1000)
        }
      }
    }

    process.setMaxListeners(Infinity)
    process.on('unhandledRejection', (err: { [key: string]: any }) => { // older versions of V8, unhandled promise rejections are silently dropped
      logger.error(`${gwName}[${pluginName}] Async function with unhandledRejection: ${err.stack}`)
    })
    process.once('SIGTERM', gracefulShutdown) // kill (windows subsystem lacks signaling support for process.kill)
    process.once('SIGINT', gracefulShutdown) // Ctrl+C
  } // constructor

  /**
  * logDebug logs debug message
  **/
  logDebug(baseEntity: string | undefined, msg: string) {
    this.logger.debug(`${this.pluginName}[${baseEntity}] ${msg}`)
  }

  /**
  * logInfo logs info message
  **/
  logInfo(baseEntity: string | undefined, msg: string) {
    this.logger.info(`${this.pluginName}[${baseEntity}] ${msg}`)
  }

  /**
  * logWarn logs warning message
  **/
  logWarn(baseEntity: string | undefined, msg: string) {
    this.logger.warn(`${this.pluginName}[${baseEntity}] ${msg}`)
  }

  /**
  * logError logs error message
  **/
  logError(baseEntity: string | undefined, msg: string) {
    this.logger.error(`${this.pluginName}[${baseEntity}] ${msg}`)
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
  *       "host": "<host>", // required when not using tenantIdGUID (Microsoft)
  *       "port": <port>, // required when not using tenantIdGUID (Microsoft)
  *       "auth": {
  *         "type": "oauth",
  *         "options": {
  *           "tenantIdGUID": "<tenantId>", // used for Microsoft Exchange Online
  *           "tokenUrl": "<tokenUrl>",     // required when not using tenantIdGUID (Microsoft)
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
  * Some notes when using OAuth and tenantIdGUID - Microsoft Exchange:  
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
    const pluginName = this.pluginName
    const logger = this.logger
    const authType = this.config.scimgateway?.email?.auth?.type ? this.config.scimgateway.email.auth.type.toLowerCase() : ''

    if (typeof msgObj !== 'object' || !msgObj.from || !msgObj.to || !msgObj.content) {
      logger.error(`${gwName}[${pluginName}] sendMail failed: missing or invalid msgObj argument`)
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
      if (this.config.scimgateway.email.auth?.options?.tenantIdGUID) {
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
          logger.debug(`${gwName}[${pluginName}] sendMail subject '${msgObj.subject}' sent to: ${msgObj.to}${(msgObj.cc) ? ',' + msgObj.cc : ''}`)
        } catch (err: any) {
          logger.error(`${gwName}[${pluginName}] sendMail subject '${msgObj.subject}' sending failed: ${err.message}`)
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
          await this.helperRest.doRequest('undefined', 'POST', path, emailMessage, null, { connection: { auth: { type: 'oauthJwtBearer', options: { scope: 'https://www.googleapis.com/auth/gmail.send', subject: msgObj.from } } } })
          logger.debug(`${gwName}[${pluginName}] sendMail subject '${msgObj.subject}' sent to: ${msgObj.to}${(msgObj.cc) ? ',' + msgObj.cc : ''}`)
        } catch (err: any) {
          logger.error(`${gwName}[${pluginName}] sendMail subject '${msgObj.subject}' sending failed: ${err.message}`)
        }
        return
      }
      logger.error(`${gwName}[${pluginName}] sendMail error: type oauth supports only ExO (scimgateway.email.auth.options.tenantIdGUID) or Google Workspace Gmail (scimgateway.email.auth.options.serviceAccountKeyFile)`)
      return
    }

    if (authType !== 'smtp') {
      logger.error(`${gwName}[${pluginName}] sendMail error: configuration scimgateway.email.auth.type must be set to oauth or smtp`)
      return
    }

    // nodemailer - SMTP Auth
    const smtpConfig: { [key: string]: any } = {
      host: this.config.scimgateway?.email?.auth?.options?.host, // e.g. smtp.office365.com
      port: this.config.scimgateway?.email?.auth?.options?.port || 587,
      secure: (this.config.scimgateway?.email?.auth?.options?.port === 465), // false on 25/587
      tls: { ciphers: 'TLSv1.2' },
      proxy: this.config.scimgateway?.email?.proxy,
    }

    smtpConfig.auth = {}
    smtpConfig.auth.user = this.config.scimgateway?.email?.auth?.options?.username
    smtpConfig.auth.pass = this.config.scimgateway?.email?.auth?.options?.password

    if (!this.config.scimgateway?.email?.auth?.options?.host || !this.config.scimgateway?.email?.auth?.options?.username) {
      logger.error(`${gwName}[${pluginName}] sendMail subject '${msgObj.subject}' sending error: missing scimgateway.email.options configuration for auth type smtp`)
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
      if (err != null) logger.error(`${gwName}[${pluginName}] sendMail subject '${msgObj.subject}' sending failed: ${err.message}`)
      else logger.debug(`${gwName}[${pluginName}] sendMail subject '${msgObj.subject}' sent to: ${msgObj.to}${(msgObj.cc) ? ',' + msgObj.cc : ''}`)
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
    let foundBearerJwtAzure = false
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
      else if (lastKey === 'tenantIdGUID' && key.startsWith('scimgateway.auth.bearerJwtAzure')) foundBearerJwtAzure = true
      else if (lastKey === 'secret' && key.startsWith('scimgateway.auth.bearerJwt')) foundBearerJwt = true
      else if (lastKey === 'clientSecret' && key.startsWith('scimgateway.auth.bearerOAuth')) foundBearerOAuth = true

      // certificate full path
      if (key.includes('.certificate.') || key.includes('.tls.')) {
        if (key.endsWith('.key') || key.endsWith('.cert') || key.endsWith('.ca') || key.endsWith('.pfx.bundle')) {
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
        const addKey = key.replace(`.${lastKey}`, '.publicKeyContent')
        dotConfig[addKey] = fs.readFileSync(keyFile)
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

    if (foundBearerJwtAzure && Array.isArray(this.config.scimgateway.auth.bearerJwtAzure)) {
      const issuers: string[] = []
      const arr = this.config.scimgateway.auth.bearerJwtAzure
      for (let i = 0; i < arr.length; i++) {
        if (arr[i].tenantIdGUID) {
          issuers.push(`https://sts.windows.net/${arr[i].tenantIdGUID}/`)
        }
      }
      if (issuers.length < 1) foundBearerJwtAzure = false
      else {
        const azureOptions: IBearerStrategyOptionWithRequest = {
          validateIssuer: true,
          passReqToCallback: false,
          loggingLevel: 'error',
          // identityMetadata: `https://login.microsoftonline.com/${tenantIdGUID}/.well-known/openid-configuration`,
          identityMetadata: 'https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration',
          clientID: '00000014-0000-0000-c000-000000000000', // Well known appid: Microsoft.Azure.SyncFabric
          audience: [
            // Well known appid: Issued for accessing Windows Azure Active Directory Graph Webservice
            '00000002-0000-0000-c000-000000000000',
            // Appid used for SCIM provisioning for non-gallery applications. See changes introduced, in reverse cronological order:
            // - https://github.com/MicrosoftDocs/azure-docs/commit/f6997c0952d2ad4f33ce7f5339eeb83c21b51f1e
            // - https://github.com/MicrosoftDocs/azure-docs/commit/64525fea0675a73b2e6b8fe42fbd03ee568cadfc
            '8adf8e6e-67b2-4cf2-a259-e3dc5476c621',
          ],
          issuer: issuers, // array => passport.authenticate supports more than one AAD tenant
        }
        passport.use(new BearerStrategy(azureOptions, (token: any, done: any) => { // using named strategy = tenantIdGUID, passport.authenticate then using name
          return done(null, token.sub) // Azure SyncFabric don't send user info claims, returning claim token.sub as user
        }))
      }
    }

    if (!foundBasic) this.config.scimgateway.auth.basic = []
    if (!foundBearerToken) this.config.scimgateway.auth.bearerToken = []
    if (!foundBearerJwtAzure) this.config.scimgateway.auth.bearerJwtAzure = []
    if (!foundBearerOAuth) this.config.scimgateway.auth.bearerOAuth = []
    if (!foundBearerJwt) this.config.scimgateway.auth.bearerJwt = []
    if (this?.config?.scimgateway?.auth?.passThrough?.enabled === true) foundPassThrough = true

    return { // valid auth methods
      Basic: foundBasic,
      BearerToken: foundBearerToken,
      BearerJwtAzure: foundBearerJwtAzure,
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
