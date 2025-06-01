// ==================================
// File:    utils.js
//
// Author:  Jarle Elshaug
//
// ==================================

import * as crypto from 'node:crypto'
import id from 'node-machine-id'
import fs from 'node:fs'
import path from 'node:path'
import { EventEmitter } from 'node:events'

/** Lock implements mutual exclusion
 *  reference: https://thecodebarbarian.com/mutual-exclusion-patterns-with-node-promises
 */
export class Lock {
  private _locked = false
  private _ee: any
  constructor() {
    this._locked = false
    this._ee = new EventEmitter()
  }

  /** If nobody has the lock, take it and resolve immediately else wait until released */
  acquire() {
    return new Promise((resolve) => {
      if (!this._locked) {
        // Safe because JS doesn't interrupt you on synchronous operations,
        // so no need for compare-and-swap or anything like that.
        this._locked = true
        return resolve(null)
      }

      // Otherwise, wait until somebody releases the lock and try again
      const tryAcquire = () => {
        if (!this._locked) {
          this._locked = true
          this._ee.removeListener('release', tryAcquire)
          return resolve(null)
        }
      }
      this._ee.on('release', tryAcquire)
    })
  }

  /** Release the lock immediately */
  release() {
    this._locked = false
    setImmediate(() => this._ee.emit('release'))
  }

  /** Return status of lock true/false */
  isLocked(): boolean {
    return this._locked
  }
}

export const getSecret = function (dotNotationAttr: string, configFile: string) {
  // get password from json-file.
  // if cleartext then encrypt and save to file + return cleartext secret
  // else return decrypted secret
  const configString = fs.readFileSync(configFile).toString()
  const config = JSON.parse(configString)
  const pw = objProp(config, dotNotationAttr, null)
  let pwclear
  let seed
  try {
    seed = path.basename(configFile) + (process.env.SEED || id.machineIdSync(true))
  } catch (err: any) {
    throw (new Error(`consider using SEED environment because machineId can't be found - error: ${err.message}`))
  }
  const ivLength = 16

  if (seed.length < ivLength) throw (new Error('Password seed length too short'))

  if (pw) {
    if (pw.includes('process.')) { // password based on external reference e.g. environment or json file
      // syntax environment = "process.env.<ENVIRONMENT>" e.g. scimgateway.password could have value "process.env.PORT", then using environment variable PORT
      // syntax file = "process.file.<PATH>" e.g. scimgateway.password could have value "process.file./tmp/myconf.json"
      const processText = 'process.text.'
      const processEnv = 'process.env.'
      const processFile = 'process.file.'
      if (pw.constructor === String && pw.includes(processEnv)) {
        const envKey = pw.substring(processEnv.length)
        pwclear = process.env[envKey]
      } else if (pw && pw.constructor === String && pw.includes(processText)) {
        const filePath = pw.substring(processFile.length)
        try {
          pwclear = fs.readFileSync(filePath, 'utf8')
        } catch (err) { pwclear = undefined } // can't read external configuration file
      } else if (pw && pw.constructor === String && pw.includes(processFile)) {
        const filePath = pw.substring(processFile.length)
        try {
          const content = fs.readFileSync(filePath, 'utf8')
          try {
            const pluginName = path.basename(configFile, '.json')
            const jContent = JSON.parse(content)
            pwclear = objProp(jContent, `${pluginName}.${dotNotationAttr}`, null)
          } catch (err) { pwclear = undefined } // can't JSON parse external file
        } catch (err) { pwclear = undefined } // can't read external configuration file
      } else pwclear = undefined
    } else { // password based on local configuration file
      try { // decrypt
        const pwencr = Buffer.from(pw, 'base64').toString('utf8')
        const textParts: any = pwencr.split(':')
        const iv = Buffer.from(textParts.shift(), 'hex')
        const encryptedText = Buffer.from(textParts.join(':'), 'hex')
        const decipher = crypto.createDecipheriv('aes-128-cbc', Buffer.from(seed.substr(-ivLength)), iv)
        pwclear = decipher.update(encryptedText)
        pwclear = Buffer.concat([pwclear, decipher.final()])
        pwclear = pwclear.toString()
      } catch (err) { // password considered as cleartext and needs to be encrypted and written back to file
        pwclear = pw
        const iv = crypto.randomBytes(ivLength)
        const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(seed.substr(-ivLength), 'utf8'), iv)
        let encrypted = cipher.update(pwclear)
        encrypted = Buffer.concat([encrypted, cipher.final()])
        let pwencr = iv.toString('hex') + ':' + encrypted.toString('hex')
        pwencr = Buffer.from(pwencr).toString('base64')
        objProp(config, dotNotationAttr, pwencr)
        let fileContent = JSON.stringify(config, null, 2) // removing white space, but use 2 space separator
        fileContent = fileContent.replace(/\n/g, '\r\n') // cr-lf instead of lf
        try {
          fs.writeFileSync(configFile, fileContent)
        } catch (err) {
          const newErr = err
          throw newErr
        }
      }
    }
  } else {
    pwclear = undefined // can't be found in configuration file or having value null/undefined
  }
  return pwclear
}

export const timestamp = function () { // new Date() do not handle current timezone
  const pad = (n: number) => { return n < 10 ? '0' + n : n }
  const d = new Date()
  return d.getFullYear() + '-'
    + pad(d.getMonth() + 1) + '-'
    + pad(d.getDate()) + 'T'
    + pad(d.getHours()) + ':'
    + pad(d.getMinutes()) + ':'
    + pad(d.getSeconds()) + '.'
    + pad(d.getMilliseconds())
}

/**
 * Fxn that returns a JSON stringified version of an object.
 * This fxn uses a custom replacer function to handle circular references
 * see http://stackoverflow.com/a/11616993/3043369
 */
export const JSONStringify = function (object: any) {
  let cache: any = []
  const str = JSON.stringify(object,
    // custom replacer fxn - gets around "TypeError: Converting circular structure to JSON"
    function (key, value) {
      if (typeof value === 'object' && value !== null) {
        if (cache.indexOf(value) !== -1) {
          return // Circular reference found, discard key
        }
        cache.push(value) // Store value in our collection
      }
      return value
    }, 2)
  cache = null // enable garbage collection
  return str
}

const objProp = function (obj: Record<string, any>, prop: string, val: any) { // return obj value based on json dot notation formatted prop
  if (Object.prototype.hasOwnProperty.call(obj, prop)) return obj[prop]
  const props = prop.split('.') // scimgateway.auth.basic[0].password
  const final = props.pop() as string
  for (let i = 0; i < props.length; i++) {
    const p = props[i]
    const arr = p.match(/^(.*)\[(.*)\]$/i)
    if (Array.isArray(arr) && arr.length === 3) { // basic[0] => [ "basic[0]", "basic", "0" ]
      obj = obj[arr[1]][Number(arr[2])] // obj['basic'][0]
    } else obj = obj[p]
    if (typeof obj === 'undefined') { return undefined }
  }
  return val ? (obj[final] = val) : obj[final]
}

export const copyObj = (o: any): any => { // deep copy/clone faster than JSON.parse(JSON.stringify(o))
  let v, key
  const output: any = Array.isArray(o) ? [] : {}
  for (key in o) {
    v = o[key]
    if (typeof v === 'object' && v !== null) {
      const objProp = Object.getPrototypeOf(v) // e.g. HttpsProxyAgent {}
      if (objProp !== null && objProp !== Object.getPrototypeOf({}) && objProp !== Object.getPrototypeOf([])) {
        output[key] = Object.assign(Object.create(v), v) // e.g. { HttpsProxyAgent {...} }
      } else output[key] = copyObj(v)
    } else output[key] = v
  }
  return output
}

const _extendObj = (obj: Record<any, any>, src: Record<any, any>) => {
  Object.keys(src).forEach((key) => {
    if (typeof src[key] === 'object' && src[key] !== null) {
      if (Object.keys(src[key]).length === 0) return
      if (typeof obj[key] === 'undefined') obj[key] = src[key]
      else if (Array.isArray(src[key])) {
        if (!Array.isArray(obj[key])) obj[key] = src[key]
        else {
          for (let i = 0; i < src[key].length; i++) {
            const val = src[key][i]
            if (typeof val === 'object') {
              if (Object.prototype.hasOwnProperty.call(val, 'type')) {
                if (!obj[key]) obj[key] = [val]
                else {
                  for (let j = 0; j < obj[key].length; j++) {
                    const el = obj[key][j]
                    if (el.type === val.type) {
                      obj[key].splice(j, 1)
                      j -= 1
                      break
                    }
                  }
                  obj[key].push(val)
                }
              } else if (Object.prototype.hasOwnProperty.call(val, 'value')) {
                if (!obj[key]) obj[key] = [val]
                else {
                  for (let j = 0; j < obj[key].length; j++) {
                    const el = obj[key][j]
                    if (el.value === val.value) {
                      obj[key].splice(j, 1)
                      j -= 1
                      break
                    }
                  }
                  obj[key].push(val)
                }
              }
            } else if (!obj[key].includes(val)) obj[key].push(val)
          }
        }
      } else obj[key] = extendObj(obj[key], src[key])
    } else if (src[key] != null) obj[key] = src[key]
  })
  return obj
}

export const extendObj = (obj: any, src: any) => { // copy src content into obj
  if (typeof src !== 'object' || Array.isArray(src)) return obj
  return _extendObj(obj, src)
}

// extendObjClear extends obj with cleared src
// if isSoftSync, extend without cleared
export const extendObjClear = (obj: Record<string, any>, src: Record<string, any>, isSoftSync?: boolean) => {
  Object.keys(src).forEach((key) => {
    if (src[key] === null) return
    if (typeof src[key] !== 'object') { // last key
      if (Object.prototype.hasOwnProperty.call(obj, key)) return
      if (isSoftSync) obj[key] = src[key]
      else {
        switch (typeof src[key]) {
          case 'string':
            obj[key] = ''
            break
          case 'boolean':
            obj[key] = false
            break
          case 'number':
            obj[key] = 0
            break
          default:
            obj[key] = ''
        }
      }
      return
    }

    if (!Array.isArray(src[key])) {
      if (!obj[key]) obj[key] = {}
      obj[key] = extendObjClear(obj[key], src[key], isSoftSync)
    } else { // array
      if (!Array.isArray(obj[key])) obj[key] = []
      for (let i = 0; i < src[key].length; i++) {
        const val = src[key][i]
        if (typeof val !== 'object') {
          if (!obj[key].includes(val)) obj[key].push(val) // e.g. ["value1", "value2"]
        } else {
          if (Object.prototype.hasOwnProperty.call(val, 'type') && key !== 'members' && key !== 'groups') {
            if (obj[key].length < 1) {
              const v: any = copyObj(val)
              if (!isSoftSync) v.operation = 'delete'
              obj[key].push(v)
            } else {
              let found = false
              for (const k in obj[key]) {
                const el = obj[key][k]
                if (el.type === val.type) {
                  found = true
                  for (const kv in val) {
                    if (kv === 'type' || kv === 'value' || isSoftSync) continue // don't clear type/value
                    if (Object.prototype.hasOwnProperty.call(el, kv)) continue
                    switch (typeof val[kv]) {
                      case 'string':
                        el[kv] = ''
                        break
                      case 'boolean':
                        el[kv] = false
                        break
                      case 'number':
                        el[kv] = 0
                        break
                      default:
                        el[kv] = ''
                    }
                  }
                }
              }
              if (!found) {
                const v: any = copyObj(val)
                if (!isSoftSync) v.operation = 'delete'
                obj[key].push(v)
              }
            }
          } else if (Object.prototype.hasOwnProperty.call(val, 'value')) { // no type
            if (obj[key].length < 1) {
              const v: any = copyObj(val)
              if (!isSoftSync) v.operation = 'delete'
              obj[key].push(v)
            } else {
              const addArr: any = []
              let found = false
              for (let j = 0; j < obj[key].length; j++) {
                const el = obj[key][j]
                if (el.value === val.value) {
                  obj[key].splice(j, 1)
                  j -= 1
                  found = true
                  break
                }
              }
              if (!found) {
                const v: any = copyObj(val)
                if (!isSoftSync) v.operation = 'delete'
                addArr.push(v)
              }
              if (addArr.length > 0) {
                obj[key] = [...obj[key], ...addArr]
              }
            }
          } else {
            obj[key].push(val)
          }
        }
      }
    }
  })
  return obj // recursive
}

// deltaObj removes from obj what matches with src, only delta remains in obj
export const deltaObj = (obj: Record<string, any>, src: Record<string, any>) => {
  for (const key in obj) {
    if (Array.isArray(obj[key])) {
      if (!src[key] || !Array.isArray(src[key])) continue
      const arr = obj[key]
      for (let i = 0; i < arr.length; i++) {
        const el = arr[i]
        if (el.operation) continue // keep operation
        if (el.type) {
          if (Object.prototype.hasOwnProperty.call(el, 'value')) {
            const a = src[key].filter(o => o.type === el.type && o.value === el.value)
            if (a.length === 1) {
              arr.splice(i, 1)
              i -= 1
            }
          } else { // only type
            const a = src[key].filter((o) => {
              for (const k in el) {
                if (el[k] !== o[k]) return false
              }
              return true
            })
            if (a.length === 1) {
              arr.splice(i, 1)
              i -= 1
            }
          }
        } else if (Object.prototype.hasOwnProperty.call(el, 'value')) {
          const a = src[key].filter(o => o.value === el.value)
          if (a.length === 1) {
            arr.splice(i, 1)
            i -= 1
          }
        }
      }
      if (arr.length === 0) {
        delete obj[key]
      }
    } else {
      if (typeof (obj[key]) === 'object') {
        for (const keySub in obj[key]) {
          if (typeof (obj[key][keySub]) === 'object') {
            for (const keySubSub in obj[key][keySub]) {
              if (src[key] && src[key][keySub] && src[key][keySub][keySubSub] === obj[key][keySub][keySubSub]) {
                delete obj[key][keySub][keySubSub]
              }
            }
            if (Object.keys(obj[key][keySub]).length === 0) delete obj[key][keySub]
          } else {
            if (src[key] && src[key][keySub] === obj[key][keySub]) {
              delete obj[key][keySub]
            }
          }
        }
        if (Object.keys(obj[key]).length === 0) delete obj[key]
      } else if (obj[key] === src[key]) delete obj[key]
    }
  }
}

// stripObj strips and return a new object according to attributes or excludedAttributes - comma separated dot object list
export const stripObj = (obj: Record<string, any>, attributes?: string, excludedAttributes?: string) => {
  if (!attributes && !excludedAttributes) return obj
  if (!obj || typeof obj !== 'object') return obj
  let arrObj
  if (!Array.isArray(obj)) arrObj = [obj]
  else {
    if (obj.length < 1) return obj
    arrObj = obj
  }
  let arrRet = []
  const arrCheckEmpty: any = []
  if (attributes) {
    const arrAttr = attributes.split(',').filter(Boolean).map(item => item.trim())
    if (!arrAttr.includes('id')) arrAttr.push('id') // always include id
    if (!arrAttr.includes('meta')) arrAttr.push('meta') // include meta if supported by endpoint
    arrRet = arrObj.map((obj) => {
      const ret: Record<string, any> = {}
      for (let i = 0; i < arrAttr.length; i++) {
        const attr = arrAttr[i].split('.') // title / name.familyName / emails.value
        if (Object.prototype.hasOwnProperty.call(obj, attr[0])) {
          if (attr.length === 1) ret[attr[0]] = obj[attr[0]]
          else if (Object.prototype.hasOwnProperty.call(obj[attr[0]], attr[1])) { // name.familyName
            if (!ret[attr[0]]) ret[attr[0]] = {}
            ret[attr[0]][attr[1]] = obj[attr[0]][attr[1]]
          } else if (Array.isArray(obj[attr[0]])) { // emails.value / phoneNumbers.type
            if (!ret[attr[0]]) ret[attr[0]] = []
            const arr = obj[attr[0]]
            for (let j = 0; j < arr.length; j++) {
              if (typeof arr[j] !== 'object') {
                ret[attr[0]].push(arr[j])
              } else if (Object.prototype.hasOwnProperty.call(arr[j], attr[1])) {
                if (ret[attr[0]].length !== arr.length) { // initiate
                  for (let i = 0; i < arr.length; i++) ret[attr[0]].push({}) // need arrCheckEmpty
                }
                ret[attr[0]][j][attr[1]] = arr[j][attr[1]]
                if (!arrCheckEmpty.includes(attr[0])) arrCheckEmpty.push(attr[0])
              }
            }
          }
        }
      }
      if (arrCheckEmpty.length > 0) {
        for (let i = 0; i < arrCheckEmpty.length; i++) {
          const arr = ret[arrCheckEmpty[i]]
          for (let j = 0; j < arr.length; j++) {
            try {
              if (JSON.stringify(arr[j]) === '{}') arr.splice(j, 1)
            } catch (err) { return }
          }
        }
      }
      return ret
    })
  } else if (excludedAttributes) {
    const arrAttr = excludedAttributes.split(',').filter(Boolean).map(item => item.trim()).filter(item => item !== 'id' && item !== 'meta')
    arrRet = arrObj.map((obj) => {
      const ret: any = copyObj(obj)
      for (let i = 0; i < arrAttr.length; i++) {
        const attr = arrAttr[i].split('.') // title / name.familyName / emails.value
        if (Object.prototype.hasOwnProperty.call(ret, attr[0])) {
          if (attr.length === 1) delete ret[attr[0]]
          else if (Object.prototype.hasOwnProperty.call(ret[attr[0]], attr[1])) delete ret[attr[0]][attr[1]] // name.familyName
          else if (Array.isArray(ret[attr[0]])) { // emails.value / phoneNumbers.type
            const arr = ret[attr[0]]
            for (let j = 0; j < arr.length; j++) {
              if (Object.prototype.hasOwnProperty.call(arr[j], attr[1])) {
                const index = arr.findIndex((el: Record<string, any>) => ((Object.prototype.hasOwnProperty.call(el, attr[1]))))
                if (index > -1) {
                  delete arr[index][attr[1]]
                  try {
                    if (JSON.stringify(arr[index]) === '{}') arr.splice(index, 1)
                  } catch (err) { return }
                }
              }
            }
          }
        }
      }
      return ret
    })
  } else { // should not be here
    arrRet = []
  }
  if (!Array.isArray(obj)) return arrRet[0]
  return arrRet
}

// sortByKey will string-sort array of objects by spesific key
// myArr.sort(sortByKey('name.familyName', 'ascending'))
export const sortByKey = (key: string, order: string = 'ascending') => {
  return (a: any, b: any) => { // inner sort
    const val: any = [undefined, undefined]
    const arrIter = [a, b]
    const levels = key.split('.')
    if (!Object.prototype.hasOwnProperty.call(a, levels[0]) || !Object.prototype.hasOwnProperty.call(b, levels[0])) return 0
    arrIter.forEach((el, index) => {
      let parent = el
      for (let i = 0; i < levels.length; i++) {
        if (Array.isArray(parent[levels[i]])) {
          if (i === levels.length - 1) {
            parent = undefined
            break
          }
          parent = parent[levels[i]][0][levels[i + 1]] // using first array element istead of primary attribute e.g key=emails.value
          break
        } else parent = parent[levels[i]]
      }
      val[index] = parent
    })
    if (typeof val[0] !== 'string') return 0
    const comparison = val[0].localeCompare(val[1])
    return (
      (order === 'descending') ? (comparison * -1) : comparison
    )
  }
}

// getEncrypted returns encrypted or cleartext secret
// same as getPassword method, but seed passed as argument and not using json configuration file
// if pw is cleartext, return encrypted secret
// if pw is encrypted, return cleartext secret
export const getEncrypted = function (pw: string, seed: string) {
  if (!pw || !seed) return undefined
  const ivLength = 16
  if (seed.length < ivLength) {
    const addStr = 'aB1cD2eF3gH4iJ5kL7'
    const diff = ivLength - seed.length
    if (diff > 0) seed += addStr.substring(0, diff)
  }
  const pwencr = Buffer.from(pw, 'base64').toString('utf8')
  try { // decrypt
    const textParts: any = pwencr.split(':')
    const iv = Buffer.from(textParts.shift(), 'hex')
    const encryptedText = Buffer.from(textParts.join(':'), 'hex')
    const decipher = crypto.createDecipheriv('aes-128-cbc', Buffer.from(seed.substr(-ivLength)), iv)
    const pw = decipher.update(encryptedText)
    const pwClear: any = Buffer.concat([pw, decipher.final()])
    return pwClear.toString()
  } catch (err) { // password considered as cleartext and needs to be encrypted
    const pwclear = pw
    const iv = crypto.randomBytes(ivLength)
    const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(seed.substr(-ivLength), 'utf8'), iv)
    let encrypted = cipher.update(pwclear)
    encrypted = Buffer.concat([encrypted, cipher.final()])
    const pwencr = iv.toString('hex') + ':' + encrypted.toString('hex')
    return Buffer.from(pwencr).toString('base64')
  }
  return undefined
}

// fsExistsSync checks if file/directory exist and returns true/false
export const fsExistsSync = function (f: string) {
  try {
    fs.accessSync(f)
    return true
  } catch (e) {
    return false
  }
}

// createRandomPassword creates a random password, syntax:
// utils.createRandomPassword(12) => 12 characters: lower, upper, numeric and special
// utils.createRandomPassword(12, utils.createRandomPassword.alphaLower, utils.createRandomPassword.alphaUpper)
// https://gist.github.com/6174/6062387
export const createRandomPassword = function (len: number, ...set: string[]) {
  const gen = (min: number, max: number) => max++ && [...Array(max - min)].map((s, i) => String.fromCharCode(min + i))
  const sets = {
    num: gen(48, 57),
    alphaLower: gen(97, 122),
    alphaUpper: gen(65, 90),
    special: [...'~!@#$%^&*()_+-=[]{}|;:\'",./<>?'],
  }
  function* iter(len: number, set: any) {
    if (set.length < 1) { set = Object.values(sets).flat() }
    for (let i = 0; i < len; i++) { yield set[Math.random() * set.length | 0] }
  }
  let res
  if (len > 3 && set.length === 0) { // ensure all variants are included: lower, upper, numeric and special
    res = Object.assign((len: number, set: any) => [...iter(len, set.flat())].join(''), sets)(len, set)
    let pos = Math.random() * len | 0
    if (pos > len - 4) pos = len - 4
    res = res.split('')
    res.splice(pos, 1, Object.assign((len: number, set: any) => [...iter(len, set.flat())].join(''), sets)(1, sets.num))
    res.splice(pos + 1, 1, Object.assign((len: number, set: any) => [...iter(len, set.flat())].join(''), sets)(1, sets.alphaUpper))
    res.splice(pos + 2, 1, Object.assign((len: number, set: any) => [...iter(len, set.flat())].join(''), sets)(1, sets.special))
    res.splice(pos + 3, 1, Object.assign((len: number, set: any) => [...iter(len, set.flat())].join(''), sets)(1, sets.alphaLower))
    res = res.join('')
  } else {
    res = Object.assign((len: number, set: any) => [...iter(len, set.flat())].join(''), sets)(len, set)
  }
  return res
}

/**
 * formUrlEncodedToJSON converts application/x-www-form-urlencoded request body to json
  * @param body http request body string
  * @returns json formatted body
 */
export const formUrlEncodedToJSON = function (body?: string): Record<string, any> {
  if (!body) return {}
  const arr = body.split('&') // "grant_type=client_credentials&client_id=id&client_secret=secret"
  const json: Record<string, any> = {}
  for (const kv of arr) {
    const a = kv.split('=')
    if (a.length === 2) {
      try {
        json[a[0]] = decodeURIComponent(a[1])
      } catch (err) { return {} }
    }
  }
  return json
}

/**
 * formDataMultipartToJSON converts multipart/form-data request body to json - Content-Type: multipart/form-data;boundary="<some-delimiter>"
  * @param body request body
  * @param boundary the boundary/delimiter defiend in header Content-Type: multipart/form-data;boundary="<some-delimiter>"
  * @returns json formatted body
 */
export const formDataMultipartToJSON = function (body?: string, boundary?: string): Record<string, any> {
  if (!body) return {} // --delimiter123\nContent-Disposition: form-data; name="field1"\n\nvalue1\n--delimiter123\nContent-Disposition: form-data; name="field2"; filename="example.txt"\n\nvalue2
  if (!boundary) { // if boundary is missing, try to infer it
    const inferredBoundary = body.match(/^--([^\r\n]+)/)
    if (inferredBoundary) {
      boundary = inferredBoundary[1]
    } else return {} // No boundary found
  }
  const parts = body.split(`--${boundary}`).filter(part => part.trim() && !part.includes('--'))
  const json: Record<string, any> = {}
  for (const part of parts) {
    const [headers, value] = part.split(/\r?\n\r?\n/)
    const nameMatch = headers.match(/name="([^"]+)"/)
    if (nameMatch) {
      const key = nameMatch[1]
      json[key] = value.trim()
      try {
        json[key] = decodeURIComponent(json[key])
      } catch (err) { return {} }
    }
  }
  return json
}

/**
 * getBase64CertificateThumbprintconverts return Base64url-encoded SHA thumbprint of the X.509 certificate's DER encoding
  * @param pemCertContent PEM formatted certificate content
  * @param shaVersion sha1 or sha256, default sha1
  * @returns Base64url-encoded SHA thumbprint
 */
export const getBase64CertificateThumbprint = function (pemCertContent: string, shaVersion: 'sha1' | 'sha256' = 'sha1'): string {
  if (!pemCertContent) return ''
  const certMatch = pemCertContent.match(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/)
  if (!certMatch) return ''
  const certBase64 = certMatch[1].replace(/\s+/g, '') // remove whitespace and newlines
  const certDer = Buffer.from(certBase64, 'base64') // decode the PEM to DER (Base64 decode)
  const hash = crypto.createHash(shaVersion).update(certDer).digest() // compute the SHA-256 hash of the DER
  // thumbprint = hash.toString('hex')
  const base64Url = hash
    .toString('base64') // convert binary hash to standard Base64
    .replace(/\+/g, '-') // replace '+' with '-'
    .replace(/\//g, '_') // replace '/' with '_'
    .replace(/=+$/, '') // remove '=' padding

  return base64Url
}

/**
 * getEtag returns an ETag for the given object and updates the object with the ETag in meta.version
  * @param obj full object to calculate ETag from
  * @returns ETag string as W/"<hash>"
 */
export const getEtag = function (obj: Record<string, any>): string {
  if (typeof obj !== 'object' || obj === null) return ''
  const hash = crypto
    .createHash('md5')
    .update(JSON.stringify(obj), 'utf8')
    .digest('base64')
    .substring(0, 22)

  let eTag = ''
  if (obj?.meta?.version) eTag = obj.meta.version
  else {
    eTag = `W/"${hash}"`
    if (!obj.meta) obj.meta = {}
    obj.meta.version = eTag
  }
  return eTag
}
