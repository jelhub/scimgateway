// ==================================
// File:    utils.js
//
// Author:  Jarle Elshaug
//
// Note, don't use arrow functions
// ==================================

'use strict'

const crypto = require('crypto')
const id = require('node-machine-id')
const path = require('path')
const EventEmitter = require('events').EventEmitter
const fs = require('fs')

/**
 * @constructor
 */
const Lock = function () { // mutual exclusion ref: https://thecodebarbarian.com/mutual-exclusion-patterns-with-node-promises
  this._locked = false
  this._ee = new EventEmitter()
}

Lock.prototype.acquire = function () {
  return new Promise(resolve => {
    if (!this._locked) { // If nobody has the lock, take it and resolve immediately
      this._locked = true
      return resolve()
    }
    const tryAcquire = () => { // Otherwise, wait until somebody releases the lock and try again
      if (!this._locked) {
        this._locked = true
        this._ee.removeListener('release', tryAcquire)
        return resolve()
      }
    }
    this._ee.on('release', tryAcquire)
  })
}

Lock.prototype.release = function () { // Release the lock immediately
  this._locked = false
  setImmediate(() => this._ee.emit('release'))
}

module.exports.Lock = Lock // export constructor - Note, must be exported before other ordinary export functions listed below
// module.exports = { 'Lock': Lock } // same as above

module.exports.getPassword = function (pwDotNotation, configFile) {
  // get password from json-file.
  // if cleartext then encrypt and save to file + return cleartext password
  // else return decrypted password
  const configString = fs.readFileSync(configFile).toString()
  const config = JSON.parse(configString)
  const pw = Object.prop(config, pwDotNotation)
  let pwclear
  let seed
  try {
    seed = path.basename(configFile) + (process.env.SEED || id.machineIdSync({ original: true }))
  } catch (err) {
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
            pwclear = Object.prop(jContent, `${pluginName}.${pwDotNotation}`)
          } catch (err) { pwclear = undefined } // can't JSON parse external file
        } catch (err) { pwclear = undefined } // can't read external configuration file
      } else pwclear = undefined
    } else { // password based on local configuration file
      try { // decrypt
        const pwencr = Buffer.from(pw, 'base64').toString('utf8')
        const textParts = pwencr.split(':')
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
        Object.prop(config, pwDotNotation, pwencr)
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

module.exports.timestamp = function () { // new Date() do not handle current timezone
  const pad = (n) => { return n < 10 ? '0' + n : n }
  const d = new Date()
  return d.getFullYear() + '-' +
    pad(d.getMonth() + 1) + '-' +
    pad(d.getDate()) + 'T' +
    pad(d.getHours()) + ':' +
    pad(d.getMinutes()) + ':' +
    pad(d.getSeconds()) + '.' +
    pad(d.getMilliseconds())
}

/**
 * Fxn that returns a JSON stringified version of an object.
 * This fxn uses a custom replacer function to handle circular references
 * see http://stackoverflow.com/a/11616993/3043369
 */
module.exports.JSONStringify = function (object) {
  let cache = []
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

Object.prop = function (obj, prop, val) { // return obj value based on json dot notation formatted prop
  if (Object.prototype.hasOwnProperty.call(obj, prop)) return obj[prop]
  const props = prop.split('.') // scimgateway.auth.basic[0].password
  const final = props.pop()
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

module.exports.copyObj = (o) => { // deep copy/clone faster than JSON.parse(JSON.stringify(o))
  let v, key
  const output = Array.isArray(o) ? [] : {}
  for (key in o) {
    v = o[key]
    if (typeof v === 'object' && v !== null) {
      const objProp = Object.getPrototypeOf(v) // e.g. HttpsProxyAgent {}
      if (objProp !== null && objProp !== Object.getPrototypeOf({}) && objProp !== Object.getPrototypeOf([])) {
        output[key] = Object.assign(Object.create(v), v) // e.g. { HttpsProxyAgent {...} }
      } else output[key] = module.exports.copyObj(v)
    } else output[key] = v
  }
  return output
}

const extendObj = (obj, src) => {
  Object.keys(src).forEach((key) => {
    if (typeof src[key] === 'object' && src[key] != null) {
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
      } else obj[key] = module.exports.extendObj(obj[key], src[key])
    } else if (src[key] != null) obj[key] = src[key]
  })
  return obj
}

module.exports.extendObj = (obj, src) => { // copy src content into obj
  if (typeof src !== 'object' || Array.isArray(src)) return obj
  return extendObj(obj, src)
}

// extendObjClear extends obj with cleared src
// if isSoftSync, extend without cleared
module.exports.extendObjClear = (obj, src, isSoftSync) => {
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
      obj[key] = module.exports.extendObjClear(obj[key], src[key], isSoftSync)
    } else { // array
      if (!Array.isArray(obj[key])) obj[key] = []
      for (let i = 0; i < src[key].length; i++) {
        const val = src[key][i]
        if (typeof val !== 'object') {
          if (!obj[key].includes(val)) obj[key].push(val) // e.g. ["value1", "value2"]
        } else {
          if (Object.prototype.hasOwnProperty.call(val, 'type')) {
            if (obj[key].length < 1) {
              const v = this.copyObj(val)
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
                const v = module.exports.copyObj(val)
                if (!isSoftSync) v.operation = 'delete'
                obj[key].push(v)
              }
            }
          } else if (Object.prototype.hasOwnProperty.call(val, 'value')) { // no type
            if (obj[key].length < 1) {
              const v = module.exports.copyObj(val)
              if (!isSoftSync) v.operation = 'delete'
              obj[key].push(v)
            } else {
              const addArr = []
              for (let j = 0; j < obj[key].length; j++) {
                const el = obj[key][j]
                if (el.value === val.value) {
                  obj[key].splice(j, 1)
                  j -= 1
                } else {
                  const v = module.exports.copyObj(val)
                  if (!isSoftSync) v.operation = 'delete'
                  addArr.push(v)
                }
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
module.exports.deltaObj = (obj, src) => {
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
            const a = src[key].filter(o => {
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
module.exports.stripObj = (obj, attributes, excludedAttributes) => {
  if (!attributes && !excludedAttributes) return obj
  if (!obj || typeof obj !== 'object') return obj
  let arrObj
  if (!Array.isArray(obj)) arrObj = [obj]
  else {
    if (obj.length < 1) return obj
    arrObj = obj
  }
  let arrRet = []
  const arrCheckEmpty = []
  if (attributes) {
    const arrAttr = attributes.split(',').map(item => item.trim())
    arrRet = arrObj.map(obj => {
      const ret = {}
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
            } catch (err) {}
          }
        }
      }
      return ret
    })
  } else if (excludedAttributes) {
    const arrAttr = excludedAttributes.split(',').map(item => item.trim())
    arrRet = arrObj.map(obj => {
      const ret = module.exports.copyObj(obj)
      for (let i = 0; i < arrAttr.length; i++) {
        const attr = arrAttr[i].split('.') // title / name.familyName / emails.value
        if (Object.prototype.hasOwnProperty.call(ret, attr[0])) {
          if (attr.length === 1) delete ret[attr[0]]
          else if (Object.prototype.hasOwnProperty.call(ret[attr[0]], attr[1])) delete ret[attr[0]][attr[1]] // name.familyName
          else if (Array.isArray(ret[attr[0]])) { // emails.value / phoneNumbers.type
            const arr = ret[attr[0]]
            for (let j = 0; j < arr.length; j++) {
              if (Object.prototype.hasOwnProperty.call(arr[j], attr[1])) {
                const index = arr.findIndex(el => ((Object.prototype.hasOwnProperty.call(el, attr[1]))))
                if (index > -1) {
                  delete arr[index][attr[1]]
                  try {
                    if (JSON.stringify(arr[index]) === '{}') arr.splice(index, 1)
                  } catch (err) {}
                }
              }
            }
          }
        }
      }
      return ret
    })
  } else { // should not be here
    arrRet = [{}]
  }
  if (!Array.isArray(obj)) return arrRet[0]
  return arrRet
}

// sortByKey will string-sort array of objects by spesific key
// myArr.sort(sortByKey('name.familyName', 'ascending'))
module.exports.sortByKey = (key, order = 'ascending') => {
  return (a, b) => { // inner sort
    const val = [undefined, undefined]
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
module.exports.getEncrypted = function (pw, seed) {
  if (!pw || !seed) return undefined
  const ivLength = 16
  if (seed.length < ivLength) {
    const addStr = 'aB1cD2eF3gH4iJ5kL7'
    const diff = ivLength - seed.length
    if (diff > 0) seed += addStr.substring(0, diff)
  }
  if (pw) {
    try { // decrypt
      const pwencr = Buffer.from(pw, 'base64').toString('utf8')
      const textParts = pwencr.split(':')
      const iv = Buffer.from(textParts.shift(), 'hex')
      const encryptedText = Buffer.from(textParts.join(':'), 'hex')
      const decipher = crypto.createDecipheriv('aes-128-cbc', Buffer.from(seed.substr(-ivLength)), iv)
      let pwclear = decipher.update(encryptedText)
      pwclear = Buffer.concat([pwclear, decipher.final()])
      pwclear = pwclear.toString()
      return pwclear
    } catch (err) { // password considered as cleartext and needs to be encrypted
      const pwclear = pw
      const iv = crypto.randomBytes(ivLength)
      const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(seed.substr(-ivLength), 'utf8'), iv)
      let encrypted = cipher.update(pwclear)
      encrypted = Buffer.concat([encrypted, cipher.final()])
      let pwencr = iv.toString('hex') + ':' + encrypted.toString('hex')
      pwencr = Buffer.from(pwencr).toString('base64')
      return pwencr
    }
  }
  return undefined
}

// fsExistsSync checks if file/directory exist and returns true/false
module.exports.fsExistsSync = function (f) {
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
module.exports.createRandomPassword = function (len, ...set) {
  const gen = (min, max) => max++ && [...Array(max - min)].map((s, i) => String.fromCharCode(min + i))
  const sets = {
    num: gen(48, 57),
    alphaLower: gen(97, 122),
    alphaUpper: gen(65, 90),
    special: [...'~!@#$%^&*()_+-=[]{}|;:\'",./<>?']
  }
  function * iter (len, set) {
    if (set.length < 1) { set = Object.values(sets).flat() }
    for (let i = 0; i < len; i++) { yield set[Math.random() * set.length | 0] }
  }
  let res
  if (len > 3 && set.length === 0) { // ensure all variants are included: lower, upper, numeric and special
    res = Object.assign((len, set) => [...iter(len, set.flat())].join(''), sets)(len, set)
    let pos = Math.random() * len | 0
    if (pos > len - 4) pos = len - 4
    res = res.split('')
    res.splice(pos, 1, Object.assign((len, set) => [...iter(len, set.flat())].join(''), sets)(1, sets.num))
    res.splice(pos + 1, 1, Object.assign((len, set) => [...iter(len, set.flat())].join(''), sets)(1, sets.alphaUpper))
    res.splice(pos + 2, 1, Object.assign((len, set) => [...iter(len, set.flat())].join(''), sets)(1, sets.special))
    res.splice(pos + 3, 1, Object.assign((len, set) => [...iter(len, set.flat())].join(''), sets)(1, sets.alphaLower))
    res = res.join('')
  } else {
    res = Object.assign((len, set) => [...iter(len, set.flat())].join(''), sets)(len, set)
  }
  return res
}
