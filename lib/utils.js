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
  const fs = require('fs')
  const configString = fs.readFileSync(configFile).toString()
  const config = JSON.parse(configString)
  const pw = Object.prop(config, pwDotNotation)
  let pwclear
  const seed = path.basename(configFile) + (process.env.SEED || id.machineIdSync({ original: true }))
  const ivLength = 16

  if (seed.length < ivLength) throw (new Error('Password seed length too short'))

  if (pw) {
    if (pw.includes('process.')) { // password based on external reference e.g. environment or json file
      // syntax environment = "process.env.<ENVIRONMENT>" e.g. scimgateway.password could have value "process.env.PORT", then using environment variable PORT
      // syntax file = "process.file.<PATH>" e.g. scimgateway.password could have value "process.file./tmp/myconf.json"
      const processEnv = 'process.env.'
      const processFile = 'process.file.'
      if (pw.constructor === String && pw.includes(processEnv)) {
        const envKey = pw.substring(processEnv.length)
        pwclear = process.env[envKey]
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
  if (obj.hasOwnProperty(prop)) return obj[prop]
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
  let output, v, key
  output = Array.isArray(o) ? [] : {}
  for (key in o) {
    v = o[key]
    output[key] = (typeof v === 'object' && v !== null) ? module.exports.copyObj(v) : v
  }
  return output
}

module.exports.extendObj = (obj, src) => { // copy src content into obj
  Object.keys(src).forEach((key) => {
    if (typeof src[key] === 'object' && src[key] != null) {
      if (typeof obj[key] === 'undefined') obj[key] = src[key]
      else obj[key] = module.exports.extendObj(obj[key], src[key])
    } else obj[key] = src[key]
  })
  return obj
}
