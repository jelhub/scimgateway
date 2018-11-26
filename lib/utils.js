// ==================================
// File:    utils.js
//
// Author:  Jarle Elshaug
// ==================================

'use strict'

const crypto = require('crypto')
const id = require('node-machine-id')
const path = require('path')
const EventEmitter = require('events').EventEmitter

class Lock { // mutual exclusion ref: https://thecodebarbarian.com/mutual-exclusion-patterns-with-node-promises
  constructor () {
    this._locked = false
    this._ee = new EventEmitter()
  }

  acquire () {
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

  release () { // Release the lock immediately
    this._locked = false
    setImmediate(() => this._ee.emit('release'))
  }
}

module.exports = { // constructors
  Lock
}

module.exports.getPassword = function (pwDotNotation, configFile) {
  // get password from json-file.
  // if cleartext then encrypt and save the new encrypted password
  let seed = path.basename(configFile) + (process.env.SEED || id.machineIdSync({ original: true }))
  let decipher = crypto.createDecipher('aes192', seed)
  let cipher = crypto.createCipher('aes192', seed)
  let fs = require('fs')
  let configString = fs.readFileSync(configFile).toString()
  let config = JSON.parse(configString)
  let pw = Object.prop(config, pwDotNotation)
  let pwclear

  if (pw) {
    if (pw.includes('process.')) { // password based on external reference e.g. environment or json file
      // syntax environment = "process.env.<ENVIRONMENT>" e.g. scimgateway.password could have value "process.env.PORT", then using environment variable PORT
      // syntax file = "process.file.<PATH>" e.g. scimgateway.password could have value "process.file./tmp/myconf.json"
      let processEnv = 'process.env.'
      let processFile = 'process.file.'
      if (pw.constructor === String && pw.includes(processEnv)) {
        let envKey = pw.substring(processEnv.length)
        pwclear = process.env[envKey]
      } else if (pw && pw.constructor === String && pw.includes(processFile)) {
        let filePath = pw.substring(processFile.length)
        try {
          let content = fs.readFileSync(filePath, 'utf8')
          try {
            let jContent = JSON.parse(content)
            pwclear = Object.prop(jContent, pwDotNotation)
          } catch (err) { pwclear = undefined } // can't JSON parse external file
        } catch (err) { pwclear = undefined } // can't read external configuration file
      } else pwclear = undefined
    } else { // password based on local configuration file
      try {  // decrypt
        pwclear = decipher.update(pw, 'base64', 'utf8')
        pwclear += decipher.final('utf8')
      } catch (err) {
        if ((err.message.indexOf('Bad input string') === 0) ||
          (err.message.indexOf('wrong final block length') > -1) ||
          (err.message.indexOf('bad decrypt') > -1)
        ) {
          // password is cleartext and needs to be encrypted and written back to file
          pwclear = pw
          let pwencr = cipher.update(pwclear, 'utf8', 'base64')
          pwencr += cipher.final('base64')
          Object.prop(config, pwDotNotation, pwencr)
          let fileContent = JSON.stringify(config, null, 2) // removing white space, but use 2 space separator
          fileContent = fileContent.replace(/\n/g, '\r\n') // cr-lf instead of lf
          try {
            fs.writeFileSync(configFile, fileContent)
          } catch (err) {
            throw err
          }
        } else {
          pwclear = undefined // something went wrong
        }
      }
    }
  } else {
    pwclear = undefined // can't be found in configuration file or having value null/undefined
  }
  return pwclear
} // getPassword

module.exports.timestamp = function () { // new Date() do not handle current timezone
  function pad (n) { return n < 10 ? '0' + n : n }
  let d = new Date()
  return new Date(d.getFullYear() + '-' +
    pad(d.getMonth() + 1) + '-' +
    pad(d.getDate()) + 'T' +
    pad(d.getHours()) + ':' +
    pad(d.getMinutes()) + ':' +
    pad(d.getSeconds()) + '.' +
    pad(d.getMilliseconds()))
}

/**
 * Fxn that returns a JSON stringified version of an object.
 * This fxn uses a custom replacer function to handle circular references
 * see http://stackoverflow.com/a/11616993/3043369
 */
module.exports.JSONStringify = function (object) {
  let cache = []
  let str = JSON.stringify(object,
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

Object.prop = function (obj, prop, val) {
  if (obj.hasOwnProperty(prop)) return obj[prop] // json dot notation formatted obj
  let props = prop.split('.')
  let final = props.pop()
  let p
  while (p = props.shift()) {
    if (typeof obj[p] === 'undefined') { return undefined }
    obj = obj[p]
  }
  return val ? (obj[final] = val) : obj[final]
}
