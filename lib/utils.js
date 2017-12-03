// ==================================
// File:    utils.js
//
// Author:  Jarle Elshaug
// ==================================

'use strict'

const crypto = require('crypto')
const id = require('node-machine-id')
const path = require('path')

module.exports.getPassword = function (pwDotNotation, configFile) {
  // get password from json-file.
  // if cleartext then encrypt and save the new encrypted password
  let seed = path.basename(configFile) + (process.env.SEED || id.machineIdSync({ original: true }))
  let decipher = crypto.createDecipher('aes192', seed)
  let cipher = crypto.createCipher('aes192', seed)
  let fs = require('fs')
  let configString = fs.readFileSync(configFile).toString()
  let config = JSON.parse(configString)
  let pw = Object.prop(config, pwDotNotation) // let pw = eval('config.' + pwDotNotation); //eval not always the best (use Object.prop)
  let pwclear = ''

  if (pw !== undefined) {
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
        pwclear = '' // something went wrong, return empty password
      }
    }
  } else {
    let err = new Error(pwDotNotation + ' can not be found in configuration file ' + configFile)
    throw (err)
  }

  return pwclear
} // getPassword

module.exports.timestamp = function () { // new Date() do not handle current timezone
  function pad(n) { return n < 10 ? '0' + n : n }
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
  let props = prop.split('.')
  let final = props.pop()
  let p
  while (p = props.shift()) {
    if (typeof obj[p] === 'undefined') { return undefined }
    obj = obj[p]
  }
  return val ? (obj[final] = val) : obj[final]
}
