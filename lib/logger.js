// ==============================================================
// File:    logger.js
//
// Author:  Jarle Elshaug
// ==============================================================

const winston = require('winston') // level: silly=0(lowest), debug=1, verbose=2, info=3, warn=4, error=5(highest)
const EventEmitter = require('events').EventEmitter
const util = require('util')
let _this = null

// 2 hours wrong time if not setting timestamp. Timezone did not work.
// moment-timezone is also an alternative to the timestamp() function.
function timestamp () {
  function pad (n) { return n < 10 ? '0' + n : n }
  var d = new Date()
  return d.getFullYear() + '-' +
    pad(d.getMonth() + 1) + '-' +
    pad(d.getDate()) + 'T' +
    pad(d.getHours()) + ':' +
    pad(d.getMinutes()) + ':' +
    pad(d.getSeconds()) + '.' +
    pad(d.getMilliseconds())
}

let Log = function (loglevel, logfile, _this) {
  winston.emitErrs = true
  _this = this // argument _this not used by caller - workaround for accessing this from nested class logic

  Log.prototype.logger = new winston.Logger({
    filters: [function (level, msg, meta) {
      // mask json (scim) passwords/secrets
      var rePattern = new RegExp(/^.*"(password|access_token)" ?: ?"([^"]+)".*$/)
      var arrMatches = msg.match(rePattern)
      if (Array.isArray(arrMatches) && arrMatches.length === 3) {
        arrMatches[2] = arrMatches[2].replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&') // escaping special regexp characters
        msg = msg.replace(new RegExp(arrMatches[2], 'g'), '********')
      }
      // mask xml (soap) passwords/secrets
      rePattern = new RegExp(/^.*(credentials"?|PasswordText"?|PasswordDigest"?|password"?)>([^<]+)<.*$/)
      arrMatches = msg.match(rePattern)
      if (Array.isArray(arrMatches) && arrMatches.length === 3) {
        arrMatches[2] = arrMatches[2].replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&')
        msg = msg.replace(new RegExp('>' + arrMatches[2] + '<', 'g'), '>********<')
      }

      if (level === 'error') { // catched by log.on('emailOnError', funcHandler)  for further message handling - e.g sending email
        _this.emit('emailOnError', msg, function () {
        })
      }
      return msg
    }],
    transports: [
      new winston.transports.File({
        level: loglevel || 'error',
        filename: logfile,
        timestamp: function () { return timestamp() },
        handleExceptions: true,
        json: false,
        maxsize: 10485760, // 10 MB
        maxFiles: 5,
        colorize: false
      }),
      new winston.transports.Console({
        level: 'error',
        handleExceptions: true,
        json: false,
        colorize: true
      })
    ],
    exitOnError: false
  })

  // flush to disk before exit (process.exit in main code will terminate logger and we may have unflushed logfile updates)
  // note, still asynchronous (using exception is an alternative that gives synchronous flush and program exit)
  Log.prototype.exitAfterFlush = function (code) {
    Log.prototype.logger.transports.file.on('flush', function () {
      process.exit(code)
    })
  }

  let logger = Log.prototype.logger // fix multiple loggers using stream
  Log.prototype.stream = {
    write: function (message, encoding) {
      logger.info(message)
    }
  }
}

util.inherits(Log, EventEmitter)
module.exports.Log = Log
