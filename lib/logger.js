// ==============================================================
// File:    logger.js
//
// Author:  Jarle Elshaug
// ==============================================================

const winston = require('winston') // level: silly=0(lowest), debug=1, verbose=2, info=3, warn=4, error=5(highest)

// Wrong time if not setting timestamp. Timezone did not work.
// moment-timezone is also an alternative to the timestamp() function.
const timestamp = () => {
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

const Log = function (loglevel, logfile, _this) { // { loglevel: { file: "debug", console: "debug" } }
  _this = this // argument _this not used by caller - workaround for accessing this from nested class logic
  const arrValidLevel = ['silly', 'debug', 'verbose', 'info', 'warn', 'error']
  if (!loglevel) loglevel = {}
  this.loglevel = loglevel

  const maskSecret = winston.format((info, opts) => {
    // mask json (SCIM) passwords/secrets
    var rePattern = new RegExp(/^.*"(password|access_token)" ?: ?"([^"]+)".*/i)
    let msg = info.message
    var arrMatches = msg.match(rePattern)
    if (Array.isArray(arrMatches) && arrMatches.length === 3) {
      arrMatches[2] = arrMatches[2].replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&') // escaping special regexp characters
      msg = msg.replace(new RegExp(arrMatches[2], 'g'), '********')
    }
    // mask xml (soap) passwords/secrets
    rePattern = new RegExp(/^.*(credentials"?|PasswordText"?|PasswordDigest"?|password"?)>([^<]+)<.*/i)
    arrMatches = msg.match(rePattern)
    if (Array.isArray(arrMatches) && arrMatches.length === 3) {
      arrMatches[2] = arrMatches[2].replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&')
      msg = msg.replace(new RegExp('>' + arrMatches[2] + '<', 'g'), '>********<')
    }

    if (info.level === 'error') { // using clients async promise without await
      try { _this.emailOnError(msg) } catch (err) {}
    }
    info.message = msg
    return info
  })

  const fileFormat = winston.format.combine(
    maskSecret(),
    winston.format.printf(info => {
      return `${timestamp()} ${info.level}: ${info.message}`
    })
  )

  const consoleFormat = winston.format.combine(
    maskSecret(),
    winston.format.colorize(),
    winston.format.printf(info => {
      return `${timestamp()} ${loglevel.category} ${info.level}: ${info.message}`
    })
  )

  Log.prototype.unColorize = () => {
    return winston.format.combine(
      consoleFormat,
      winston.format.uncolorize()
    )
  }

  Log.prototype.logger = winston.createLogger({
    filters: [function (level, msg, meta) {
      // mask json (scim) passwords/secrets
      var rePattern = new RegExp(/^.*"(password|access_token)" ?: ?"([^"]+)".*$/i)
      var arrMatches = msg.match(rePattern)
      if (Array.isArray(arrMatches) && arrMatches.length === 3) {
        arrMatches[2] = arrMatches[2].replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&') // escaping special regexp characters
        msg = msg.replace(new RegExp(arrMatches[2], 'g'), '********')
      }
      // mask xml (soap) passwords/secrets
      rePattern = new RegExp(/^.*(credentials"?|PasswordText"?|PasswordDigest"?|password"?)>([^<]+)<.*$/i)
      arrMatches = msg.match(rePattern)
      if (Array.isArray(arrMatches) && arrMatches.length === 3) {
        arrMatches[2] = arrMatches[2].replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&')
        msg = msg.replace(new RegExp('>' + arrMatches[2] + '<', 'g'), '>********<')
      }

      if (level === 'error') { // using clients async promise without await
        try { _this.emailOnError(msg) } catch (err) {}
      }
      return msg
    }],
    transports: [
      new winston.transports.File({
        level: (loglevel.file && arrValidLevel.includes(loglevel.file.toLowerCase())) ? loglevel.file : 'debug',
        filename: logfile,
        handleExceptions: true,
        format: fileFormat,
        maxsize: 10485760, // 10 MB
        maxFiles: 5
      }),
      new winston.transports.Console({ // note, console logging is synchronous e.g. node.js halts when console window is scrolled
        level: (loglevel.console && arrValidLevel.includes(loglevel.console.toLowerCase())) ? loglevel.console : 'debug',
        handleExceptions: true,
        stderrLevels: ['error'],
        format: (loglevel.colorize) ? consoleFormat : Log.prototype.unColorize()
      })
    ],
    exitOnError: false
  })

  // flush to disk before exit (process.exit in main code will terminate logger and we may have unflushed logfile updates)
  // note, still asynchronous (using exception is an alternative that gives synchronous flush and program exit)
  Log.prototype.exitAfterFlush = (code) => {
    Log.prototype.logger.transports[0].on('flush', function () {
      process.exit(code)
    })
  }

  const logger = Log.prototype.logger // fix multiple loggers using stream
  Log.prototype.stream = {
    write: function (message, encoding) {
      logger.info(message)
    }
  }
}

module.exports.Log = Log
