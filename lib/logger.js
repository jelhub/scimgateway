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

const Log = function (config, logfile, _this) { // { loglevel: { file: "debug", console: "debug" } }
  _this = this // argument _this not used by caller - workaround for accessing this from nested class logic
  const arrValidLevel = ['silly', 'debug', 'verbose', 'info', 'warn', 'error']
  if (!config) {
    config = {
      loglevel: {}
    }
  }
  if (!config.loglevel) config.loglevel = {}
  this.config = config

  let customMaskJson = ''
  let customMaskSoap = ''
  if (config.customMasking && Array.isArray(config.customMasking) && config.customMasking.length > 0) {
    customMaskJson = config.customMasking.join('|')
    customMaskSoap = config.customMasking.join('"?|')
    customMaskJson = '|' + customMaskJson
    customMaskSoap = '|' + customMaskSoap + '"?'
  }
  const reJson = `^.*"(password|access_token${customMaskJson})" ?: ?"([^"]+)".*`
  const reXml = `^.*(credentials"?|PasswordText"?|PasswordDigest"?|password"?${customMaskSoap})>([^<]+)<.*`

  const maskSecret = winston.format((info, opts) => {
    // mask json secrets
    var rePattern = new RegExp(reJson, 'i')
    let msg = info.message
    let endPos = msg.length - 1
    let found = false
    do {
      var arrMatches = msg.substring(0, endPos).match(rePattern)
      if (Array.isArray(arrMatches) && arrMatches.length === 3) {
        arrMatches[2] = arrMatches[2].replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&') // escaping special regexp characters
        msg = msg.replace(new RegExp(arrMatches[2], 'g'), '********')
        endPos = msg.indexOf('"********"') - 1
        found = true
      } else found = false
    } while (found === true)

    // mask xml/soap secrets
    rePattern = new RegExp(reXml, 'i')
    endPos = msg.length - 1
    do {
      arrMatches = msg.substring(0, endPos).match(rePattern)
      if (Array.isArray(arrMatches) && arrMatches.length === 3) {
        arrMatches[2] = arrMatches[2].replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&')
        msg = msg.replace(new RegExp('>' + arrMatches[2] + '<', 'g'), '>********<')
        endPos = msg.indexOf('>********<') - 1
        found = true
      } else found = false
    } while (found === true)

    if (info.level === 'error') { // using clients async promise without await
      try { _this.emailOnError(msg) } catch (err) {}
    }
    info.message = msg
    return info
  })

  const fileFormat = winston.format.combine(
    winston.format.printf(info => {
      return `${timestamp()} ${info.level}: ${info.message}`
    })
  )

  const consoleFormat = winston.format.combine(
    winston.format.colorize(),
    winston.format.printf(info => {
      return `${timestamp()} ${config.category} ${info.level}: ${info.message}`
    })
  )

  Log.prototype.unColorize = () => {
    return winston.format.combine(
      consoleFormat,
      winston.format.uncolorize()
    )
  }

  Log.prototype.logger = winston.createLogger({
    format: winston.format.combine(
      maskSecret()
    ),
    transports: [
      new winston.transports.File({
        level: (config.loglevel.file && arrValidLevel.includes(config.loglevel.file.toLowerCase())) ? config.loglevel.file : 'debug',
        filename: logfile,
        handleExceptions: true,
        format: fileFormat,
        maxsize: 10485760, // 10 MB
        maxFiles: 5
      }),
      new winston.transports.Console({ // note, console logging is synchronous e.g. node.js halts when console window is scrolled
        level: (config.loglevel.console && arrValidLevel.includes(config.loglevel.console.toLowerCase())) ? config.loglevel.console : 'debug',
        handleExceptions: true,
        stderrLevels: ['error'],
        format: (config.colorize) ? consoleFormat : Log.prototype.unColorize()
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
