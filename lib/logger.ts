// ==============================================================
// File:    logger.js
//
// Author:  Jarle Elshaug
// ==============================================================

import winston, { Logger } from 'winston' // level: silly=0, debug=1, verbose=2, info=3, warn=4, error=5

// Wrong time if not setting timestamp. Timezone did not work.
// moment-timezone is also an alternative to the timestamp() function.
const timestamp = () => {
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

export class Log {
  private logger: Logger
  private emailOnError: any
  private category: string
  private transports: any[]
  private reJson: string = ''
  private reXml: string = ''
  private arrValidLevel = ['off', 'silly', 'debug', 'verbose', 'info', 'warn', 'error']

  private consoleFormat = winston.format.combine(
    winston.format.colorize(),
    winston.format.printf((info) => {
      return `${timestamp()} ${this.category} ${info.level}: ${info.message}`
    }),
  )

  private fileFormat = winston.format.combine(
    winston.format.printf((info) => {
      return `${timestamp()} ${info.level}: ${info.message}`
    }),
  )

  private unColorize = () => {
    return winston.format.combine(
      this.consoleFormat,
      winston.format.uncolorize(),
    )
  }

  private maskSecret = winston.format((info) => {
    // mask json secrets
    let rePattern = new RegExp(this.reJson, 'i')
    let msg: string = info.message
    if (!msg) return info
    let endPos = msg.length - 1
    let found = false
    do {
      const arrMatches = msg.substring(0, endPos).match(rePattern)
      if (Array.isArray(arrMatches) && arrMatches.length === 3) {
        arrMatches[2] = arrMatches[2].replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&') // escaping special regexp characters
        msg = msg.replace(new RegExp(arrMatches[2], 'g'), '********')
        endPos = msg.indexOf('"********"') - 1
        found = true
      } else found = false
    } while (found === true)

    // mask xml/soap secrets
    rePattern = new RegExp(this.reXml, 'i')
    endPos = msg.length - 1
    do {
      const arrMatches = msg.substring(0, endPos).match(rePattern)
      if (Array.isArray(arrMatches) && arrMatches.length === 3) {
        arrMatches[2] = arrMatches[2].replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&')
        msg = msg.replace(new RegExp('>' + arrMatches[2] + '<', 'g'), '>********<')
        endPos = msg.indexOf('>********<') - 1
        found = true
      } else found = false
    } while (found === true)

    if (info.level === 'error' && this.emailOnError) { // async promise without await
      try { this.emailOnError(msg) } catch (err) { void 0 }
    }
    info.message = msg
    return info
  })

  constructor(loglevelConsole: string, loglevelFile: string, logFile: string, category: string, customMasking?: string) { // { loglevel: { file: "debug", console: "debug" } }
    this.category = category
    let customMaskJson = ''
    let customMaskXml = ''
    if (customMasking && Array.isArray(customMasking) && customMasking.length > 0) {
      customMaskJson = customMasking.join('|')
      customMaskJson = '|' + customMaskJson
      customMaskXml = customMasking.join('"?|')
      customMaskXml = '|' + customMaskXml + '"?'
    }
    this.reJson = `^.*"(password|access_token|client_secret|assertion${customMaskJson})" ?: ?"([^"]+)".*`
    this.reXml = `^.*(credentials"?|PasswordText"?|PasswordDigest"?|password"?${customMaskXml})>([^<]+)</.*`

    const trans: any = [
      new winston.transports.Console({ // note, console logging is synchronous e.g. node.js halts when console window is scrolled
        level: (loglevelConsole && this.arrValidLevel.includes(loglevelConsole.toLowerCase())) ? loglevelConsole : 'debug',
        handleExceptions: true,
        stderrLevels: ['error'],
        format: (process.stdout.isTTY) ? this.consoleFormat : this.unColorize(),
        silent: (loglevelConsole && loglevelConsole === 'off') ? true : false,
      }),
    ]
    if (loglevelFile && loglevelFile !== 'off' && logFile) {
      trans.push(
        new winston.transports.File({
          level: (loglevelFile && this.arrValidLevel.includes(loglevelFile.toLowerCase())) ? loglevelFile : 'debug',
          filename: logFile,
          handleExceptions: true,
          format: this.fileFormat,
          maxsize: 1024 * 1024 * 20, // 20 MB
          maxFiles: 5,
        }),
      )
    }
    if (!process.stdout.isTTY && loglevelConsole !== 'off') { // redirected stdout/stderr
      trans.push(
        new winston.transports.Stream({
          stream: process.stdout,
        }),
      )
      trans.push(
        new winston.transports.Stream({
          stream: process.stderr,
        }),
      )
    }

    this.logger = winston.createLogger({
      format: winston.format.combine(
        this.maskSecret(),
      ),
      transports: trans,
      exitOnError: false,
    })
    this.transports = this.logger.transports
  } // constructor

  silly(message: string): void {
    this.logger.silly(message)
  }

  debug(message: string): void {
    this.logger.debug(message)
  }

  info(message: string): void {
    this.logger.info(message)
  }

  warn(message: string): void {
    this.logger.warn(message)
  }

  error(message: string): void {
    this.logger.error(message)
  }

  setLoglevelConsole(loglevel: string): void {
    if (!loglevel) return
    if (!this.arrValidLevel.includes(loglevel.toLowerCase())) return
    for (let i = 0; i < this.transports.length; i++) {
      if (this.transports[i].name === 'console') {
        if (loglevel === 'off') this.transports[i].silent = true
        else this.transports[i].level = loglevel
        break
      }
    }
  }

  setLoglevelFile(loglevel: string): void {
    if (!loglevel) return
    if (!this.arrValidLevel.includes(loglevel.toLowerCase())) return
    for (let i = 0; i < this.transports.length; i++) {
      if (this.transports[i].name === 'file') {
        if (loglevel === 'off') this.transports[i].silent = true
        else this.transports[i].level = loglevel
        break
      }
    }
  }

  setEmailOnError(fnx: any): void {
    if (this.emailOnError) return
    this.emailOnError = fnx
  }

  close(): void {
    this.logger.close()
  }
} // class
