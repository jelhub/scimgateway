// ==============================================================
// File:    logger.ts
//
// Author:  Jarle Elshaug
// ==============================================================

import { existsSync, renameSync, readdirSync, unlinkSync, mkdirSync, createWriteStream } from 'node:fs'
import { join } from 'node:path'
import diagnostics_channel from 'node:diagnostics_channel'

// Node does not support "export enum LogLevel"
// instead using LogLevel as object and the type "LogLevel"
export const LogLevel = {
  Off: 0,
  Debug: 1,
  Info: 2,
  Warn: 3,
  Error: 4,
}
type LogLevel = typeof LogLevel[keyof typeof LogLevel]

// mapping log levels to their severity
const LEVEL_TO_INT: Record<string, LogLevel> = {
  off: LogLevel.Off,
  debug: LogLevel.Debug,
  info: LogLevel.Info,
  warn: LogLevel.Warn,
  error: LogLevel.Error,
}

const COLORS: Record<string, string> = {
  reset: '\x1b[0m', // Reset color
  debug: '\x1b[90m', // Gray
  info: '\x1b[32m', // Green
  warn: '\x1b[33m', // Yellow
  error: '\x1b[31m', // Red
}

interface LoggerOptions {
  type: 'console' | 'file'
  level: 'off' | 'debug' | 'info' | 'warn' | 'error'
  category?: string
  customMasking?: string[]
  logFileName?: string
  logDir?: string
  maxSize?: number
  maxFiles?: number
  colorize?: boolean
}

/**
 * Example: 
  ```
  const logger = new Logger(
    'plugin-loki',
    {
      type: 'console',
      level: 'error',
      customMasking: null,
      colorize: true,
    },
    {
      type: 'file',
      level: 'debug',
      customMasking: null,
      logDir: '/opt/my-scimgateway/logs',
      logFileName: 'plugin-loki.log',
      maxSize: 20,
      maxFiles: 5,
    },
  )
  ```
  */
export class Logger {
  private logStream: any // either Bun's FileSink or Node's WriteStream
  private logChannel: diagnostics_channel.Channel
  private category: string
  private customMasking: string[] | undefined
  private file: Record<string, any> | undefined
  private console: Record<string, any> | undefined
  private rotating = false
  private buffer: string[] = []
  private reJson: RegExp
  private reXml: RegExp
  private callbacks: Set<(message: any) => Promise<void>> = new Set()
  private LOG_DIR: string
  private LOG_FILE_PREFIX: string
  private LOG_FILE_SUFFIX: string
  private LOG_FILE_NAME: string
  private LOG_FILE: string
  private MAX_LOG_SIZE: number
  private MAX_LOG_FILES: number
  private HIGH_WATER_MARK: number

  constructor(category: string, ...options: LoggerOptions[]) {
    this.LOG_DIR = './logs'
    this.LOG_FILE_PREFIX = 'app'
    this.LOG_FILE_SUFFIX = 'log'
    this.LOG_FILE_NAME = this.LOG_FILE_PREFIX + '.' + this.LOG_FILE_SUFFIX
    this.LOG_FILE = this.LOG_DIR + '/' + this.LOG_FILE_NAME
    this.MAX_LOG_SIZE = 20 * 1024 * 1024 // 20 MB max file size
    this.MAX_LOG_FILES = 5 // keep only the last 5 logs - note, new and rotated file on startup
    this.HIGH_WATER_MARK = 16 * 1024 // 16KB buffer size before auto-flushing

    if (!category) throw Error('Logger constructor missing mandatory category')
    this.category = category
    for (const option of options) {
      if (option.type === 'file') {
        if (option.logDir) this.LOG_DIR = option.logDir
        if (option.logFileName) this.LOG_FILE_NAME = option.logFileName
        this.LOG_FILE = this.LOG_DIR + '/' + this.LOG_FILE_NAME
        this.LOG_FILE_PREFIX = this.LOG_FILE_NAME.substring(0, this.LOG_FILE_NAME.lastIndexOf('.'))
        this.LOG_FILE_SUFFIX = this.LOG_FILE_NAME.substring(this.LOG_FILE_NAME.lastIndexOf('.') + 1)

        this.file = {
          level: option.level || 'off',
          logSize: 0,
          maxSize: option.maxSize ? option.maxSize * 1024 * 1024 : this.MAX_LOG_SIZE,
          maxFiles: option.maxFiles || this.MAX_LOG_FILES,
        }
      } else if (option.type === 'console') {
        if (option.colorize === undefined) {
          if (process.stdout.isTTY) option.colorize = true
          else option.colorize = false // stdout/stderr redirect
        }
        this.console = { level: option.level, colorize: option.colorize }
      }
      if (option.customMasking) this.customMasking = option.customMasking
    }

    let customMaskJson = ''
    let customMaskXml = ''
    if (this.customMasking && Array.isArray(this.customMasking) && this.customMasking.length > 0) {
      customMaskJson = this.customMasking.join('|')
      customMaskJson = '|' + customMaskJson
      customMaskXml = this.customMasking.join('"?|')
      customMaskXml = '|' + customMaskXml + '"?'
    }
    this.reJson = new RegExp(
      `("(password|access_token|client_secret|assertion|client_assertion|${customMaskJson})"\\s*:\\s*)"([^"]+)"`,
      'gi',
    )
    this.reXml = new RegExp(
      `(<(?:\\w+:)?(credentials"?|PasswordText"?|PasswordDigest"?|password"?|${customMaskXml})[^>]*>)([^<]+)(<\\/(:?\\w+:)?\\2>)`,
      'gi',
    )

    this.logChannel = diagnostics_channel.channel(this.category)

    if (this.file && LEVEL_TO_INT[this.file.level] > 0) {
      if (!existsSync(this.LOG_DIR)) mkdirSync(this.LOG_DIR, { recursive: true })
      else if (existsSync(this.LOG_FILE)) this.rotateExistingLog()
      if (typeof Bun !== 'undefined') { // Bun
        this.logStream = Bun.file(this.LOG_FILE).writer({ highWaterMark: this.HIGH_WATER_MARK })
      } else { // Node.js
        this.logStream = createWriteStream(this.LOG_FILE, { flags: 'a' })
      }
      this.subscribe(this.logToFile)
    }
    if (this.console && LEVEL_TO_INT[this.console.level] > 0) {
      this.subscribe(this.logToConsole)
    }
  }

  private maskSecret(msg: string): string {
    if (!msg) return msg
    // Mask JSON secrets
    msg = msg.replace(
      this.reJson,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      (_, keyValuePair, key) => `${keyValuePair}"********"`,
    )
    // Mask XML/Soap secrets
    // console.log('XML matches found:', msg.match(this.reXml)
    msg = msg.replace(
      this.reXml,
      (_, startTag, tagName, value, endTag) => `${startTag}********${endTag}`,
    )

    return msg
  }

  private async rotateExistingLog() {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
    const archivedFile = `${this.LOG_DIR}/${this.LOG_FILE_PREFIX}-${timestamp}.${this.LOG_FILE_SUFFIX}`
    renameSync(this.LOG_FILE, archivedFile)
    this.cleanupOldLogs()
  }

  private async rotateLogs(isFlushRotate = false) {
    if (!isFlushRotate && (this.rotating || !this.file)) return
    this.rotating = true
    try {
      if (this.logStream) {
        await this.logStream.end()
      }
      await this.rotateExistingLog()
      if (typeof Bun !== 'undefined') {
        this.logStream = Bun.file(this.LOG_FILE).writer({ highWaterMark: this.HIGH_WATER_MARK })
      } else {
        this.logStream = createWriteStream(this.LOG_FILE, { flags: 'a' })
      }
      this.flushBuffer()
    } catch (error) {
      console.error('Log rotation failed:', error)
    } finally {
      this.rotating = false
    }
  }

  private cleanupOldLogs() {
    if (!this.file) return
    const logFiles = readdirSync(this.LOG_DIR)
      .filter(file => file.startsWith(`${this.LOG_FILE_PREFIX}-`) && file.endsWith(`.${this.LOG_FILE_SUFFIX}`))
      .sort((a, b) => b.localeCompare(a))

    if (logFiles.length > this.file.maxFiles) {
      logFiles.slice(this.file.maxFiles).forEach(file => unlinkSync(join(this.LOG_DIR, file)))
    }
  }

  private flushBuffer() {
    let sizeWritten = 0
    while (this.buffer.length > 0) {
      const str = this.buffer.shift()
      if (this.file && str) {
        this.logStream.write(str)
        sizeWritten += Buffer.byteLength(str, 'utf-8')
        if (sizeWritten >= this.file.maxSize) break
      }
    }
    if (this.file) {
      if (sizeWritten >= this.file.maxSize) {
        this.rotateLogs(true)
      }
      this.file.logSize = sizeWritten
    }
  }

  private logToFile = async (msgObj: Record<string, any>): Promise<boolean> => {
    if (!this.file || !this.file.level || LEVEL_TO_INT[msgObj.level] < LEVEL_TO_INT[this.file.level] || LEVEL_TO_INT[this.file.level] === 0) return false
    let logData = JSON.stringify(msgObj) + '\n'
    if (this.rotating) {
      this.buffer.push(logData)
      return false
    }
    this.logStream.write(logData)
    this.file.logSize += Buffer.byteLength(logData, 'utf-8')
    // Rotate if max size reached
    if (this.file.logSize >= this.file.maxSize) {
      this.rotateLogs()
    }
    return true
  }

  private logToConsole = async (msgObj: Record<string, any>): Promise<boolean> => {
    if (!this.console || !this.console.level || LEVEL_TO_INT[msgObj.level] < LEVEL_TO_INT[this.console.level] || LEVEL_TO_INT[this.console.level] === 0) return false
    let logData = ''
    if (this.console.colorize) {
      const color = COLORS[msgObj.level] || COLORS.reset
      logData = `${msgObj.time} ${this.category} ${color}${msgObj.level}${COLORS.reset}: ${msgObj.message}\n`
    } else logData = JSON.stringify(msgObj) + '\n'
    if (LEVEL_TO_INT[msgObj.level] >= LEVEL_TO_INT['error']) {
      if (typeof Bun !== 'undefined') Bun.write(Bun.stderr, logData)
      else process.stderr.write(logData)
    } else {
      if (typeof Bun !== 'undefined') Bun.write(Bun.stdout, logData)
      else process.stdout.write(logData)
    }
    return true
  }

  /**
  * log message with log level
  * @param level log level
  * @param message the message that will be logged
  */
  private async log(level: 'debug' | 'info' | 'warn' | 'error', message: string) {
    const time = new Date().toISOString()
    message = this.maskSecret(message)
    const msgObj: Record<string, any> = {
      time,
      category: this.category,
      level,
      message,
    }
    this.logChannel.publish(msgObj)
  }

  public debug(message: string) {
    this.log('debug', message)
  }

  public info(message: string) {
    this.log('info', message)
  }

  public warn(message: string) {
    this.log('warn', message)
  }

  public error(message: string) {
    this.log('error', message)
  }

  /**
  * setLoglevelConsole set console log level
  * @param level log level
  */
  public levelToInt(level: string): number {
    return LEVEL_TO_INT[level] || LogLevel.Info
  }

  /**
  * levelToInt returns the integer value of level
  * @param level log level: "off", "debug",  "info", "warn" or "error"
  */
  public setLoglevelConsole(loglevel: string): void {
    if (this?.console?.level) this.console.level = loglevel
  }

  /**
  * setLoglevelFile set file log level
  * @param level log level: "off", "debug",  "info", "warn" or "error"
  */
  public setLoglevelFile(loglevel: string): void {
    if (this?.file?.level) this.file.level = loglevel
  }

  /**
  * close will close all subscribtions and the logger
  */
  public async close() {
    this.callbacks.forEach(callback => this.unsubscribe(callback))
    if (this.logStream) {
      await this.logStream.end()
    }
  }

  /**
   * subscribe sets a callback function to be called for subscribing to JSON log message
   * @param callback callback function
   */
  public subscribe(callback: any) {
    diagnostics_channel.subscribe(this.category, callback)
    this.callbacks.add(callback)
  }

  /**
   * unsubscribe from previous subscription callback
   * @param callback callback function
   */
  public unsubscribe(callback: any) {
    diagnostics_channel.unsubscribe(this.category, callback)
    this.callbacks.delete(callback)
  }
}
