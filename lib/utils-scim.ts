import { fileURLToPath } from 'url'
import dot from 'dot-object'
import fs from 'node:fs'
import path from 'node:path'
import * as utils from './utils.ts'

type SCIMBulkOperation = {
  method: string
  path: string
  bulkId?: string
  data?: any
}

let countries: { 'name': string, 'alpha-2': string, 'country-code': string }[]

// Multi-value attributes are customized from array to object based on type
// except: groups, members and roles
// e.g "emails":[{"value":"bjensen@example.com","type":"work"}] => {"emails": {"work": {"value":"bjensen@example.com","type":"work"}}}
// Cleared values are set as user attributes with blank value ""
// e.g {meta:{attributes:['name.givenName','title']}} => {"name": {"givenName": ""}), "title": ""}

/**
* convert SCIM 1.1 regarding "type converted Object" and blank deleted values, also used by convertedScim20()
*/
export function convertedScim(obj: any, multiValueTypes: string[]): any {
  let err: any = null
  const scimdata: any = utils.copyObj(obj)
  if (scimdata.schemas) delete scimdata.schemas
  const newMulti: Record<string, any> = {}
  if (!multiValueTypes) multiValueTypes = []

  for (const key in scimdata) {
    if (Array.isArray(scimdata[key]) && (scimdata[key].length > 0)) {
      if (key === 'groups' || key === 'members' || key === 'roles') {
        scimdata[key].forEach(function (element, index) {
          if (element.value) scimdata[key][index].value = decodeURIComponent(element.value)
        })
      } else if (multiValueTypes.includes(key)) { // "type converted object" // groups, roles, member and scim.excludeTypeConvert are not included
        const tmpAddr: any = []
        scimdata[key].forEach(function (element) {
          if (!element.type) element.type = 'undefined' // "none-type"
          if (element.operation && element.operation === 'delete') { // add as delete if same type not included as none delete
            const arr = scimdata[key].filter((obj: Record<string, any>) => obj.type && obj.type === element.type && !obj.operation)
            if (arr.length < 1) {
              if (!newMulti[key]) newMulti[key] = {}
              if (newMulti[key][element.type]) {
                if (['addresses'].includes(key)) { // not checking type, but the others have to be unique
                  for (const i in element) {
                    if (i !== 'type') {
                      if (tmpAddr.includes(i)) {
                        err = new Error(`'type converted object' ${key} - includes more than one element having same ${i}, or ${i} is blank on more than one element - note, setting configuration scim.skipTypeConvert=true will disable this logic/check`)
                      }
                      tmpAddr.push(i)
                    }
                  }
                } else {
                  err = new Error(`'type converted object' ${key} - includes more than one element having same type, or type is blank on more than one element - note, setting configuration scim.skipTypeConvert=true will disable this logic/check`)
                }
              }
              newMulti[key][element.type] = {}
              for (const i in element) {
                newMulti[key][element.type][i] = element[i]
              }
              newMulti[key][element.type].value = '' // delete
            }
          } else {
            if (!newMulti[key]) newMulti[key] = {}
            if (newMulti[key][element.type]) {
              if (['addresses'].includes(key)) { // not checking type, but the others have to be unique
                for (const i in element) {
                  if (i !== 'type') {
                    if (tmpAddr.includes(i)) {
                      err = new Error(`'type converted object' ${key} - includes more than one element having same ${i}, or ${i} is blank on more than one element - note, setting configuration scim.skipTypeConvert=true will disable this logic/check`)
                    }
                    tmpAddr.push(i)
                  }
                }
              } else {
                err = new Error(`'type converted object' ${key} - includes more than one element having same type, or type is blank on more than one element - note, setting configuration scim.skipTypeConvert=true will disable this logic/check`)
              }
            }
            newMulti[key][element.type] = {}
            for (const i in element) {
              newMulti[key][element.type][i] = element[i]
            }
          }
        })
        delete scimdata[key]
      }
    }
  }
  if (scimdata.active && typeof scimdata.active === 'string') {
    const lcase = scimdata.active.toLowerCase()
    if (lcase === 'true') scimdata.active = true
    else if (lcase === 'false') scimdata.active = false
  }
  if (scimdata.meta) { // cleared attributes e.g { meta: { attributes: [ 'name.givenName', 'title' ] } }
    if (Array.isArray(scimdata.meta.attributes)) {
      scimdata.meta.attributes.forEach((el: string) => {
        let rootKey = ''
        let subKey = ''
        if (el.startsWith('urn:')) { // can't use dot.str on key having dot e.g. urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department
          const i = el.lastIndexOf(':')
          subKey = el.substring(i + 1)
          if (subKey === 'User' || subKey === 'Group') rootKey = el
          else rootKey = el.substring(0, i)
        }
        if (rootKey) {
          if (!scimdata[rootKey]) scimdata[rootKey] = {}
          dot.str(subKey, '', scimdata[rootKey])
        } else {
          dot.str(el, '', scimdata)
        }
      })
    }
    delete scimdata.meta
  }
  for (const key in newMulti) {
    dot.copy(key, key, newMulti, scimdata)
  }
  return [scimdata, err]
}

/**
* convertedScim20 convert SCIM 2.0 patch request to SCIM 1.1 and calls convertedScim() for "type converted Object" and blank deleted values
*
* Scim 2.0:  
* {"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"name.givenName","value":"Rocky"},{"op":"Remove","path":"name.formatted","value":"Rocky Balboa"},{"op":"Add","path":"emails","value":[{"value":"user@compay.com","type":"work"}]}]}
*
* Scim 1.1  
* {"name":{"givenName":"Rocky","formatted":"Rocky Balboa"},"meta":{"attributes":["name.formatted"]},"emails":[{"value":"user@compay.com","type":"work"}]}
*
* "type converted object" and blank deleted values  
* {"name":{"givenName":"Rocky",formatted:""},"emails":{"work":{"value":"user@company.com","type":"work"}}}
*/
export function convertedScim20(obj: any, multiValueTypes: string[]): any {
  let scimdata: { [key: string]: any } = {}
  if (!obj.Operations || !Array.isArray(obj.Operations)) return scimdata
  const o: any = utils.copyObj(obj)
  const arrPrimaryDone: any = []
  const primaryOrgType: any = {}

  for (let i = 0; i < o.Operations.length; i++) {
    const element = o.Operations[i]
    let type: any = null
    let typeElement: any = null
    let path: any = null
    let pathRoot: any = null
    let rePattern: any = /^.*\[(.*) eq (.*)\].*$/
    let arrMatches: any = null
    let primaryValue: any = null

    if (element.op) element.op = element.op.toLowerCase()

    if (element.path) {
      arrMatches = element.path.match(rePattern)

      if (Array.isArray(arrMatches) && arrMatches.length === 3) { // [type eq "work"]
        if (arrMatches[1] === 'primary') {
          type = 'primary'
          primaryValue = arrMatches[2].replace(/"/g, '') // True
        } else type = arrMatches[2].replace(/"/g, '') // work
      }

      rePattern = /^(.*)\[(type|primary) eq .*\]\.(.*)$/ // "path":"addresses[type eq \"work\"].streetAddress" - "path":"roles[primary eq \"True\"].streetAddress"
      arrMatches = element.path.match(rePattern)
      if (Array.isArray(arrMatches)) {
        if (arrMatches.length === 2) {
          if (type) path = `${arrMatches[1]}.${type}`
          else path = arrMatches[1]
          pathRoot = arrMatches[1]
        } else if (arrMatches.length === 4) {
          if (type) {
            path = `${arrMatches[1]}.${type}.${arrMatches[3]}`
            typeElement = arrMatches[3] // streetAddress

            if (type === 'primary' && !arrPrimaryDone.includes(arrMatches[1])) { // make sure primary is included
              const pObj: any = utils.copyObj(element)
              pObj.path = pObj.path.substring(0, pObj.path.lastIndexOf('.')) + '.primary'
              pObj.value = primaryValue
              o.Operations.push(pObj)
              arrPrimaryDone.push(arrMatches[1])
              primaryOrgType[arrMatches[1]] = 'primary'
            }
          } else path = `${arrMatches[1]}.${arrMatches[3]}` // NA
          pathRoot = arrMatches[1]
        }
      } else {
        rePattern = /^(.*)\[type eq .*\]$/ // "path":"addresses[type eq \"work\"]"
        arrMatches = element.path.match(rePattern)
        if (Array.isArray(arrMatches) && arrMatches.length === 2) {
          if (type) path = `${arrMatches[1]}.${type}`
          else path = arrMatches[1]
          pathRoot = arrMatches[1]
        }
      }

      rePattern = /^(.*)\[value eq (.*)\]$/ // "path":"members[value eq \"bjensen\"]"
      arrMatches = element.path.match(rePattern)
      if (Array.isArray(arrMatches) && arrMatches.length === 3) {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        path = arrMatches[1]
        pathRoot = arrMatches[1]
        const val = arrMatches[2].replace(/"/g, '') // "bjensen" => bjensen
        element.value = val
        typeElement = 'value'
      }

      if (element.value && Array.isArray(element.value)) {
        element.value.forEach(function (el: any, i: any) { // {"value": [{ "value": "jsmith" }]}
          if (el.value) {
            if (typeof el.value === 'object') { // "value": [{"value": {"id":"c20e145e-5459-4a6c-a074-b942bbd4cfe1","value":"admin","displayName":"Administrator"}}]
              element.value[i] = el.value
            } else if (typeof el.value === 'string' && el.value.substring(0, 1) === '{') { // "value": [{"value":"{\"id\":\"c20e145e-5459-4a6c-a074-b942bbd4cfe1\",\"value\":\"admin\",\"displayName\":\"Administrator\"}"}}]
              try {
                element.value[i] = JSON.parse(el.value)
              } catch (err) { void 0 }
            }
          }
        })
      }

      if (element.value && element.value.value && typeof element.value.value === 'string') { // "value": { "value": "new_email@testing.org" }
        const el: { [key: string]: any } = {}
        el.value = element.value.value
        if (element.op && element.op === 'remove') el.operation = 'delete'
        element.value = []
        element.value.push(el)
      }

      if (pathRoot) { // pathRoot = emails and path = emails.work.value (we may also have path = pathRoot)
        if (!scimdata[pathRoot]) scimdata[pathRoot] = []
        const index = scimdata[pathRoot].findIndex((el: Record<string, any>) => el.type === type)
        if (index < 0) {
          if (typeof element.value === 'object') { // e.g. addresses with no typeElement - value includes object having all attributes
            if (element.op && element.op === 'remove') element.value.operation = 'delete'
            scimdata[pathRoot].push(element.value)
          } else {
            const el: { [key: string]: any } = {}
            if (element.op && element.op === 'remove') el.operation = 'delete'
            if (type) el.type = type // members no type
            if (element.value) el[typeElement] = element.value // {"value": "some-value"} or {"steetAddress": "some-address"}
            scimdata[pathRoot].push(el)
          }
        } else {
          if (typeElement === 'value' && scimdata[pathRoot][index].value) { // type exist for value index => duplicate type => push new - duplicates handled by last step confertedScim() if needed
            const el: { [key: string]: any } = {}
            if (element.op && element.op === 'remove') el.operation = 'delete'
            if (type) el.type = type
            el[typeElement] = element.value
            scimdata[pathRoot].push(el)
          } else {
            if (type === 'primary' && typeElement === 'type') { // type=primary, don't change but store and correct to original type later
              primaryOrgType[pathRoot] = element.value
            } else scimdata[pathRoot][index][typeElement] = element.value
            if (element.op && element.op === 'remove') scimdata[pathRoot][index].operation = 'delete'
          }
        }
      } else { // use element.path e.g name.familyName and members
        if (Array.isArray(element.value)) {
          if (element.op === 'replace' && element.value.length === 0) { // members:[]
            scimdata[element.path] = []
          }
          for (let i = 0; i < element.value.length; i++) {
            if (!scimdata[element.path]) scimdata[element.path] = []
            if (element.op && element.op === 'remove') {
              if (typeof element.value[i] === 'object') element.value[i].operation = 'delete'
            }
            scimdata[element.path].push(element.value[i])
          }
        } else { // add to operations loop without path => handled by "no path"
          const obj: { [key: string]: any } = {}
          obj.op = element.op
          obj.value = {}
          obj.value[element.path] = element.value
          o.Operations.push(obj)
        }
      }
    } else { // no path
      for (const key in element.value) {
        if (Array.isArray(element.value[key])) {
          if (element.op === 'replace' && element.value[key].length === 0) { // members:[]
            scimdata[key] = []
          }
          element.value[key].forEach(function (el) {
            if (element.op && element.op === 'remove') el.operation = 'delete'
            if (!scimdata[key]) scimdata[key] = []
            scimdata[key].push(el)
          })
        } else {
          let value = element.value[key]
          if (element.op && element.op === 'remove') {
            if (!scimdata.meta) scimdata.meta = {}
            if (!scimdata.meta.attributes) scimdata.meta.attributes = []
            scimdata.meta.attributes.push(key)
          }
          if (key.startsWith('urn:')) { // can't use dot.str on key having dot e.g. urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department
            const i = key.lastIndexOf(':')
            let k = key.substring(i + 1) // User, Group or <parentAttribute>.<childAttribute> - <URN>:<parentAttribute>.<childAttribute> e.g. :User:manager.value
            let rootKey
            if (k === 'User' || k === 'Group') rootKey = key
            else rootKey = key.substring(0, i) // urn:ietf:params:scim:schemas:extension:enterprise:2.0:User
            if (k === 'User' || k === 'Group') { // value is object
              const o: Record<string, any> = {}
              o[rootKey] = value
              scimdata = utils.extendObj(scimdata, o)
            } else {
              if (!scimdata[rootKey]) scimdata[rootKey] = {}
              if (k === 'manager' && typeof value !== 'object') { // fix Azure bug sending manager instead of manager.value
                k = 'manager.value'
              }
              if (!element.op || element.op !== 'remove') { // remove handled by general logic above
                dot.str(k, value, scimdata[rootKey])
              }
            }
          } else {
            if (typeof value === 'object') {
              for (const k in element.value[key]) {
                if (element.op && element.op === 'remove') {
                  if (!scimdata.meta) scimdata.meta = {}
                  if (!scimdata.meta.attributes) scimdata.meta.attributes = []
                  scimdata.meta.attributes.push(`${key}.${k}`)
                } else {
                  value = element.value[key][k]
                  dot.str(`${key}.${k}`, value, scimdata)
                }
              }
            } else dot.str(key, value, scimdata)
          }
        }
      }
    }
  }

  for (const key in primaryOrgType) { // revert back to original type when included
    if (scimdata[key]) {
      const index = scimdata[key].findIndex((el: Record<string, any>) => el.type === 'primary')
      if (index >= 0) {
        if (primaryOrgType[key] === 'primary') delete scimdata[key][index].type // temp have not been changed - remove
        else scimdata[key][index].type = primaryOrgType[key]
      }
    }
  }

  // scimdata now SCIM 1.1 formatted, using convertedScim to get "type converted Object" and blank deleted values
  return convertedScim(scimdata, multiValueTypes)
}

// recursiveStrMap is used by endpointMapper() for converting obj according to endpointMap type definition
const recursiveStrMap = function (direction: string, dotMap: any, obj: any, dotPath: any) {
  for (const key in obj) {
    if (obj[key] && obj[key].constructor === Object) recursiveStrMap(direction, dotMap, obj[key], (dotPath ? `${dotPath}.${key}` : key))
    let dotKey = ''
    if (!dotPath) dotKey = key
    else dotKey = `${dotPath}.${key}`
    if (direction === 'outbound') { // outbound
      if (dotMap[`${dotKey}.type`]) {
        const type = dotMap[`${dotKey}.type`].toLowerCase()
        if (type === 'boolean' && obj[key].constructor === String) {
          if ((obj[key]).toLowerCase() === 'true') obj[key] = true
          else if ((obj[key]).toLowerCase() === 'false') obj[key] = false
        } else if (type === 'array') {
          if (!Array.isArray(obj[key])) {
            if (!obj[key]) obj[key] = []
            else obj[key] = obj[key].split(',').map((item: string) => item.trim())
          }
        } else if (dotMap.sAMAccountName) { // Active Directory
          if (dotMap[`${dotKey}.mapTo`].startsWith('addresses.') && dotMap[`${dotKey}.mapTo`].endsWith('.country')) {
            if (!countries) {
              countries = (() => {
                try {
                  const currFilePath = path.dirname(fileURLToPath(import.meta.url))
                  return JSON.parse(fs.readFileSync(path.join(currFilePath, 'countries.json')).toString())
                } catch (err) {
                  return []
                }
              })()
            }
            const arr = countries.filter(el => obj[key] && el.name === obj[key].toUpperCase())
            if (arr.length === 1) { // country name found in countries, include corresponding c (shortname) and countryCode
              obj.c = arr[0]['alpha-2']
              obj.countryCode = arr[0]['country-code']
            }
          }
        }
      }
    } else { // inbound - convert all values to string unless array or boolean
      if (obj[key] === null) delete obj[key] // or set to ''
      else if (obj[key] || obj[key] === false) {
        if (key === 'id') {
          obj[key] = encodeURIComponent(obj[key]) // escaping in case idp don't e.g. Symantec/Broadcom/CA
        }
        if (Array.isArray(obj[key])) { // array
          if (key === 'members' || key === 'groups') {
            for (const el in obj[key]) {
              if (obj[key][el].value) {
                obj[key][el].value = encodeURIComponent(obj[key][el].value) // escaping values because id have also been escaped
              }
            }
          }
        } else if (obj[key].constructor !== Object) {
          if (obj[key].constructor !== Boolean) obj[key] = obj[key].toString() // might have integer that also should be SCIM integer?
        }
      }
    }
  }
}

/**
* SCIM/CustomScim <=> endpoint attribute parsing used by plugins  
* TODO: rewrite and simplify...
* @returns [object/string, err]
*/
export function endpointMapper(direction: string, parseObj: any, mapObj: any) {
  if (direction !== 'inbound' && direction !== 'outbound') {
    const msg = 'Plugin using endpointMapper(direction, parseObj, mapObj) with incorrect direction - direction must be set to \'outbound\' or \'inbound\''
    return [parseObj, new Error(msg)]
  }

  const dotMap = dot.dot(mapObj)
  let str: any
  let isObj = false
  let noneCore = false
  const arrUnsupported: any = []
  const inboundArrCheck: any = []
  const complexArr: any = []
  const complexObj: Record<string, any> = {
    addresses: {},
    emails: {},
    phoneNumbers: {},
    entitlements: {},
    ims: {},
    photos: {},
    // roles: {} using array
  }
  let dotParse: any = null
  const dotNewObj: any = {}

  if (parseObj.constructor === String || parseObj.constructor === Array) str = parseObj // parseObj is attributes list e.g. 'userName,id' or ['userName', 'id']
  else {
    isObj = true
    if (parseObj['@odata.context']) delete parseObj['@odata.context'] // AAD cleanup
    if (parseObj.controls) delete parseObj.controls // Active Directory cleanup
    dotParse = dot.dot(parseObj) // {"name": {"givenName": "myName"}} => {"name.givenName": "myName"}

    // deletion of complex entry => set to blank
    const arrDelete: any = []
    for (const key in dotParse) {
      if (key.endsWith('.operation')) {
        const arr: string[] = key.split('.') // addresses.work.operation
        if (arr.length > 2 && complexObj[arr[0]] && dotParse[key] === 'delete') {
          arrDelete.push(`${arr[0]}.${arr[1]}.`) // addresses.work.
          delete dotParse[key]
        }
      }
    }
    for (let i = 0; i < arrDelete.length; i++) {
      for (const key in dotParse) {
        if (key.startsWith(arrDelete[i])) dotParse[key] = '' // Active Directory: if country included, no logic on country codes cleanup - c (shortname) and countryCode
      }
    }
  }

  switch (direction) {
    case 'outbound':
      if (isObj) { // body (patch/put)
        for (let key in dotParse) {
          let found = false
          let arrIndex = 0
          const arr = key.split('.') // multivalue/array - servicePlan.0.value
          const keyOrg = key
          if (arr.length > 1 && arr[arr.length - 1] === 'value') {
            const secondLast = arr.length - 2
            if (!isNaN(parseInt(arr[secondLast]))) { // servicePlan.0.value => servicePlan.0
              for (let i = 0; i < (secondLast); i++) {
                if (i === 0) key = arr[i]
                else key += `.${arr[i]}`
              }
              arrIndex = parseInt(arr[secondLast])
            } else if (arr[secondLast].slice(-1) === ']') { // groups[0].value => groups.value
              const prefix = arr.slice(0, -1).join('.')
              const startPos = prefix.indexOf('[')
              if (startPos > 0) {
                key = prefix.substring(0, startPos) + '.value' // groups.value
                arrIndex = parseInt(prefix.substring(startPos + 1, prefix.length - 1)) // 1
              }
            }
          }
          for (const key2 in dotMap) {
            if (!key2.endsWith('.mapTo')) continue
            if (dotMap[key2].split(',').map((item: string) => item.trim().toLowerCase()).includes(key.toLowerCase())) {
              found = true
              const keyRoot = key2.split('.').slice(0, -1).join('.') // xx.yy.mapTo => xx.yy
              if (dotMap[`${keyRoot}.type`] === 'array' && arrIndex >= 0) {
                dotNewObj[`${keyRoot}.${arrIndex}`] = dotParse[keyOrg] // servicePlan.0.value => servicePlan.0 and groups[0].value => memberOf.0
              }
              dotNewObj[keyRoot] = dotParse[key] // {"accountEnabled": {"mapTo": "active"} => str.replace("accountEnabled", "active")
              break
            }
          }
          if (!found) arrUnsupported.push(key)
        }
      } else { // string (get)
        const resArr: any = []
        let strArr: any = []
        if (Array.isArray(str)) {
          for (let i = 0; i < str.length; i++) {
            strArr = strArr.concat(str[i].split(',').map((item: string) => item.trim())) // supports "id,userName" e.g. {"mapTo": "id,userName"}
          }
        } else strArr = str.split(',').map((item: string) => item.trim())
        for (let i = 0; i < strArr.length; i++) {
          const attr = strArr[i]
          let found = false
          for (const key in dotMap) {
            if (!key.endsWith('.mapTo')) continue
            const keyNotDot: string = key.substring(0, key.indexOf('.mapTo'))
            if (dotMap[key].split(',').map((item: string) => item.trim()).includes(attr)) { // supports { "mapTo": "userName,id" }
              found = true
              if (!resArr.includes(keyNotDot)) resArr.push(keyNotDot)
              break
            } else if (attr === 'roles' && dotMap[key] === 'roles.value') { // allow get using attribute roles - convert to correct roles.value
              found = true
              resArr.push(keyNotDot)
              break
            } else {
              if (dotMap[key].startsWith(attr + '.')) { // e.g. emails - complex definition
                if (complexObj[attr]) {
                  found = true
                  resArr.push(keyNotDot)
                  // don't break - check for multiple complex definitions
                }
              }
            }
          }
          if (!found) {
            arrUnsupported.push(attr) // comment out? - let caller decide if not to handle unsupported on GET requests (string)
          }
        }
        if (Array.isArray(str)) str = resArr
        else str = resArr.toString()
      }
      break

    case 'inbound':
      for (let key in dotParse) {
        if (Array.isArray(dotParse[key]) && dotParse[key].length < 1) continue // avoid including 'value' in empty array if mapTo xx.value
        if (key.startsWith('lastLogon') && !isNaN(dotParse[key])) { // Active Directory date convert e.g. 132340394347050132 => "2020-05-15 20:03:54"
          const ll = new Date(parseInt(dotParse[key], 10) / 10000 - 11644473600000)
          dotParse[key] = ll.getFullYear() + '-'
          + ('00' + (ll.getMonth() + 1)).slice(-2) + '-' // eslint-disable-line
          + ('00' + ll.getDate()).slice(-2) + ' '
          + ('00' + (ll.getHours())).slice(-2) + ':'
          + ('00' + ll.getMinutes()).slice(-2) + ':'
          + ('00' + ll.getSeconds()).slice(-2)
        }

        // first element array gives xxx[0] instead of xxx.0
        let keyArr: any = key.split('.')
        if (keyArr[0].slice(-1) === ']') { // last character=]
          let newStr = keyArr[0]
          newStr = newStr.replace('[', '.')
          newStr = newStr.replace(']', '') // member[0] => member.0
          dotParse[newStr] = dotParse[key]
          key = newStr // will be handled below
        }

        let dotArrIndex = null
        keyArr = key.split('.')
        if (keyArr.length > 1 && !isNaN(keyArr[1])) { // array
          key = keyArr[0] // "proxyAddresses.0" => "proxyAddresses"
          dotArrIndex = keyArr[1]
        }

        let mapTo = dotMap[`${key}.mapTo`]
        if (!mapTo) continue
        if (mapTo.startsWith('urn:')) { // dot workaround for none core (e.g. enterprise and custom schema attributes) having dot in key e.g "2.0": urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.department
          mapTo = mapTo.replace('.', '##') // only first occurence
          noneCore = true
        }

        if (dotMap[`${key}.type`] === 'array') {
          let newStr = mapTo
          if (newStr === 'roles') { // {"mapTo": "roles"} should be {"mapTo": "roles.value"}
            arrUnsupported.push('roles.value')
          }
          let multiValue = true
          if (newStr.indexOf('.value') > 0) newStr = newStr.substring(0, newStr.indexOf('.value')) // multivalue back to ScimGateway - remove .value if defined
          else multiValue = false
          if (dotArrIndex !== null) { // array e.g proxyAddresses.value mapTo proxyAddresses converts proxyAddresses.0 => proxyAddresses.0.value
            if (multiValue) dotNewObj[`${newStr}.${dotArrIndex}.value`] = dotParse[`${key}.${dotArrIndex}`]
            else {
              if (dotMap[`${key}.typeInbound`] && dotMap[`${key}.typeInbound`] === 'string') {
                if (!dotNewObj[newStr]) dotNewObj[newStr] = dotParse[`${key}.${dotArrIndex}`]
                else dotNewObj[newStr] = `${dotParse[`${key}.${dotArrIndex}`]},${dotNewObj[newStr]}`
              } else dotNewObj[`${newStr}.${dotArrIndex}`] = dotParse[`${key}.${dotArrIndex}`]
            }
          } else { // type=array but element is not array
            if (multiValue) dotNewObj[`${newStr}.0.value`] = dotParse[key]
            else dotNewObj[newStr] = dotParse[key]
            if (!dotMap[`${key}.typeInbound`] || dotMap[`${key}.typeInbound`] !== 'string') {
              if (!inboundArrCheck.includes(newStr)) inboundArrCheck.push(newStr) // will be checked
            }
          }
        } else { // none array
          const arrMapTo = mapTo.split(',').map((item: string) => item.trim()) // supports {"mapTo": "id,userName"}
          for (let i = 0; i < arrMapTo.length; i++) {
            dotNewObj[arrMapTo[i]] = dotParse[key] // {"active": {"mapTo": "accountEnabled"} => str.replace("accountEnabled", "active")
          }
        }
        const arr = mapTo.split('.') // addresses.work.postalCode
        if (arr.length > 2 && complexObj[arr[0]]) complexArr.push(arr[0]) // addresses
      }
      break

    default:
      str = parseObj
  }

  // error handling (only outbound, not inbound)
  let err: any = null
  const arrErr: string[] = []
  for (let i = 0; i < arrUnsupported.length; i++) {
    const arr = arrUnsupported[i].split('.')
    if (arr.length > 2 && complexObj[arr[0]]) continue // no error on complex
    else if (arr.length === 2 && arr[0].startsWith('roles')) {
      if (arr[1] === 'operation') err = new Error('endpointMapper: roles cannot include operation - telling to be deleted - roles needs proper preprocessing when used by endpointMapper')
      else if (arr[1] !== 'value') continue // no error on roles.display, roles.primary
    }
    arrErr.push(arrUnsupported[i])
  }
  if (!err && arrErr.length > 0) {
    err = new Error(`endpointMapper: skipping - no mapping found for attributes: ${arrErr.toString()}`)
  }

  if (isObj) {
    let newObj = dot.object(dotNewObj) as Record<string, any>// from dot to normal
    if (noneCore) { // revert back dot workaround
      const tmpObj: Record<string, any> = {}
      for (const key in newObj) {
        if (key.startsWith('urn:') && key.includes('##')) {
          const newKey = key.replace('##', '.')
          tmpObj[newKey] = newObj[key]
        } else tmpObj[key] = newObj[key]
      }
      newObj = tmpObj
    }

    if (arrUnsupported.length > 0) { // delete from newObj when not included in map
      for (const i in arrUnsupported) {
        const arr = arrUnsupported[i].split('.') // emails.work.type
        dot.delete(arrUnsupported[i], newObj) // delete leaf
        for (let i = arr.length - 2; i > -1; i--) { // delete above if not empty
          let oStr = arr[0]
          for (let j = 1; j <= i; j++) {
            oStr += `.${arr[j]}`
          }
          const sub = dot.pick(oStr, newObj)
          if (!sub || JSON.stringify(sub) === '{}') {
            dot.delete(oStr, newObj)
          }
        }
      }
    }

    recursiveStrMap(direction, dotMap, newObj, null) // converts according to type defined

    if (direction === 'inbound' && newObj.constructor === Object) { // convert any multivalue object syntax to array
      //
      // map config e.g.:
      // "postalCode": {
      //  "mapTo": "addresses.work.postalCode",
      //  "type": "string"
      // }
      //
      if (complexArr.length > 0) {
        const tmpObj: Record<string, any> = {}
        for (let i = 0; i < complexArr.length; i++) { // e.g. ['emails', 'addresses', 'phoneNumbers', 'ims', 'photos']
          const el = complexArr[i]
          if (newObj[el]) { // { work: { postalCode: '1733' }, work: { streetAddress: 'Roteveien 10' } }
            const tmp: Record<string, any> = {}
            for (const key in newObj[el]) {
              if (newObj[el][key].constructor === Object) { // { postalCode: '1733' }
                if (!tmp[key]) tmp[key] = [{ type: key }]
                const o = tmp[key][0]
                for (const k in newObj[el][key]) { // merge into one object
                  o[k] = newObj[el][key][k]
                }
                tmp[key][0] = o // { addresses: [ { type: 'work', postalCode: '1733', streetAddress: 'Roteveien 10'} ] } - !isNaN because of push
              }
            }
            delete newObj[el]
            tmpObj[el] = []
            for (const key in tmp) {
              tmpObj[el].push(tmp[key][0])
            }
          }
        }
        utils.extendObj(newObj, tmpObj)
      }

      // make sure inboundArrCheck elements are array
      // e.g. AD group "member" could be string if one, and array if more than one
      for (const i in inboundArrCheck) {
        const el = inboundArrCheck[i]
        if (newObj[el] && !Array.isArray(newObj[el])) {
          newObj[el] = [newObj[el]]
        }
      }
    }

    return [newObj, err]
  } else return [str, err]
}

/**
* returns an array of mulitvalue attributes allowing type e.g [emails,addresses,...]  
* objName should be 'User' or 'Group'
*/
export function getMultivalueTypes(objName: string, scimDef: Record<string, any>) { // objName = 'User' or 'Group'
  if (!objName) return []

  const obj = scimDef.Schemas.Resources.find((el: Record<string, any>) => {
    return (el.name === objName)
  })
  if (!obj) return []

  return obj.attributes
    .filter((el: Record<string, any>) => {
      return (el.multiValued === true && el.subAttributes
        && el.subAttributes
          .find(function (subel: Record<string, any>) {
            return (subel.name === 'type')
          })
      )
    })
    .map((obj: Record<string, any>) => obj.name)
}

export function addResources(data: any, startIndex?: string, sortBy?: string, sortOrder?: string) {
  if (!data || JSON.stringify(data) === '{}') data = [] // no user/group found
  const res: { [key: string]: any } = { Resources: [] }
  if (Array.isArray(data)) res.Resources = data
  else if (data.Resources) {
    res.Resources = data.Resources
    res.totalResults = data.totalResults
  } else res.Resources.push(data)

  // pagination
  if (!res.totalResults) res.totalResults = res.Resources.length // Specifies the total number of results matching the Consumer query
  res.itemsPerPage = res.Resources.length // Specifies the number of search results returned in a query response page
  if (startIndex) res.startIndex = parseInt(startIndex) // The 1-based index of the first result in the current set of search results
  else res.startIndex = 1
  if (res.startIndex > res.totalResults) { // invalid paging request
    res.Resources = []
    res.itemsPerPage = 0
  }

  if (sortBy) res.Resources.sort(utils.sortByKey(sortBy, sortOrder))
  return res
}

export function addSchemas(data: Record<string, any>, isScimv2: boolean, type?: string, location?: string) {
  if (!type) {
    if (isScimv2) data.schemas = ['urn:ietf:params:scim:api:messages:2.0:ListResponse']
    else data.schemas = ['urn:scim:schemas:core:1.0']
    return data
  }

  if (data.Resources) {
    if (isScimv2) data.schemas = ['urn:ietf:params:scim:api:messages:2.0:ListResponse']
    else data.schemas = ['urn:scim:schemas:core:1.0']
    for (let i = 0; i < data.Resources.length; i++) {
      if (isScimv2) { // scim v2 add schemas/resourceType on each element
        if (type === 'User') {
          const val = 'urn:ietf:params:scim:schemas:core:2.0:User'
          if (!data.Resources[i].schemas) data.Resources[i].schemas = [val]
          else if (!data.Resources[i].schemas.includes(val)) data.Resources[i].schemas.push(val)
          if (!data.Resources[i].meta) data.Resources[i].meta = {}
          data.Resources[i].meta.resourceType = type
          if (location && data.Resources[i].id) data.Resources[i].meta.location = `${location}/${data.Resources[i].id}`
        } else if (type === 'Group') {
          const val = 'urn:ietf:params:scim:schemas:core:2.0:Group'
          if (!data.Resources[i].schemas) data.Resources[i].schemas = [val]
          else if (!data.Resources[i].schemas.includes(val)) data.Resources[i].schemas.push(val)
          if (!data.Resources[i].meta) data.Resources[i].meta = {}
          data.Resources[i].meta.resourceType = 'Group'
        }
      }
      if (location && data.Resources[i].id) {
        if (!data.Resources[i].meta) data.Resources[i].meta = {}
        data.Resources[i].meta.location = `${location}/${data.Resources[i].id}`
      }
      for (const key in data.Resources[i]) {
        if (key.startsWith('urn:')) {
          if (key.includes(':1.0')) {
            if (!data.schemas) data.schemas = []
            if (!data.schemas.includes(key)) data.schemas.push(key)
          } else { // scim v2 add none core schemas on each element
            if (!data.Resources[i].schemas) data.Resources[i].schemas = []
            if (!data.Resources[i].schemas.includes(key)) data.Resources[i].schemas.push(key)
          }
        } else if (key === 'password') delete data.Resources[i].password // exclude password, null and empty object/array
        else if (data.Resources[i][key] === null) delete data.Resources[i][key]
        else if (JSON.stringify(data.Resources[i][key]) === '{}') delete data.Resources[i][key]
        else if (Array.isArray(data.Resources[i][key])) {
          if (data.Resources[i][key].length < 1) delete data.Resources[i][key]
          else if (key !== 'members' && key !== 'groups') { // any primary attribute should be boolean
            for (let j = 0; j < data.Resources[i][key].length; j++) {
              let el = data.Resources[i][key][j]
              if (typeof el !== 'object') break
              if (el.type && el.primary && typeof el.primary === 'string') {
                if (el.primary.toLowerCase() === 'true') el.primary = true
                else if (el.primary.toLowerCase() === 'false') el.primary = false
              }
            }
          }
        }
      }
      if (Object.keys(data.Resources[i]).length === 0) {
        data.Resources.splice(i, 1) // delete
        i -= 1
      }
    }
  } else {
    if (isScimv2) {
      if (type === 'User') {
        const val = 'urn:ietf:params:scim:schemas:core:2.0:User'
        if (!data.schemas) data.schemas = [val]
        else if (!data.schemas.includes(val)) data.schemas.push(val)
        if (!data.meta) data.meta = {}
        data.meta.resourceType = type
      } else if (type === 'Group') {
        const val = 'urn:ietf:params:scim:schemas:core:2.0:Group'
        if (!data.schemas) data.schemas = [val]
        else if (!data.schemas.includes(val)) data.schemas.push(val)
        if (!data.meta) data.meta = {}
        data.meta.resourceType = type
      }
    } else {
      const val = 'urn:scim:schemas:core:1.0'
      if (!data.schemas) data.schemas = [val]
      else if (!data.schemas.includes(val)) data.schemas.push(val)
    }
    for (const key in data) {
      if (key.startsWith('urn:')) { // add none core schema e.g. urn:ietf:params:scim:schemas:extension:enterprise:2.0:User
        if (!data.schemas) data.schemas = [key]
        else if (!data.schemas.includes(key)) data.schemas.push(key)
      } else if (key === 'password') delete data.password // exclude password, null and empty object/array
      else if (data[key] === null) delete data[key]
      else if (JSON.stringify(data[key]) === '{}') delete data[key]
      else if (Array.isArray(data[key])) {
        if (data[key].length < 1) delete data[key]
        else if (key !== 'members' && key !== 'groups') { // any primary attribute should be boolean
          for (let j = 0; j < data[key].length; j++) {
            let el = data[key][j]
            if (typeof el !== 'object') break
            if (el.type && el.primary && typeof el.primary === 'string') {
              if (el.primary.toLowerCase() === 'true') el.primary = true
              else if (el.primary.toLowerCase() === 'false') el.primary = false
            }
          }
        }
      }
    }
  }

  return data
}

/**
* SCIM error formatting
*/
export function jsonErr(scimVersion: string | number, pluginName: string, htmlErrCode: number | undefined, err: Error): [Record<string, any>, number] {
  let errJson = {}
  let customErrCode: any = null
  let scimType = 'invalidSyntax'
  let msg = `scimgateway[${pluginName}] `
  if (err.constructor === Error) {
    if (err.name) { // customErrCode can be set by including suffix "#<number>" e.g., "<scimType>#404"
      const arr: any = err.name.split('#')
      if (arr.length > 1 && !isNaN(arr[arr.length - 1])) {
        customErrCode = arr[arr.length - 1]
        const code = parseInt(customErrCode)
        if (code < 300 && code > 199) customErrCode = null
        arr.splice(-1)
        err.name = arr.join('#') // back to original having customErrCode removed
      } else { // !customErrCode
        try {
          const startPos = err.message.indexOf('{')
          const endPos = err.message.lastIndexOf('}')
          if (startPos > -1 && endPos > startPos) {
            const m = JSON.parse((err.message.substring(startPos, endPos + 1)))
            if (!isNaN(m.statusCode)) {
              if (m.statusCode === 401 || m.statusCode === 403 || m.statusCode === 404 || m.statusCode === 409) { // retur these endpoint status "as-is" to client
                customErrCode = m.statusCode
              }
            }
          }
        } catch (err) { void 0 }
      }
      scimType = err.name
      if (scimType === 'Error') scimType = 'invalidSyntax' // default err.name used
      if (customErrCode === 409) scimType = 'uniqueness'
    }
    msg += err.message
  } else {
    msg += err
  }

  let errCode = customErrCode || htmlErrCode
  if (scimVersion !== '2.0' && scimVersion !== 2) { // v1.1
    errJson
      = {
        Errors: [
          {
            description: msg,
            code: errCode.toString(),
          },
        ],
      }
  } else { // v2.0
    errJson
      = {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        scimType,
        detail: msg,
        status: errCode.toString(),
      }
  }

  if (customErrCode) customErrCode = parseInt(customErrCode)
  return [errJson, customErrCode as number]
}

/**
* api plugin formatted error
*/
export function apiErr(pluginName: string, err: any) {
  let msg
  if (err.constructor !== Error) err = { message: err }
  try {
    msg = JSON.parse(err.message)
    msg.originator = `ScimGateway[${pluginName}]`
  } catch (e) { msg = `ScimGateway[${pluginName}] ${err.message}` }
  const errObj = {
    meta: {
      result: 'error',
      description: msg,
    },
  }
  return errObj
}

/**
* resolve bulkId values in data to actual objects
*/
export function bulkResolveIdReferences(data: any, map: Map<string, any>): any {
  if (Array.isArray(data)) {
    return data.map(item => bulkResolveIdReferences(item, map))
  } else if (typeof data === 'object' && data !== null) {
    const result: any = {}
    for (const key in data) {
      const value = data[key]
      if (typeof value === 'string' && value.startsWith('bulkId:')) {
        const refId = value.split(':')[1]
        if (!map.has(refId)) throw new Error(`unresolved bulkId: ${refId}`)
        result[key] = map.get(refId).id ?? map.get(refId) // assume object with `id`
      } else {
        result[key] = bulkResolveIdReferences(value, map)
      }
    }
    return result
  }
  return data
}

function bulkCollectIdDeps(obj: any, deps: Set<string>) {
  if (Array.isArray(obj)) {
    obj.forEach(item => bulkCollectIdDeps(item, deps))
  } else if (typeof obj === 'object' && obj !== null) {
    for (const value of Object.values(obj)) {
      if (typeof value === 'string' && value.startsWith('bulkId:')) {
        deps.add(value.split(':')[1])
      } else {
        bulkCollectIdDeps(value, deps)
      }
    }
  }
}

/**
* create a dependency graph (bulkId -> dependsOn[])
*/
export function bulkBuildDependencyGraph(ops: SCIMBulkOperation[]): Map<SCIMBulkOperation, Set<string>> {
  const graph = new Map<SCIMBulkOperation, Set<string>>()
  for (const op of ops) {
    const deps = new Set<string>()
    bulkCollectIdDeps(op.data, deps)
    graph.set(op, deps)
  }
  return graph
}

/**
* topological bulk sort (returns null on circular dependency)
*/
export function bulkTopologicalSort(graph: Map<SCIMBulkOperation, Set<string>>): SCIMBulkOperation[] | null {
  const result: SCIMBulkOperation[] = []
  const visited = new Set<SCIMBulkOperation>()
  const visiting = new Set<SCIMBulkOperation>()

  function visit(node: SCIMBulkOperation): boolean {
    if (visited.has(node)) return true
    if (visiting.has(node)) return false // cycle

    visiting.add(node)
    const deps = graph.get(node) || new Set()
    for (const depId of deps) {
      const depOp = [...graph.keys()].find(o => o.bulkId === depId)
      if (!depOp || !visit(depOp)) return false
    }
    visiting.delete(node)
    visited.add(node)
    result.push(node)
    return true
  }

  for (const node of graph.keys()) {
    if (!visit(node)) return null
  }

  return result
}
