// https://bun.sh/docs/test/writing

import { expect, test, describe } from 'bun:test'
import * as loki from '../../lib/plugin-loki'
// eslint-disable-next-line @typescript-eslint/no-unused-expressions
loki

const baseUrl = 'http://localhost:8880'
const auth = 'Basic ' + Buffer.from('gwadmin:password').toString('base64')
const options = {
  std: {
    headers: {
      Authorization: auth,
    },
  },
  content: {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': auth,
    },
  },
}

async function fetchSCIM(method: string, endpoint: string, body?: any, headers?: any) {
  const response = await fetch(`${baseUrl}${endpoint}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  })
  const data = response.status !== 204 ? await response.json() : null
  return { status: response.status, body: data, headers: response.headers }
}

describe('plugin-loki', async () => {
  test('ServiceProviderConfig test', async () => {
    const response: any = await fetchSCIM('GET', '/ServiceProviderConfig', undefined, options.std.headers)
    expect(response.status).toBe(200)
    expect(response.body.schemas).toContain('urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig')
  })

  test('Schemas test', async () => {
    const response: any = await fetchSCIM('GET', '/Schemas', undefined, options.std.headers)
    expect(response.status).toBe(200)
    expect(Array.isArray(response.body.Resources)).toBe(true)
    response.body.Resources.forEach((schema: any) => {
      expect(schema.id).toBeDefined()
      expect(schema.name).toBeDefined()
    })
  })

  test('ResourceTypes test', async () => {
    const response: any = await fetchSCIM('GET', '/ResourceTypes', undefined, options.std.headers)
    expect(response.status).toBe(200)
    expect(Array.isArray(response.body.Resources)).toBe(true)
    expect(response.body.Resources.length).toEqual(2)
    expect(response.body.Resources[0].schemas).toContain('urn:ietf:params:scim:schemas:core:2.0:ResourceType')
    expect(response.body.Resources[0].id).toBe('urn:ietf:params:scim:schemas:core:2.0:User')
    expect(response.body.Resources[1].id).toBe('urn:ietf:params:scim:schemas:core:2.0:Group')
  })

  test('getUsers all test (1)', async () => {
    const response: any = await fetchSCIM('GET', '/Users?startIndex=1&count=100', undefined, options.std.headers)
    const users = response?.body
    expect(response.status).toBe(200)
    expect(users.totalResults).toBe(2)
    expect(users.itemsPerPage).toBe(2)
    expect(users.startIndex).toBe(1)
    expect(users).toBeDefined()
    expect(users.Resources[0].userName).toBe('bjensen')
    expect(users.Resources[0].id).toBe('bjensen')
    expect(users.Resources[0].name.givenName).toBe('Barbara')
    expect(users.Resources[0].groups[0].value).toBe('Admins')
    expect(users.Resources[0].groups[0].display).toBe('Admins')
    expect(users.Resources[0].groups[0].type).toBe('direct')
    expect(users.Resources[0].meta.version).toBeDefined()
    expect(users.Resources[1].userName).toBe('jsmith')
    expect(users.Resources[1].id).toBe('jsmith')
    expect(users.Resources[1].name.givenName).toBe('John')
    expect(users.Resources[1].groups[0].value).toBe('Employees')
    expect(users.Resources[1].groups[0].display).toBe('Employees')
    expect(users.Resources[1].groups[0].type).toBe('direct')
    expect(users.Resources[1].meta.version).toBeDefined()
  })

  test('getUsers all test (2)', async () => {
    const res = await fetchSCIM('GET', '/Users?attributes=userName&startIndex=1&count=100', undefined, options.std.headers) // id and meta is always returned
    const users = res.body
    expect(res.status).toBe(200)
    expect(users.totalResults).toBe(2)
    expect(users.itemsPerPage).toBe(2)
    expect(users.startIndex).toBe(1)
    expect(users).toBeDefined()
    expect(users.Resources[0].userName).toBe('bjensen')
    expect(users.Resources[0].id).toBe('bjensen')
    expect(users.Resources[0].meta.version).toBeDefined()
    expect(users.Resources[0].groups).toBe(undefined)
    expect(users.Resources[1].userName).toBe('jsmith')
    expect(users.Resources[1].id).toBe('jsmith')
    expect(users.Resources[1].meta.version).toBeDefined()
    expect(users.Resources[1].groups).toBe(undefined)
  })

  test('getUsers unique test (1)', async () => {
    const res = await fetchSCIM('GET', '/Users/bjensen', undefined, options.std.headers)
    const user = res.body
    expect(res.headers.get('etag')).toBe('W/"0"')
    expect(res.headers.get('location')).toBe('http://localhost:8880/Users/bjensen')
    expect(res.status).toBe(200)
    expect(user).toBeDefined()
    expect(user.id).toBe('bjensen')
    expect(user.active).toBe(true)
    expect(user.name.givenName).toBe('Barbara')
    expect(user.name.familyName).toBe('Jensen')
    expect(user.name.formatted).toBe('Ms. Barbara J Jensen, III')
    expect(user.entitlements[0].type).toBe('newentitlement')
    expect(user.entitlements[0].value).toBe('bjensen entitlement')
    expect(user.phoneNumbers[0].type).toBe('work')
    expect(user.phoneNumbers[0].value).toBe('555-555-5555')
    expect(user.emails[0].type).toBe('work')
    expect(user.emails[0].value).toBe('bjensen@example.com')
    expect(user.groups[0].value).toBe('Admins')
    expect(user.groups[0].display).toBe('Admins')
    expect(user.groups[0].type).toBe('direct')
    expect(user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'].manager.value).toBe('jsmith')
    expect(user.meta.version).toBeDefined()
    expect(user.meta.location).toBeDefined()
    expect(user.schemas[0]).toBe('urn:ietf:params:scim:schemas:core:2.0:User')
    expect(user.schemas[1]).toBe('urn:ietf:params:scim:schemas:extension:enterprise:2.0:User')
  })

  test('getUsers unique test (2)', async () => {
    const res = await fetchSCIM('GET', '/Users'
      + '?filter=userName eq "bjensen"&attributes=ims,locale,name.givenName,externalId,preferredLanguage,userType,id,title,timezone,name.middleName,name.familyName,nickName,name.formatted,meta.location,userName,name.honorificSuffix,meta.version,meta.lastModified,meta.created,name.honorificPrefix,emails,phoneNumbers,photos,x509Certificates.value,profileUrl,roles,active,addresses,displayName,entitlements',
    undefined, options.std.headers)
    const user = res?.body?.Resources[0]
    expect(res.status).toBe(200)
    expect(user).toBeDefined()
    expect(user.id).toBe('bjensen')
    expect(user.active).toBe(true)
    expect(user.name.givenName).toBe('Barbara')
    expect(user.name.familyName).toBe('Jensen')
    expect(user.name.formatted).toBe('Ms. Barbara J Jensen, III')
    expect(user.entitlements[0].type).toBe('newentitlement')
    expect(user.entitlements[0].value).toBe('bjensen entitlement')
    expect(user.phoneNumbers[0].type).toBe('work')
    expect(user.phoneNumbers[0].value).toBe('555-555-5555')
    expect(user.emails[0].type).toBe('work')
    expect(user.emails[0].value).toBe('bjensen@example.com')
    expect(user.groups).toBe(undefined)
  })

  test('getUsers filter test (1)', async () => {
    const res = await fetchSCIM('GET', '/Users'
      + '?filter=emails.value eq "bjensen@example.com"&attributes=emails,id,name.givenName',
    undefined, options.std.headers)
    const users = res?.body?.Resources
    expect(res.status).toBe(200)
    expect(users.length).toBe(1)
    expect(users[0]).toBeDefined()
    expect(users[0].emails[0].value).toBe('bjensen@example.com')
    expect(users[0].id).toBe('bjensen')
    expect(users[0].name.givenName).toBe('Barbara')
    expect(users[0].active).toBe(undefined)
    expect(users[0].entitlements).toBe(undefined)
    expect(users[0].phoneNumbers).toBe(undefined)
    expect(users[0].groups).toBe(undefined)
  })

  test('getUsers filter test (2)', async () => {
    const res = await fetchSCIM('GET', '/Users'
      + '?filter=meta.created gte "2010-01-01T00:00:00Z"&attributes=userName,id,name.familyName,meta.created&sortBy=name.familyName&sortOrder=descending',
    undefined, options.std.headers)
    const users = res?.body?.Resources
    expect(res.status).toBe(200)
    expect(users.length).toBe(2)
    expect(users[0].id).toBe('jsmith')
    expect(users[1].id).toBe('bjensen')
  })

  test('getGroups all test (1)', async () => {
    const res = await fetchSCIM('GET', '/Groups'
      + '?startIndex=1&count=100',
    undefined, options.std.headers)
    const groups = res.body
    expect(res.status).toBe(200)
    expect(groups.totalResults).toBe(2)
    expect(groups.itemsPerPage).toBe(2)
    expect(groups.startIndex).toBe(1)
    expect(groups).toBeDefined()
    expect(groups.Resources[0].members).toBeDefined()
    expect(groups.Resources[0].displayName).toBe('Admins')
    expect(groups.Resources[0].id).toBe('Admins')
    expect(groups.Resources[1].members).toBeDefined()
    expect(groups.Resources[1].displayName).toBe('Employees')
    expect(groups.Resources[1].id).toBe('Employees')
  })

  test('getGroups all test (2)', async () => {
    const res = await fetchSCIM('GET', '/Groups'
      + '?attributes=displayName&startIndex=1&count=100', // id and meta is always returned
    undefined, options.std.headers)
    const groups = res.body
    expect(res.status).toBe(200)
    expect(groups.totalResults).toBe(2)
    expect(groups.itemsPerPage).toBe(2)
    expect(groups.startIndex).toBe(1)
    expect(groups).toBeDefined()
    expect(groups.Resources[0].members).toBe(undefined)
    expect(groups.Resources[0].displayName).toBe('Admins')
    expect(groups.Resources[0].id).toBe('Admins')
    expect(groups.Resources[0].meta).toBeDefined()
    expect(groups.Resources[1].members).toBe(undefined)
    expect(groups.Resources[1].displayName).toBe('Employees')
    expect(groups.Resources[1].id).toBe('Employees')
    expect(groups.Resources[1].meta).toBeDefined()
  })

  test('getGroups unique test (1)', async () => {
    const res = await fetchSCIM('GET', '/Groups/Admins', undefined, options.std.headers)
    const group = res.body
    expect(res.status).toBe(200)
    expect(res.headers.get('etag')).toBe('W/"0"')
    expect(res.headers.get('location')).toBe('http://localhost:8880/Groups/Admins')
    expect(group).toBeDefined()
    expect(group.schemas).toBeDefined()
    expect(group.meta.location).toBeDefined()
    expect(group.displayName).toBe('Admins')
    expect(group.id).toBe('Admins')
    expect(group.members[0].value).toBe('bjensen')
    // expect(group.members[0].display).toBe('bjensen');
  })

  test('getGroups unique test (2)', async () => {
    const res = await fetchSCIM('GET', '/Groups'
      + '?filter=displayName eq "Admins"&attributes=externalId,id,members.value,displayName',
    undefined, options.std.headers)
    const groups = res.body
    expect(res.status).toBe(200)
    expect(groups).toBeDefined()
    expect(groups.schemas).toBeDefined()
    expect(groups.Resources[0].displayName).toBe('Admins')
    expect(groups.Resources[0].id).toBe('Admins')
    expect(groups.Resources[0].members[0].value).toBe('bjensen')
    // expect(groups.Resources[0].members[0].display).toBe('bjensen');
  })

  test('getGroups members test', async () => {
    const res = await fetchSCIM('GET', '/Groups'
      + '?filter=members.value eq "bjensen"&attributes=members.value,displayName',
    undefined, options.std.headers)
    const groupMembers = res.body
    expect(res.status).toBe(200)
    expect(groupMembers).toBeDefined()
    expect(groupMembers.Resources[0].displayName).toBe('Admins')
    expect(groupMembers.Resources[0].members[0].value).toBe('bjensen')
    expect(groupMembers.Resources[0].totalResults).toBe(groupMembers.Resources[0].members[0].length)
  })

  test('createUser test', async () => {
    const newUser = {
      'userName': 'jgilber',
      'active': true,
      'password': 'secretpassword',
      'name': {
        formatted: 'Mr. Jeff Gilbert',
        familyName: 'Gilbert',
        givenName: 'Jeff',
      },
      'title': 'test title',
      'emails': [{
        value: 'jgilber@example.com',
        type: 'work',
      }],
      'phoneNumbers': [{
        value: 'tel:555-555-8376',
        type: 'work',
      }],
      'entitlements': [{
        value: 'Test Company',
        type: 'company',
      }],
      'addresses': [{
        type: 'work',
        streetAddress: 'City Plaza',
        postalCode: '9559',
      }],
      'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User': {
        employeeNumber: '123456',
        test1: 'xxx',
        test2: 'yyy',
      },
    }
    const res = await fetchSCIM('POST', '/Users', newUser, options.content.headers)
    expect(res.status).toBe(201)
    expect(res.body.meta.location).toBe('http://localhost:8880/Users/jgilber')
  })

  test('getUser just created test', async () => {
    const res = await fetchSCIM('GET', '/Users/jgilber', undefined, options.std.headers)
    const user = res.body
    expect(res.headers.get('etag')).toBe('W/"0"')
    expect(res.headers.get('location')).toBe('http://localhost:8880/Users/jgilber')
    expect(res.status).toBe(200)
    expect(user).toBeDefined()
    expect(user.id).toBe('jgilber')
    expect(user.active).toBe(true)
    expect(user.name.givenName).toBe('Jeff')
    expect(user.name.familyName).toBe('Gilbert')
    expect(user.name.formatted).toBe('Mr. Jeff Gilbert')
    expect(user.title).toBe('test title')
    expect(user.emails[0].type).toBe('work')
    expect(user.emails[0].value).toBe('jgilber@example.com')
    expect(user.entitlements[0].type).toBe('company')
    expect(user.entitlements[0].value).toBe('Test Company')
    expect(user.phoneNumbers[0].type).toBe('work')
    expect(user.phoneNumbers[0].value).toBe('tel:555-555-8376')
    expect(user.addresses[0].type).toBe('work')
    expect(user.addresses[0].streetAddress).toBe('City Plaza')
    expect(user.addresses[0].postalCode).toBe('9559')
    expect(user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'].employeeNumber).toBe('123456')
    expect(user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'].test1).toBe('xxx')
    expect(user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'].test2).toBe('yyy')
    expect(user.meta.version).toBe('W/"0"')
    expect(user.schemas[0]).toBe('urn:ietf:params:scim:schemas:core:2.0:User')
    expect(user.schemas[1]).toBe('urn:ietf:params:scim:schemas:extension:enterprise:2.0:User')
  })

  // scim v1.1
  /*
  test('modifyUser test', async () => {
    var user = {
      name: {
        givenName: 'Jeff-Modified'
      },
      active: false,
      title: 'New title',
      phoneNumbers: [{
        type: 'work',
        value: 'tel:123'
      }],
      entitlements: [{
        type: 'company',
        value: 'New Company'
      }],
      emails: [{
        operation: 'delete',
        type: 'work',
        value: 'jgilber@example.com'
      }],
      addresses: [{
        type: 'work',
        streetAddress: 'New Address',
        postalCode: '1111'
      }],
      meta: { attributes: ['name.familyName'] }
    }
  */

  test('modifyUser test', async () => {
    const user = {
      Operations: [
        {
          op: 'replace',
          path: 'name.givenName',
          value: 'Jeff-Modified',
        },
        {
          op: 'replace',
          path: 'active',
          value: false,
        },
        {
          op: 'replace',
          path: 'phoneNumbers[type eq "work"].value',
          value: 'tel:123',
        },
        {
          op: 'replace',
          value: {
            title: 'New title',
            entitlements: [{
              value: 'New Company',
              type: 'company',
            }],
          },
        },
        {
          op: 'remove',
          path: 'emails[type eq "work"].value',
        },
        {
          op: 'replace',
          path: 'addresses[type eq "work"]',
          value: {
            type: 'work',
            streetAddress: 'New Address',
            postalCode: '1111',
          },
        },
        {
          op: 'Remove',
          path: 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber',
        },
        {
          op: 'add',
          path: 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department',
          value: 'Top Floor',
        },
        {
          op: 'add',
          path: 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value',
          value: 'bjensen',
        },
        {
          op: 'replace',
          path: 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User',
          value: {
            test1: 'test1-value',
            test2: 'test2-value',
          },
        },
      ],
    }
    const res = await fetchSCIM('PATCH', '/Users/jgilber', user, options.content.headers)
    expect(res.status).toBe(200)
    expect(res.headers.get('etag')).toBe('W/"1"')
    expect(res.headers.get('location')).toBe('http://localhost:8880/Users/jgilber')
    expect(res.body.meta.version).toBe('W/"1"')
    expect(res.body.meta.location).toBe('http://localhost:8880/Users/jgilber')
  })

  test('getUser just modified test', async () => {
    const res = await fetchSCIM('GET', '/Users/jgilber', undefined, options.std.headers)
    const user = res.body
    expect(res.status).toBe(200)
    expect(res.headers.get('etag')).toBe('W/"1"')
    expect(res.headers.get('location')).toBe('http://localhost:8880/Users/jgilber')
    expect(user).toBeDefined()
    expect(user.id).toBe('jgilber')
    expect(user.active).toBe(false) // modified
    expect(user.name.givenName).toBe('Jeff-Modified') // modified
    // expect(user.name.familyName).toBe(undefined) // cleared - scim 1.1
    expect(user.name.formatted).toBe('Mr. Jeff Gilbert')
    expect(user.title).toBe('New title') // modified
    expect(user.emails).toBe(undefined) // deleted
    expect(user.entitlements[0].type).toBe('company')
    expect(user.entitlements[0].value).toBe('New Company') // modified
    expect(user.phoneNumbers[0].type).toBe('work')
    expect(user.phoneNumbers[0].value).toBe('tel:123') // modiied
    expect(user.addresses[0].type).toBe('work')
    expect(user.addresses[0].streetAddress).toBe('New Address') // modified
    expect(user.addresses[0].postalCode).toBe('1111') // modified
    expect(user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'].employeeNumber).toBe(undefined) // deleted
    expect(user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'].department).toBe('Top Floor') // added
    expect(user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'].manager.value).toBe('bjensen') // added
    expect(user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'].test1).toBe('test1-value') // modified
    expect(user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'].test2).toBe('test2-value') // modified
    expect(user.meta.version).toBe('W/"1"')
    expect(user.meta.location).toBe('http://localhost:8880/Users/jgilber')
  })

  test('replaceUser test', async () => {
    const putUser = {
      'userName': 'jgilber',
      'name': {
        formatted: 'Mr. Jeff Gilbert-2',
        familyName: 'Gilbert-2',
        givenName: 'Jeff-2',
      },
      'emails': [{
        value: 'jgilber-2@example.com',
        type: 'work',
      }],
      'phoneNumbers': [{
        value: 'tel:555-555-8376',
        type: 'home',
      }],
      'addresses': [{
        type: 'work',
        streetAddress: 'City Plaza-2',
        postalCode: '9559-2',
      }],
      'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User': {
        employeeNumber: '1111',
      },
      'groups': [
        { value: 'Employees', display: 'Employees' },
        { value: 'Admins', display: 'Admins' },
      ],
    }

    const res = await fetchSCIM('PUT', '/Users/jgilber', putUser, options.content.headers)
    const user = res.body
    expect(res.status).toBe(200)
    expect(res.headers.get('etag')).toBe('W/"2"')
    expect(res.headers.get('location')).toBe('http://localhost:8880/Users/jgilber')
    expect(user).toBeDefined()
    expect(user.id).toBe('jgilber')
    expect(user.active).toBe(false)
    expect(user.name.givenName).toBe('Jeff-2') // modified
    expect(user.name.formatted).toBe('Mr. Jeff Gilbert-2') // modified
    expect(user.title).toBe(undefined) // deleted
    expect(user.emails[0].type).toBe('work')
    expect(user.emails[0].value).toBe('jgilber-2@example.com') // modified
    expect(user.entitlements).toBe(undefined) // deleted
    expect(user.addresses[0].streetAddress).toBe('City Plaza-2') // modified
    expect(user.addresses[0].postalCode).toBe('9559-2') // modified
    expect(user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'].employeeNumber).toBe('1111') // modified
    expect(user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'].department).toBe(undefined) // deleted
    expect(user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'].manager).toBe(undefined) // deleted
    expect(user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'].test1).toBe(undefined) // deleted
    expect(user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'].test2).toBe(undefined) // deleted
    expect(user.groups.length).toBe(2)
    expect(user.groups[0].value).toBe('Admins')
    expect(user.groups[1].value).toBe('Employees')
    expect(user.meta.version).toBe('W/"2"')
    expect(user.meta.location).toBe('http://localhost:8880/Users/jgilber')
  })

  test('deleteUser test', async () => {
    const res = await fetchSCIM('DELETE', '/Users/jgilber', undefined, options.std.headers)
    expect(res.status).toBe(204)
  })

  test('createGroup test', async () => {
    const newGroup = {
      displayName: 'GoGoLoki',
      externalId: undefined,
      members: [{
        value: 'bjensen',
      }],
    }
    const res = await fetchSCIM('POST', '/Groups', newGroup, options.content.headers)
    expect(res.status).toBe(201)
    expect(res.headers.get('etag')).toBe('W/"0"')
    expect(res.headers.get('location')).toBe('http://localhost:8880/Groups/GoGoLoki')
    expect(res.body.meta.version).toBe('W/"0"')
    expect(res.body.meta.location).toBe('http://localhost:8880/Groups/GoGoLoki')
  })

  test('getGroup just created test', async () => {
    const res = await fetchSCIM('GET', '/Groups/GoGoLoki', undefined, options.std.headers)
    const group = res.body
    expect(res.status).toBe(200)
    expect(res.headers.get('etag')).toBe('W/"0"')
    expect(res.headers.get('location')).toBe('http://localhost:8880/Groups/GoGoLoki')
    expect(group).toBeDefined()
    expect(group.displayName).toBe('GoGoLoki')
    expect(group.id).toBe('GoGoLoki')
    expect(group.meta.version).toBe('W/"0"')
    expect(group.meta.location).toBe('http://localhost:8880/Groups/GoGoLoki')
  })

  test('modifyGroupMembers test', async () => {
    const body = {
      Operations: [
        {
          op: 'add',
          path: 'members',
          value: [
            { value: 'jsmith' },
          ],
        },
        {
          op: 'remove',
          path: 'members',
          value: [
            { value: 'bjensen' },
          ],
        },
      ],
    }
    // body = { members: [{ value: 'jsmith' }, { operation: 'delete', value: 'bjensen' }], schemas: ['urn:scim:schemas:core:1.0'] } // scim v1.1

    const res = await fetchSCIM('PATCH', '/Groups/GoGoLoki?attributes=members', body, options.content.headers)
    const group = res.body
    expect(res.status).toBe(200)
    expect(res.headers.get('etag')).toBe('W/"1"')
    expect(res.headers.get('location')).toBe('http://localhost:8880/Groups/GoGoLoki')
    expect(group.members).toBeDefined()
    expect(group.schemas[0]).toBe('urn:ietf:params:scim:schemas:core:2.0:Group')
    expect(group.meta.version).toBe('W/"1"')
    expect(group.meta.location).toBe('http://localhost:8880/Groups/GoGoLoki')
  })

  test('getGroup just modified members test', async () => {
    const res = await fetchSCIM('GET', '/Groups/GoGoLoki', undefined, options.std.headers)
    const group = res.body
    expect(res.status).toBe(200)
    expect(res.headers.get('etag')).toBe('W/"1"')
    expect(res.headers.get('location')).toBe('http://localhost:8880/Groups/GoGoLoki')
    expect(group).toBeDefined()
    expect(group.displayName).toBe('GoGoLoki')
    expect(group.id).toBe('GoGoLoki')
    expect(group.members.length).toBe(1) // bjensen removed
    expect(group.members[0].value).toBe('jsmith') // 
    expect(group.meta.version).toBe('W/"1"')
    expect(group.meta.location).toBe('http://localhost:8880/Groups/GoGoLoki')
  })

  test('replaceGroup test', async () => {
    const obj = {
      displayName: 'NewGoGoLoki',
      externalId: undefined,
      members: [{
        value: 'bjensen',
      },
      {
        value: 'jsmith',
      }],
    }
    const res = await fetchSCIM('PUT', '/Groups/GoGoLoki', obj, options.content.headers)
    const group = res.body
    expect(res.status).toBe(200)
    expect(res.headers.get('etag')).toBe('W/"2"')
    expect(res.headers.get('location')).toBe('http://localhost:8880/Groups/GoGoLoki')
    expect(group.displayName).toBe('NewGoGoLoki')
    expect(group.members.length).toBe(2)
    expect(group.meta.version).toBe('W/"2"')
    expect(group.meta.location).toBe('http://localhost:8880/Groups/GoGoLoki')
  })

  test('deleteGroup test', async () => {
    const res = await fetchSCIM('DELETE', '/Groups/GoGoLoki', undefined, options.std.headers)
    expect(res.status).toBe(204)
  })

  test('bulkOperations test', async () => {
    const body = {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:BulkRequest'],
      Operations: [
        {
          method: 'POST',
          path: '/Groups',
          bulkId: 'ytrewq',
          data: {
            schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
            displayName: 'Tour Guides',
            members: [
              {
                type: 'User',
                value: 'bulkId:qwerty',
              },
            ],
          },
        },
        {
          method: 'POST',
          path: '/Users',
          bulkId: 'qwerty',
          data: {
            schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
            userName: 'alice',
          },
        },
        {
          method: 'PATCH',
          path: '/Groups/Tour Guides',
          version: 'W/"0"',
          data: {
            op: 'add',
            path: 'members',
            value: [
              {
                value: 'bjensen',
              },
            ],
          },
        },
        {
          method: 'DELETE',
          path: '/Groups/Tour Guides',
        },
        {
          method: 'DELETE',
          path: '/Users/alice',
        },
      ],
    }
    const res = await fetchSCIM('POST', '/Bulk', body, options.std.headers)
    expect(res.status).toBe(200)
    expect(res.body.Operations.length).toBe(5)
    expect(res.body.Operations[0].bulkId).toBe('qwerty')
    expect(res.body.Operations[0].status.code).toBe('201')
    expect(res.body.Operations[0].location).toBe('http://localhost:8880/Users/alice')
    expect(res.body.Operations[1].bulkId).toBe('ytrewq')
    expect(res.body.Operations[1].status.code).toBe('201')
    expect(res.body.Operations[1].location).toBe('http://localhost:8880/Groups/Tour%20Guides')
    expect(res.body.Operations[2].bulkId).toBeUndefined()
    expect(res.body.Operations[2].status.code).toBe('200')
    expect(res.body.Operations[2].method).toBe('PATCH')
    expect(res.body.Operations[2].path).toBe('/Groups/Tour Guides')
    expect(res.body.Operations[2].location).toBe('http://localhost:8880/Groups/Tour%20Guides')
    expect(res.body.Operations[3].bulkId).toBeUndefined()
    expect(res.body.Operations[3].status.code).toBe('204')
    expect(res.body.Operations[3].path).toBe('/Groups/Tour Guides')
    expect(res.body.Operations[4].bulkId).toBeUndefined()
    expect(res.body.Operations[4].status.code).toBe('204')
    expect(res.body.Operations[4].path).toBe('/Users/alice')
  })
})
