import { expect, test, describe } from 'bun:test'
import * as scim from '../../lib/plugin-scim'
// eslint-disable-next-line @typescript-eslint/no-unused-expressions
scim

const baseUrl = 'http://localhost:8886'
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
  return { status: response.status, body: data }
}

describe('plugin-scim', async () => {
  test('getUsers all test (1)', async () => {
    const res = await fetchSCIM('GET', '/Users?startIndex=1&count=100', undefined, options.std.headers)
    const users = res.body
    expect(res.status).toBe(200)
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
    expect(users.Resources[1].userName).toBe('jsmith')
    expect(users.Resources[1].id).toBe('jsmith')
    expect(users.Resources[1].name.givenName).toBe('John')
    expect(users.Resources[1].groups[0].value).toBe('Employees')
    expect(users.Resources[1].groups[0].display).toBe('Employees')
    expect(users.Resources[1].groups[0].type).toBe('direct')
  })

  test('getUsers all test (2)', async () => {
    const res = await fetchSCIM('GET', '/Users?attributes=userName&startIndex=1&count=100', undefined, options.std.headers) // id is always returned
    const users = res.body
    expect(res.status).toBe(200)
    expect(users.totalResults).toBe(2)
    expect(users.itemsPerPage).toBe(2)
    expect(users.startIndex).toBe(1)
    expect(users).toBeDefined()
    expect(users.Resources[0].userName).toBe('bjensen')
    expect(users.Resources[0].id).toBe('bjensen')
    expect(users.Resources[0].groups).toBe(undefined)
    expect(users.Resources[1].userName).toBe('jsmith')
    expect(users.Resources[1].id).toBe('jsmith')
    expect(users.Resources[1].groups).toBe(undefined)
  })

  test('getUsers unique test (1)', async () => {
    const res = await fetchSCIM('GET', '/Users/bjensen', undefined, options.std.headers)
    const user = res.body
    expect(res.status).toBe(200)
    expect(user).toBeDefined()
    expect(user.id).toBe('bjensen')
    expect(user.active).toBe(true)
    expect(user.name.givenName).toBe('Barbara')
    expect(user.name.familyName).toBe('Jensen')
    expect(user.name.formatted).toBe('Ms. Barbara J Jensen, III')
    expect(user.entitlements).toBe(undefined)
    expect(user.phoneNumbers[0].type).toBe('work')
    expect(user.phoneNumbers[0].value).toBe('555-555-5555')
    expect(user.emails[0].type).toBe('work')
    expect(user.emails[0].value).toBe('bjensen@example.com')
    expect(user.groups[0].value).toBe('Admins')
    expect(user.groups[0].display).toBe('Admins')
    expect(user.groups[0].type).toBe('direct')
    expect(user.meta.location).toBeDefined()
    expect(user.schemas[0]).toBe('urn:ietf:params:scim:schemas:core:2.0:User')
  })

  test('getUsers unique test (2)', async () => {
    const res = await fetchSCIM('GET', '/Users'
      + '?filter=userName eq "bjensen"&attributes=attributes=ims,locale,name.givenName,externalId,preferredLanguage,userType,id,title,timezone,name.middleName,name.familyName,nickName,name.formatted,meta.location,userName,name.honorificSuffix,meta.version,meta.lastModified,meta.created,name.honorificPrefix,emails,phoneNumbers,photos,x509Certificates.value,profileUrl,roles,active,addresses,displayName,entitlements',
    undefined, options.std.headers)
    const user = res?.body?.Resources[0]
    expect(res.status).toBe(200)
    expect(user).toBeDefined()
    expect(user.id).toBe('bjensen')
    expect(user.active).toBe(true)
    expect(user.name.givenName).toBe('Barbara')
    expect(user.name.familyName).toBe('Jensen')
    expect(user.name.formatted).toBe('Ms. Barbara J Jensen, III')
    expect(user.entitlements).toBe(undefined)
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
    const user = res?.body?.Resources[0]
    expect(res.status).toBe(200)
    expect(user).toBeDefined()
    expect(user.emails[0].value).toBe('bjensen@example.com')
    expect(user.id).toBe('bjensen')
    expect(user.name.givenName).toBe('Barbara')
    expect(user.active).toBe(undefined)
    expect(user.entitlements).toBe(undefined)
    expect(user.phoneNumbers).toBe(undefined)
  })

  test('getUsers filter test (2)', async () => {
    const res = await fetchSCIM('GET', '/Users'
      + '?filter=emails.value co "@example.com"&attributes=userName,id,emails&sortBy=emails.value&sortOrder=descending',
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
    expect(groups).toBeDefined()
    expect(groups.totalResults).toBe(2)
    expect(groups.itemsPerPage).toBe(2)
    expect(groups.startIndex).toBe(1)
    expect(groups.Resources[0].displayName).toBe('Admins')
    expect(groups.Resources[0].id).toBe('Admins')
    expect(groups.Resources[1].displayName).toBe('Employees')
    expect(groups.Resources[1].id).toBe('Employees')
  })

  test('getGroups all test (2)', async () => {
    const res = await fetchSCIM('GET', '/Groups'
      + '?attributes=displayName&startIndex=1&count=100', // id is always returned
    undefined, options.std.headers)
    const groups = res.body
    expect(res.status).toBe(200)
    expect(groups).toBeDefined()
    expect(groups.totalResults).toBe(2)
    expect(groups.itemsPerPage).toBe(2)
    expect(groups.startIndex).toBe(1)
    expect(groups.Resources[0].displayName).toBe('Admins')
    expect(groups.Resources[0].id).toBe('Admins')
    expect(groups.Resources[0].members).toBe(undefined)
    expect(groups.Resources[1].displayName).toBe('Employees')
    expect(groups.Resources[1].id).toBe('Employees')
    expect(groups.Resources[1].members).toBe(undefined)
  })

  test('getGroups uniqe test (1)', async () => {
    const res = await fetchSCIM('GET', '/Groups/Admins', undefined, options.std.headers)
    const group = res.body
    expect(res.status).toBe(200)
    expect(group).toBeDefined()
    expect(group.schemas).toBeDefined()
    expect(group.meta.location).toBeDefined()
    expect(group.displayName).toBe('Admins')
    expect(group.id).toBe('Admins')
    expect(group.members[0].value).toBe('bjensen')
    expect(group.members[0].display).toBe('Babs Jensen')
  })

  test('getGroups uniqe test (2)', async () => {
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
  })

  test('getGroups member test', async () => {
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
      userName: 'jgilber',
      active: true,
      password: 'secretpassword',
      name: {
        formatted: 'Mr. Jeff Gilbert',
        familyName: 'Gilbert',
        givenName: 'Jeff',
      },
      title: 'test title',
      emails: [{
        value: 'jgilber@example.com',
        type: 'work',
      }],
      phoneNumbers: [{
        value: 'tel:555-555-8376',
        type: 'work',
      }],
      entitlements: [{
        value: 'Test Company',
        type: 'company',
      }],
    }
    const res = await fetchSCIM('POST', '/Users', newUser, options.content.headers)
    expect(res.status).toBe(201)
    expect(res.body.meta.location).toBe('http://localhost:8886/Users/jgilber')
  })

  test('getUser just created test', async () => {
    const res = await fetchSCIM('GET', '/Users/jgilber', undefined, options.std.headers)
    const user = res.body
    expect(res.status).toBe(200)
    expect(user).toBeDefined()
    expect(user.id).toBe('jgilber')
    expect(user.active).toBe(true)
    expect(user.name.givenName).toBe('Jeff')
    expect(user.name.familyName).toBe('Gilbert')
    expect(user.name.formatted).toBe('Mr. Jeff Gilbert')
    expect(user.title).toBe('test title')
    expect(user.emails[0].value).toBe('jgilber@example.com')
    expect(user.emails[0].type).toBe('work')
    expect(user.entitlements[0].value).toBe('Test Company')
    expect(user.entitlements[0].type).toBe('company')
    expect(user.phoneNumbers[0].value).toBe('tel:555-555-8376')
    expect(user.phoneNumbers[0].type).toBe('work')
  })

  // scim v1.1
  /*
  test('modifyUser test', async () => {
    var user = {
      name: {
        givenName: 'Jeff-Modified'
      },
      active: false,
      phoneNumbers: [{
        type: 'work',
        value: 'tel:123'
      }],
      emails: [{
        operation: 'delete',
        type: 'work',
        value: 'jgilber@example.com'
      }],
      meta: { attributes: ['name.familyName'] }
    }
  
    const res = await fetchSCIM('PATCH', '/Users/jgilber')
      .set(options.headers)
      .send(user)
      
        expect(err).toBe(null)
        expect(res.status).toBe(204)
        
      })
  })
  */

  test('modifyUser test', async () => {
    const user = {
      Operations: [
        {
          op: 'replace',
          value: {
            name: {
              givenName: 'Jeff-Modified',
              familyName: '',
            },
            active: false,
            phoneNumbers: [{
              type: 'work',
              value: 'tel:123',
            }],
            /* alternative to below
            emails: [{
              type: 'work',
              value: ''
            }]
            */
          },
        },
        {
          op: 'remove',
          path: 'emails[type eq "work"].value',
        },
      ],
    }
    const res = await fetchSCIM('PATCH', '/Users/jgilber', user, options.content.headers)
    expect(res.status).toBe(200)
  })

  test('getUser just modified test', async () => {
    const res = await fetchSCIM('GET', '/Users/jgilber', undefined, options.std.headers)
    const user = res.body
    expect(res.status).toBe(200)
    expect(user).toBeDefined()
    expect(user.id).toBe('jgilber')
    expect(user.active).toBe(false) // modified
    expect(user.name.givenName).toBe('Jeff-Modified') // modified
    expect(user.name.familyName).toBe(undefined) // deleted by ''
    expect(user.name.formatted).toBe('Mr. Jeff Gilbert')
    expect(user.title).toBe('test title')
    expect(user.emails).toBe(undefined) // deleted
    expect(user.entitlements[0].value).toBe('Test Company')
    expect(user.entitlements[0].type).toBe('company')
    expect(user.phoneNumbers[0].value).toBe('tel:123') // modiied
    expect(user.phoneNumbers[0].type).toBe('work')
  })

  test('deleteUser test', async () => {
    const res = await fetchSCIM('DELETE', '/Users/jgilber', undefined, options.std.headers)
    expect(res.status).toBe(204)
  })

  test('createGroup test', async () => {
    const newGroup = {
      displayName: 'GoGoRest',
      externalId: undefined,
      members: [{
        value: 'bjensen',
      }],
    }
    const res = await fetchSCIM('POST', '/Groups', newGroup, options.content.headers)
    expect(res.status).toBe(201)
    expect(res.body.meta.location).toBe('http://localhost:8886/Groups/GoGoRest')
  })

  test('getGroup just created test', async () => {
    const res = await fetchSCIM('GET', '/Groups/GoGoRest', undefined, options.std.headers)
    const group = res.body
    expect(res.status).toBe(200)
    expect(group).toBeDefined()
    expect(group.displayName).toBe('GoGoRest')
    expect(group.id).toBe('GoGoRest')
  })

  test('modifyGroupMembers test', async () => {
    const payload = { Operations: [
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
    // payload = { members: [{ value: 'jsmith' }, { operation: 'delete', value: 'bjensen' }], schemas: ['urn:scim:schemas:core:1.0'] } // scim v1.1
    const res = await fetchSCIM('PATCH', '/Groups/GoGoRest?attributes=members', payload, options.content.headers)
    const group = res.body
    expect(res.status).toBe(200)
    expect(group.members).toBeDefined()
    expect(group.schemas[0]).toBe('urn:ietf:params:scim:schemas:core:2.0:Group')
  })

  test('getGroup just modified members test', async () => {
    const res = await fetchSCIM('GET', '/Groups/GoGoRest', undefined, options.std.headers)
    const group = res.body
    expect(res.status).toBe(200)
    expect(group).toBeDefined()
    expect(group.displayName).toBe('GoGoRest')
    expect(group.id).toBe('GoGoRest')
    expect(group.members.length).toBe(1)
    expect(group.members[0].value).toBe('jsmith')
  })

  test('deleteGroup test', async () => {
    const res = await fetchSCIM('DELETE', '/Groups/GoGoRest', undefined, options.std.headers)
    expect(res.status).toBe(204)
  })
})
