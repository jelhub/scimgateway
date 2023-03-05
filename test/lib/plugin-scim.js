'use strict'

const expect = require('chai').expect
const scimgateway = require('../../lib/plugin-scim.js')
const server_8886 = require('supertest').agent('http://localhost:8886') // module request is an alternative

const auth = 'Basic ' + Buffer.from('gwadmin:password').toString('base64')
var options = {
  headers: {
    'Content-Type': 'application/json',
    Authorization: auth
  }
}

describe('plugin-scim tests', () => {

  it('getUsers all test (1)', function (done) {
    server_8886.get('/Users' +
      '?startIndex=1&count=100')
      .set(options.headers)
      .end(function (err, res) {
        if (err) { }
        const users = res.body
        expect(res.statusCode).to.equal(200)
        expect(users.totalResults).to.equal(2)
        expect(users.itemsPerPage).to.equal(2)
        expect(users.startIndex).to.equal(1)
        expect(users).to.not.equal('undefined')
        expect(users.Resources[0].userName).to.equal('bjensen')
        expect(users.Resources[0].id).to.equal('bjensen')
        expect(users.Resources[0].name.givenName).to.equal('Barbara')
        expect(users.Resources[0].groups[0].value).to.equal('Admins')
        expect(users.Resources[0].groups[0].display).to.equal('Admins')
        expect(users.Resources[0].groups[0].type).to.equal('direct')
        expect(users.Resources[1].userName).to.equal('jsmith')
        expect(users.Resources[1].id).to.equal('jsmith')
        expect(users.Resources[1].name.givenName).to.equal('John')
        expect(users.Resources[1].groups[0].value).to.equal('Employees')
        expect(users.Resources[1].groups[0].display).to.equal('Employees')
        expect(users.Resources[1].groups[0].type).to.equal('direct')
        done()
      })
  })

  it('getUsers all test (2)', function (done) {
    server_8886.get('/Users' +
      '?attributes=userName&startIndex=1&count=100')
      .set(options.headers)
      .end(function (err, res) {
        if (err) { }
        const users = res.body
        expect(res.statusCode).to.equal(200)
        expect(users.totalResults).to.equal(2)
        expect(users.itemsPerPage).to.equal(2)
        expect(users.startIndex).to.equal(1)
        expect(users).to.not.equal('undefined')
        expect(users.Resources[0].userName).to.equal('bjensen')
        expect(users.Resources[0].id).to.equal(undefined)
        expect(users.Resources[0].groups).to.equal(undefined)
        expect(users.Resources[1].userName).to.equal('jsmith')
        expect(users.Resources[1].id).to.equal(undefined)
        expect(users.Resources[1].groups).to.equal(undefined)
        done()
      })
  })

  it('getUsers unique test (1)', function (done) {
    server_8886.get('/Users/bjensen')
      .set(options.headers)
      .end(function (err, res) {
        if (err) {}
        const user = res.body
        expect(res.statusCode).to.equal(200)
        expect(user).to.not.equal(undefined)
        expect(user.id).to.equal('bjensen')
        expect(user.active).to.equal(true)
        expect(user.name.givenName).to.equal('Barbara')
        expect(user.name.familyName).to.equal('Jensen')
        expect(user.name.formatted).to.equal('Ms. Barbara J Jensen, III')
        expect(user.entitlements).to.equal(undefined)
        expect(user.phoneNumbers[0].type).to.equal('work')
        expect(user.phoneNumbers[0].value).to.equal('555-555-5555')
        expect(user.emails[0].type).to.equal('work')
        expect(user.emails[0].value).to.equal('bjensen@example.com')
        expect(user.groups[0].value).to.equal('Admins')
        expect(user.groups[0].display).to.equal('Admins')
        expect(user.groups[0].type).to.equal('direct')
        expect(user.meta.location).to.not.equal(undefined)
        expect(user.schemas[0]).to.equal('urn:ietf:params:scim:schemas:core:2.0:User')
        done()
      })
  })

  it('getUsers unique test (2)', function (done) {
    server_8886.get('/Users' +
      '?filter=userName eq "bjensen"&attributes=attributes=ims,locale,name.givenName,externalId,preferredLanguage,userType,id,title,timezone,name.middleName,name.familyName,nickName,name.formatted,meta.location,userName,name.honorificSuffix,meta.version,meta.lastModified,meta.created,name.honorificPrefix,emails,phoneNumbers,photos,x509Certificates.value,profileUrl,roles,active,addresses,displayName,entitlements')
      .set(options.headers)
      .end(function (err, res) {
        if (err) {}
        let user = res.body
        user = user.Resources[0]
        expect(res.statusCode).to.equal(200)
        expect(user).to.not.equal(undefined)
        expect(user.id).to.equal('bjensen')
        expect(user.active).to.equal(true)
        expect(user.name.givenName).to.equal('Barbara')
        expect(user.name.familyName).to.equal('Jensen')
        expect(user.name.formatted).to.equal('Ms. Barbara J Jensen, III')
        expect(user.entitlements).to.equal(undefined)
        expect(user.phoneNumbers[0].type).to.equal('work')
        expect(user.phoneNumbers[0].value).to.equal('555-555-5555')
        expect(user.emails[0].type).to.equal('work')
        expect(user.emails[0].value).to.equal('bjensen@example.com')
        expect(user.groups).to.equal(undefined)
        done()
      })
  })

  it('getUsers filter test (1)', function (done) {
    server_8886.get('/Users' +
      '?filter=emails.value eq "bjensen@example.com"&attributes=emails,id,name.givenName')
      .set(options.headers)
      .end(function (err, res) {
        if (err) { }
        let user = res.body
        user = user.Resources[0]
        expect(res.statusCode).to.equal(200)
        expect(user).to.not.equal(undefined)
        expect(user.emails[0].value).to.equal('bjensen@example.com')
        expect(user.id).to.equal('bjensen')
        expect(user.name.givenName).to.equal('Barbara')
        expect(user.active).to.equal(undefined)
        expect(user.entitlements).to.equal(undefined)
        expect(user.phoneNumbers).to.equal(undefined)
        done()
      })
  })

  it('getUsers filter test (2)', function (done) {
    server_8886.get('/Users' +
      '?filter=emails.value co "@example.com"&attributes=userName,id,emails&sortBy=emails.value&sortOrder=descending')
      .set(options.headers)
      .end(function (err, res) {
        if (err) { }
        const users = res.body.Resources
        expect(res.statusCode).to.equal(200)
        expect(users.length).to.equal(2)
        expect(users[0].id).to.equal('jsmith')
        expect(users[1].id).to.equal('bjensen')
        done()
      })
  })

  it('getGroups all test (1)', (done) => {
    server_8886.get('/Groups' +
      '?startIndex=1&count=100')
      .set(options.headers)
      .end(function (err, res) {
        if (err) {}
        const groups = res.body
        expect(res.statusCode).to.equal(200)
        expect(groups).to.not.equal(undefined)
        expect(groups.totalResults).to.equal(2)
        expect(groups.itemsPerPage).to.equal(2)
        expect(groups.startIndex).to.equal(1)
        expect(groups.Resources[0].displayName).to.equal('Admins')
        expect(groups.Resources[0].id).to.equal('Admins')
        expect(groups.Resources[1].displayName).to.equal('Employees')
        expect(groups.Resources[1].id).to.equal('Employees')
        done()
      })
  })

  it('getGroups all test (2)', (done) => {
    server_8886.get('/Groups' +
      '?attributes=displayName&startIndex=1&count=100')
      .set(options.headers)
      .end(function (err, res) {
        if (err) {}
        const groups = res.body
        expect(res.statusCode).to.equal(200)
        expect(groups).to.not.equal(undefined)
        expect(groups.totalResults).to.equal(2)
        expect(groups.itemsPerPage).to.equal(2)
        expect(groups.startIndex).to.equal(1)
        expect(groups.Resources[0].displayName).to.equal('Admins')
        expect(groups.Resources[0].id).to.equal(undefined)
        expect(groups.Resources[1].displayName).to.equal('Employees')
        expect(groups.Resources[1].id).to.equal(undefined)
        done()
      })
  })

  it('getGroups uniqe test (1)', function (done) {
    server_8886.get('/Groups/Admins')
      .set(options.headers)
      .end(function (err, res) {
        if (err) {}
        const group = res.body
        expect(res.statusCode).to.equal(200)
        expect(group).to.not.equal(undefined)
        expect(group.schemas).to.not.equal(undefined)
        expect(group.meta.location).to.not.equal(undefined)
        expect(group.displayName).to.equal('Admins')
        expect(group.id).to.equal('Admins')
        expect(group.members[0].value).to.equal('bjensen')
        expect(group.members[0].display).to.equal('Babs Jensen')
        done()
      })
  })

  it('getGroups uniqe test (2)', function (done) {
    server_8886.get('/Groups' +
      '?filter=displayName eq "Admins"&attributes=externalId,id,members.value,displayName')
      .set(options.headers)
      .end(function (err, res) {
        if (err) {}
        const groups = res.body
        expect(res.statusCode).to.equal(200)
        expect(groups).to.not.equal(undefined)
        expect(groups.schemas).to.not.equal(undefined)
        expect(groups.Resources[0].displayName).to.equal('Admins')
        expect(groups.Resources[0].id).to.equal('Admins')
        expect(groups.Resources[0].members[0].value).to.equal('bjensen')
        done()
      })
  })

  it('getGroups member test', (done) => {
    server_8886.get('/Groups' +
      '?filter=members.value eq "bjensen"&attributes=members.value,displayName')
      .set(options.headers)
      .end(function (err, res) {
        if (err) {}
        const groupMembers = res.body
        expect(res.statusCode).to.equal(200)
        expect(groupMembers).to.not.equal('undefined')
        expect(groupMembers.Resources[0].displayName).to.equal('Admins')
        expect(groupMembers.Resources[0].members[0].value).to.equal('bjensen')
        expect(groupMembers.Resources[0].totalResults).to.equal(groupMembers.Resources[0].members[0].length)
        done()
      })
  })

  it('createUser test', (done) => {
    const newUser = {
      userName: 'jgilber',
      active: true,
      password: 'secretpassword',
      name: {
        formatted: 'Mr. Jeff Gilbert',
        familyName: 'Gilbert',
        givenName: 'Jeff'
      },
      title: 'test title',
      emails: [{
        value: 'jgilber@example.com',
        type: 'work'
      }],
      phoneNumbers: [{
        value: 'tel:555-555-8376',
        type: 'work'
      }],
      entitlements: [{
        value: 'Test Company',
        type: 'company'
      }]
    }

    server_8886.post('/Users')
      .set(options.headers)
      .send(newUser)
      .end(function (err, res) {
        expect(err).to.equal(null)
        expect(res.statusCode).to.equal(201)
        expect(res.body.meta.location).to.equal('http://localhost:8886/Users/jgilber')
        done()
      })
  })

  it('getUser just created test', (done) => {
    server_8886.get('/Users/jgilber')
      .set(options.headers)
      .end(function (err, res) {
        if (err) {}
        const user = res.body
        expect(res.statusCode).to.equal(200)
        expect(user).to.not.equal(undefined)
        expect(user.id).to.equal('jgilber')
        expect(user.active).to.equal(true)
        expect(user.name.givenName).to.equal('Jeff')
        expect(user.name.familyName).to.equal('Gilbert')
        expect(user.name.formatted).to.equal('Mr. Jeff Gilbert')
        expect(user.title).to.equal('test title')
        expect(user.emails[0].value).to.equal('jgilber@example.com')
        expect(user.emails[0].type).to.equal('work')
        expect(user.entitlements[0].value).to.equal('Test Company')
        expect(user.entitlements[0].type).to.equal('company')
        expect(user.phoneNumbers[0].value).to.equal('tel:555-555-8376')
        expect(user.phoneNumbers[0].type).to.equal('work')
        done()
      })
  })

  // scim v1.1
  /*
  it('modifyUser test', (done) => {
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

    server_8886.patch('/Users/jgilber')
      .set(options.headers)
      .send(user)
      .end(function (err, res) {
        expect(err).to.equal(null)
        expect(res.statusCode).to.equal(204)
        done()
      })
  })
  */

  it('modifyUser test', (done) => {
    var user = {
      Operations: [
        {
          op: 'replace',
          value: {
            name: {
              givenName: 'Jeff-Modified',
              familyName: ''
            },
            active: false,
            phoneNumbers: [{
              type: 'work',
              value: 'tel:123'
            }]
            /* alternative to below
            emails: [{
              type: 'work',
              value: ''
            }]
            */
          }
        },
        {
          op: 'remove',
          path: 'emails[type eq \"work\"].value'
        }
      ]
    }

    server_8886.patch('/Users/jgilber')
      .set(options.headers)
      .send(user)
      .end(function (err, res) {
        expect(err).to.equal(null)
        expect(res.statusCode).to.equal(200)
        done()
      })
  })

  it('getUser just modified test', (done) => {
    server_8886.get('/Users/jgilber')
      .set(options.headers)
      .end(function (err, res) {
        if (err) {}
        const user = res.body
        expect(res.statusCode).to.equal(200)
        expect(user).to.not.equal(undefined)
        expect(user.id).to.equal('jgilber')
        expect(user.active).to.equal(false) // modified
        expect(user.name.givenName).to.equal('Jeff-Modified') // modified
        expect(user.name.familyName).to.equal(undefined) // deleted by ''
        expect(user.name.formatted).to.equal('Mr. Jeff Gilbert')
        expect(user.title).to.equal('test title')
        expect(user.emails).to.equal(undefined) // deleted
        expect(user.entitlements[0].value).to.equal('Test Company')
        expect(user.entitlements[0].type).to.equal('company')
        expect(user.phoneNumbers[0].value).to.equal('tel:123') // modiied
        expect(user.phoneNumbers[0].type).to.equal('work')
        done()
      })
  })

  it('deleteUser test', (done) => {
    server_8886.delete('/Users/jgilber')
      .set(options.headers)
      .end(function (err, res) {
        expect(err).to.equal(null)
        expect(res.statusCode).to.equal(204)
        done()
      })
  })

  it('createGroup test', (done) => {
    const newGroup = {
      displayName: 'GoGoRest',
      externalId: undefined,
      members: [{
        value: 'bjensen'
      }]
    }

    server_8886.post('/Groups')
      .set(options.headers)
      .send(newGroup)
      .end(function (err, res) {
        expect(err).to.equal(null)
        expect(res.statusCode).to.equal(201)
        expect(res.body.meta.location).to.equal('http://localhost:8886/Groups/GoGoRest')
        done()
      })
  })

  it('getGroup just created test', (done) => {
    server_8886.get('/Groups/GoGoRest')
      .set(options.headers)
      .end(function (err, res) {
        if (err) {}
        const group = res.body
        expect(res.statusCode).to.equal(200)
        expect(group).to.not.equal('undefined')
        expect(group.displayName).to.equal('GoGoRest')
        expect(group.id).to.equal('GoGoRest')
        done()
      })
  })

  it('modifyGroupMembers test', (done) => {
    server_8886.patch('/Groups/GoGoRest?attributes=members')
      .set(options.headers)
      // .send({ members: [{ value: 'jsmith' }, { operation: 'delete', value: 'bjensen' }], schemas: ['urn:scim:schemas:core:1.0'] }) // scim v1.1
      .send({
        Operations: [
          {
            op: 'add',
            path: 'members',
            value: [
              { value: 'jsmith' }
            ]
          },
          {
            op: 'remove',
            path: 'members',
            value: [
              { value: 'bjensen' }
            ]
          }
        ]
      })
      .end(function (err, res) {
        const group = res.body
        expect(err).to.equal(null)
        expect(res.statusCode).to.equal(200)
        expect(group.members).to.not.equal('undefined')
        expect(group.schemas[0]).to.equal('urn:ietf:params:scim:schemas:core:2.0:Group')
        done()
      })
  })

  it('getGroup just modified members test', (done) => {
    server_8886.get('/Groups/GoGoRest')
      .set(options.headers)
      .end(function (err, res) {
        if (err) {}
        const group = res.body
        expect(res.statusCode).to.equal(200)
        expect(group).to.not.equal('undefined')
        expect(group.displayName).to.equal('GoGoRest')
        expect(group.id).to.equal('GoGoRest')
        expect(group.members.length).to.equal(1)
        expect(group.members[0].value).to.equal('jsmith')
        done()
      })
  })

  it('deleteGroup test', (done) => {
    server_8886.delete('/Groups/GoGoRest')
      .set(options.headers)
      .end(function (err, res) {
        expect(err).to.equal(null)
        expect(res.statusCode).to.equal(204)
        done()
      })
  })
})
