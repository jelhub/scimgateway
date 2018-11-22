'use strict'

// Natural language-like assertions
const expect = require('chai').expect
const scimgateway = require('../../lib/plugin-api.js')
const server_8890 = require('supertest').agent('http://localhost:8890') // module request is an alternative

const auth = 'Basic ' + new Buffer.from('gwadmin:password').toString('base64')

var options = {
  headers: {
    'Content-Type': 'application/json',
    'Authorization': auth
  }
}

describe('plugin-api remote tests', () => {
  it('post /api test', (done) => {
    let objApi = {
      'eventName': 'AsignAccessRoleEvent',
      'subjectName': 'RACF_System-B',
      'userID': 'peter01'}

    server_8890.post('/api')
          .set(options.headers)
          .send(objApi)
          .end(function (err, res) {
            expect(err).to.equal(null)
            expect(res.statusCode).to.equal(201)
            expect(res.body.meta.result).to.equal('success')
            done()
          })
  })

  it('put /api/1 test', (done) => {
    let objApi = {
      'eventName': 'AsignAccessRoleEvent',
      'subjectName': 'RACF_System-B',
      'userID': 'peter01'}

    server_8890.put('/api/1')
          .set(options.headers)
          .send(objApi)
          .end(function (err, res) {
            expect(err).to.equal(null)
            expect(res.statusCode).to.equal(200)
            expect(res.body.meta.result).to.equal('success')
            done()
          })
  })

  /*
  it('patch /api/1 test', (done) => {
    let objApi = {
      'eventName': 'AsignAccessRoleEvent',
      'subjectName': 'RACF_System-B',
      'userID': 'peter01'}

    server_8890.patch('/api/1')
          .set(options.headers)
          .send(objApi)
          .end(function (err, res) {
            expect(err).to.equal(null)
            expect(res.statusCode).to.equal(500)
            expect(res.body.meta.result).to.equal('error')
            done()
          })
  })
  */

  it('get /api/1 test', (done) => {
    server_8890.get('/api/1')
          .set(options.headers)
          .end(function (err, res) {
            expect(err).to.equal(null)
            expect(res.statusCode).to.equal(200)
            expect(res.body.meta.result).to.equal('success')
            done()
          })
  })

  it('delete /api/1 test', (done) => {
    server_8890.delete('/api/1')
          .set(options.headers)
          .end(function (err, res) {
            expect(err).to.equal(null)
            expect(res.statusCode).to.equal(200)
            expect(res.body.meta.result).to.equal('success')
            done()
          })
  })
})
