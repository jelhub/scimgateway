'use strict'

// Natural language-like assertions
const expect = require('chai').expect
const scimgateway = require('../../lib/plugin-api.js')
const server_8890 = require('supertest').agent('http://localhost:8890') // module request is an alternative

const auth = 'Basic ' + Buffer.from('gwadmin:password').toString('base64')

const options = {
  headers: {
    'Content-Type': 'application/json',
    Authorization: auth
  }
}

describe('plugin-api remote dummyjson.com tests', () => {
  it('post /api test', (done) => {
    const objApi = {
      title: 'BMW X5',
      price: 58
    }

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

  it('put /api/100 test', (done) => {
    const objApi = {
      title: 'BMW X1',
      price: 21
    }

    server_8890.put('/api/100')
      .set(options.headers)
      .send(objApi)
      .end(function (err, res) {
        expect(err).to.equal(null)
        expect(res.statusCode).to.equal(200)
        expect(res.body.meta.result).to.equal('success')
        done()
      })
  })

  it('patch /api/100 test', (done) => {
    const objApi = {
      title: 'BMW X3'
    }

    server_8890.patch('/api/100')
      .set(options.headers)
      .send(objApi)
      .end(function (err, res) {
        expect(err).to.equal(null)
        expect(res.statusCode).to.equal(200)
        expect(res.body.meta.result).to.equal('success')
        done()
      })
  })

  it('get /api/100 test', (done) => {
    server_8890.get('/api/100')
      .set(options.headers)
      .end(function (err, res) {
        expect(err).to.equal(null)
        expect(res.statusCode).to.equal(200)
        expect(res.body.meta.result).to.equal('success')
        done()
      })
  })

  it('delete /api/100 test', (done) => {
    server_8890.delete('/api/100')
      .set(options.headers)
      .end(function (err, res) {
        expect(err).to.equal(null)
        expect(res.statusCode).to.equal(200)
        expect(res.body.meta.result).to.equal('success')
        done()
      })
  })
})
