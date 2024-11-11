'use strict'

import { expect, test, describe } from 'bun:test'
import * as server from 'supertest'
import * as api from '../../lib/plugin-api'
// eslint-disable-next-line @typescript-eslint/no-unused-expressions
api

const server_8890 = server.agent('http://localhost:8890')
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

describe('plugin-api', () => {
  test('post /api test', async () => {
    const objApi = {
      title: 'BMW X5',
      price: 58,
    }
    const res = await server_8890.post('/api')
      .set(options.content.headers)
      .send(objApi)
    expect(res.statusCode).toBe(201)
    expect(res.body.meta.result).toBe('success')
  })

  test('put /api/100 test', async () => {
    const objApi = {
      title: 'BMW X1',
      price: 21,
    }
    const res = await server_8890.put('/api/100')
      .set(options.content.headers)
      .send(objApi)
    expect(res.statusCode).toBe(200)
    expect(res.body.meta.result).toBe('success')
  })

  test('patch /api/100 test', async () => {
    const objApi = {
      title: 'BMW X3',
    }
    const res = await server_8890.patch('/api/100')
      .set(options.content.headers)
      .send(objApi)
    expect(res.statusCode).toBe(200)
    expect(res.body.meta.result).toBe('success')
  })

  test('get /api/100 test', async () => {
    const res = await server_8890.get('/api/100')
      .set(options.std.headers)
    expect(res.statusCode).toBe(200)
    expect(res.body.meta.result).toBe('success')
  })
  test('delete /api/100 test', async () => {
    const res = await server_8890.delete('/api/100')
      .set(options.std.headers)
    expect(res.statusCode).toBe(200)
    expect(res.body.meta.result).toBe('success')
  })
})
