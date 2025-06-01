import { expect, test, describe } from 'bun:test'
import * as api from '../../lib/plugin-api'
// eslint-disable-next-line @typescript-eslint/no-unused-expressions
api

const baseUrl = 'http://localhost:8890'
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

describe('plugin-api', () => {
  test('post /api test', async () => {
    const objApi = {
      title: 'BMW X5',
      price: 58,
    }
    const res = await fetchSCIM('POST', '/api', objApi, options.content.headers)
    expect(res.status).toBe(201)
    expect(res.body.meta.result).toBe('success')
  })

  test('put /api/100 test', async () => {
    const objApi = {
      title: 'BMW X1',
      price: 21,
    }
    const res = await fetchSCIM('PUT', '/api/100', objApi, options.content.headers)
    expect(res.status).toBe(200)
    expect(res.body.meta.result).toBe('success')
  })

  test('patch /api/100 test', async () => {
    const objApi = {
      title: 'BMW X3',
    }
    const res = await fetchSCIM('PATCH', '/api/100', objApi, options.content.headers)
    expect(res.status).toBe(200)
    expect(res.body.meta.result).toBe('success')
  })

  test('get /api/100 test', async () => {
    const res = await fetchSCIM('GET', '/api/100', undefined, options.std.headers)
    expect(res.status).toBe(200)
    expect(res.body.meta.result).toBe('success')
  })
  test('delete /api/100 test', async () => {
    const res = await fetchSCIM('DELETE', '/api/100', undefined, options.std.headers)
    expect(res.status).toBe(200)
    expect(res.body.meta.result).toBe('success')
  })
})
