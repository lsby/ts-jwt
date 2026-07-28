import assert from 'assert'
import { test } from 'vitest'
import { JWT管理器 } from '../src/node.js'

test('异步签名和解析 JWT', async () => {
  let jwt = new JWT管理器<{ userId: string }>('test-secret', '1h')
  let token = await jwt.异步签名({ userId: 'user-1' })
  let payload = await jwt.异步解析(`Bearer ${token}`)

  assert.equal(payload?.userId, 'user-1')
})
