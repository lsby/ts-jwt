import { jwtVerify, SignJWT, type JWTPayload } from 'jose'
import jwt from 'jsonwebtoken'
import type { StringValue } from 'ms'

export class JWT管理器<JWT负载 extends string | object | Buffer> {
  constructor(
    private secret: string,
    private expiresIn: number | StringValue,
  ) {}

  签名(负载: JWT负载): string {
    var token = jwt.sign(负载, this.secret, {
      expiresIn: this.expiresIn,
    })
    return token
  }

  解析(token: string | undefined): JWT负载 | undefined {
    if (token === undefined) {
      return undefined
    }

    token = token.replace('Bearer ', '')
    try {
      return jwt.verify(token, this.secret) as JWT负载
    } catch {
      return undefined
    }
  }

  async 异步签名(负载: JWT负载): Promise<string> {
    let payload: unknown = 负载
    if (typeof payload !== 'object' || payload === null) {
      throw new TypeError('异步 JWT 签名只支持对象负载')
    }

    return await new SignJWT(payload as JWTPayload)
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setIssuedAt()
      .setExpirationTime(this.expiresIn)
      .sign(new TextEncoder().encode(this.secret))
  }

  async 异步解析(token: string | undefined): Promise<JWT负载 | undefined> {
    if (token === undefined) return undefined

    token = token.replace(/^Bearer\s+/i, '')
    try {
      let result = await jwtVerify(token, new TextEncoder().encode(this.secret))
      return result.payload as JWT负载
    } catch {
      return undefined
    }
  }
}
