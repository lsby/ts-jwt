import { jwtVerify, SignJWT, type JWTPayload } from 'jose'

export class JWT管理器<JWT负载 extends object> {
  constructor(
    private secret: string,
    private expiresIn: number | string,
  ) {}

  async 异步签名(负载: JWT负载): Promise<string> {
    return await new SignJWT(负载 as JWTPayload)
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
