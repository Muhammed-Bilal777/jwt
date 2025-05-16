import { SignJWT, jwtVerify } from "jose";

// Keep this safe in env in production

export async function generateToken(payload: object): Promise<string> {
  const encoder = new TextEncoder();
  const secret = encoder.encode("your-secret-key");
  const token = await new SignJWT(payload as any)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(secret);

  return token;
}

export async function verifyToken(token: string): Promise<{}> {
  const encoder = new TextEncoder();
  const secret = encoder.encode("your-secret-key");
  try {
    const { payload } = await jwtVerify(token, secret);
    return { payload };
  } catch (err: any) {
    if (err.code === "ERR_JWT_EXPIRED") {
      return { error: "Token has expired" };
    }

    if (err.code === "ERR_JWT_CLAIM_INVALID") {
      return { error: `Invalid claim: ${err.claim}` };
    }

    if (err.code === "ERR_JWT_MALFORMED") {
      return { error: "Malformed token" };
    }

    if (err.code === "ERR_JWS_SIGNATURE_VERIFICATION_FAILED") {
      return { error: "Invalid signature" };
    }

    return { error: `Unknown error: ${err.message}` };
  }
}
