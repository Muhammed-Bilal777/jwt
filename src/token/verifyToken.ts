import { jwtVerify, importJWK, JWK, JWTPayload } from "jose";

const publicJwk: JWK = {
  kty: "RSA",
  n: "wnS5wFE_AAwJ8lQ-rIsHPRh5lojiOx7BEz80VuXCDAIqSdjAZ9AF5JlLfCndXI5r--jtGHDrm0TyAFsYxnI2Aq7FFkuIlxPNdS9KZ15Rr8zoLFHcrXocZUMQVWna4FlADioecijkbZ67WC4Xux4J_ILpUUgDxtAzk5ix8Iy6clhZ1u9FJpwxM7DjZ4kqFBzE-l3kc15QVFxO6X198QqhJgjlJnXuB71SgdJKRcbabE71zq5EOpUGXfkrNa8UOAceN8Y8HXf7wUrcgHICYxrDbv5ykWztIhuNC2uep9wiurphfA-EVctz-lKaDcZ-_kDxbNK_BA72EVHvVnO-aZrs0Q",
  e: "AQAB",
  alg: "RS256",
  use: "sig",
  kid: "34eafeeb-60dc-42a4-b0b0-3bc5d5b78f4f",
};

/**
 * Verifies a JWT using the provided RSA public JWK and expected claims.
 */
export async function verifyJwtWithPublicKey(
  token: string
): Promise<JWTPayload> {
  // Import the JWK as a public CryptoKey
  const publicKey = await importJWK(publicJwk, "RS256");

  // Verify the token with expected issuer and audience
  const { payload } = await jwtVerify(token, publicKey, {
    issuer: "my-issuer",
    audience: "my-audience",
  });

  return payload;
}
const token = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjM0ZWFmZWViLTYwZGMtNDJhNC1iMGIwLTNiYzVkNWI3OGY0ZiJ9.eyJzdWIiOiJ1c2VyMTIiLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiaWF0IjoxNzQ3NDUzNjE1LCJpc3MiOiJteS1pc3N1ZXIiLCJhdWQiOiJteS1hdWRpZW5jZSIsImV4cCI6MTc0NzQ1MzY3NX0.NCalgbjGxnxYTKd0nZ6cdg09kSfwn27MzAqVRotJfNvd8m3wt4WzFsfBkEjtDIf_FTMuwzoU5V1YNtDKdA_TDRmt1K9rme6bQ-sgLAXsVdNeqIm9F9DjsvcMUN1MP2dE2TKNpTXEim1ENjh70MspkT_ZLM4oqvyY7B95KhRLaI5S4RnAgYHOao45yKeF0ZdSm42lAqffv8GxzHGcqDS07V933Id0UnjMxJQWCg4T42pko5aIQP-4uXdvh_6yboLKn_OdgvKJ0pBLZ9VCu1R_h0xmupV6_oA7BUrPFCYtc2SMYskUXsx1JTImyUSoBaVLSSgg7IXB-btSxEyonsuHmQ`;

async function verify() {
  try {
    const { payload } = await verifyJwtWithPublicKey(token);
    console.log(payload);
    return payload;
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
async function main() {
  const result = await verify();
  console.log(result); // ✅ Correct output here
}
main();
