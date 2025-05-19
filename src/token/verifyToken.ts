import { jwtVerify, importJWK, JWK, JWTPayload } from "jose";
import dotenv from "dotenv";
dotenv.config();
const publicJwk: JWK = {
  kty: "RSA",
  n: "uG6tV1oQgfqSw8kauQ-upUyow7MGMkhIqypQsDUR6-DZyQgTgkUDpx6pAvaZaV0wwQjUwsEIj2DIVeb1sk0uams_IUQ5WRmyNn9-s_pz5bXpOc1peFfphHLzPZ1DYoB6y_6cRuChJaz0bUkxXY-bW9dVjNzavCC6IcUejo2FeDgfwLG1PlKlxzXuWZSfNZdqCyfDfXdPn4newCiV5oIVKM2NJ8QEtfoLViRcn42I6iABKQazQmJA8Wv0239w0Ge5tO81gTSY8gVYAa_9zdAEzbfRs623CU8jATp-eK1O2KzC151eCkZ_CjHFw-ku19Jhhu-c4QJrfzrDgNeCryUB4w",
  e: "AQAB",
  alg: "RS256",
  use: "sig",
  kid: "2a26a6e8-a605-4a47-97cb-fc89602575a3",
};
const audience = process.env.JWT_AUDIENCE || "";
//invalid audience
// const audience = "sdfgb";
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
    issuer: "zopsmart",
    audience: audience,
  });
  if (payload.azp) {
    console.log(payload.azp);
  }
  return payload;
}
const token = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjJhMjZhNmU4LWE2MDUtNGE0Ny05N2NiLWZjODk2MDI1NzVhMyJ9.eyJzdWIiOiJ6b3BzbWFydCIsIm5hbWUiOiJ6b3BzbWFydCIsImFkbWluIjp0cnVlLCJhenAiOiJ6b3BzbWFydC1jbGllbnQtaWQiLCJpYXQiOjE3NDc2MjQwMDAsImlzcyI6InpvcHNtYXJ0IiwiYXVkIjoiem9wc21hcnQiLCJleHAiOjE4MTA3MzkyMDB9.BncnfEq2rtZVX2dlrkjVRlFkWzmJQb5bFUJwMCKxkCj6bW_Dg5cMooKPmYsP6Q3MQDiTV3wB6iDMMuGE5_n9OsUmdQo25_cbR6_l0DEgEi0CvPv1UJsjw8LzsHffVbIFbJp2fPm_WAIo13ZTP49t6IV_zx7P6i65usLy5gcBYHt-LzA2iyWyqQ68lgyIZtF-l-ww8n62N01eTi3QQ9CNFNlHtyLlo-BzhN0iNE0nn2wVZSKU0Rg0eGrVPDbs_lz1zx0Nhvq9HCHPwATy0coZ72do2v3Re0I3QKDQJLgkfGbry7lyWOAyySLd-EqfMf6YujpNLIUXkM9Ph1P8WTk0vA`;

async function verify() {
  try {
    const payload = await verifyJwtWithPublicKey(token);

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
  console.log(result);
}
main();
