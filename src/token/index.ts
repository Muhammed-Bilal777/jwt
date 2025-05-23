import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { randomUUID } from "crypto";
import dotenv from "dotenv";
dotenv.config();
async function generateRsaJwt() {
  const audience = process.env.JWT_AUDIENCE || "";

  // Step 1: Generate RSA key pair
  const { publicKey, privateKey } = await generateKeyPair("RS256");

  // Step 2: Export public JWK and enrich with additional metadata
  const publicJwk = await exportJWK(publicKey);
  publicJwk.alg = "RS256";
  publicJwk.use = "sig";
  publicJwk.kid = randomUUID();

  // Step 3: Define JWT payload (claims)
  const payload = {
    sub: "zopsmart",
    name: "zopsmart",
    admin: true,
    azp: "zopsmart-client-id",
  };

  // Step 4: Sign the JWT with RS256
  const jwt = await new SignJWT(payload)
    .setProtectedHeader({
      alg: "RS256",
      typ: "JWT",
      kid: publicJwk.kid,
    })
    .setIssuedAt()
    .setIssuer("zopsmart")
    .setAudience(audience)
    .setExpirationTime("1m")
    .sign(privateKey);

  console.log("🔐 JWT Token:\n", jwt);
  console.log("\n📢 Public JWK (shareable):\n", publicJwk);
}

generateRsaJwt();
