import express, { Request, Response, NextFunction } from "express";
import jwt, {
  JwtPayload,
  TokenExpiredError,
  JsonWebTokenError,
  NotBeforeError,
} from "jsonwebtoken";

declare global {
  namespace Express {
    interface Request {
      user?: JwtPayload | string;
    }
  }
}
export function verifyJWT(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const token = process.env.JWT_TOKEN || "";

  try {
    if (!process.env.JWT_SECRET) {
      throw new Error("JWT_SECRET is not defined in environment");
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      audience: "api-client-id",
    }) as JwtPayload;

    // Check for azp claim
    if (!decoded.azp) {
      res.status(400).json({ error: "Missing azp (authorized party) claim" });
    }

    if (decoded.azp !== "app_client_id") {
      res.status(403).json({ error: "Invalid azp (authorized party) claim" });
    }

    req.user = decoded;
    next();
  } catch (err: any) {
    if (err instanceof TokenExpiredError) {
      res.status(401).json({ error: "Token has expired" });
    }

    if (err instanceof JsonWebTokenError) {
      res.status(401).json({ error: `Invalid token: ${err.message}` });
    }

    if (err instanceof NotBeforeError) {
      res.status(401).json({ error: "Token not active yet (nbf claim)" });
    }

    console.error("JWT verification failed:", err);
    res
      .status(500)
      .json({ error: "Internal server error during token verification" });
  }
}
