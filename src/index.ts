// src/index.ts
import express, { Request, Response, NextFunction } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";

import dotenv from "dotenv";
import { verifyJWT } from "./middlewares/jwtMiddleware";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ Extend Request type properly
declare global {
  namespace Express {
    interface Request {
      user?: JwtPayload | string;
    }
  }
}

// 🔒 Protected route
app.get("/protected", verifyJWT, (req: Request, res: Response) => {
  res.json({
    message: "Protected content",
    user: req.user,
  });
});

app.get("/token", (req: Request, res: Response) => {
  console.log("Using secret:", process.env.JWT_SECRET);
  const token = jwt.sign(
    {
      sub: "user_id_123",
      aud: "api-client-id",
      azp: "app_client_id",
    },
    `your-256-bit-secret`,
    {
      expiresIn: "60",
    }
  );

  res.json({ token });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
