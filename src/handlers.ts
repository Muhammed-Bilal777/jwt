import { Request, Response } from "express";
import { generateToken, verifyToken } from "./jwt";

export const generateHandler = async (
  req: Request,
  res: Response
): Promise<any> => {
  try {
    const { userId, role } = req.body;
    if (!userId || !role) {
      return res.status(400).json({ error: "Missing userId or role" });
    }

    const token = await generateToken({ userId, role });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: "Token generation failed" });
  }
};

export const verifyHandler = async (
  req: Request,
  res: Response
): Promise<any> => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: "Token is required" });

    const payload = await verifyToken(token);
    res.json({ valid: true, payload });
  } catch (err) {
    res.status(401).json({ error: "Invalid or expired token" });
  }
};
