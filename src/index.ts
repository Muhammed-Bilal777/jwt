import express from "express";

import { generateHandler, verifyHandler } from "./handlers";

const app = express();
app.use(express.json());

// Endpoint 1: Generate JWT
app.post("/token", generateHandler);

// Endpoint 2: Verify JWT
app.post("/verify", verifyHandler);

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
