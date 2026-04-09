// import { Request, Response } from 'express';
// import jwt from 'jsonwebtoken';

// export const login = (req: Request, res: Response) => {
//     // Mock authentication logic
//     const { username, password } = req.body;

//     // In a real application, you would verify the credentials against the database
//     if (username === 'admin' && password === 'password') {
//         const user = { id: 1, username: 'admin' };
//         const secret = process.env.JWT_SECRET || 'your_jwt_secret';

//         const token = jwt.sign(user, secret, { expiresIn: '1h' });

//         res.json({ token });
//     } else {
//         res.status(401).json({ message: 'Invalid credentials' });
//     }
// };
import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";
import { ethers } from "ethers";

const sessions = new Map<string, any>();

export const login = (req: Request, res: Response) => {
  const { operator_wallet } = req.body;

  const secret = process.env.JWT_SECRET || "your_jwt_secret";

  if (!operator_wallet) {
    return res.status(400).json({ message: "operator_wallet is required" });
  }

  const token = jwt.sign({ operator_wallet }, secret, { expiresIn: "1h" });

  return res.json({ token });
};

export const getNonce = async (req: Request, res: Response) => {
  try {
    const { address } = req.query;

    if (!address || typeof address !== "string") {
      return res.status(400).json({ message: "Address is required" });
    }

    const normalizedAddress = address.toLowerCase();

    const nonce = crypto.randomBytes(16).toString("hex");
    const sessionId = uuidv4();

    console.log("🆕 NEW NONCE:", sessionId, nonce);

    // 🔥 store in memory instead of DB
    sessions.set(sessionId, {
      address: normalizedAddress,
      nonce,
      createdAt: new Date(),
      is_used: false,
    });

    return res.json({ nonce, sessionId });
  } catch (error) {
    console.error("Nonce error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};
// add at top if not present

export const verifyWallet = async (req: Request, res: Response) => {
  try {
    const { sessionId, signature, message } = req.body;

    console.log("🔍 VERIFY CALLED:", sessionId);

    if (!sessionId || !signature || !message) {
      return res
        .status(400)
        .json({ message: "Missing sessionId or signature" });
    }

    const record = sessions.get(sessionId);

    if (!record) {
      return res.status(400).json({ message: "Invalid session" });
    }

    if (record.is_used) {
      return res.status(400).json({ message: "Nonce already used" });
    }

    // ⏱ expiry (5 min)
    const diff =
      (Date.now() - new Date(record.createdAt).getTime()) / (1000 * 60);

    if (diff > 5) {
      return res.status(400).json({ message: "Nonce expired" });
    }

    // 🔐 recover address
    const recoveredAddress = ethers.verifyMessage(message, signature);

    if (recoveredAddress.toLowerCase() !== record.address) {
      return res.status(400).json({ message: "Invalid signature" });
    }

    // mark used
    record.is_used = true;

    const installToken = crypto.randomBytes(16).toString("hex");

    return res.json({
      success: true,
      wallet: recoveredAddress,
      installToken,
    });
  } catch (error) {
    console.error("Verify error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};
