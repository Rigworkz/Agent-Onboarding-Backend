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
import { pool } from "../config/database";

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
  let connection;

  try {
    const { address } = req.query;

    if (!address || typeof address !== "string") {
      return res.status(400).json({ message: "Address is required" });
    }

    const normalizedAddress = address.toLowerCase();
    const nonce = crypto.randomBytes(16).toString("hex");
    const sessionId = uuidv4();
    const timestamp = Date.now();

    connection = await pool.getConnection();

    await connection.query(
      "DELETE FROM wallet_sessions WHERE operator_wallet = ? AND is_verified = false",
      [normalizedAddress],
    );

    await connection.query(
      `INSERT INTO wallet_sessions 
       (operator_wallet, session_id, nonce, timestamp, is_verified) 
       VALUES (?, ?, ?, ?, false)`,
      [normalizedAddress, sessionId, nonce, timestamp],
    );

    return res.json({ nonce, sessionId, timestamp });
  } catch (error) {
    console.error("GET NONCE ERROR:", error);
    return res.status(500).json({ message: "Internal server error" });
  } finally {
    if (connection) connection.release();
  }
};

export const verifyWallet = async (req: Request, res: Response) => {
  try {
    const { address, sessionId, signature } = req.body;
    // 1. Fetch session from DB
    const [rows]: any = await pool.query(
      `SELECT * FROM wallet_sessions WHERE session_id = ? AND operator_wallet = ?`,
      [sessionId, address],
    );
    if (rows.length === 0) {
      return res.status(400).json({ message: "Invalid session" });
    }
    const session = rows[0];
    // 2. Recreate message
    const message = `Welcome to RigWorkZ Wallet: ${address} Nonce: ${session.nonce} Timestamp: ${session.timestamp}`;

    // 3. Verify signature
    const recoveredAddress = ethers.verifyMessage(message, signature);
    if (recoveredAddress.toLowerCase() !== address.toLowerCase()) {
      return res.status(400).json({ message: "Invalid signature" });
    }
    // 4. Mark session verified
    await pool.query(
      `UPDATE wallet_sessions SET is_verified = true WHERE session_id = ?`,
      [sessionId],
    );
    //  5. GENERATE JWT HERE
    const secret = process.env.JWT_SECRET || "your_jwt_secret";

    const installToken = crypto.randomBytes(32).toString("hex");
    const expiresAt = Date.now() + 20 * 60 * 1000; // 20 min expiry
    await pool.query(
      `UPDATE wallet_sessions 
      SET is_verified = true,
          install_token = ?,
          signature = ?,
          token_expires_at=?
      WHERE session_id = ?`,
      [installToken, signature, expiresAt, sessionId],
    );

    const token = jwt.sign({ operator_wallet: address }, secret, {
      expiresIn: "1h",
    });

    return res.json({
      success: true,
      token,
      installToken,
    });
  } catch (error) {
    console.error("Verify error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const validateInstallToken = async (req: Request, res: Response) => {
  try {
    const { installToken } = req.body;
    if (!installToken) {
      return res.status(401).json({ message: "No token provided" });
    }

    const [rows]: any = await pool.query(
      `SELECT * FROM wallet_sessions 
       WHERE install_token = ? 
       AND token_expires_at > ?`,
      [installToken, Date.now()],
    );
    if (rows.length === 0) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }
    // mark as used (one-time)
    await pool.query(
      `UPDATE wallet_sessions 
       SET machine_count = machine_count + 1 
       WHERE install_token = ?`,
      [installToken],
    );

    return res.json({ success: true });
  } catch (error) {
    console.error("Token validation error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const bootstrapInstall = async (req: Request, res: Response) => {
  try {
    const { sid } = req.query;

    if (!sid || typeof sid !== "string") {
      return res.status(400).json({ message: "session id required" });
    }

    const [rows]: any = await pool.query(
      `SELECT install_token, token_expires_at 
       FROM wallet_sessions 
       WHERE session_id = ? AND is_verified = true`,
      [sid],
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "session not found" });
    }

    const session = rows[0];

    if (!session.install_token || session.token_expires_at < Date.now()) {
      return res.status(401).json({ message: "token expired or missing" });
    }

    return res.json({
      success: true,
      installToken: session.install_token,
    });
  } catch (err) {
    console.error("bootstrap error:", err);
    return res.status(500).json({ message: "internal error" });
  }
};
