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
import { pool } from '../config/database';

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
    if (!address || typeof address !== 'string') {
      return res.status(400).json({ message: 'Address is required' });
    }
    const normalizedAddress = address.toLowerCase();
    const nonce = crypto.randomBytes(16).toString('hex');
    const sessionId = uuidv4();
    const timestamp = Date.now();
    const connection = await pool.getConnection();
    // Remove any old unused sessions for this address
    await connection.query(
      'DELETE FROM wallet_sessions WHERE address = ? AND is_verified = false',
      [normalizedAddress]
    );
    // Insert new session into the database
    try {
      const [result]: any = await connection.query(
        `INSERT INTO wallet_sessions 
        (address, session_id, nonce, timestamp, is_verified) 
        VALUES (?, ?, ?, ?, false)`,
        [normalizedAddress, sessionId, nonce, timestamp]
      );

    } catch (err) {
      console.error("Insert failed", err);
    }
    connection.release();
    // Return nonce and session ID to frontend
    return res.json({ nonce, sessionId, timestamp });
  } catch (error) {
    console.error('Nonce error:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};


export const verifyWallet = async (req: Request, res: Response) => {
  try {
    const { address, sessionId, signature } = req.body;
    // 1. Fetch session from DB
    const [rows]: any = await pool.query(
      `SELECT * FROM wallet_sessions WHERE session_id = ? AND address = ?`,
      [sessionId, address]
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
      [sessionId]
    );
    //  5. GENERATE JWT HERE
    const secret = process.env.JWT_SECRET || "your_jwt_secret";

    const installToken = crypto.randomBytes(32).toString("hex");
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 min expiry
    await pool.query(
      `UPDATE wallet_sessions 
      SET is_verified = true,
          install_token = ?,
          token_expires_at = ?,
          signature = ?
      WHERE session_id = ?`,
      [installToken, expiresAt, signature, sessionId]
    );

    const token = jwt.sign(
      { operator_wallet: address },
      secret,
      { expiresIn: "1h" }
    );

    // const payload = JSON.stringify({ installToken, address });
    // const secretIT = process.env.PAYLOAD_SECRET || "my_secret";
    // const combined = secretIT + payload;
    // const encodedPayload = Buffer.from(combined).toString("base64");

    // const decoded = Buffer.from(encodedPayload, "base64").toString("utf8");
    // const secret = "my_secret";
    // const json = decoded.substring(secret.length);
    // const data = JSON.parse(json);
    // const installToken = data.installToken;
    // const address = data.address;

    return res.json({
      success: true,
      token,
      installToken
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
       WHERE address = ?
       AND token_is_used = false 
       AND token_expires_at > ?`,
      [installToken, Date.now()]
    );
    if (rows.length === 0) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }
    // mark as used (one-time)
    await pool.query(
      `UPDATE wallet_sessions 
       SET token_is_used = true 
       WHERE install_token = ?`,
      [installToken]
    );

    return res.json({ success: true });

  } catch (error) {
    console.error("Token validation error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};
