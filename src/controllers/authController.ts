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

    // 3. Verify signature (you already have logic or use ethers)
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

    const token = jwt.sign(
      { operator_wallet: address },
      secret,
      { expiresIn: "1h" }
    );

    return res.json({
      success: true,
      token
    });

  } catch (error) {
    console.error("Verify error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};


export const validateInstallToken = (req: any, res: any) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ message: "No token" });
    }

    const token = authHeader.startsWith("Bearer ")
      ? authHeader.split(" ")[1]
      : null;

    if (!token) {
      return res.status(401).json({ message: "Invalid token format" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET!);

    req.user = decoded;

    return res.json({ success: true });

  } catch (err) {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
};


// export const verifyWallet = async (req: Request, res: Response) => {
//   try {
//     const { address, sessionId, signature } = req.body;

//     console.log("VERIFY CALLED:", sessionId);

//     if (!sessionId || !signature || !address) {
//       return res.status(400).json({
//         message: "sessionId, signature and address are required",
//       });
//     }
//     const connection = await pool.getConnection();
//     await connection.query(
//       `UPDATE wallet_sessions SET signature = ? WHERE session_id = ?`,
//       [signature, sessionId]
//     );

//     //  Fetch session from DB
//     const [rows]: any = await connection.query(
//       `SELECT * FROM wallet_sessions WHERE session_id = ?`,
//       [sessionId]
//     );

//     if (rows.length === 0) {
//       connection.release();
//       return res.status(400).json({ message: "Invalid session" });
//     }

//     const session = rows[0];

//     //  Check already used
//     if (session.is_verified) {
//       connection.release();
//       return res.status(400).json({ message: "Session already verified" });
//     }

//     // Expiry check (5 min)
//     const now = Date.now();
//     const sessionTime = session.timestamp;

//     if (now - sessionTime > 5 * 60 * 1000) {
//       connection.release();
//       return res.status(400).json({ message: "Session expired" });
//     }

//     //Reconstruct message (DO NOT trust frontend)
//     const message = `Welcome to RigWorkZ Wallet: ${session.address} Nonce: ${session.nonce} Timestamp: ${session.timestamp}`;

//     console.log(" Message used:", message);

//     //  Verify signature
//     const recoveredAddress = ethers.verifyMessage(message, signature);

//     if (recoveredAddress.toLowerCase() !== session.address.toLowerCase()) {
//       connection.release();
//       return res.status(400).json({ message: "Invalid signature" });
//     }

//     // Generate install token
//     const installToken = crypto.randomBytes(32).toString("hex");
//     const expiresAt = Date.now() + 5 * 60 * 1000; // 5 min

//     // Update DB
//     await connection.query(
//       `UPDATE wallet_sessions
//        SET is_verified = true, install_token = ?, token_expires_at = ?
//        WHERE session_id = ?`,
//       [installToken, expiresAt, sessionId]
//     );

//     connection.release();

//     //  Return response
//     return res.json({
//       success: true,
//       wallet: recoveredAddress,
//       installToken,
//     });

//   } catch (error) {
//     console.error(" Verify error:", error);
//     return res.status(500).json({ message: "Internal server error" });
//   }
// };

// export const validateInstallToken = async (req: Request, res: Response) => {
//   let connection;
//   try {
//     console.log(" Validate Token API HIT");

//     const { installToken } = req.body;

//     if (!installToken) {
//       return res.status(400).json({ message: "Token is required" });
//     }

//     connection = await pool.getConnection();

//     const [rows]: any = await connection.query(
//       `SELECT * FROM wallet_sessions
//        WHERE install_token = ?
//        LIMIT 1`,
//       [installToken]
//     );

//     if (rows.length === 0) {
//       return res.status(401).json({ message: "Invalid token" });
//     }

//     const session = rows[0];

//     // Check verified
//     if (!session.is_verified) {
//       return res.status(403).json({ message: "Not verified" });
//     }

//     // Check already used
//     if (session.token_is_used) {
//       return res.status(401).json({ message: "Token already used" });
//     }

//     //  Check expiry (TIMESTAMP → convert to JS Date)
//     const expiryTime = new Date(session.token_expires_at).getTime();

//     if (Date.now() > expiryTime) {
//       return res.status(401).json({ message: "Token expired" });
//     }

//     // Mark token as used (IMPORTANT)
//     await connection.query(
//       `UPDATE wallet_sessions
//        SET token_is_used = TRUE
//        WHERE session_id = ?`,
//       [session.session_id]
//     );

//     return res.json({
//       success: true,
//       message: "Token is valid",
//       wallet: session.address,
//     });

//   } catch (error) {
//     console.error(" Validate token error:", error);
//     return res.status(500).json({ message: "Internal server error" });
//   } finally {
//     if (connection) connection.release();
//   }
// };

