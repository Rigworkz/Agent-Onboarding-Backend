
import { Request, Response } from "express";
import { pool } from "../config/database";
import { RowDataPacket } from "mysql2";
import { buildUpsertQuery } from "../utils/queryBuilder";
import * as crypto from "crypto";
import { machineToSocket } from "../websocket/socketServer";

/* ================= INTERFACES ================= */

interface MachineInfo {
    machine_id: string;
    operator: string;
    pool: string;
    operator_wallet: string;
    worker_id: string;
    fingerprint: string;
    created_at: number;
}

interface MachineStatus {
    operator_wallet?: string;
    machine_id: string;
    status: string;
    hashrate: number;
    uptime: number;
    last_heartbeat: number;
    temperature?: number;
    watt?: number;
}

interface MachineTelemetry {
    machine_id: string;
    operator_wallet: string;
    hashrate: number;
    rate_avg: number;
    temperature: number;
    uptime: number;
    watt: number;
    timestamp: number;
}

interface OnboardPayload {
    machine: MachineInfo;
    status: MachineStatus;
    telemetry: MachineTelemetry;
}

/* ================= ONBOARD ================= */

export const onboardMachine = async (req: Request, res: Response) => {
    const connection = await pool.getConnection();
    try {
        const data: OnboardPayload = req.body;
        const machine = data.machine;
        const status = {
            ...data.status,
            operator_wallet: machine.operator_wallet,
        };
        const telemetry = {
            ...data.telemetry,
            operator_wallet: machine.operator_wallet,
        };
        //console.log("FULL BODY:", req.body);
        if (!machine || !status || !telemetry) {
            return res.status(400).json({ message: "Invalid payload structure" });
        }
        if (!data.machine?.machine_id || !data.machine?.operator_wallet) {
            return res
                .status(400)
                .json({ message: "machine_id and operator_wallet are required" });
        }
        await connection.beginTransaction();
        /* ===== 1. MACHINES TABLE ===== */
        const { query: machineQuery, values: machineValues } = buildUpsertQuery(
            "machines",
            machine,
        );
        await connection.execute(machineQuery, machineValues);
        /* ===== 2. MACHINE STATUS ===== */
        const { query: statusQuery, values: statusValues } = buildUpsertQuery(
            "machine_status",
            status,
        );
        await connection.execute(statusQuery, statusValues);

        /* ===== 3. MACHINE TELEMETRY ===== */
        const fingerprintPayload = [
            telemetry.machine_id,
            telemetry.operator_wallet,
            telemetry.hashrate,
            telemetry.rate_avg,
            telemetry.temperature,
            telemetry.uptime,
            telemetry.watt,
            telemetry.timestamp,
        ].join("|");

        const childFingerprint = crypto
            .createHash("sha256")
            .update(fingerprintPayload)
            .digest("hex");


        const telemetryQuery = `
            INSERT INTO machine_telemetry 
            (operator_wallet, machine_id, child_fingerprint, hashrate, rate_avg, temperature, uptime, watt, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        const telemetryValues = [
            telemetry.operator_wallet,
            telemetry.machine_id,
            childFingerprint,
            telemetry.hashrate,
            telemetry.rate_avg,
            telemetry.temperature,
            telemetry.uptime,
            telemetry.watt,
            telemetry.timestamp,
        ];
        await connection.execute(telemetryQuery, telemetryValues);
        await connection.commit();

        res.status(200).json({
            message: "Machine onboarded successfully",
            machine_id: data.machine.machine_id,
        });
    } catch (error) {
        await connection.rollback();
        console.error("Error onboarding machine:", error);
        res.status(500).json({ message: "Internal server error" });
    } finally {
        connection.release();
    }
};

/* ================= GET MACHINE ================= */

export const getMachine = async (req: Request, res: Response) => {
    let connection;

    try {
        const { machine_id } = req.params;
        connection = await pool.getConnection();

        const [rows] = await connection.execute<RowDataPacket[]>(
            `SELECT 
            m.operator_wallet,
            m.machine_id,
            m.operator,
            m.pool,
            m.worker_id,
            m.fingerprint,
            m.created_at,
            
            s.status,
            s.hashrate,
            s.uptime,
            s.last_heartbeat,
            s.temperature,
            s.watt
        FROM machines m
        LEFT JOIN machine_status s 
        ON m.operator_wallet = s.operator_wallet
        WHERE m.machine_id = ?`,
            [machine_id],
        );
        if (rows.length === 0) {
            return res.status(404).json({ message: "Machine not found" });
        }

        res.json(rows[0]);
    } catch (error) {
        console.error("Error fetching machine:", error);
        res.status(500).json({ message: "Internal server error" });
    } finally {
        if (connection) connection.release();
    }
};
/* ================= GET MACHINE STATUS ================= */

export const getMachineStatus = async (req: Request, res: Response) => {
    let connection;

    try {
        const { machine_id } = req.params;
        connection = await pool.getConnection();

        const [rows] = await connection.execute<RowDataPacket[]>(
            "SELECT * FROM machine_status WHERE machine_id = ?",
            [machine_id],
        );
        if (rows.length === 0) {
            return res.status(404).json({ message: "Status not found" });
        }
        res.json(rows[0]);
    } catch (error) {
        console.error("Error fetching status:", error);
        res.status(500).json({ message: "Internal server error" });
    } finally {
        if (connection) connection.release(); //
    }
};

/* ================= GET TELEMETRY ================= */

export const getMachineTelemetry = async (req: Request, res: Response) => {
    try {
        const { machine_id } = req.params;
        const connection = await pool.getConnection();

        const [rows] = await connection.execute<RowDataPacket[]>(
            `SELECT * FROM machine_telemetry 
             WHERE machine_id = ? 
             ORDER BY timestamp DESC 
             LIMIT 50`,
            [machine_id],
        );

        connection.release();

        res.json(rows);
    } catch (error) {
        console.error("Error fetching telemetry:", error);
        res.status(500).json({ message: "Internal server error" });
    }
};


export const getAllMachines = async (req: Request, res: Response) => {
    let connection;

    try {
        connection = await pool.getConnection();

        const [rows] = await connection.execute(`
      SELECT 
        m.machine_id AS id,
        m.operator,
        m.pool,
        s.status,
        s.hashrate,
        s.uptime,
        s.last_heartbeat
      FROM machines m
      LEFT JOIN machine_status s 
      ON m.machine_id = s.machine_id
    `);

        res.json(rows);
    } catch (error) {
        console.error("Error fetching machines:", error);
        res.status(500).json({ message: "Internal server error" });
    } finally {
        if (connection) connection.release();
    }
};

export const getMachineIdByWallet = async (req: Request, res: Response) => {
    try {
        const { address } = req.params;

        const connection = await pool.getConnection();

        const [rows]: any = await connection.execute(
            `SELECT machine_id FROM machines WHERE operator_wallet = ?`,
            [address],
        );

        connection.release();

        if (rows.length === 0) {
            return res.status(404).json({ message: "Machine not found" });
        }
        // return res.json({
        //     machine_id: rows[0].machine_id,
        // });
        return res.json({
            machine_ids: rows.map(
                (row: any) => row.machine_id
            ),
        });


    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Server error" });
    }

};

export const generateAndSaveFingerprint = async (req: Request, res: Response) => {
    let connection;

    try {
        const { machineId } = req.body;

        if (!machineId) {
            return res.status(400).json({ message: "Missing required fields" });
        }
        connection = await pool.getConnection();

        // 1. Get machine_id using address
        const [machineRows]: any = await connection.execute(
            `SELECT * FROM machines WHERE machine_id = ?`,
            [machineId]
        );
        if (machineRows.length === 0) {
            return res.status(404).json({ message: "Machine not found" });
        }
        const machine = machineRows[0];

        if (machine.fingerprint) {
            return res.status(400).json({
                message: "Machine is already registered"
            });
        }

        const parent_secret = process.env.PARENT_SIGN_SECRET;
        const address = machine.operator_wallet;
        const payload = {
            machineId,
            address,
            parent_secret
        };
        //  4. Generate hash
        const crypto = require("crypto");
        const fingerprint = crypto
            .createHash("sha256")
            .update(JSON.stringify(payload), "utf8")
            .digest("hex");
        //  5. Update machines table
        await connection.execute(
            `UPDATE machines SET fingerprint = ? WHERE machine_id = ?`,
            [fingerprint, machineId]
        );

        return res.json({ fingerprint, machineId });

    } catch (error) {
        console.error("Error generating fingerprint:", error);
        return res.status(500).json({ message: "Internal server error" });
    } finally {
        if (connection) connection.release();
    }
};

export const registerMachine = async (req: Request, res: Response) => {
    try {
        const { installToken, machineId, publicKey, detectedOS, minerIp } = req.body;
        if (!installToken || !machineId || !publicKey || !minerIp) {
            return res.status(400).json({ message: "Missing required fields" });
        }

        const [rows]: any = await pool.query(
            `SELECT * FROM wallet_sessions 
                WHERE install_token = ? 
                AND token_expires_at > ?`,
            [installToken, Date.now()]
        );
        if (rows.length === 0) {
            return res.status(401).json({ message: "Invalid or expired token" });
        }
        const session = rows[0];
        const walletAddress = session.operator_wallet;
        if (!walletAddress) {
            console.error("Session missing operator_wallet:", session);
            return res.status(500).json({ message: "Wallet address missing in session" });
        }
        await pool.query(
            `INSERT INTO machines (machine_id, operator_wallet, public_key, detected_os, miner_ip)
            VALUES (?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE 
                detected_os = VALUES(detected_os),
                miner_ip = VALUES(miner_ip),
                public_key = VALUES(public_key)`,
            [machineId, walletAddress.toLowerCase(), publicKey, detectedOS, minerIp]
        );
        return res.json({ success: true });

    } catch (error) {
        console.error("Registration error:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
};


export const getEncryptedAddress = async (req: Request, res: Response) => {
    try {
        const { machineId } = req.query;
        if (!machineId) {
            return res.status(400).json({ message: "Machine id is required" });
        }
        const [rows]: any = await pool.query(
            `SELECT operator_wallet, public_key
             FROM machines
             WHERE machine_id =?`,
            [machineId]
        );
        if (rows.length === 0) {
            return res.status(404).json({ message: "Machine not found" });
        }
        const { operator_wallet, public_key } = rows[0];
        if (!operator_wallet || !public_key) {
            return res.status(500).json({ message: "missing data in DB" });
        }
        const cleanKey: string = public_key.replace(/\\n/g, "\n").replace(/^\s+|\s+$/gm, "").trim();
        const encrypted = crypto.publicEncrypt(
            {
                key: cleanKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            },
            Buffer.from(operator_wallet)
        );
        const encryptedBase64 = encrypted.toString("base64");
        return res.json({
            success: true,
            encryptedAddress: encryptedBase64
        });
    } catch (error) {
        console.error("Encryption error: ", error);
        return res.status(500).json({ message: "Internal Server error" });
    }
};



export const runConnectivityTest = async (req: Request, res: Response) => {
    let connection;

    try {
        const { machineId } = req.body;

        if (!machineId) {
            return res.status(400).json({
                success: false,
                message: "machineId is required",
            });
        }

        connection = await pool.getConnection();

        const [machineRows]: any = await connection.execute(
            `
            SELECT *
            FROM machines
            WHERE machine_id = ?
            LIMIT 1
            `,
            [machineId]
        );

        if (machineRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Machine not found",
            });
        }

        const machine = machineRows[0];

        const ws = machineToSocket.get(machine.machine_id);

        if (!ws) {
            return res.status(400).json({
                success: false,
                message: "Agent is offline",
            });
        }

        const testRunId = crypto.randomUUID();
        const challengeNonce = crypto.randomUUID();

        await connection.execute(
            `INSERT INTO connectivity_tests(
                test_run_id,
                machine_id,
                challenge_nonce,
                status
            ) VALUES(
                ?, ?, ?, ?
            )`, [testRunId, machine.machine_id, challengeNonce, "PENDING"]
        );

        console.log(
            `Starting connectivity test ${testRunId} for machine ${machine.machine_id}`
        );
        ws.send(
            JSON.stringify({
                action: "CHALLENGE_REQUEST",
                machine_id: machine.machine_id,
                testRunId,
                challengeNonce,
            })
        );

        console.log(
            `Connectivity test started for machine ${machine.machine_id}`
        );

        return res.status(200).json({
            success: true,
            machineId: machine.machine_id,
            testRunId,
            status: "RUNNING",
            message: "Connectivity test started",
        });
    } catch (error) {
        console.error("Connectivity test failed:", error);
        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }
};

export const getConnectivityTestResult = async (
    req: Request,
    res: Response
) => {
    let connection;

    try {
        const { testRunId } = req.params;

        connection = await pool.getConnection();

        const [rows]: any = await connection.execute(
            `
            SELECT
                test_run_id,
                machine_id,
                status,
                network_result,
                security_result,
                heartbeat_result,
                completed_at
            FROM connectivity_tests
            WHERE test_run_id = ?
            LIMIT 1
            `,
            [testRunId]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Test not found",
            });
        }

        const test = rows[0];

        return res.status(200).json({
            success: true,

            machineId: test.machine_id,
            testRunId: test.test_run_id,

            status: test.status,

            network: Boolean(test.network_result),
            security: Boolean(test.security_result),
            heartbeat: Boolean(test.heartbeat_result),

            completedAt: test.completed_at,
        });

    } catch (error) {
        console.error(error);

        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }
};

export const getUnregisteredMachinesByWallet = async (
    req: Request,
    res: Response
) => {
    let connection;
    console.log(1);
    try {
        const { walletAddress } = req.params;

        console.log(2);
        if (!walletAddress) {
            console.log(3);
            return res.status(400).json({
                success: false,
                message: "Wallet address is required",
            });
        }
        const wallet = String(walletAddress).toLowerCase();
        connection = await pool.getConnection();

        const [rows]: any = await connection.execute(
            `
            SELECT *
            FROM machines
            WHERE operator_wallet = ?
            
            ORDER BY created_at DESC
            `,
            [wallet]
        );
        console.log(4);
        return res.status(200).json({
            success: true,
            machines: rows,
        });
        console.log(1);

    } catch (error) {
        console.error("Error fetching unregistered machines:", error);
        console.log(5);
        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }
};