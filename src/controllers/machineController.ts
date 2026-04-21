// import { Request, Response } from 'express';
// import { pool } from '../config/database';
// import { RowDataPacket, ResultSetHeader } from 'mysql2';
// import { buildUpsertQuery } from '../utils/queryBuilder';

// interface MachineMetrics {
//     hashrate_ths: number;
//     last_share_ts: number;
//     est_earnings_24h: number;
//     pool_status_code: number;
// }

// interface MachineData {
//     machine_id: string;
//     derived_device_id: string;
//     operator_wallet: string;
//     operator_name: string;
//     pool: string;
//     actual_worker_name: string;
//     rig_fingerprint: string,
//     worker_compliance_status: string;
//     computed_status: string;
//     last_heartbeat_at: number;
//     metrics: MachineMetrics;

// }

// export const onboardMachine = async (req: Request, res: Response) => {
//     try {
//         const data = req.body;

//         // Basic validation
//         if (!data.machine_id || !data.operator_wallet) {
//             return res.status(400).json({ message: 'machine_id and operator_wallet are required' });
//         }

//         // Flatten the data for the database
//         const dbData = {
//             machine_id: data.machine_id,
//             derived_device_id: data.derived_device_id,
//             operator_wallet: data.operator_wallet,
//             operator_name: data.operator_name,
//             pool: data.pool,
//             actual_worker_name: data.actual_worker_name,
//             rig_fingerprint: data.rig_fingerprint,
//             worker_compliance_status: data.worker_compliance_status,
//             computed_status: data.computed_status,
//             last_heartbeat_at: data.last_heartbeat_at,
//             hashrate_ths: data.metrics?.hashrate_ths || 0,
//             last_share_ts: data.metrics?.last_share_ts || 0,
//             est_earnings_24h: data.metrics?.est_earnings_24h || 0,
//             pool_status_code: data.metrics?.pool_status_code || 0
//         };

//         const { query, values } = buildUpsertQuery('machines', dbData);

//         const connection = await pool.getConnection();
//         await connection.execute(query, values);
//         connection.release();

//         res.status(200).json({ message: 'Machine onboarded/updated successfully', machine_id: data.machine_id });
//     } catch (error) {
//         console.error('Error onboarding machine:', error);
//         res.status(500).json({ message: 'Internal server error' });
//     }
// };

// export const getMachine = async (req: Request, res: Response) => {
//     try {
//         const { machine_id } = req.params;
//         const connection = await pool.getConnection();

//         const [rows] = await connection.execute<RowDataPacket[]>('SELECT * FROM machines WHERE machine_id = ?', [machine_id]);
//         connection.release();

//         if (rows.length === 0) {
//             return res.status(404).json({ message: 'Machine not found' });
//         }

//         const row = rows[0];

//         // Reconstruct the response object to match the requested format
//         const responseData: MachineData = {
//             machine_id: row.machine_id,
//             derived_device_id: row.derived_device_id,
//             operator_wallet: row.operator_wallet,
//             operator_name: row.operator_name,
//             pool: row.pool,
//             actual_worker_name: row.actual_worker_name,
//             rig_fingerprint: row.rig_fingerprint,
//             worker_compliance_status: row.worker_compliance_status,
//             computed_status: row.computed_status,
//             last_heartbeat_at: parseInt(row.last_heartbeat_at), // Ensure number
//             metrics: {
//                 hashrate_ths: row.hashrate_ths,
//                 last_share_ts: parseInt(row.last_share_ts),
//                 est_earnings_24h: row.est_earnings_24h,
//                 pool_status_code: row.pool_status_code
//             }
//         };

//         res.json(responseData);
//     } catch (error) {
//         console.error('Error fetching machine:', error);
//         res.status(500).json({ message: 'Internal server error' });
//     }
// };
// export const getAllMachines = async (req: Request, res: Response) => {
//     try {
//         const connection = await pool.getConnection();

//         const [rows] = await connection.execute<RowDataPacket[]>(
//             'SELECT * FROM machines'
//         );

//         connection.release();

//         const machines: MachineData[] = rows.map((row) => ({
//             machine_id: row.machine_id,
//             derived_device_id: row.derived_device_id,
//             operator_wallet: row.operator_wallet,
//             operator_name: row.operator_name,
//             pool: row.pool,
//             actual_worker_name: row.actual_worker_name,
//             rig_fingerprint: row.rig_fingerprint,
//             worker_compliance_status: row.worker_compliance_status,
//             computed_status: row.computed_status,
//             last_heartbeat_at: parseInt(row.last_heartbeat_at),
//             metrics: {
//                 hashrate_ths: row.hashrate_ths,
//                 last_share_ts: parseInt(row.last_share_ts),
//                 est_earnings_24h: row.est_earnings_24h,
//                 pool_status_code: row.pool_status_code
//             }
//         }));

//         res.json(machines);

//     } catch (error) {
//         console.error('Error fetching machines:', error);
//         res.status(500).json({ message: 'Internal server error' });
//     }
// };


import { Request, Response } from 'express';
import { pool } from '../config/database';
import { RowDataPacket } from 'mysql2';
import { buildUpsertQuery } from '../utils/queryBuilder';

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
    machine_id: string;
    status: string;
    hashrate: number;
    uptime: number;
    last_heartbeat: number;
}

interface MachineTelemetry {
    machine_id: string;
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
        const status = data.status;
        const telemetry = data.telemetry;

        console.log("FULL BODY:", req.body);
        if (!machine || !status || !telemetry) {
            return res.status(400).json({ message: 'Invalid payload structure' });
        }
        if (!data.machine?.machine_id || !data.machine?.operator_wallet) {
            return res.status(400).json({ message: 'machine_id and operator_wallet are required' });
        }

        await connection.beginTransaction();

        /* ===== 1. MACHINES TABLE ===== */
        const { query: machineQuery, values: machineValues } = buildUpsertQuery(
            'machines',
            machine
        );
        await connection.execute(machineQuery, machineValues);

        /* ===== 2. MACHINE STATUS ===== */
        const { query: statusQuery, values: statusValues } = buildUpsertQuery(
            'machine_status',
            status
        );
        await connection.execute(statusQuery, statusValues);

        /* ===== 3. MACHINE TELEMETRY ===== */
        const telemetryQuery = `
            INSERT INTO machine_telemetry 
            (machine_id, hashrate, rate_avg, temperature, uptime, watt, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;

        const telemetryValues = [
            telemetry.machine_id,
            telemetry.hashrate,
            telemetry.rate_avg,
            telemetry.temperature,
            telemetry.uptime,
            telemetry.watt,
            telemetry.timestamp
        ];

        await connection.execute(telemetryQuery, telemetryValues);

        await connection.commit();

        res.status(200).json({
            message: 'Machine onboarded successfully',
            machine_id: data.machine.machine_id
        });

    } catch (error) {
        await connection.rollback();
        console.error('Error onboarding machine:', error);
        res.status(500).json({ message: 'Internal server error' });
    } finally {
        connection.release();
    }
};

/* ================= GET MACHINE ================= */

// export const getMachine = async (req: Request, res: Response) => {
//     try {
//         const { machine_id } = req.params;
//         const connection = await pool.getConnection();

//         const [rows] = await connection.execute<RowDataPacket[]>(
//             'SELECT * FROM machines WHERE machine_id = ?',
//             [machine_id]
//         );

//         connection.release();

//         if (rows.length === 0) {
//             return res.status(404).json({ message: 'Machine not found' });
//         }

//         res.json(rows[0]);

//     } catch (error) {
//         console.error('Error fetching machine:', error);
//         res.status(500).json({ message: 'Internal server error' });
//     }
// };
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
            m.signature,
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
            [machine_id]
        );
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Machine not found' });
        }

        res.json(rows[0]);

    } catch (error) {
        console.error('Error fetching machine:', error);
        res.status(500).json({ message: 'Internal server error' });
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
            'SELECT * FROM machine_status WHERE machine_id = ?',
            [machine_id]
        );
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Status not found' });
        }
        res.json(rows[0]);

    } catch (error) {
        console.error('Error fetching status:', error);
        res.status(500).json({ message: 'Internal server error' });
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
            [machine_id]
        );

        connection.release();

        res.json(rows);

    } catch (error) {
        console.error('Error fetching telemetry:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

/* ================= GET ALL MACHINES ================= */

// export const getAllMachines = async (_req: Request, res: Response) => {
//     try {
//         const connection = await pool.getConnection();

//         const [rows] = await connection.execute<RowDataPacket[]>(
//             'SELECT * FROM machines'
//         );

//         connection.release();

//         res.json(rows);

//     } catch (error) {
//         console.error('Error fetching machines:', error);
//         res.status(500).json({ message: 'Internal server error' });
//     }
// };
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
            [address]
        );

        connection.release();

        if (rows.length === 0) {
            return res.status(404).json({ message: "Machine not found" });
        }

        return res.json({
            machine_id: rows[0].machine_id
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Server error" });
    }
};


export const generateAndSaveFingerprint = async (req: Request, res: Response) => {
    let connection;

    try {
        const { address, signature } = req.body;

        if (!address || !signature) {
            return res.status(400).json({ message: "Missing required fields" });
        }

        connection = await pool.getConnection();

        // 1. Get machine_id using address
        const [machineRows]: any = await connection.execute(
            `SELECT machine_id, fingerprint FROM machines WHERE operator_wallet = ?`,
            [address]
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
        const machineId = machine.machine_id;

        //  2. Fetch latest telemetry
        const [telemetryRows]: any = await connection.execute(
            `SELECT * FROM machine_telemetry 
             WHERE machine_id = ? 
             ORDER BY timestamp DESC 
             LIMIT 1`,
            [machineId]
        );

        if (telemetryRows.length === 0) {
            return res.status(404).json({ message: "Telemetry not found" });
        }

        const telemetry = telemetryRows[0];

        //  3. Create payload
        const payload = {
            telemetry,
            address,
            signature
        };

        //  4. Generate hash
        const crypto = require("crypto");
        const fingerprint = crypto
            .createHash("sha256")
            .update(JSON.stringify(payload), "utf8")
            .digest("hex");

        //  5. Update machines table
        await connection.execute(
            `UPDATE machines SET fingerprint = ? WHERE operator_wallet = ?`,
            [fingerprint, address]
        );

        return res.json({ fingerprint, machineId });

    } catch (error) {
        console.error("Error generating fingerprint:", error);
        return res.status(500).json({ message: "Internal server error" });
    } finally {
        if (connection) connection.release();
    }
};