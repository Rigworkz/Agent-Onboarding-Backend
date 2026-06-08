import crypto from "crypto";
import { pool } from "../config/database";

export async function handleChallengeResponse(msg: any) {
    let connection;

    try {
        connection = await pool.getConnection();

        const [rows]: any = await connection.execute(
            `
            SELECT *
            FROM connectivity_tests
            WHERE test_run_id = ?
            LIMIT 1
            `,
            [msg.testRunId]
        );

        if (rows.length === 0) {
            console.log("Test not found");
            return;
        }

        const test = rows[0];

        if (test.status !== "PENDING") {
            console.log("Test already completed");
            return;
        }

        let networkPassed = false;
        let securityPassed = false;
        let heartbeatPassed = false;

        // ====================================
        // NETWORK TEST
        // ====================================
        // If backend received CHALLENGE_RESPONSE,
        // websocket communication is working.

        networkPassed = true;

        // ====================================
        // NONCE VALIDATION
        // ====================================

        if (test.challenge_nonce === msg.challengeNonce) {

            const [machineRows]: any = await connection.execute(
                `
                SELECT *
                FROM machines
                WHERE machine_id = ?
                LIMIT 1
                `,
                [msg.machine_id]
            );

            if (machineRows.length > 0) {

                const machine = machineRows[0];

                // ====================================
                // SECURITY TEST
                // ====================================

                const payload =
                    `${msg.testRunId}|${msg.challengeNonce}`;

                const verify = crypto.createVerify("SHA256");

                verify.update(payload);
                verify.end();

                securityPassed = verify.verify(
                    machine.public_key,
                    Buffer.from(msg.signature, "base64")
                );

                if (securityPassed) {

                    console.log(
                        `Security verification passed for ${msg.machine_id}`
                    );

                    // ====================================
                    // HEARTBEAT TEST
                    // ====================================

                    const thirtySecondsAgo =
                        Date.now() - 30000;

                    const [telemetryRows]: any =
                        await connection.execute(
                            `
                            SELECT id
                            FROM machine_telemetry
                            WHERE machine_id = ?
                            AND timestamp >= ?
                            ORDER BY timestamp DESC
                            LIMIT 1
                            `,
                            [
                                msg.machine_id,
                                thirtySecondsAgo
                            ]
                        );

                    heartbeatPassed =
                        telemetryRows.length > 0;

                    console.log(
                        `Heartbeat verification: ${heartbeatPassed}`
                    );
                } else {
                    console.log("Signature verification failed");
                }
            } else {
                console.log("Machine not found");
            }

        } else {
            console.log("Nonce mismatch");
        }

        // ====================================
        // FINAL RESULT
        // ====================================

        const finalStatus =
            networkPassed &&
                securityPassed &&
                heartbeatPassed
                ? "PASS"
                : "FAIL";

        await connection.execute(
            `
            UPDATE connectivity_tests
            SET
                network_result = ?,
                security_result = ?,
                heartbeat_result = ?,
                status = ?,
                completed_at = NOW()
            WHERE test_run_id = ?
            `,
            [
                networkPassed,
                securityPassed,
                heartbeatPassed,
                finalStatus,
                msg.testRunId
            ]
        );

        console.log("================================");
        console.log("Connectivity Test Completed");
        console.log("Machine:", msg.machine_id);
        console.log("Network:", networkPassed);
        console.log("Security:", securityPassed);
        console.log("Heartbeat:", heartbeatPassed);
        console.log("Status:", finalStatus);
        console.log("================================");

    } catch (err) {

        console.error(
            "handleChallengeResponse error:",
            err
        );

    } finally {

        if (connection) {
            connection.release();
        }

    }
}