import { Request, Response } from 'express';
import { pool } from '../config/database';
import { buildUpsertQuery } from '../utils/queryBuilder';
import { RowDataPacket } from 'mysql2';

export const upsertOperatorProfile = async (req: Request, res: Response) => {
    try {
        const data = req.body;

        if (!data.operator_wallet) {
            return res.status(400).json({ message: 'operator_wallet is required' });
        }

        // Flatten/Prepare data for DB
        const dbData = {
            operator_wallet: data.operator_wallet,
            btc_reward_address: data.btc_reward_address,
            operator_name: data.operator_name,
            pool_name: data.pool_credentials?.pool_name || data.pool_name,
            pool_account: data.pool_credentials?.pool_account || data.pool_account,
            notification_email: data.notifications?.email || data.notification_email,
            preferences: JSON.stringify({
                alert_rig_offline: data.notifications?.alert_rig_offline,
                alert_hashrate_drop: data.notifications?.alert_hashrate_drop,
                alert_pool_failure: data.notifications?.alert_pool_failure
            })
        };

        const { query, values } = buildUpsertQuery('operators', dbData);

        const connection = await pool.getConnection();
        await connection.execute(query, values);
        connection.release();

        res.status(200).json({
            message: 'Operator profile updated successfully',
            operator_wallet: data.operator_wallet
        });

    } catch (error) {
        console.error('Error updating operator profile:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const getOperatorProfile = async (req: Request, res: Response) => {
    try {
        const { operator_wallet } = req.params;
        const connection = await pool.getConnection();

        const [rows] = await connection.execute<RowDataPacket[]>('SELECT * FROM operators WHERE operator_wallet = ?', [operator_wallet]);
        connection.release();

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Operator not found' });
        }

        const row = rows[0];
        const preferences = typeof row.preferences === 'string' ? JSON.parse(row.preferences) : row.preferences;

        // Reconstruct response to match frontend expectations
        const responseData = {
            operator_wallet: row.operator_wallet,
            btc_reward_address: row.btc_reward_address,
            operator_name: row.operator_name,
            pool_credentials: {
                pool_name: row.pool_name,
                pool_account: row.pool_account
            },
            notifications: {
                email: row.notification_email,
                ...preferences
            }
        };

        res.json(responseData);
    } catch (error) {
        console.error('Error fetching operator profile:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};
