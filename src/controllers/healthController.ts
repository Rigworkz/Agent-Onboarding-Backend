import { Request, Response } from 'express';
import { checkDatabaseConnection } from '../config/database';

export const getHealth = async (req: Request, res: Response) => {
    const isDbConnected = await checkDatabaseConnection();

    if (isDbConnected) {
        res.status(200).json({ status: 'UP', database: 'CONNECTED' });
    } else {
        res.status(503).json({ status: 'DOWN', database: 'DISCONNECTED' });
    }
};
