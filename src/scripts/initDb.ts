import fs from 'fs';
import path from 'path';
import { pool } from '../config/database';

const initDb = async () => {
    try {
        const schemaPath = path.join(__dirname, 'schema.sql');
        const schemaSql = fs.readFileSync(schemaPath, 'utf8');

        const connection = await pool.getConnection();

        // Split queries by semicolon to handle multiple statements if any
        const queries = schemaSql.split(';').filter(query => query.trim().length > 0);

        for (const query of queries) {
            await connection.query(query);
        }

        connection.release();
        console.log('Database schema initialized or updated successfully.');
        process.exit(0);
    } catch (error) {
        console.error('Failed to initialize database schema:', error);
        process.exit(1);
    }
};

initDb();
