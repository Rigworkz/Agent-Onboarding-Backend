export const buildUpsertQuery = (tableName: string, data: Record<string, any>) => {
    const keys = Object.keys(data);
    const values = Object.values(data);

    if (keys.length === 0) {
        throw new Error('No data provided for upsert');
    }

    const columns = keys.join(', ');
    const placeholders = keys.map(() => '?').join(', ');
    const updates = keys.map((key) => `${key} = VALUES(${key})`).join(', ');

    // const updates = keys
    //     .filter((key) => key !== 'machine_id')
    //     .map((key) => `${key} = VALUES(${key})`)
    //     .join(', ');

    const query = `INSERT INTO ${tableName} (${columns}) VALUES (${placeholders}) ON DUPLICATE KEY UPDATE ${updates}`;

    return { query, values };
};
