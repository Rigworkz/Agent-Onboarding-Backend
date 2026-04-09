-- Create operators table
CREATE TABLE IF NOT EXISTS operators (
    operator_wallet VARCHAR(255) PRIMARY KEY,
    btc_reward_address VARCHAR(255),
    operator_name VARCHAR(255);
    pool_name VARCHAR(100),
    pool_account VARCHAR(100),
    notification_email VARCHAR(255),
    is_notification_enabled BOOLEAN DEFAULT TRUE,
    preferences JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Modify machines table to ensure data integrity
-- Note: We are NOT enforcing a strict FOREIGN KEY constraint initially to allow 
-- machines to report heartbeats even if the operator profile isn't fully set up yet.
-- This ensures the "seamless" experience where order of operations doesn't matter.
ALTER TABLE machines 
ADD COLUMN IF NOT EXISTS operator_name VARCHAR(255);
