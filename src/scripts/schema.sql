-- CREATE TABLE IF NOT EXISTS machines (
--     machine_id VARCHAR(255) PRIMARY KEY,
--     derived_device_id VARCHAR(255) NOT NULL,
--     operator_wallet VARCHAR(255) NOT NULL,
--     operator_name VARCHAR(255),
--     pool VARCHAR(255),
--     actual_worker_name VARCHAR(255),
--     worker_compliance_status VARCHAR(50),
--     computed_status VARCHAR(50),
--     last_heartbeat_at BIGINT,
--     hashrate_ths DOUBLE DEFAULT 0.0,
--     last_share_ts BIGINT,
--     est_earnings_24h DOUBLE DEFAULT 0.0,
--     pool_status_code INT,
--     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
--     updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
--     INDEX idx_operator_wallet (operator_wallet)
-- );

CREATE TABLE IF NOT EXISTS machines (
    machine_id VARCHAR(100) PRIMARY KEY,
    operator VARCHAR(100),
    pool VARCHAR(100),
    operator_wallet VARCHAR(255),
    worker_id VARCHAR(100),
    fingerprint VARCHAR(255) UNIQUE,
    created_at BIGINT
);

CREATE TABLE IF NOT EXISTS machine_status (
    machine_id VARCHAR(100) PRIMARY KEY,
    status VARCHAR(50), -- active / offline / suspended
    hashrate DOUBLE,
    uptime DOUBLE,
    last_heartbeat BIGINT,
    temperature DOUBLE DEFAULT 0,
    watt INT DEFAULT 0,
    FOREIGN KEY (machine_id) REFERENCES machines(machine_id)
);

CREATE TABLE IF NOT EXISTS machine_telemetry (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    machine_id VARCHAR(100),
    hashrate DOUBLE,
    rate_avg DOUBLE,
    temperature DOUBLE,
    uptime DOUBLE,
    watt INT,
    timestamp BIGINT,
    FOREIGN KEY (machine_id) REFERENCES machines(machine_id), 
    INDEX (machine_id, timestamp)
);

CREATE TABLE wallet_nonces (
    id INT AUTO_INCREMENT PRIMARY KEY,
    address VARCHAR(100) NOT NULL,
    nonce VARCHAR(255) NOT NULL,
    session_id VARCHAR(255) NOT NULL UNIQUE,
    timestamp BIGINT,
    message TEXT,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);