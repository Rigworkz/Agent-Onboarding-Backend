

-- CREATE TABLE IF NOT EXISTS machines (
--     operator_wallet VARCHAR(255) PRIMARY KEY,
--     machine_id VARCHAR(100) UNIQUE,
--     operator VARCHAR(100),
--     pool VARCHAR(100),
--     worker_id VARCHAR(100),
--     fingerprint VARCHAR(255) UNIQUE,
--     created_at BIGINT,
--     signature TEXT,
--     public_key TEXT
-- );

-- CREATE TABLE IF NOT EXISTS machine_status (
--     operator_wallet VARCHAR(255) PRIMARY KEY,
--     machine_id VARCHAR(100),
--     status VARCHAR(50),
--     hashrate DOUBLE,
--     uptime DOUBLE,
--     last_heartbeat BIGINT,
--     temperature DOUBLE DEFAULT 0,
--     watt INT DEFAULT 0,
--     FOREIGN KEY (operator_wallet) REFERENCES machines(operator_wallet)
-- );

-- CREATE TABLE IF NOT EXISTS machine_telemetry (
--     id BIGINT AUTO_INCREMENT PRIMARY KEY,
--     operator_wallet VARCHAR(255),
--     machine_id VARCHAR(100),
--     child_fingerprint VARCHAR(255),    --child finger_print added
--     hashrate DOUBLE,
--     rate_avg DOUBLE,
--     temperature DOUBLE,
--     uptime DOUBLE,
--     watt INT,
--     timestamp BIGINT,
--     FOREIGN KEY (operator_wallet) REFERENCES machines(operator_wallet),
--     INDEX (machine_id, timestamp)
-- );

-- CREATE TABLE IF NOT EXISTS wallet_sessions (

--     id INT AUTO_INCREMENT PRIMARY KEY,
--     address VARCHAR(100) NOT NULL,
--     session_id VARCHAR(255) NOT NULL UNIQUE,
--     timestamp BIGINT,
--     message TEXT,
--     is_used BOOLEAN DEFAULT FALSE,
--     nonce VARCHAR(255) NOT NULL,
--     is_verified BOOLEAN DEFAULT FALSE,
--     install_token VARCHAR(255),
--     token_expires_at BIGINT,
--     token_is_used BOOLEAN DEFAULT FALSE,
--     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
--     signature TEXT,
--     machine_id VARCHAR(100)
-- );



CREATE TABLE IF NOT EXISTS machines (
    machine_id VARCHAR(100) PRIMARY KEY,
    operator_wallet VARCHAR(255),
    operator VARCHAR(100),
    detected_os VARCHAR(100),
    pool VARCHAR(100),
    worker_id VARCHAR(100),
    fingerprint VARCHAR(255) UNIQUE,
    created_at BIGINT,
    public_key TEXT,
    INDEX(operator_wallet)
);
CREATE TABLE IF NOT EXISTS machine_status (
    machine_id VARCHAR(100) PRIMARY KEY,
    operator_wallet VARCHAR(255),
    status VARCHAR(50),
    hashrate DOUBLE,
    uptime DOUBLE,
    last_heartbeat BIGINT,
    temperature DOUBLE DEFAULT 0,
    watt INT DEFAULT 0,
    FOREIGN KEY (machine_id) REFERENCES machines(machine_id),
    INDEX(operator_wallet)
);
CREATE TABLE IF NOT EXISTS machine_telemetry (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    machine_id VARCHAR(100),
    operator_wallet VARCHAR(255),
    child_fingerprint VARCHAR(255),
    hashrate DOUBLE,
    rate_avg DOUBLE,
    temperature DOUBLE,
    uptime DOUBLE,
    watt INT,
    timestamp BIGINT,
    FOREIGN KEY (machine_id) REFERENCES machines(machine_id),
    INDEX(machine_id, timestamp),
    INDEX(operator_wallet)
);

CREATE TABLE IF NOT EXISTS wallet_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    operator_wallet VARCHAR(100) NOT NULL,
    session_id VARCHAR(255) NOT NULL UNIQUE,
    timestamp BIGINT,
    message TEXT,
    is_used BOOLEAN DEFAULT FALSE,
    nonce VARCHAR(255) NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    install_token VARCHAR(255),
    machine_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    signature TEXT
);
