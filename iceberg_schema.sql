-- Iceberg table schema for Prysm logs
-- This should be executed on your Iceberg catalog to create the expected table structure

-- Create the kubeaccess namespace if it doesn't exist
CREATE SCHEMA IF NOT EXISTS kubeaccess;

-- Create the logs table for each organization
-- Note: In practice, you may want separate tables per organization for better isolation
CREATE TABLE IF NOT EXISTS kubeaccess.logs_org_1 (
    -- Core log fields
    id VARCHAR NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    level VARCHAR NOT NULL,
    message TEXT NOT NULL,
    source VARCHAR NOT NULL,
    
    -- Kubernetes context
    cluster_id VARCHAR,
    namespace VARCHAR,
    pod VARCHAR,
    container VARCHAR,
    
    -- Organization isolation
    organization_id BIGINT NOT NULL,
    
    -- Structured fields (JSON)
    labels MAP(VARCHAR, VARCHAR),
    fields MAP(VARCHAR, VARCHAR),
    
    -- Optional performance metrics
    response_time DOUBLE,
    request_id VARCHAR,
    user_id VARCHAR,
    
    -- Partitioning for performance
    date_partition DATE GENERATED ALWAYS AS (DATE(timestamp))
) 
USING iceberg
PARTITIONED BY (date_partition, organization_id)
TBLPROPERTIES (
    'write.format.default' = 'parquet',
    'write.parquet.compression-codec' = 'snappy',
    'history.expire.max-snapshot-age-ms' = '432000000', -- 5 days
    'write.target-file-size-bytes' = '134217728' -- 128MB
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_logs_org_1_timestamp ON kubeaccess.logs_org_1 (timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_org_1_level ON kubeaccess.logs_org_1 (level);
CREATE INDEX IF NOT EXISTS idx_logs_org_1_source ON kubeaccess.logs_org_1 (source);
CREATE INDEX IF NOT EXISTS idx_logs_org_1_cluster ON kubeaccess.logs_org_1 (cluster_id);

-- Example of creating additional organization tables
-- CREATE TABLE IF NOT EXISTS kubeaccess.logs_org_2 (
--     -- Same schema as above
-- ) USING iceberg PARTITIONED BY (date_partition, organization_id);

-- Sample data insertion (for testing)
INSERT INTO kubeaccess.logs_org_1 VALUES (
    'log-001',
    CURRENT_TIMESTAMP(),
    'INFO',
    'Application started successfully',
    'api-gateway',
    'prod-cluster-us-east',
    'default',
    'api-gateway-7d8b9c456-xyz12',
    'api-gateway-container',
    1,
    MAP('app', 'api-gateway', 'version', 'v1.2.3'),
    MAP('startup_time', '2.5s', 'port', '8080'),
    NULL,
    'req-12345',
    'user-67890',
    CURRENT_DATE()
);

INSERT INTO kubeaccess.logs_org_1 VALUES (
    'log-002',
    CURRENT_TIMESTAMP(),
    'ERROR',
    'Database connection failed',
    'auth-service',
    'prod-cluster-us-east',
    'default',
    'auth-service-5f6g7h8i9-abc34',
    'auth-service-container',
    1,
    MAP('app', 'auth-service', 'version', 'v2.1.0'),
    MAP('error_code', 'DB_CONN_ERR', 'retry_count', '3'),
    NULL,
    'req-54321',
    'user-11111',
    CURRENT_DATE()
);

INSERT INTO kubeaccess.logs_org_1 VALUES (
    'log-003',
    CURRENT_TIMESTAMP(),
    'WARN',
    'High memory usage detected',
    'user-service',
    'prod-cluster-eu-west',
    'applications',
    'user-service-2a3b4c5d6-def78',
    'user-service-container',
    1,
    MAP('app', 'user-service', 'version', 'v1.5.2'),
    MAP('memory_usage', '85%', 'threshold', '80%'),
    250.5,
    'req-98765',
    'user-22222',
    CURRENT_DATE()
);

-- Views for common analytics queries
CREATE VIEW IF NOT EXISTS kubeaccess.logs_org_1_hourly_summary AS
SELECT 
    DATE_TRUNC('hour', timestamp) as hour,
    level,
    source,
    cluster_id,
    COUNT(*) as log_count,
    COUNT(DISTINCT pod) as unique_pods,
    AVG(response_time) as avg_response_time
FROM kubeaccess.logs_org_1
WHERE timestamp >= CURRENT_TIMESTAMP() - INTERVAL '7' DAY
GROUP BY DATE_TRUNC('hour', timestamp), level, source, cluster_id;

CREATE VIEW IF NOT EXISTS kubeaccess.logs_org_1_error_summary AS
SELECT 
    DATE_TRUNC('hour', timestamp) as hour,
    source,
    cluster_id,
    COUNT(*) as error_count,
    COLLECT_LIST(DISTINCT message) as error_messages
FROM kubeaccess.logs_org_1
WHERE level IN ('ERROR', 'FATAL')
AND timestamp >= CURRENT_TIMESTAMP() - INTERVAL '24' HOUR
GROUP BY DATE_TRUNC('hour', timestamp), source, cluster_id;
