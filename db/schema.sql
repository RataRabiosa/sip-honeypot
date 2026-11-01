-- db/schema.sql
-- Executed once by the mysql:8.4 image when the data volume is empty
-- (mounted at /docker-entrypoint-initdb.d/01-schema.sql). The image has already
-- created and selected the database named by MYSQL_DATABASE; do not CREATE/USE here.
-- Standalone: mysql -u <user> -p <database> < db/schema.sql

CREATE TABLE IF NOT EXISTS request_events (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  ts          DATETIME(3)     NOT NULL,
  src_ip      VARCHAR(45)     NOT NULL,
  src_port    INT UNSIGNED    NOT NULL,
  dst_host    VARCHAR(45)     NOT NULL,
  dst_port    INT UNSIGNED    NOT NULL,
  method      VARCHAR(32)     NOT NULL,
  user_agent  VARCHAR(255)    NULL,
  from_uri    VARCHAR(255)    NULL,
  to_uri      VARCHAR(255)    NULL,
  call_id     VARCHAR(255)    NULL,
  PRIMARY KEY (id),
  KEY idx_request_events_ts        (ts),
  KEY idx_request_events_src_ip_ts (src_ip, ts),
  KEY idx_request_events_method_ts (method, ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS source_ips (
  src_ip        VARCHAR(45)     NOT NULL,
  first_seen    DATETIME(3)     NOT NULL,
  last_seen     DATETIME(3)     NOT NULL,
  request_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (src_ip),
  KEY idx_source_ips_request_count (request_count),
  KEY idx_source_ips_last_seen     (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS blocked_ips (
  src_ip           VARCHAR(45)  NOT NULL,
  status           ENUM('pending','blocked','failed') NOT NULL DEFAULT 'pending',
  attempts         INT UNSIGNED NOT NULL DEFAULT 0,
  first_attempt_at DATETIME(3)  NOT NULL,
  last_attempt_at  DATETIME(3)  NOT NULL,
  blocked_at       DATETIME(3)  NULL,
  firewall_id      VARCHAR(64)  NOT NULL,
  last_http_status SMALLINT     NULL,
  last_error       VARCHAR(512) NULL,
  PRIMARY KEY (src_ip),
  KEY idx_blocked_ips_status     (status),
  KEY idx_blocked_ips_blocked_at (blocked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
