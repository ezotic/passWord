-- Runs once on first container start when the volume is empty.
-- The database named by MYSQL_DATABASE is already created by the official
-- MySQL entrypoint before this script runs.

USE password_app;

-- Login credentials for app users (must exist before users table due to FK)
CREATE TABLE IF NOT EXISTS app_users (
    id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username             VARCHAR(64)  NOT NULL,
    is_admin             TINYINT(1)   NOT NULL DEFAULT 0,
    must_change_password TINYINT(1)   NOT NULL DEFAULT 0,
    password_hash        VARCHAR(255) NOT NULL,
    created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Password entries, scoped per app user
CREATE TABLE IF NOT EXISTS users (
    id         INT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id    INT UNSIGNED NOT NULL,
    website    VARCHAR(255) NOT NULL DEFAULT '',
    username   VARCHAR(64)  NOT NULL,
    password   VARCHAR(255) NOT NULL,
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT fk_users_app_user FOREIGN KEY (user_id) REFERENCES app_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- App user is created by the official image entrypoint from MYSQL_USER/MYSQL_PASSWORD.
-- We only need to grant the minimum privileges required.
GRANT SELECT, INSERT, DELETE ON password_app.users TO 'appuser'@'%';
GRANT SELECT, INSERT, UPDATE ON password_app.app_users TO 'appuser'@'%';
FLUSH PRIVILEGES;
