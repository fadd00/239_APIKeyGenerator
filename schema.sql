-- Database Schema for API Key Management System
-- Database: prak7

-- 1. Tabel untuk menyimpan data admin yang bisa login ke dashboard
CREATE TABLE IF NOT EXISTS admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Tabel untuk menyimpan data user yang generate API key
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    firstname VARCHAR(100) NOT NULL,
    lastname VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Tabel untuk menyimpan API keys
CREATE TABLE IF NOT EXISTS apikeys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    api_key VARCHAR(255) NOT NULL UNIQUE,
    api_secret TEXT NOT NULL,
    hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    last_used TIMESTAMP NULL DEFAULT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    INDEX idx_api_key (api_key),
    INDEX idx_user_id (user_id),
    INDEX idx_hash (hash),
    INDEX idx_expires_at (expires_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Tabel untuk log aktivitas API
CREATE TABLE IF NOT EXISTS api_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    apikey_id INT,
    user_id INT,
    activity_type VARCHAR(50) NOT NULL,
    endpoint VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    status VARCHAR(20),
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_apikey_id (apikey_id),
    INDEX idx_user_id (user_id),
    INDEX idx_activity_type (activity_type),
    INDEX idx_created_at (created_at),
    FOREIGN KEY (apikey_id) REFERENCES apikeys(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Insert admin default untuk testing (password: admin123 - harus di-hash di backend)
INSERT INTO admins (email, password) 
VALUES ('admin@example.com', 'admin123')
ON DUPLICATE KEY UPDATE email=email;
