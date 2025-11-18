const express = require('express');
const crypto = require('crypto');
const path = require('path');
const mysql = require('mysql2/promise');

const app = express();
const PORT = 3000;

const dbConfig = {
    host: 'localhost',      
    port: 3306,             
    user: 'root',           
    password: '',           
    database: 'prak7',  
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};
const pool = mysql.createPool(dbConfig);

async function testConnection() {
    try {
        const connection = await pool.getConnection();
        console.log('✓ Database connected successfully!');
        connection.release();
    } catch (error) {
        console.error('✗ Database connection failed:', error.message);
        console.log('Please check your database configuration in index.js');
    }
}

testConnection();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

function generateApiKey() {
    return crypto.randomBytes(32).toString('hex');
}

function generateApiSecret() {
    return crypto.randomBytes(64).toString('base64');
}

function hashApiKey(apiKey) {
    return crypto.createHash('sha256').update(apiKey).digest('hex');
}

function generateId() {
    return crypto.randomUUID();
}

app.post('/api/generate-key', async (req, res) => {
    const { username, apiName } = req.body;
    
    if (!username) {
        return res.status(400).json({ 
            success: false, 
            message: 'Username diperlukan' 
        });
    }

    if (!apiName) {
        return res.status(400).json({ 
            success: false, 
            message: 'Nama API diperlukan' 
        });
    }

    try {
        const apiKey = generateApiKey();
        const apiSecret = generateApiSecret();
        const apiId = generateId();
        const apiHash = hashApiKey(apiKey);
        const timestamp = new Date();
        
        // Insert ke database
        const query = `
            INSERT INTO api_keys (id, username, api_name, api_key, api_secret, api_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        
        await pool.execute(query, [apiId, username, apiName, apiKey, apiSecret, apiHash, timestamp]);

        // Log aktivitas
        await logActivity(apiId, 'created', req.ip, req.get('user-agent'), null, 'success', 'API Key created');

        res.json({
            success: true,
            apiId: apiId,
            apiKey: apiKey,
            apiSecret: apiSecret,
            username: username,
            apiName: apiName,
            createdAt: timestamp,
            note: 'Simpan API Key dan Secret dengan aman. Secret tidak dapat dilihat kembali.'
        });
    } catch (error) {
        console.error('Error generating API key:', error);
        res.status(500).json({
            success: false,
            message: 'Gagal membuat API key: ' + error.message
        });
    }
});

// Endpoint untuk validasi API key
app.post('/api/validate-key', async (req, res) => {
    const { apiKey } = req.body;
    
    if (!apiKey) {
        return res.status(400).json({ 
            success: false, 
            message: 'API Key diperlukan' 
        });
    }

    try {
        const query = 'SELECT * FROM api_keys WHERE api_key = ? AND is_active = TRUE';
        const [rows] = await pool.execute(query, [apiKey]);
        
        if (rows.length > 0) {
            const keyData = rows[0];
            
            // Update last used
            await pool.execute('UPDATE api_keys SET last_used = NOW() WHERE api_key = ?', [apiKey]);
            
            // Log aktivitas
            await logActivity(keyData.id, 'validated', req.ip, req.get('user-agent'), null, 'success', 'API Key validated');
            
            return res.json({
                success: true,
                message: 'API Key valid',
                data: {
                    username: keyData.username,
                    apiName: keyData.api_name,
                    createdAt: keyData.created_at,
                    lastUsed: keyData.last_used
                }
            });
        } else {
            return res.status(401).json({
                success: false,
                message: 'API Key tidak valid atau tidak aktif'
            });
        }
    } catch (error) {
        console.error('Error validating API key:', error);
        res.status(500).json({
            success: false,
            message: 'Gagal memvalidasi API key: ' + error.message
        });
    }
});

// Endpoint untuk mendapatkan semua API keys
app.get('/api/keys', async (req, res) => {
    try {
        const query = 'SELECT * FROM api_keys ORDER BY created_at DESC';
        const [rows] = await pool.execute(query);
        
        const keysArray = rows.map(row => ({
            id: row.id,
            apiKey: row.api_key,
            username: row.username,
            apiName: row.api_name,
            hash: row.api_hash,
            createdAt: row.created_at,
            lastUsed: row.last_used,
            isActive: row.is_active
        }));
        
        res.json({
            success: true,
            count: keysArray.length,
            keys: keysArray
        });
    } catch (error) {
        console.error('Error fetching API keys:', error);
        res.status(500).json({
            success: false,
            message: 'Gagal mengambil data API keys: ' + error.message
        });
    }
});

// Endpoint untuk regenerate API key (ganti key, nama tetap)
app.post('/api/regenerate-key', async (req, res) => {
    const { oldApiKey } = req.body;
    
    if (!oldApiKey) {
        return res.status(400).json({ 
            success: false, 
            message: 'API Key lama diperlukan' 
        });
    }

    try {
        // Cari data key lama
        const [rows] = await pool.execute('SELECT * FROM api_keys WHERE api_key = ?', [oldApiKey]);
        
        if (rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'API Key tidak ditemukan'
            });
        }

        const oldKeyData = rows[0];

        // Generate new key
        const newApiKey = generateApiKey();
        const newApiSecret = generateApiSecret();
        const newApiId = generateId();
        const newApiHash = hashApiKey(newApiKey);
        const timestamp = new Date();
        
        // Insert new key
        const insertQuery = `
            INSERT INTO api_keys (id, username, api_name, api_key, api_secret, api_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        await pool.execute(insertQuery, [newApiId, oldKeyData.username, oldKeyData.api_name, newApiKey, newApiSecret, newApiHash, timestamp]);

        // Insert history
        const historyQuery = `
            INSERT INTO api_key_history (old_api_key, new_api_key_id, username, api_name, reason)
            VALUES (?, ?, ?, ?, ?)
        `;
        await pool.execute(historyQuery, [oldApiKey, newApiId, oldKeyData.username, oldKeyData.api_name, 'User requested regeneration']);

        // Delete old key
        await pool.execute('DELETE FROM api_keys WHERE api_key = ?', [oldApiKey]);

        // Log aktivitas
        await logActivity(newApiId, 'regenerated', req.ip, req.get('user-agent'), null, 'success', 'API Key regenerated');

        res.json({
            success: true,
            oldApiKey: oldApiKey,
            newApiKey: newApiKey,
            newApiSecret: newApiSecret,
            username: oldKeyData.username,
            apiName: oldKeyData.api_name,
            createdAt: timestamp,
            note: 'API Key berhasil di-regenerate. Simpan Key dan Secret yang baru.'
        });
    } catch (error) {
        console.error('Error regenerating API key:', error);
        res.status(500).json({
            success: false,
            message: 'Gagal regenerate API key: ' + error.message
        });
    }
});

// Endpoint untuk delete API key
app.delete('/api/delete-key', async (req, res) => {
    const { apiKey } = req.body;
    
    if (!apiKey) {
        return res.status(400).json({ 
            success: false, 
            message: 'API Key diperlukan' 
        });
    }

    try {
        // Cari data key
        const [rows] = await pool.execute('SELECT * FROM api_keys WHERE api_key = ?', [apiKey]);
        
        if (rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'API Key tidak ditemukan'
            });
        }

        const keyData = rows[0];

        // Log aktivitas sebelum delete
        await logActivity(keyData.id, 'deleted', req.ip, req.get('user-agent'), null, 'success', 'API Key deleted');

        // Delete key
        await pool.execute('DELETE FROM api_keys WHERE api_key = ?', [apiKey]);

        return res.json({
            success: true,
            message: 'API Key berhasil dihapus'
        });
    } catch (error) {
        console.error('Error deleting API key:', error);
        res.status(500).json({
            success: false,
            message: 'Gagal menghapus API key: ' + error.message
        });
    }
});

// Protected endpoint example
app.get('/api/protected-data', async (req, res) => {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
        return res.status(401).json({
            success: false,
            message: 'API Key tidak ditemukan di header'
        });
    }

    try {
        const query = 'SELECT * FROM api_keys WHERE api_key = ? AND is_active = TRUE';
        const [rows] = await pool.execute(query, [apiKey]);
        
        if (rows.length > 0) {
            const keyData = rows[0];
            
            // Update last used
            await pool.execute('UPDATE api_keys SET last_used = NOW() WHERE api_key = ?', [apiKey]);
            
            // Log aktivitas
            await logActivity(keyData.id, 'used', req.ip, req.get('user-agent'), '/api/protected-data', 'success', 'Accessed protected endpoint');
            
            return res.json({
                success: true,
                message: 'Akses diberikan',
                data: {
                    message: 'Ini adalah data yang dilindungi',
                    user: keyData.username,
                    timestamp: new Date().toISOString()
                }
            });
        } else {
            return res.status(401).json({
                success: false,
                message: 'API Key tidak valid'
            });
        }
    } catch (error) {
        console.error('Error accessing protected data:', error);
        res.status(500).json({
            success: false,
            message: 'Gagal mengakses data: ' + error.message
        });
    }
});

// Helper function untuk logging aktivitas
async function logActivity(apiKeyId, activityType, ipAddress, userAgent, endpoint, status, message) {
    try {
        const query = `
            INSERT INTO api_key_logs (api_key_id, activity_type, ip_address, user_agent, endpoint, status, message)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        await pool.execute(query, [apiKeyId, activityType, ipAddress, userAgent, endpoint, status, message]);
    } catch (error) {
        console.error('Error logging activity:', error);
    }
}

app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});
