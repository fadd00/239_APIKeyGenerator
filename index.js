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
    database: 'prak7_',  
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
    const { firstname, lastname, email } = req.body;
    
    if (!firstname) {
        return res.status(400).json({ 
            success: false, 
            message: 'First Name diperlukan' 
        });
    }

    if (!lastname) {
        return res.status(400).json({ 
            success: false, 
            message: 'Last Name diperlukan' 
        });
    }

    if (!email) {
        return res.status(400).json({ 
            success: false, 
            message: 'Email diperlukan' 
        });
    }

    try {
        // Check if user exists, if not create new user
        let userId;
        const [existingUser] = await pool.execute('SELECT id FROM users WHERE email = ?', [email]);
        
        if (existingUser.length > 0) {
            // User exists, update name if needed
            userId = existingUser[0].id;
            await pool.execute(
                'UPDATE users SET firstname = ?, lastname = ?, updated_at = NOW() WHERE id = ?',
                [firstname, lastname, userId]
            );
        } else {
            // Create new user
            const [result] = await pool.execute(
                'INSERT INTO users (firstname, lastname, email) VALUES (?, ?, ?)',
                [firstname, lastname, email]
            );
            userId = result.insertId;
        }

        // Generate API Key
        const apiKey = generateApiKey();
        const apiSecret = generateApiSecret();
        const apiHash = hashApiKey(apiKey);
        const createdAt = new Date();
        
        // Set expiration date to 1 week from now
        const expiresAt = new Date(createdAt.getTime() + 7 * 24 * 60 * 60 * 1000);
        
        // Insert API key into apikeys table
        const [apiKeyResult] = await pool.execute(
            'INSERT INTO apikeys (user_id, api_key, api_secret, hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
            [userId, apiKey, apiSecret, apiHash, createdAt, expiresAt]
        );

        // Log activity
        await logActivity(apiKeyResult.insertId, userId, 'created', null, req.ip, req.get('user-agent'), 'success', 'API Key created');

        res.json({
            success: true,
            userId: userId,
            apiKey: apiKey,
            apiSecret: apiSecret,
            firstname: firstname,
            lastname: lastname,
            email: email,
            createdAt: createdAt,
            expiresAt: expiresAt,
            note: 'Simpan API Key dan Secret dengan aman. Secret tidak dapat dilihat kembali. API Key akan hangus dalam 7 hari.'
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
        const query = `
            SELECT a.*, u.firstname, u.lastname, u.email 
            FROM apikeys a
            JOIN users u ON a.user_id = u.id
            WHERE a.api_key = ? AND a.is_active = TRUE
        `;
        const [rows] = await pool.execute(query, [apiKey]);
        
        if (rows.length > 0) {
            const keyData = rows[0];
            
            // Check if expired
            const now = new Date();
            const expiresAt = new Date(keyData.expires_at);
            
            if (now > expiresAt) {
                // Mark as inactive if expired
                await pool.execute('UPDATE apikeys SET is_active = FALSE WHERE api_key = ?', [apiKey]);
                
                await logActivity(keyData.id, keyData.user_id, 'validation_failed', null, req.ip, req.get('user-agent'), 'expired', 'API Key expired');
                
                return res.status(401).json({
                    success: false,
                    message: 'API Key sudah hangus (expired)'
                });
            }
            
            // Update last used
            await pool.execute('UPDATE apikeys SET last_used = NOW() WHERE api_key = ?', [apiKey]);
            
            await logActivity(keyData.id, keyData.user_id, 'validated', null, req.ip, req.get('user-agent'), 'success', 'API Key validated');
            
            return res.json({
                success: true,
                message: 'API Key valid',
                data: {
                    firstname: keyData.firstname,
                    lastname: keyData.lastname,
                    email: keyData.email,
                    createdAt: keyData.created_at,
                    expiresAt: keyData.expires_at,
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
        const query = `
            SELECT a.*, u.firstname, u.lastname, u.email 
            FROM apikeys a
            JOIN users u ON a.user_id = u.id
            ORDER BY a.created_at DESC
        `;
        const [rows] = await pool.execute(query);
        
        const now = new Date();
        
        const keysArray = rows.map(row => {
            const expiresAt = new Date(row.expires_at);
            const isExpired = now > expiresAt;
            
            return {
                id: row.id,
                apiKey: row.api_key,
                firstname: row.firstname,
                lastname: row.lastname,
                email: row.email,
                username: `${row.firstname} ${row.lastname}`,
                apiName: row.email,
                hash: row.hash,
                createdAt: row.created_at,
                expiresAt: row.expires_at,
                lastUsed: row.last_used,
                isActive: row.is_active && !isExpired,
                isExpired: isExpired
            };
        });
        
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

// Endpoint untuk regenerate API key (ganti key, user tetap)
app.post('/api/regenerate-key', async (req, res) => {
    const { oldApiKey } = req.body;
    
    if (!oldApiKey) {
        return res.status(400).json({ 
            success: false, 
            message: 'API Key lama diperlukan' 
        });
    }

    try {
        // Cari data key lama dengan join ke users
        const [rows] = await pool.execute(`
            SELECT a.*, u.firstname, u.lastname, u.email 
            FROM apikeys a
            JOIN users u ON a.user_id = u.id
            WHERE a.api_key = ?
        `, [oldApiKey]);
        
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
        const newApiHash = hashApiKey(newApiKey);
        const createdAt = new Date();
        const expiresAt = new Date(createdAt.getTime() + 7 * 24 * 60 * 60 * 1000);
        
        // Insert new key
        const [result] = await pool.execute(
            'INSERT INTO apikeys (user_id, api_key, api_secret, hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
            [oldKeyData.user_id, newApiKey, newApiSecret, newApiHash, createdAt, expiresAt]
        );

        // Delete old key
        await pool.execute('DELETE FROM apikeys WHERE api_key = ?', [oldApiKey]);

        // Log activity
        await logActivity(result.insertId, oldKeyData.user_id, 'regenerated', null, req.ip, req.get('user-agent'), 'success', 'API Key regenerated');

        res.json({
            success: true,
            oldApiKey: oldApiKey,
            newApiKey: newApiKey,
            newApiSecret: newApiSecret,
            firstname: oldKeyData.firstname,
            lastname: oldKeyData.lastname,
            email: oldKeyData.email,
            createdAt: createdAt,
            expiresAt: expiresAt,
            note: 'API Key berhasil di-regenerate. Simpan Key dan Secret yang baru. API Key baru akan hangus dalam 7 hari.'
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
        const [rows] = await pool.execute('SELECT * FROM apikeys WHERE api_key = ?', [apiKey]);
        
        if (rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'API Key tidak ditemukan'
            });
        }

        const keyData = rows[0];

        // Log aktivitas sebelum delete
        await logActivity(keyData.id, keyData.user_id, 'deleted', null, req.ip, req.get('user-agent'), 'success', 'API Key deleted');

        // Delete key (CASCADE akan menghapus logs terkait)
        await pool.execute('DELETE FROM apikeys WHERE api_key = ?', [apiKey]);

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
        const query = `
            SELECT a.*, u.firstname, u.lastname, u.email 
            FROM apikeys a
            JOIN users u ON a.user_id = u.id
            WHERE a.api_key = ? AND a.is_active = TRUE
        `;
        const [rows] = await pool.execute(query, [apiKey]);
        
        if (rows.length > 0) {
            const keyData = rows[0];
            
            // Check if expired
            const now = new Date();
            const expiresAt = new Date(keyData.expires_at);
            
            if (now > expiresAt) {
                await pool.execute('UPDATE apikeys SET is_active = FALSE WHERE api_key = ?', [apiKey]);
                await logActivity(keyData.id, keyData.user_id, 'access_denied', '/api/protected-data', req.ip, req.get('user-agent'), 'expired', 'API Key expired');
                
                return res.status(401).json({
                    success: false,
                    message: 'API Key sudah hangus (expired)'
                });
            }
            
            // Update last used
            await pool.execute('UPDATE apikeys SET last_used = NOW() WHERE api_key = ?', [apiKey]);
            
            // Log aktivitas
            await logActivity(keyData.id, keyData.user_id, 'used', '/api/protected-data', req.ip, req.get('user-agent'), 'success', 'Accessed protected endpoint');
            
            return res.json({
                success: true,
                message: 'Akses diberikan',
                data: {
                    message: 'Ini adalah data yang dilindungi',
                    user: `${keyData.firstname} ${keyData.lastname}`,
                    email: keyData.email,
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

// Helper function untuk logging aktivitas ke database
async function logActivity(apikeyId, userId, activityType, endpoint, ipAddress, userAgent, status, message) {
    try {
        const query = `
            INSERT INTO api_logs (apikey_id, user_id, activity_type, endpoint, ip_address, user_agent, status, message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `;
        await pool.execute(query, [apikeyId, userId, activityType, endpoint, ipAddress, userAgent, status, message]);
    } catch (error) {
        console.error('Error logging activity:', error);
    }
}

// Endpoint untuk register admin
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ 
            success: false, 
            message: 'Email dan password diperlukan' 
        });
    }

    try {
        // Check if admin already exists
        const [existing] = await pool.execute('SELECT id FROM admins WHERE email = ?', [email]);
        
        if (existing.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'Email sudah terdaftar'
            });
        }

        // Hash password (gunakan bcrypt di production)
        const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
        
        // Insert admin
        await pool.execute(
            'INSERT INTO admins (email, password) VALUES (?, ?)',
            [email, hashedPassword]
        );

        res.json({
            success: true,
            message: 'Registrasi berhasil'
        });
    } catch (error) {
        console.error('Error registering admin:', error);
        res.status(500).json({
            success: false,
            message: 'Gagal registrasi: ' + error.message
        });
    }
});

// Endpoint untuk login admin
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ 
            success: false, 
            message: 'Email dan password diperlukan' 
        });
    }

    try {
        // Hash password untuk compare
        const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
        
        const [rows] = await pool.execute(
            'SELECT * FROM admins WHERE email = ? AND password = ?',
            [email, hashedPassword]
        );
        
        if (rows.length > 0) {
            res.json({
                success: true,
                message: 'Login berhasil',
                data: {
                    email: email
                }
            });
        } else {
            res.status(401).json({
                success: false,
                message: 'Email atau password salah'
            });
        }
    } catch (error) {
        console.error('Error login:', error);
        res.status(500).json({
            success: false,
            message: 'Gagal login: ' + error.message
        });
    }
});

app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});
