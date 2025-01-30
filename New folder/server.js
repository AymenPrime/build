const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// MySQL Connection Pool for better performance
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'ranking_system',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
}).promise();

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access denied' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Register endpoint
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validate input
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }

        // Check if username exists
        const [existingUsers] = await pool.query(
            'SELECT id FROM users WHERE username = ?',
            [username]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({ message: 'Username already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const [result] = await pool.query(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [username, hashedPassword]
        );

        // Create member profile
        await pool.query(
            'INSERT INTO members (user_id, username) VALUES (?, ?)',
            [result.insertId, username]
        );

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // First check if user exists
        const [users] = await pool.query(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );

        if (users.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const user = users[0];

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        // Check if member exists, if not create one
        const [members] = await pool.query(
            'SELECT * FROM members WHERE user_id = ?',
            [user.id]
        );

        if (members.length === 0) {
            // Create member profile if it doesn't exist
            await pool.query(
                'INSERT INTO members (user_id, username) VALUES (?, ?)',
                [user.id, username]
            );
        }

        // Get updated member data
        const [updatedMembers] = await pool.query(
            'SELECT * FROM members WHERE user_id = ?',
            [user.id]
        );

        // Generate token
        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                points: updatedMembers[0]?.points || 0,
                qualified: updatedMembers[0]?.qualified || false
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get all members
app.get('/api/members', authenticateToken, async (req, res) => {
    try {
        // Get all members ordered by points
        const [members] = await pool.query(`
            SELECT 
                m.id,
                m.user_id,
                m.username,
                m.points,
                m.profile_picture,
                m.qualified
            FROM members m
            ORDER BY m.points DESC
        `);

        res.json(members);
    } catch (error) {
        console.error('Get members error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Add a new endpoint to get member count
app.get('/api/members/count', authenticateToken, async (req, res) => {
    try {
        const [result] = await pool.query('SELECT COUNT(*) as count FROM members');
        res.json({ count: result[0].count });
    } catch (error) {
        console.error('Get member count error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update points
app.post('/api/members/points', authenticateToken, async (req, res) => {
    try {
        const { memberIds, points } = req.body;
        
        for (const memberId of memberIds) {
            await pool.query(
                'UPDATE members SET points = points + ? WHERE id = ?',
                [points, memberId]
            );
        }

        res.json({ message: 'Points updated successfully' });
    } catch (error) {
        console.error('Update points error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Delete user
app.delete('/api/users/delete/:username', authenticateToken, async (req, res) => {
    try {
        const { username } = req.params;

        // Delete user (will cascade to members table)
        const [result] = await pool.query(
            'DELETE FROM users WHERE username = ?',
            [username]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Create .env file with these variables
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 