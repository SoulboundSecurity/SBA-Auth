// server-example.js
// Example server implementation for Soulbound Auth

const express = require('express');
const ethers = require('ethers');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3');

const app = express();
app.use(express.json());

// Configuration
const CONFIG = {
    SBT_CONTRACT: process.env.SBT_CONTRACT || '0x...',
    RPC_URL: process.env.RPC_URL || 'http://localhost:8545',
    JWT_SECRET: process.env.JWT_SECRET || 'change-this-secret',
    PORT: process.env.PORT || 3000
};

// Initialize database (no address storage)
const db = new sqlite3.Database(':memory:');
db.run(`
    CREATE TABLE accounts (
        account_id TEXT PRIMARY KEY,
        created_at INTEGER,
        eula_hash TEXT,
        role TEXT DEFAULT 'user'
    )
`);

// Minimal Contract ABI
const SBT_ABI = [
    "function getAccountInfo(address) view returns (bool, bytes32, uint256)"
];

// Initialize provider and contract
const provider = new ethers.providers.JsonRpcProvider(CONFIG.RPC_URL);
const sbtContract = new ethers.Contract(CONFIG.SBT_CONTRACT, SBT_ABI, provider);

// POST /auth - Authenticate user
app.post('/auth', async (req, res) => {
    try {
        const { address, signature, message } = req.body;
        
        // Verify signature
        const recovered = ethers.utils.verifyMessage(message, signature);
        if (recovered.toLowerCase() !== address.toLowerCase()) {
            return res.status(401).json({ error: 'Invalid signature' });
        }
        
        // Check SBT on-chain
        const [hasSBT, accountId] = await sbtContract.getAccountInfo(address);
        
        // Generate JWT (no address stored)
        const token = jwt.sign(
            { 
                hasSBT, 
                accountId: hasSBT ? accountId : null,
                timestamp: Date.now()
            },
            CONFIG.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({ token, hasSBT, accountId: hasSBT ? accountId : null });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST /confirm-mint - Confirm SBT minting
app.post('/confirm-mint', async (req, res) => {
    try {
        const { address, signature, eulaHash, txHash } = req.body;
        
        // Verify signature
        const message = `Confirm SBT mint: ${txHash}`;
        const recovered = ethers.utils.verifyMessage(message, signature);
        if (recovered.toLowerCase() !== address.toLowerCase()) {
            return res.status(401).json({ error: 'Invalid signature' });
        }
        
        // Get account ID from chain
        const [hasSBT, accountId] = await sbtContract.getAccountInfo(address);
        if (!hasSBT) {
            return res.status(400).json({ error: 'SBT not found' });
        }
        
        // Store account (NOT address)
        db.run(
            `INSERT OR IGNORE INTO accounts (account_id, created_at, eula_hash) 
             VALUES (?, ?, ?)`,
            [accountId, Date.now(), eulaHash]
        );
        
        // Return new JWT with account ID
        const token = jwt.sign(
            { hasSBT: true, accountId, timestamp: Date.now() },
            CONFIG.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({ token, accountId });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// GET /account - Get account info (requires JWT)
app.get('/account', (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ error: 'No token' });
        
        const decoded = jwt.verify(token, CONFIG.JWT_SECRET);
        if (!decoded.hasSBT) return res.status(403).json({ error: 'No SBT' });
        
        db.get(
            `SELECT * FROM accounts WHERE account_id = ?`,
            [decoded.accountId],
            (err, row) => {
                if (err || !row) return res.status(404).json({ error: 'Not found' });
                res.json(row);
            }
        );
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

app.listen(CONFIG.PORT, () => {
    console.log(`Server running on port ${CONFIG.PORT}`);
    console.log('No addresses will be stored');
});
