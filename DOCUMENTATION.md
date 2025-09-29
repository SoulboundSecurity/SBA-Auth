# Soulbound Auth (SBA) - Technical Documentation

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Privacy Guarantees](#privacy-guarantees)
4. [Implementation Guide](#implementation-guide)
5. [API Reference](#api-reference)
6. [Security Considerations](#security-considerations)
7. [RBAC Implementation](#rbac-implementation)

## Overview

Soulbound Auth (SBA) is a revolutionary Web3 authentication system that achieves perfect privacy by **never storing Ethereum addresses** on the server. Instead, it uses non-transferable Soulbound Tokens (SBTs) combined with cryptographic proofs to maintain user identity.

### Core Principles

1. **Zero Address Storage**: Server databases never contain wallet addresses
2. **Ephemeral Authentication**: Each session validates ownership through signatures
3. **Privacy by Design**: Only hashed Account IDs are stored
4. **No External Dependencies**: No email, phone, or OAuth required

## Architecture

### System Components

```
┌────────────────────────────────────────────────────┐
│                   User Wallet                       │
│  • Signs authentication messages                    │
│  • Holds SBT (non-transferable)                    │
│  • Never reveals private key                        │
└────────────────┬───────────────────────────────────┘
                 │
┌────────────────▼───────────────────────────────────┐
│              SBA Client Library                     │
│  • Manages wallet connection                        │
│  • Handles signature generation                     │
│  • Manages JWT tokens                              │
│  • Interfaces with SBT contract                    │
└────────────────┬───────────────────────────────────┘
                 │
┌────────────────▼───────────────────────────────────┐
│                 SBA Server                          │
│  • Validates signatures                             │
│  • Generates/validates JWTs                         │
│  • Stores Account IDs (NOT addresses)               │
│  • Manages RBAC                                     │
└────────────────┬───────────────────────────────────┘
                 │
┌────────────────▼───────────────────────────────────┐
│           SBT Smart Contract                        │
│  • Mints non-transferable tokens                    │
│  • Generates unique Account IDs                     │
│  • Stores EULA acceptance                          │
│  • Provides on-chain verification                   │
└────────────────────────────────────────────────────┘
```

### Authentication Flow

#### 1. Initial Connection (New User)
```javascript
// User connects wallet
await ethereum.request({ method: 'eth_requestAccounts' });

// Sign authentication message
const message = generateAuthMessage();
const signature = await signer.signMessage(message);

// Server validates signature and checks for SBT
const jwt = await server.authenticate(address, signature, message);
// Returns: { hasSBT: false, accountId: null }
```

#### 2. SBT Minting (Account Creation)
```javascript
// User accepts EULA
const eulaHash = keccak256(eulaText);

// Mint SBT on-chain
const tx = await sbtContract.mintSBT(eulaHash, version);

// Server creates account with Account ID (no address!)
await server.confirmMint(txHash, eulaHash);
// Returns: { hasSBT: true, accountId: "0x..." }
```

#### 3. Subsequent Connections
```javascript
// User signs new message
const signature = await signer.signMessage(message);

// Server validates and retrieves Account ID from chain
const jwt = await server.authenticate(address, signature, message);
// Returns: { hasSBT: true, accountId: "0x..." }
```

## Privacy Guarantees

### What IS Stored
- ✅ Hashed Account IDs (non-reversible)
- ✅ EULA acceptance records
- ✅ Role assignments
- ✅ Application-specific metadata

### What is NEVER Stored
- ❌ Ethereum addresses
- ❌ Transaction histories
- ❌ Wallet balances
- ❌ Personal identifiable information

### Account ID Generation

The Account ID is generated using multiple layers of hashing:

```solidity
function _generateAccountId(address owner, uint256 tokenId) 
    private pure returns (bytes32) 
{
    bytes32 layer1 = keccak256(abi.encodePacked(owner, tokenId));
    bytes32 layer2 = keccak256(abi.encodePacked(layer1, "SBA_PRIVACY_SALT_V1"));
    
    return keccak256(abi.encodePacked(
        uint128(uint256(layer2)),
        uint128(uint256(layer1)),
        "SOULBOUND_AUTH"
    ));
}
```

This ensures:
- Account IDs cannot be reversed to addresses
- Each ID is unique and deterministic
- No correlation between IDs and addresses

## Implementation Guide

### 1. Deploy the SBT Contract

```bash
# Install dependencies
npm install

# Deploy to local network
npx hardhat node
npx hardhat run scripts/deploy.js --network localhost

# Deploy to testnet
npx hardhat run scripts/deploy.js --network sepolia
```

### 2. Configure the Server

```javascript
// server.js
const SoulboundAuthServer = require('soulbound-auth/server');

const server = new SoulboundAuthServer({
    sbtContractAddress: '0x...',  // Your deployed SBT
    rpcUrl: 'https://eth-mainnet.g.alchemy.com/v2/...',
    jwtSecret: 'your-secure-secret',
    adminSBTIds: ['0x...']  // Optional admin Account IDs
});

server.start();
```

### 3. Integrate the Client

```javascript
// client.js
import { SoulboundAuthClient } from 'soulbound-auth/client';

const sbaClient = new SoulboundAuthClient({
    serverUrl: 'https://api.yourapp.com',
    sbtContractAddress: '0x...'
});

// Connect and authenticate
const auth = await sbaClient.connect();

// Mint SBT if needed
if (!auth.hasSBT) {
    const eulaHash = generateEulaHash();
    await sbaClient.mintSBT(eulaHash, 1);
}
```

## API Reference

### Server Endpoints

#### `POST /auth`
Authenticate a user with signature verification.

**Request:**
```json
{
    "address": "0x...",
    "signature": "0x...",
    "message": "Soulbound Auth\n\n..."
}
```

**Response:**
```json
{
    "token": "jwt...",
    "hasSBT": true,
    "accountId": "0x...",
    "role": "user"
}
```

#### `POST /confirm-mint`
Confirm SBT minting and create account.

**Request:**
```json
{
    "address": "0x...",
    "signature": "0x...",
    "eulaHash": "0x...",
    "version": 1,
    "txHash": "0x..."
}
```

#### `GET /account`
Get account information (requires JWT).

**Headers:**
```
Authorization: Bearer <jwt>
```

**Response:**
```json
{
    "account_id": "0x...",
    "created_at": 1234567890,
    "role": "user",
    "permissions": ["read", "write"]
}
```

### Smart Contract Methods

#### `mintSBT(bytes32 eulaHash, uint8 version)`
Mint a new Soulbound Token.

**Returns:**
- `tokenId`: The minted token ID
- `accountId`: The generated Account ID

#### `getAccountInfo(address owner)`
Get account information for an address.

**Returns:**
- `hasToken`: Whether the address has an SBT
- `accountId`: The Account ID if exists
- `tokenId`: The token ID if exists

## Security Considerations

### 1. Signature Validation
- Always verify signatures server-side
- Use time-based nonces to prevent replay attacks
- Implement rate limiting

### 2. JWT Security
- Use strong, random secrets
- Set appropriate expiration times
- Rotate secrets regularly

### 3. Contract Security
- SBTs are non-transferable by design
- Account IDs use strong cryptographic hashing
- EULA hashes provide legal compliance

### 4. Database Security
- Never store addresses, even encrypted
- Use Account IDs as primary keys
- Implement proper access controls

## RBAC Implementation

### Role Assignment

```javascript
// Define roles by Account ID
const ROLES = {
    admins: [
        '0xabc123...',  // Account ID, not address!
        '0xdef456...'
    ],
    moderators: [
        '0x789ghi...'
    ]
};

// Check role in middleware
function requireRole(role) {
    return (req, res, next) => {
        const accountId = req.user.accountId;
        
        if (ROLES[role].includes(accountId)) {
            next();
        } else {
            res.status(403).json({ error: 'Insufficient permissions' });
        }
    };
}

// Use in routes
app.get('/admin', requireAuth, requireRole('admins'), (req, res) => {
    // Admin-only endpoint
});
```

### Permission Management

```sql
-- Store permissions by Account ID
CREATE TABLE permissions (
    account_id TEXT PRIMARY KEY,
    can_read BOOLEAN DEFAULT true,
    can_write BOOLEAN DEFAULT false,
    can_delete BOOLEAN DEFAULT false,
    can_admin BOOLEAN DEFAULT false
);
```

## Best Practices

1. **Never Log Addresses**: Even in development, avoid logging wallet addresses
2. **Use Standard Auth Messages**: Consistent message format prevents phishing
3. **Implement Rate Limiting**: Protect against brute force attacks
4. **Regular Token Rotation**: Refresh JWTs regularly
5. **Audit Trail**: Log actions by Account ID, not address

## Troubleshooting

### Common Issues

**Issue: "Already has SBT" error**
- Each address can only mint one SBT
- This is by design for identity uniqueness

**Issue: JWT expired**
- Implement automatic refresh in client
- Use refresh endpoint before expiration

**Issue: Account not found**
- Ensure SBT was minted successfully
- Verify mint confirmation was called

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please submit PRs to the GitHub repository.

## Support

- GitHub Issues: https://github.com/your-org/soulbound-auth/issues
- Discord: https://discord.gg/soulbound-auth
- Documentation: https://docs.soulbound-auth.io
