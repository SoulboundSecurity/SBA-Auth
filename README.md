# Soulbound Auth (SBA)

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)

A Web3 authentication system that avoids server-side storage of Ethereum addresses by using non-transferable Soulbound Tokens (SBTs) and hashed account identifiers.

## Overview

Traditional Web3 authentication often requires storing wallet addresses in databases, creating privacy concerns and potential liability. This implementation explores an alternative approach using Soulbound Tokens to maintain persistent identity without address storage. This is a simple AI generated pseudocode example implementation, not representative of the Soulbound Finance implementation. 

## Technical Approach

### Core Concept

Instead of storing Ethereum addresses, the system:
1. Validates ownership through ephemeral signatures
2. Issues non-transferable SBTs as identity markers
3. Generates hashed Account IDs that cannot be reversed to addresses
4. Stores only these Account IDs in the database

### Account ID Generation

The Account ID uses multi-layer hashing as a stub out and example of use for ZKP KYC, account IDs, and other data as may be needed:

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

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Web3 Client                        │
│  - Wallet connection and signature generation        │
│  - SBT contract interaction                         │
│  - JWT token management                             │
└──────────────────┬──────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────┐
│                  Backend Server                      │
│  - Signature verification                            │
│  - JWT issuance and validation                      │
│  - Account ID database (no addresses)               │
│  - Role-based access control                        │
└──────────────────┬──────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────┐
│              SBT Smart Contract                      │
│  - Non-transferable token minting                    │
│  - Account ID generation                            │
│  - EULA/Terms hash storage                          │
└──────────────────────────────────────────────────────┘
```

## Authentication Flow

### Initial Connection (New User)

1. User connects wallet and signs authentication message
2. Server validates signature without storing address
3. Server checks blockchain for existing SBT
4. Returns JWT with `hasSBT: false`

### SBT Minting (Account Creation)

1. User accepts EULA/Terms
2. User mints SBT through smart contract
3. Contract generates unique Account ID
4. Server stores Account ID (not address) in database
5. Returns JWT with `hasSBT: true, accountId: <hash>`

### Subsequent Authentication

1. User signs new authentication message
2. Server validates signature
3. Server retrieves Account ID from blockchain
4. Returns JWT with Account ID for session management

## Implementation Details

### Smart Contract

The Soulbound Token contract implements:
- Non-transferable ERC721-like tokens
- Deterministic Account ID generation
- One token per address restriction
- EULA acceptance tracking

Key functions:
```solidity
mintSBT(bytes32 eulaHash, uint8 version) returns (uint256 tokenId, bytes32 accountId)
getAccountInfo(address owner) returns (bool hasToken, bytes32 accountId, uint256 tokenId)
```

### Server Component

The Node.js server provides:
- Signature verification endpoint
- JWT token generation and refresh
- Account ID based session management
- RBAC implementation using Account IDs

Example endpoints:
```
POST /auth          - Authenticate with signature
POST /confirm-mint  - Confirm SBT minting
POST /refresh       - Refresh JWT token
GET  /account       - Get account information
```

### Client SDK

JavaScript client library handles:
- Wallet connection
- Signature generation
- SBT minting transactions
- JWT token management

Basic usage:
```javascript
const sba = new SoulboundAuthClient({
  contractAddress: '0x...',
  serverUrl: 'https://api.example.com'
});

const auth = await sba.connect();
if (!auth.hasSBT) {
  await sba.mintSBT(eulaHash, version);
}
```

## Privacy Considerations

### What Gets Stored

- Hashed Account IDs (32 bytes)
- EULA acceptance records
- Role assignments
- Application metadata

### What Doesn't Get Stored

- Ethereum addresses
- Transaction histories
- Wallet balances
- Any reversible identifier

### Limitations

- Account IDs are deterministic but non-reversible
- No account recovery if wallet is lost
- One SBT per address by design
- Gas costs for initial SBT minting

## Security Notes

1. **Signature Validation**: All signatures must be verified server-side
2. **Replay Protection**: Include timestamps in signed messages
3. **Rate Limiting**: Implement on authentication endpoints
4. **JWT Security**: Use strong secrets and appropriate expiration times

## RBAC Implementation

Roles are assigned to Account IDs rather than addresses:

```javascript
const roles = {
  admins: ['0xabc...'],     // Account IDs
  moderators: ['0x123...']
};

function requireRole(role) {
  return (req, res, next) => {
    const accountId = req.user.accountId;
    if (roles[role].includes(accountId)) {
      next();
    } else {
      res.status(403).json({ error: 'Insufficient permissions' });
    }
  };
}
```

## Database Schema

```sql
CREATE TABLE accounts (
    account_id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    eula_hash TEXT NOT NULL,
    eula_version INTEGER NOT NULL,
    metadata TEXT
);

CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    account_id TEXT,
    expires_at INTEGER,
    created_at INTEGER
);

CREATE TABLE access_control (
    account_id TEXT PRIMARY KEY,
    role TEXT DEFAULT 'user',
    permissions TEXT
);
```

## Development Setup

1. Deploy the SBT contract:
```bash
npx hardhat run scripts/deploy.js --network localhost
```

2. Configure environment variables:
```bash
SBT_CONTRACT_ADDRESS=0x...
RPC_URL=http://localhost:8545
JWT_SECRET=your-secret-key
```

3. Start the server:
```bash
node server/index.js
```

## Testing Considerations

- Test signature validation thoroughly
- Verify Account ID generation consistency
- Ensure SBTs are truly non-transferable
- Validate JWT expiration and refresh logic
- Test RBAC with various role configurations

## Future Improvements

Potential enhancements to explore:

- Zero-knowledge proof integration for additional privacy
- Cross-chain SBT verification
- Account recovery mechanisms using social recovery
- Batch signature verification for performance
- Decentralized session management

## Contributing

This is an AI Psudo-code generated experimental implementation, not representative of the Soulbound Finance implementation. Issues and pull requests are welcome for improving the approach.

## License

MIT License - See LICENSE file for details.

## Acknowledgments

This implementation builds upon concepts from:
- ERC-721 token standard
- Soulbound token proposals (EIP-5192)
- JWT authentication patterns
- Privacy-preserving authentication research

## Disclaimer

This is an experimental authentication system. This is an AI pseudocode generated experimental implementation, not representative of the Soulbound Finance implementation. It has not been audited and should be thoroughly reviewed before any use. The approach trades some convenience (no account recovery) for privacy benefits.
