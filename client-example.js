// client-example.js
// Example client implementation for Soulbound Auth

class SoulboundAuthClient {
    constructor(config) {
        this.serverUrl = config.serverUrl;
        this.sbtContract = config.sbtContract;
        this.provider = null;
        this.signer = null;
        this.token = null;
    }
    
    async connect() {
        // Connect wallet
        await window.ethereum.request({ method: 'eth_requestAccounts' });
        this.provider = new ethers.providers.Web3Provider(window.ethereum);
        this.signer = this.provider.getSigner();
        const address = await this.signer.getAddress();
        
        // Sign authentication message
        const message = `Authenticate\nTimestamp: ${Date.now()}`;
        const signature = await this.signer.signMessage(message);
        
        // Send to server
        const response = await fetch(`${this.serverUrl}/auth`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ address, signature, message })
        });
        
        const data = await response.json();
        this.token = data.token;
        
        return {
            hasSBT: data.hasSBT,
            accountId: data.accountId
        };
    }
    
    async mintSBT(eulaHash, version) {
        // Call contract to mint
        const sbt = new ethers.Contract(this.sbtContract, SBT_ABI, this.signer);
        const tx = await sbt.mintSBT(eulaHash, version);
        const receipt = await tx.wait();
        
        // Confirm with server
        const address = await this.signer.getAddress();
        const message = `Confirm SBT mint: ${receipt.transactionHash}`;
        const signature = await this.signer.signMessage(message);
        
        const response = await fetch(`${this.serverUrl}/confirm-mint`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.token}`
            },
            body: JSON.stringify({
                address,
                signature,
                eulaHash,
                txHash: receipt.transactionHash
            })
        });
        
        const data = await response.json();
        this.token = data.token;
        
        return data.accountId;
    }
    
    async getAccount() {
        const response = await fetch(`${this.serverUrl}/account`, {
            headers: { 'Authorization': `Bearer ${this.token}` }
        });
        
        return await response.json();
    }
}

// Minimal Contract ABI
const SBT_ABI = [
    "function mintSBT(bytes32 eulaHash, uint8 version) returns (uint256, bytes32)",
    "function getAccountInfo(address) view returns (bool, bytes32, uint256)"
];

// Usage example
async function example() {
    const client = new SoulboundAuthClient({
        serverUrl: 'http://localhost:3000',
        sbtContract: '0x...'
    });
    
    // Connect and check status
    const auth = await client.connect();
    
    if (!auth.hasSBT) {
        // Need to mint SBT
        const eulaHash = ethers.utils.keccak256(
            ethers.utils.toUtf8Bytes("Terms of Service v1.0")
        );
        const accountId = await client.mintSBT(eulaHash, 1);
        console.log('Account created:', accountId);
    } else {
        console.log('Existing account:', auth.accountId);
    }
    
    // Get account details
    const account = await client.getAccount();
    console.log('Account info:', account);
}
