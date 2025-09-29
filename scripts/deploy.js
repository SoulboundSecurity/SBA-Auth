// scripts/deploy.js
// Deploy script for Soulbound Auth Token contract

const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
    console.log("🚀 Deploying Soulbound Auth Token...\n");

    // Get the deployer account
    const [deployer] = await hre.ethers.getSigners();
    console.log("Deploying with account:", deployer.address);
    
    const balance = await deployer.getBalance();
    console.log("Account balance:", hre.ethers.utils.formatEther(balance), "ETH\n");

    // Deploy the SBT contract
    console.log("Deploying SoulboundAuthToken contract...");
    const SoulboundAuthToken = await hre.ethers.getContractFactory("SoulboundAuthToken");
    const sbtContract = await SoulboundAuthToken.deploy();
    await sbtContract.deployed();

    console.log("✅ SoulboundAuthToken deployed to:", sbtContract.address);
    console.log("Transaction hash:", sbtContract.deployTransaction.hash);
    
    // Wait for confirmation
    console.log("\nWaiting for confirmations...");
    await sbtContract.deployTransaction.wait(3);
    console.log("✅ Deployment confirmed!\n");

    // Save deployment info
    const deploymentInfo = {
        network: hre.network.name,
        chainId: (await hre.ethers.provider.getNetwork()).chainId,
        contracts: {
            SoulboundAuthToken: {
                address: sbtContract.address,
                deployer: deployer.address,
                deploymentBlock: sbtContract.deployTransaction.blockNumber,
                timestamp: new Date().toISOString()
            }
        }
    };

    // Save to file
    const deploymentsDir = path.join(__dirname, "../deployments");
    if (!fs.existsSync(deploymentsDir)) {
        fs.mkdirSync(deploymentsDir, { recursive: true });
    }

    const filename = `${hre.network.name}-${Date.now()}.json`;
    const filepath = path.join(deploymentsDir, filename);
    
    fs.writeFileSync(filepath, JSON.stringify(deploymentInfo, null, 2));
    console.log(`Deployment info saved to: ${filepath}\n`);

    // Create .env template if it doesn't exist
    const envPath = path.join(__dirname, "../.env.example");
    if (!fs.existsSync(envPath)) {
        const envContent = `# Soulbound Auth Configuration
SBT_CONTRACT_ADDRESS=${sbtContract.address}
RPC_URL=http://localhost:8545
JWT_SECRET=your-secret-key-here
PORT=3000

# For production
# RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY
# JWT_SECRET=generate-a-secure-random-string
`;
        fs.writeFileSync(envPath, envContent);
        console.log("Created .env.example file");
    }

    console.log("=" * 50);
    console.log("\n🎉 Deployment Complete!\n");
    console.log("Next steps:");
    console.log("1. Copy .env.example to .env and update values");
    console.log("2. Start the server: npm run dev");
    console.log("3. Open the example app: example/index.html");
    console.log("\nSBT Contract Address:", sbtContract.address);
    console.log("=" * 50);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
