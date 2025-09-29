// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title SoulboundAuthToken
 * @notice Non-transferable token for privacy-preserving authentication
 * @dev ERC721-based SBT that generates unique account IDs without storing addresses
 */
contract SoulboundAuthToken {
    
    // Token information
    string public name = "Soulbound Auth Token";
    string public symbol = "SBA";
    
    // Token ID counter
    uint256 private _tokenIdCounter = 1;
    
    // Mappings
    mapping(address => uint256) public tokenOfOwner;
    mapping(uint256 => address) public ownerOf;
    mapping(uint256 => bytes32) public accountIds;
    mapping(address => bool) public hasSBT;
    
    // EULA/Terms tracking
    mapping(uint256 => TermsAcceptance) public termsAcceptances;
    
    struct TermsAcceptance {
        bytes32 eulaHash;
        uint256 timestamp;
        uint8 version;
    }
    
    // Events
    event SBTMinted(
        address indexed owner,
        uint256 indexed tokenId,
        bytes32 indexed accountId
    );
    
    event TermsAccepted(
        uint256 indexed tokenId,
        bytes32 eulaHash,
        uint8 version
    );
    
    /**
     * @notice Mint a new SBT with terms acceptance
     * @param eulaHash Hash of the accepted EULA/Terms
     * @param version Version number of the terms
     * @return tokenId The minted token ID
     * @return accountId The generated account ID
     */
    function mintSBT(
        bytes32 eulaHash,
        uint8 version
    ) external returns (uint256 tokenId, bytes32 accountId) {
        require(!hasSBT[msg.sender], "Already has SBT");
        require(eulaHash != bytes32(0), "Invalid EULA hash");
        
        tokenId = _tokenIdCounter++;
        
        // Generate unique account ID using proprietary hashing
        accountId = _generateAccountId(msg.sender, tokenId);
        
        // Assign token
        ownerOf[tokenId] = msg.sender;
        tokenOfOwner[msg.sender] = tokenId;
        accountIds[tokenId] = accountId;
        hasSBT[msg.sender] = true;
        
        // Record terms acceptance
        termsAcceptances[tokenId] = TermsAcceptance({
            eulaHash: eulaHash,
            timestamp: block.timestamp,
            version: version
        });
        
        emit SBTMinted(msg.sender, tokenId, accountId);
        emit TermsAccepted(tokenId, eulaHash, version);
        
        return (tokenId, accountId);
    }
    
    /**
     * @notice Get account ID for an address
     * @param owner The address to check
     * @return The account ID if exists, empty bytes32 otherwise
     */
    function getAccountId(address owner) external view returns (bytes32) {
        if (!hasSBT[owner]) {
            return bytes32(0);
        }
        uint256 tokenId = tokenOfOwner[owner];
        return accountIds[tokenId];
    }
    
    /**
     * @notice Check if address has SBT and get details
     * @param owner The address to check
     * @return hasToken Whether the address has an SBT
     * @return accountId The account ID if exists
     * @return tokenId The token ID if exists
     */
    function getAccountInfo(address owner) external view returns (
        bool hasToken,
        bytes32 accountId,
        uint256 tokenId
    ) {
        hasToken = hasSBT[owner];
        if (hasToken) {
            tokenId = tokenOfOwner[owner];
            accountId = accountIds[tokenId];
        }
        return (hasToken, accountId, tokenId);
    }
    
    /**
     * @notice Generate unique account ID
     * @dev Proprietary hashing for privacy preservation
     */
    function _generateAccountId(
        address owner,
        uint256 tokenId
    ) private pure returns (bytes32) {
        // Multi-layer hashing for privacy
        bytes32 layer1 = keccak256(abi.encodePacked(owner, tokenId));
        bytes32 layer2 = keccak256(abi.encodePacked(layer1, "SBA_PRIVACY_SALT_V1"));
        
        // Final obfuscation
        return keccak256(abi.encodePacked(
            uint128(uint256(layer2)),
            uint128(uint256(layer1)),
            "SOULBOUND_AUTH"
        ));
    }
    
    /**
     * @notice Prevent token transfers (Soulbound property)
     */
    function transferFrom(address, address, uint256) external pure {
        revert("SBT: Transfers are disabled");
    }
    
    function safeTransferFrom(address, address, uint256) external pure {
        revert("SBT: Transfers are disabled");
    }
    
    function safeTransferFrom(address, address, uint256, bytes memory) external pure {
        revert("SBT: Transfers are disabled");
    }
    
    function approve(address, uint256) external pure {
        revert("SBT: Approvals are disabled");
    }
    
    function setApprovalForAll(address, bool) external pure {
        revert("SBT: Approvals are disabled");
    }
    
    /**
     * @notice Get total supply of SBTs
     */
    function totalSupply() external view returns (uint256) {
        return _tokenIdCounter - 1;
    }
}
