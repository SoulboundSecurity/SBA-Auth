// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.19;

/**
 * @title SoulboundAuthToken
 * @notice Non-transferable identity registry for SBA-Auth: wallet-native
 *         authentication with no stored credentials
 * @dev SBA-Auth is an enrollment/authentication split. This contract is the
 *      enrollment ceremony: minting writes an address-derived identity value
 *      into a non-transferable registry entry, paid for by the candidate key
 *      itself. Authentication (see SPEC.md) then verifies, per request, that
 *      a presented signature recovers to an address whose registered identity
 *      derives from that same address and appears on a deployment allowlist.
 *      Enrollment policy is the extension surface: open (anyone may enroll)
 *      or approval-gated (an enrollment authority co-signs each candidate,
 *      pushing KYC, HR onboarding, or multi-party approval into the mint).
 *      Role administration follows appointment semantics: the controller
 *      administers configuration, and administrative authority never travels
 *      with anything it administers. Identities cannot be transferred,
 *      reassigned, or burned: enrollment is append-only and publicly
 *      auditable through the event log.
 * @custom:security-contact security@soulboundsecurity.io
 */
contract SoulboundAuthToken {
    /// @dev Fork deployments MUST set a unique salt before deploying: the
    ///      salt namespaces identity derivation per deployment.
    string private constant IDENTITY_SALT = "SBA_SALT_V1";

    struct Identity {
        bytes32 identityId;   // keccak256(owner, IDENTITY_SALT, chainid)
        bytes32 commitment;   // ZK/KYC commitment attachment point (may be zero)
        bytes32 eulaHash;     // Terms hash accepted at enrollment
        uint256 enrolledAt;
        bool exists;
    }

    mapping(address => Identity) private _registry;
    uint256 private _totalIdentities;

    address public controller;
    address public enrollmentAuthority; // address(0) = open enrollment
    bytes32 public currentEulaHash;

    bytes32 private immutable DOMAIN_SEPARATOR;
    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant ENROLLMENT_TYPEHASH = keccak256(
        "EnrollmentApproval(address candidate,bytes32 eulaHash)"
    );

    event IdentityMinted(
        address indexed owner,
        bytes32 indexed identityId,
        bytes32 commitment,
        bytes32 eulaHash,
        uint256 timestamp
    );
    event EulaUpdated(bytes32 indexed oldHash, bytes32 indexed newHash);
    event EnrollmentAuthorityChanged(address indexed oldAuthority, address indexed newAuthority);
    event ControllerTransferred(address indexed oldController, address indexed newController);

    error IdentityExists();
    error IdentityNotFound();
    error UnauthorizedAccess();
    error InvalidAddress();
    error EulaNotSet();
    error EulaMismatch();
    error InvalidEnrollmentApproval();

    modifier onlyController() {
        if (msg.sender != controller) revert UnauthorizedAccess();
        _;
    }

    modifier validAddress(address addr) {
        if (addr == address(0)) revert InvalidAddress();
        _;
    }

    /**
     * @dev The EIP-712 domain is bound to this contract address and chain,
     *      so enrollment approvals cannot be replayed across deployments.
     * @param _controller Initial controller (multisig custody expected)
     * @param _enrollmentAuthority Enrollment co-signer; address(0) enables
     *        open enrollment
     */
    constructor(address _controller, address _enrollmentAuthority) validAddress(_controller) {
        controller = _controller;
        enrollmentAuthority = _enrollmentAuthority;
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256("SBA Enrollment"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
        emit ControllerTransferred(address(0), _controller);
    }

    // ─── Enrollment ────────────────────────────────────────────────────

    /**
     * @notice Enroll the caller: mint their non-transferable identity
     * @dev The identity derives from msg.sender, so enrollment cannot be
     *      performed on another address's behalf and the candidate key
     *      proves it can transact, not merely sign. When an enrollment
     *      authority is set, its EIP-712 approval over (candidate, eulaHash)
     *      must accompany the mint: the organization's enrollment process
     *      (KYC, onboarding, approvals) gates here, once, and never touches
     *      the per-request authentication path.
     * @param commitment Optional ZK/KYC commitment (bytes32(0) if unused)
     * @param eulaHash Must match currentEulaHash; the transaction signature
     *        is the acceptance
     * @param enrollmentSig EIP-712 EnrollmentApproval signature from the
     *        enrollment authority; ignored under open enrollment
     */
    function mintIdentity(
        bytes32 commitment,
        bytes32 eulaHash,
        bytes calldata enrollmentSig
    ) external {
        if (_registry[msg.sender].exists) revert IdentityExists();
        if (currentEulaHash == bytes32(0)) revert EulaNotSet();
        if (eulaHash != currentEulaHash) revert EulaMismatch();

        if (enrollmentAuthority != address(0)) {
            _verifyEnrollmentApproval(msg.sender, eulaHash, enrollmentSig);
        }

        bytes32 identityId = keccak256(
            abi.encodePacked(msg.sender, IDENTITY_SALT, block.chainid)
        );

        _registry[msg.sender] = Identity({
            identityId: identityId,
            commitment: commitment,
            eulaHash: eulaHash,
            enrolledAt: block.timestamp,
            exists: true
        });

        unchecked { ++_totalIdentities; }

        emit IdentityMinted(msg.sender, identityId, commitment, eulaHash, block.timestamp);
    }

    // ─── Identity predicate (consumed by the auth middleware) ─────────

    /**
     * @notice Whether the account holds an enrolled identity
     */
    function hasIdentity(address account) external view returns (bool) {
        return _registry[account].exists;
    }

    /**
     * @notice The account's identity value; reverts if not enrolled
     */
    function identityOf(address account) external view returns (bytes32) {
        if (!_registry[account].exists) revert IdentityNotFound();
        return _registry[account].identityId;
    }

    /**
     * @notice Full registry entry for an account
     */
    function getIdentity(address account) external view returns (
        bytes32 identityId,
        bytes32 commitment,
        bytes32 eulaHash,
        uint256 enrolledAt,
        bool exists
    ) {
        Identity storage id = _registry[account];
        return (id.identityId, id.commitment, id.eulaHash, id.enrolledAt, id.exists);
    }

    /**
     * @notice Canonical identity derivation for an address (matches
     *         mintIdentity); lets verifiers compute the expected value
     *         locally without trusting this contract's storage
     */
    function deriveIdentity(address account) external view validAddress(account) returns (bytes32) {
        return keccak256(abi.encodePacked(account, IDENTITY_SALT, block.chainid));
    }

    /**
     * @notice Count of identities ever enrolled
     */
    function totalIdentities() external view returns (uint256) {
        return _totalIdentities;
    }

    // ─── Administration (appointment semantics, controller-only) ──────

    /**
     * @notice Set or update the required terms hash
     */
    function setEulaHash(bytes32 _eulaHash) external onlyController {
        if (_eulaHash == bytes32(0)) revert EulaMismatch();
        bytes32 old = currentEulaHash;
        currentEulaHash = _eulaHash;
        emit EulaUpdated(old, _eulaHash);
    }

    /**
     * @notice Appoint the enrollment authority; address(0) switches to open
     *         enrollment
     */
    function setEnrollmentAuthority(address _authority) external onlyController {
        address old = enrollmentAuthority;
        enrollmentAuthority = _authority;
        emit EnrollmentAuthorityChanged(old, _authority);
    }

    /**
     * @notice Transfer the controller role
     */
    function transferController(address _newController) external onlyController validAddress(_newController) {
        address old = controller;
        controller = _newController;
        emit ControllerTransferred(old, _newController);
    }

    // ─── Internal ──────────────────────────────────────────────────────

    /**
     * @dev Verifies the enrollment authority's EIP-712 approval over
     *      (candidate, eulaHash), domain-bound to this contract and chain.
     */
    function _verifyEnrollmentApproval(
        address candidate,
        bytes32 eulaHash,
        bytes calldata sig
    ) internal view {
        bytes32 structHash = keccak256(abi.encode(ENROLLMENT_TYPEHASH, candidate, eulaHash));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        if (_recoverSigner(digest, sig) != enrollmentAuthority) revert InvalidEnrollmentApproval();
    }

    /**
     * @dev ecrecover with malleability hardening: 65-byte signatures only,
     *      EIP-2 low-s enforcement, v restricted to 27/28, zero-address
     *      recovery rejected.
     */
    function _recoverSigner(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert InvalidEnrollmentApproval();

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }

        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert InvalidEnrollmentApproval();
        }
        if (v != 27 && v != 28) revert InvalidEnrollmentApproval();

        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0)) revert InvalidEnrollmentApproval();
        return recovered;
    }
}
