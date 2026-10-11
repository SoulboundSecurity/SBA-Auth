// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ISBAIdentity
 * @notice Minimal identity predicate consumed by SBA-Auth verifiers.
 *         MIT-licensed so any system can expose or integrate against this
 *         surface without license questions; implementations may carry
 *         their own licenses.
 */
interface ISBAIdentity {
    /// @notice Whether the account holds an enrolled, non-transferable identity
    function hasIdentity(address account) external view returns (bool);

    /// @notice The account's identity value; reverts if not enrolled
    function identityOf(address account) external view returns (bytes32);
}
