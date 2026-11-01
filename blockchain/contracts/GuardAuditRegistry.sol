// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Local development registry for non-sensitive Guard AI audit hashes.
/// @dev Never submit personal data, credentials, or encryption keys to this contract.
contract GuardAuditRegistry {
    struct AuditRecord {
        bytes32 eventHash;
        uint64 recordedAt;
        bool exists;
    }

    mapping(bytes32 => AuditRecord) private records;
    event AuditHashRegistered(bytes32 indexed auditId, bytes32 indexed eventHash, uint64 recordedAt);
    error EmptyIdentifier();
    error EmptyEventHash();
    error AlreadyRegistered(bytes32 auditId);

    function registerEventHash(bytes32 auditId, bytes32 eventHash) external {
        if (auditId == bytes32(0)) revert EmptyIdentifier();
        if (eventHash == bytes32(0)) revert EmptyEventHash();
        if (records[auditId].exists) revert AlreadyRegistered(auditId);
        uint64 recordedAt = uint64(block.timestamp);
        records[auditId] = AuditRecord(eventHash, recordedAt, true);
        emit AuditHashRegistered(auditId, eventHash, recordedAt);
    }

    function verifyEventHash(bytes32 auditId, bytes32 candidateHash) external view returns (bool) {
        AuditRecord storage record = records[auditId];
        return record.exists && record.eventHash == candidateHash;
    }

    function getRecord(bytes32 auditId) external view returns (bytes32 eventHash, uint64 recordedAt, bool exists) {
        AuditRecord storage record = records[auditId];
        return (record.eventHash, record.recordedAt, record.exists);
    }
}
