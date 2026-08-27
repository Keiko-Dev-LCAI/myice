// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * MyICEStore — On-chain health data vault
 *
 * Two-tier storage per user address:
 *   emergency  — opaque bytes; client encrypts AES-256-GCM with a key carried in QR/NFC
 *                (URL fragment). Contract stays blind — getEmergency returns ciphertext.
 *   private    — AES-256-GCM encrypted blob, only owner can decrypt with their password
 *
 * storeFor() is open — anyone can store for any address.
 * Emergency data is public by design.
 * Private data is AES-256-GCM encrypted before upload; unreadable without the user's password.
 * Gas is sponsored by the MyICE dApp wallet — users pay zero.
 */
contract MyICEStore {

    struct HealthRecord {
        bytes  emergencyData;
        bytes  privateData;
        uint64 updatedAt;
        bool   exists;
    }

    mapping(address => HealthRecord) private records;

    event RecordStored(address indexed user, uint64 timestamp);
    event RecordDeleted(address indexed user);

    // ── Write (called by gas-sponsor dApp wallet on behalf of user) ────────────

    function storeFor(address user, bytes calldata emergency, bytes calldata priv) external {
        records[user] = HealthRecord({
            emergencyData: emergency,
            privateData:   priv,
            updatedAt:     uint64(block.timestamp),
            exists:        true
        });
        emit RecordStored(user, uint64(block.timestamp));
    }

    function storeEmergencyFor(address user, bytes calldata emergency) external {
        HealthRecord storage r = records[user];
        r.emergencyData = emergency;
        r.updatedAt     = uint64(block.timestamp);
        r.exists        = true;
        emit RecordStored(user, uint64(block.timestamp));
    }

    /// Users can delete their own data directly (they sign this tx themselves)
    function deleteRecord() external {
        delete records[msg.sender];
        emit RecordDeleted(msg.sender);
    }

    // ── Read ───────────────────────────────────────────────────────────────────

    function getEmergency(address user) external view returns (bytes memory) {
        return records[user].emergencyData;
    }

    function getPrivate(address user) external view returns (bytes memory) {
        return records[user].privateData;
    }

    function getUpdatedAt(address user) external view returns (uint64) {
        return records[user].updatedAt;
    }

    function hasRecord(address user) external view returns (bool) {
        return records[user].exists;
    }
}
