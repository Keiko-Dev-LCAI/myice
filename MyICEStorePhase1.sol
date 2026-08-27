// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * MyICEStorePhase1 — sponsor-gated writes for today's hash-based accounts
 *
 * DEPLOYABLE (after Keiko's separate go): onlySponsor closes open public writes
 * while keeping V1 function shapes so password-derived addresses can still sync.
 *
 * For full user-signed meta-tx (ecrecover + nonces), see MyICEStoreV2.sol —
 * that file is NOT deployable until accounts migrate to real EOAs / secp256k1.
 *
 * Users still pay zero gas — the dApp sponsor wallet submits txs.
 */
contract MyICEStorePhase1 {

    struct HealthRecord {
        bytes  emergencyData;
        bytes  privateData;
        uint64 updatedAt;
        bool   exists;
    }

    mapping(address => HealthRecord) private records;

    address public sponsor;
    address public owner;

    event RecordStored(address indexed user, uint64 timestamp);
    event RecordDeleted(address indexed user);
    event SponsorUpdated(address indexed previous, address indexed next);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlySponsor() {
        require(msg.sender == sponsor, "not sponsor");
        _;
    }

    constructor(address sponsor_) {
        require(sponsor_ != address(0), "bad sponsor");
        owner = msg.sender;
        sponsor = sponsor_;
    }

    function setSponsor(address sponsor_) external onlyOwner {
        require(sponsor_ != address(0), "bad sponsor");
        emit SponsorUpdated(sponsor, sponsor_);
        sponsor = sponsor_;
    }

    // V1 shapes — no user signature (hash-based accounts cannot ecrecover)
    function storeFor(address user, bytes calldata emergency, bytes calldata priv) external onlySponsor {
        require(user != address(0), "bad user");
        records[user] = HealthRecord({
            emergencyData: emergency,
            privateData:   priv,
            updatedAt:     uint64(block.timestamp),
            exists:        true
        });
        emit RecordStored(user, uint64(block.timestamp));
    }

    function storeEmergencyFor(address user, bytes calldata emergency) external onlySponsor {
        require(user != address(0), "bad user");
        HealthRecord storage r = records[user];
        r.emergencyData = emergency;
        r.updatedAt     = uint64(block.timestamp);
        r.exists        = true;
        emit RecordStored(user, uint64(block.timestamp));
    }

    /// Users delete their own data (they sign this tx themselves)
    function deleteRecord() external {
        delete records[msg.sender];
        emit RecordDeleted(msg.sender);
    }

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
