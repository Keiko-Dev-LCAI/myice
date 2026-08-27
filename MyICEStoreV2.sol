// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * MyICEStoreV2 — FULL signed meta-tx (post-account-migration)
 *
 * *** NOT DEPLOYABLE YET ***
 * Today's MyICE accounts use sha256(password+username) truncated addresses —
 * there is no secp256k1 key, so ecrecover can never match. Deploy
 * MyICEStorePhase1.sol instead (onlySponsor, V1 function shapes).
 *
 * Keep this file for after accounts migrate to real EOAs / secp256k1 keys.
 *
 * Changes vs V1 / Phase1:
 *  - onlySponsor: only the dApp gas wallet may call store*
 *  - user signature (ecrecover) + per-user nonce: proves the named `user`
 *    authorized this write
 *
 * Users still pay zero gas — sponsor submits the tx.
 */
contract MyICEStoreV2 {

    struct HealthRecord {
        bytes  emergencyData;
        bytes  privateData;
        uint64 updatedAt;
        bool   exists;
    }

    mapping(address => HealthRecord) private records;
    mapping(address => uint256) public nonces;

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

    function _digest(
        address user,
        bytes32 emergencyHash,
        bytes32 privHash,
        uint256 nonce
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                user,
                emergencyHash,
                privHash,
                nonce,
                address(this),
                block.chainid
            )
        );
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig len");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "bad v");
        // Ethereum signed message prefix (EIP-191)
        bytes32 ethHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
        );
        address signer = ecrecover(ethHash, v, r, s);
        require(signer != address(0), "bad recover");
        return signer;
    }

    function storeFor(
        address user,
        bytes calldata emergency,
        bytes calldata priv,
        uint256 nonce,
        bytes calldata sig
    ) external onlySponsor {
        require(user != address(0), "bad user");
        require(nonce == nonces[user], "bad nonce");
        bytes32 digest = _digest(user, keccak256(emergency), keccak256(priv), nonce);
        require(_recover(digest, sig) == user, "bad signer");
        nonces[user] = nonce + 1;

        records[user] = HealthRecord({
            emergencyData: emergency,
            privateData:   priv,
            updatedAt:     uint64(block.timestamp),
            exists:        true
        });
        emit RecordStored(user, uint64(block.timestamp));
    }

    function storeEmergencyFor(
        address user,
        bytes calldata emergency,
        uint256 nonce,
        bytes calldata sig
    ) external onlySponsor {
        require(user != address(0), "bad user");
        require(nonce == nonces[user], "bad nonce");
        bytes32 digest = _digest(user, keccak256(emergency), bytes32(0), nonce);
        require(_recover(digest, sig) == user, "bad signer");
        nonces[user] = nonce + 1;

        HealthRecord storage r = records[user];
        r.emergencyData = emergency;
        r.updatedAt     = uint64(block.timestamp);
        r.exists        = true;
        emit RecordStored(user, uint64(block.timestamp));
    }

    /// Users delete their own data (they pay/sign this tx themselves)
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
