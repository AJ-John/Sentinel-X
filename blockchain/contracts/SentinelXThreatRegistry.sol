// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SentinelXThreatRegistry {

    struct ThreatRecord {
        string threatHash;
        string sourceIP;
        string attackType;
        string riskLevel;
        uint256 riskScore;
        uint256 timestamp;
        address reporter;
    }

    ThreatRecord[] private threats;

    event ThreatRecorded(
        uint256 indexed threatId,
        string threatHash,
        string sourceIP,
        string attackType,
        string riskLevel,
        uint256 riskScore,
        uint256 timestamp,
        address reporter
    );

    function recordThreat(
        string memory threatHash,
        string memory sourceIP,
        string memory attackType,
        string memory riskLevel,
        uint256 riskScore
    ) public returns (uint256) {

        ThreatRecord memory newThreat = ThreatRecord({
            threatHash: threatHash,
            sourceIP: sourceIP,
            attackType: attackType,
            riskLevel: riskLevel,
            riskScore: riskScore,
            timestamp: block.timestamp,
            reporter: msg.sender
        });

        threats.push(newThreat);

        uint256 threatId = threats.length - 1;

        emit ThreatRecorded(
            threatId,
            threatHash,
            sourceIP,
            attackType,
            riskLevel,
            riskScore,
            block.timestamp,
            msg.sender
        );

        return threatId;
    }

    function getThreat(uint256 threatId)
        public
        view
        returns (ThreatRecord memory)
    {
        require(threatId < threats.length, "Threat does not exist");

        return threats[threatId];
    }

    function getThreatCount()
        public
        view
        returns (uint256)
    {
        return threats.length;
    }
}