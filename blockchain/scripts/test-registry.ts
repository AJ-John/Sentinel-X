import { network } from "hardhat";

const { ethers } = await network.create();

async function main() {
    const contractAddress =
        "0x5FbDB2315678afecb367f032d93F642f64180aa3";

    const registry = await ethers.getContractAt(
        "SentinelXThreatRegistry",
        contractAddress
    );

    console.log("Recording simulated threat...");

    const tx = await registry.recordThreat(
        "sha256-demo-threat-001",
        "192.168.1.99",
        "BRUTE_FORCE",
        "CRITICAL",
        90
    );

    await tx.wait();

    console.log("Threat recorded successfully.");

    const count = await registry.getThreatCount();

    console.log("Threat count:", count.toString());

    const threat = await registry.getThreat(0);

    console.log("\nBlockchain Threat Record:");
    console.log("Threat Hash:", threat[0]);
    console.log("Source IP:", threat[1]);
    console.log("Attack Type:", threat[2]);
    console.log("Risk Level:", threat[3]);
    console.log("Risk Score:", threat[4].toString());
    console.log("Timestamp:", threat[5].toString());
    console.log("Reporter:", threat[6]);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});