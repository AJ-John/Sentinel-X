import { network } from "hardhat";

const { ethers } = await network.create();

async function main() {
    console.log("Deploying SentinelXThreatRegistry...");

    const registry = await ethers.deployContract(
        "SentinelXThreatRegistry"
    );

    await registry.waitForDeployment();

    const address = await registry.getAddress();

    console.log("SentinelXThreatRegistry deployed!");
    console.log("Contract address:", address);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});