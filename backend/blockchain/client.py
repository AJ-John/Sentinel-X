import hashlib
import json
import os

from dotenv import load_dotenv
from web3 import Web3

load_dotenv()

RPC_URL = os.getenv("BLOCKCHAIN_RPC_URL")
CONTRACT_ADDRESS = os.getenv("BLOCKCHAIN_CONTRACT_ADDRESS")
PRIVATE_KEY = os.getenv("BLOCKCHAIN_PRIVATE_KEY")

if not RPC_URL:
    raise RuntimeError("BLOCKCHAIN_RPC_URL is not configured")

if not CONTRACT_ADDRESS:
    raise RuntimeError("BLOCKCHAIN_CONTRACT_ADDRESS is not configured")

if not PRIVATE_KEY:
    raise RuntimeError("BLOCKCHAIN_PRIVATE_KEY is not configured")

ABI_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "blockchain",
        "artifacts",
        "contracts",
        "SentinelXThreatRegistry.sol",
        "SentinelXThreatRegistry.json",
    )
)

w3 = Web3(Web3.HTTPProvider(RPC_URL))

with open(ABI_PATH, "r", encoding="utf-8") as file:
    contract_data = json.load(file)

contract = w3.eth.contract(
    address=Web3.to_checksum_address(CONTRACT_ADDRESS),
    abi=contract_data["abi"],
)

ACCOUNT = w3.eth.account.from_key(PRIVATE_KEY).address


def create_threat_hash(
    source_ip: str,
    attack_type: str,
    risk_level: str,
    risk_score: int,
):
    raw_data = f"{source_ip}|{attack_type}|{risk_level}|{risk_score}"

    return hashlib.sha256(
        raw_data.encode("utf-8")
    ).hexdigest()


def record_threat_on_blockchain(
    source_ip: str,
    attack_type: str,
    risk_level: str,
    risk_score: int,
):
    if not w3.is_connected():
        return {
            "blockchain_status": "DISCONNECTED",
        }

    try:
        threat_hash = create_threat_hash(
            source_ip,
            attack_type,
            risk_level,
            risk_score,
        )

        nonce = w3.eth.get_transaction_count(ACCOUNT)

        transaction = contract.functions.recordThreat(
            threat_hash,
            source_ip,
            attack_type,
            risk_level,
            risk_score,
        ).build_transaction(
            {
                "from": ACCOUNT,
                "nonce": nonce,
                "gas": 500000,
                "gasPrice": w3.to_wei(1, "gwei"),
            }
        )

        signed_transaction = w3.eth.account.sign_transaction(
            transaction,
            private_key=PRIVATE_KEY,
        )

        tx_hash = w3.eth.send_raw_transaction(
            signed_transaction.raw_transaction
        )

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        threat_count = contract.functions.getThreatCount().call()
        threat_id = int(threat_count) - 1

        return {
            "blockchain_status": "RECORDED",
            "threat_id": threat_id,
            "threat_hash": threat_hash,
            "transaction_hash": tx_hash.hex(),
            "block_number": receipt.blockNumber,
            "threat_count": threat_count,
            "contract_address": CONTRACT_ADDRESS,
        }

    except Exception as error:
        return {
            "blockchain_status": "ERROR",
            "message": str(error),
        }


def get_threat_from_blockchain(threat_id: int):
    if not w3.is_connected():
        return {
            "blockchain_status": "DISCONNECTED",
        }

    try:
        threat = contract.functions.getThreat(threat_id).call()

        return {
            "blockchain_status": "VERIFIED",
            "threat_id": threat_id,
            "threat_hash": threat[0],
            "source_ip": threat[1],
            "attack_type": threat[2],
            "risk_level": threat[3],
            "risk_score": threat[4],
            "timestamp": threat[5],
            "reporter": threat[6],
            "contract_address": CONTRACT_ADDRESS,
        }

    except Exception as error:
        return {
            "blockchain_status": "ERROR",
            "message": str(error),
        }


def get_all_threats_from_blockchain():
    if not w3.is_connected():
        return {
            "blockchain_status": "DISCONNECTED",
            "threats": [],
        }

    try:
        threat_count = contract.functions.getThreatCount().call()
        threats = []

        for threat_id in range(threat_count):
            threat = contract.functions.getThreat(threat_id).call()

            threats.append(
                {
                    "threat_id": threat_id,
                    "threat_hash": threat[0],
                    "source_ip": threat[1],
                    "attack_type": threat[2],
                    "risk_level": threat[3],
                    "risk_score": threat[4],
                    "timestamp": threat[5],
                    "reporter": threat[6],
                }
            )

        return {
            "blockchain_status": "VERIFIED",
            "threat_count": threat_count,
            "threats": threats,
            "contract_address": CONTRACT_ADDRESS,
        }

    except Exception as error:
        return {
            "blockchain_status": "ERROR",
            "message": str(error),
            "threats": [],
        }


def verify_threat_hash(
    threat_id: int,
    source_ip: str,
    attack_type: str,
    risk_level: str,
    risk_score: int,
):
    blockchain_record = get_threat_from_blockchain(threat_id)

    if blockchain_record.get("blockchain_status") != "VERIFIED":
        return {
            **blockchain_record,
            "hash_match": False,
        }

    expected_hash = create_threat_hash(
        source_ip,
        attack_type,
        risk_level,
        risk_score,
    )

    stored_hash = blockchain_record.get("threat_hash")

    return {
        **blockchain_record,
        "expected_hash": expected_hash,
        "hash_match": expected_hash == stored_hash,
    }
