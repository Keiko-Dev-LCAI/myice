"""
MyICE ⚕️ — Railway Backend Server
Flask API for AI health analysis features (Premium tier)
Powered by Lightchain AIVM decentralized inference.

Set LIGHTCHAIN_PRIVATE_KEY env var (dApp wallet) on Railway.
"""

import os
import json
import threading
import time
import secrets
import base64
from urllib.parse import quote as url_quote
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins="*")

PORT = int(os.environ.get("PORT", 5000))
TEST_MODE = os.environ.get("MYICE_TEST_MODE", "").lower() in ("true", "1", "yes")

MEDICAL_DISCLAIMER = (
    "⚠️ MyICE is a personal health organizer — not a medical device. "
    "This AI analysis is for informational purposes only and is not a substitute "
    "for professional medical advice, diagnosis, or treatment. "
    "Always consult a qualified healthcare provider with questions about your health."
)


# ════════════════════════════════════════════════════════════════════════
# AIVM CLIENT
# ════════════════════════════════════════════════════════════════════════

AIVM_GATEWAY  = "https://chat-api.mainnet.lightchain.ai"
AIVM_RELAY    = "wss://relay.mainnet.lightchain.ai/ws"
AIVM_RPC      = "https://rpc.mainnet.lightchain.ai"
AIVM_JOB_REG  = "0xfB15F90298e4CcD7106E76fFB5e520315cC42B0b"
AIVM_JOB_FEE  = 20_000_000_000_000_000   # 0.02 LCAI in wei
AIVM_CHAIN_ID = 9200

AIVM_ABI = [
    {
        "name": "createSession", "type": "function", "stateMutability": "payable",
        "inputs": [
            {"name": "paramsHash",     "type": "bytes32"},
            {"name": "worker",         "type": "address"},
            {"name": "encWorkerKey",   "type": "bytes"},
            {"name": "ephemeralPubKey","type": "bytes"},
            {"name": "initState",      "type": "bytes"},
            {"name": "expiry",         "type": "uint256"},
        ],
        "outputs": [{"name": "sessionId", "type": "uint256"}],
    },
    {
        "name": "submitJob", "type": "function", "stateMutability": "payable",
        "inputs": [
            {"name": "sessionId",  "type": "uint256"},
            {"name": "promptHash", "type": "bytes32"},
        ],
        "outputs": [{"name": "jobId", "type": "uint256"}],
    },
    {
        "anonymous": False, "name": "SessionCreated", "type": "event",
        "inputs": [
            {"indexed": True,  "name": "sessionId",     "type": "uint256"},
            {"indexed": True,  "name": "user",           "type": "address"},
            {"indexed": True,  "name": "paramsHash",     "type": "bytes32"},
            {"indexed": False, "name": "worker",         "type": "address"},
            {"indexed": False, "name": "encWorkerKey",   "type": "bytes"},
            {"indexed": False, "name": "ephemeralPubKey","type": "bytes"},
        ],
    },
    {
        "anonymous": False, "name": "JobSubmitted", "type": "event",
        "inputs": [
            {"indexed": True,  "name": "jobId",     "type": "uint256"},
            {"indexed": True,  "name": "sessionId", "type": "uint256"},
            {"indexed": False, "name": "worker",    "type": "address"},
        ],
    },
    {
        "anonymous": False, "name": "JobCompleted", "type": "event",
        "inputs": [
            {"indexed": True,  "name": "jobId",          "type": "uint256"},
            {"indexed": True,  "name": "worker",          "type": "address"},
            {"indexed": False, "name": "responseHash",    "type": "bytes32"},
            {"indexed": False, "name": "ciphertextHash",  "type": "bytes32"},
        ],
    },
]


def _decode_pubkey(s):
    if isinstance(s, (bytes, bytearray)):
        return bytes(s)
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        b = bytes.fromhex(s[2:])
    elif len(s) == 130 and all(c in "0123456789abcdefABCDEF" for c in s):
        b = bytes.fromhex(s)
    else:
        b = base64.b64decode(s)
    if len(b) != 65:
        raise ValueError(f"pubkey decode: expected 65 bytes, got {len(b)}")
    return b


def _ecdh_wrap(session_key: bytes, peer_pub_bytes: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        generate_private_key, ECDH, EllipticCurvePublicNumbers, SECP256R1,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend

    x = int.from_bytes(peer_pub_bytes[1:33], "big")
    y = int.from_bytes(peer_pub_bytes[33:65], "big")
    peer_pub  = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key(default_backend())
    ephem_priv = generate_private_key(SECP256R1(), default_backend())
    shared     = ephem_priv.exchange(ECDH(), peer_pub)
    pub_nums   = ephem_priv.public_key().public_numbers()
    ephem_pub_bytes = (
        b"\x04"
        + pub_nums.x.to_bytes(32, "big")
        + pub_nums.y.to_bytes(32, "big")
    )
    nonce  = secrets.token_bytes(12)
    ct_tag = AESGCM(shared).encrypt(nonce, session_key, None)
    return ephem_pub_bytes + nonce + ct_tag


def _aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def _aes_decrypt(key: bytes, blob: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(blob) < 28:
        raise ValueError("ciphertext too short")
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)


class AIVMClient:
    def __init__(self, private_key: str):
        import requests as _req
        from web3 import Web3
        from eth_account import Account

        self._req      = _req
        self._w3       = Web3(Web3.HTTPProvider(AIVM_RPC))
        self._account  = Account.from_key(private_key)
        self._registry = self._w3.eth.contract(
            address=Web3.to_checksum_address(AIVM_JOB_REG),
            abi=AIVM_ABI,
        )
        self._jwt     = None
        self._jwt_exp = 0
        print(f"  [AIVM] wallet: {self._account.address}")

    def _get_jwt(self) -> str:
        from eth_account.messages import encode_defunct
        if self._jwt and time.time() < self._jwt_exp - 30:
            return self._jwt
        r = self._req.get(
            f"{AIVM_GATEWAY}/api/auth/challenge",
            params={"address": self._account.address}, timeout=15,
        )
        r.raise_for_status()
        message = r.json()["message"]
        sig = self._account.sign_message(encode_defunct(text=message))
        r2 = self._req.post(
            f"{AIVM_GATEWAY}/api/auth/verify",
            json={"message": message, "signature": "0x" + sig.signature.hex()},
            timeout=15,
        )
        r2.raise_for_status()
        v = r2.json()
        self._jwt = v["token"]
        exp_str   = v["expiresAt"][:19].replace("T", " ")
        self._jwt_exp = time.mktime(time.strptime(exp_str, "%Y-%m-%d %H:%M:%S"))
        return self._jwt

    def _auth_headers(self):
        return {
            "Authorization": f"Bearer {self._get_jwt()}",
            "Accept":        "application/json",
            "Content-Type":  "application/json",
        }

    def run_inference(self, prompt: str, timeout_secs: int = 360) -> str:
        import websocket as _ws
        from web3 import Web3

        req = self._req
        print(f"  [AIVM] starting inference ({len(prompt)} chars)")

        r = req.get(f"{AIVM_GATEWAY}/api/models", timeout=15)
        r.raise_for_status()
        models = r.json().get("models", [])
        model  = next((m for m in models if m["name"] == "llama3-8b"), models[0] if models else None)
        if not model:
            raise RuntimeError("No models available from AIVM gateway")
        model_id = model["id"]
        print(f"  [AIVM] model: {model['name']} id={model_id[:10]}...")

        MY_WORKER = "0x1F899FaD2C8BD70b6eF356ae6cC3c0abDbB15EB5"
        sel = None
        for attempt_body in [
            {"modelId": model_id, "workerAddress": MY_WORKER},
            {"modelId": model_id, "worker": MY_WORKER},
            {"modelId": model_id},
        ]:
            try:
                r = req.post(
                    f"{AIVM_GATEWAY}/api/sessions/select",
                    json=attempt_body,
                    headers=self._auth_headers(), timeout=15,
                )
                if r.ok:
                    sel = r.json()
                    break
            except Exception:
                continue
        if not sel:
            raise RuntimeError("Worker selection failed")
        routed_to = sel.get("worker", "?")
        if routed_to.lower() == MY_WORKER.lower():
            print(f"  [AIVM] worker: {routed_to} (OUR NODE ✓)")
        else:
            print(f"  [AIVM] worker: {routed_to}")

        session_key  = secrets.token_bytes(32)
        enc_worker   = _ecdh_wrap(session_key, _decode_pubkey(sel["workerEncryptionKey"]))
        enc_disputer = _ecdh_wrap(session_key, _decode_pubkey(sel["disputerEncryptionKey"]))

        r = req.post(
            f"{AIVM_GATEWAY}/api/sessions/prepare",
            json={
                "modelId":        model_id,
                "encWorkerKey":   base64.b64encode(enc_worker).decode(),
                "encDisputerKey": base64.b64encode(enc_disputer).decode(),
            },
            headers=self._auth_headers(), timeout=15,
        )
        r.raise_for_status()
        prep = r.json()

        def _h(s): return s[2:] if isinstance(s, str) and s[:2].lower() == "0x" else s
        params_hash = bytes.fromhex(_h(model_id).zfill(64))
        sig_bytes   = bytes.fromhex(_h(prep["signature"]))
        gas_price   = self._w3.eth.gas_price
        nonce_val   = self._w3.eth.get_transaction_count(self._account.address)

        tx = self._registry.functions.createSession(
            params_hash,
            Web3.to_checksum_address(prep["worker"]),
            enc_worker,
            enc_disputer,
            sig_bytes,
            prep["expiry"],
        ).build_transaction({
            "from":     self._account.address,
            "nonce":    nonce_val,
            "gas":      1_000_000,
            "gasPrice": gas_price,
            "value":    0,
            "chainId":  AIVM_CHAIN_ID,
        })
        signed  = self._account.sign_transaction(tx)
        tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
        print(f"  [AIVM] createSession tx: {tx_hash.hex()}")
        receipt1 = self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=90)
        if receipt1.status != 1:
            raise RuntimeError("createSession reverted on-chain")

        session_id = None
        for log in receipt1.logs:
            try:
                evt = self._registry.events.SessionCreated().process_log(log)
                session_id = evt["args"]["sessionId"]
                break
            except Exception:
                pass
        if session_id is None:
            raise RuntimeError("SessionCreated event not found in receipt")
        print(f"  [AIVM] sessionId: {session_id}")

        relay_token = None
        deadline = time.time() + 120
        while time.time() < deadline:
            r = req.get(
                f"{AIVM_GATEWAY}/api/sessions/{session_id}/token",
                headers=self._auth_headers(), timeout=10,
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("token"):
                    relay_token = d["token"]
                    break
            time.sleep(1)
        if not relay_token:
            raise RuntimeError("Relay token not ready within 120s")

        chunks   = []
        ws_ready = threading.Event()
        ws_err   = [None]

        def _on_message(ws_obj, message):
            try:
                frame   = json.loads(message)
                payload = frame.get("payload")
                if not payload:
                    return
                blob = base64.b64decode(payload)
                try:
                    pt = _aes_decrypt(session_key, blob)
                    chunks.append(pt.decode("utf-8", errors="replace"))
                except Exception:
                    pass
            except Exception:
                pass

        def _on_open(ws_obj):
            ws_ready.set()

        def _on_error(ws_obj, err):
            ws_err[0] = err
            ws_ready.set()

        ws = _ws.WebSocketApp(
            f"{AIVM_RELAY}?token={url_quote(relay_token)}",
            on_message=_on_message,
            on_open=_on_open,
            on_error=_on_error,
        )
        ws_thread = threading.Thread(target=ws.run_forever, daemon=True)
        ws_thread.start()
        ws_ready.wait(timeout=15)
        if ws_err[0]:
            raise RuntimeError(f"WebSocket failed: {ws_err[0]}")
        print("  [AIVM] relay connected")

        cipher = _aes_encrypt(session_key, prompt.encode("utf-8"))
        r = req.post(
            f"{AIVM_GATEWAY}/api/blobs",
            json={"data": base64.b64encode(cipher).decode()},
            headers=self._auth_headers(), timeout=15,
        )
        r.raise_for_status()
        blob_hashes = r.json().get("blobHashes", [])
        if not blob_hashes:
            raise RuntimeError("No blob hash returned from gateway")
        prompt_hash = bytes.fromhex(_h(blob_hashes[0]).zfill(64))

        nonce_val2 = self._w3.eth.get_transaction_count(self._account.address)
        tx2 = self._registry.functions.submitJob(
            session_id,
            prompt_hash,
        ).build_transaction({
            "from":     self._account.address,
            "nonce":    nonce_val2,
            "gas":      500_000,
            "gasPrice": gas_price,
            "value":    AIVM_JOB_FEE,
            "chainId":  AIVM_CHAIN_ID,
        })
        signed2  = self._account.sign_transaction(tx2)
        tx_hash2 = self._w3.eth.send_raw_transaction(signed2.raw_transaction)
        print(f"  [AIVM] submitJob tx: {tx_hash2.hex()}")
        receipt2 = self._w3.eth.wait_for_transaction_receipt(tx_hash2, timeout=90)
        if receipt2.status != 1:
            raise RuntimeError("submitJob reverted — check LCAI balance")

        job_id = None
        for log in receipt2.logs:
            try:
                evt = self._registry.events.JobSubmitted().process_log(log)
                job_id = evt["args"]["jobId"]
                break
            except Exception:
                pass
        if job_id is None:
            raise RuntimeError("JobSubmitted event not found in receipt")
        print(f"  [AIVM] jobId: {job_id}")

        from web3 import Web3 as _Web3
        job_completed_topic = "0x" + _Web3.keccak(
            text="JobCompleted(uint256,address,bytes32,bytes32)"
        ).hex()
        job_id_topic = "0x" + hex(job_id)[2:].zfill(64)

        done     = False
        deadline = time.time() + timeout_secs
        while time.time() < deadline and not done:
            time.sleep(5)
            if chunks:
                print(f"  [AIVM] relay data arrived ({len(chunks)} chunks)")
                done = True
                break
            try:
                head = self._w3.eth.block_number
                logs = self._w3.eth.get_logs({
                    "address":   _Web3.to_checksum_address(AIVM_JOB_REG),
                    "fromBlock": receipt2.blockNumber,
                    "toBlock":   head,
                    "topics":    [job_completed_topic, job_id_topic],
                })
                if logs:
                    done = True
                    print("  [AIVM] JobCompleted on-chain!")
            except Exception as e:
                print(f"  [AIVM] log poll error (retrying): {e}")

        time.sleep(2)
        ws.close()

        result = "".join(chunks)
        if result:
            print(f"  [AIVM] inference done ({len(result)} chars)")
            return result
        if not done:
            raise RuntimeError(f"Timeout after {timeout_secs}s")
        return result


_aivm_client = None


def get_aivm_client():
    global _aivm_client
    pk = os.environ.get("LIGHTCHAIN_PRIVATE_KEY", "").strip()
    if not pk:
        return None
    if _aivm_client is None:
        try:
            _aivm_client = AIVMClient(pk)
        except Exception as e:
            print(f"  [AIVM] init failed: {e}")
            return None
    return _aivm_client


def aivm_call(prompt: str, timeout: int = 360) -> str:
    if TEST_MODE:
        print("  [TEST MODE] returning mock response — no LCAI spent")
        time.sleep(1)  # simulate a small delay
        return (
            "TEST MODE RESPONSE — This is a simulated AI response for testing purposes. "
            "No AIVM call was made and no LCAI was spent.\n\n"
            "When MYICE_TEST_MODE is removed from Railway env vars, real AIVM responses will appear here."
        )
    client = get_aivm_client()
    if not client:
        raise RuntimeError("AIVM unavailable — LIGHTCHAIN_PRIVATE_KEY not set")
    return client.run_inference(prompt, timeout_secs=timeout)


# ════════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ════════════════════════════════════════════════════════════════════════

@app.route("/api/health", methods=["GET"])
def health():
    pk = os.environ.get("LIGHTCHAIN_PRIVATE_KEY", "")
    return jsonify({
        "status": "ok",
        "service": "MyICE ⚕️ API",
        "version": "2.0.0",
        "aivm": "configured" if pk else "not configured",
        "test_mode": TEST_MODE
    })


@app.route("/api/analyze-labs", methods=["POST"])
def analyze_labs():
    data     = request.get_json(silent=True) or {}
    lab_text = data.get("text", "").strip()
    test_name = data.get("testName", "Lab Result")
    conditions = data.get("conditions", [])
    medications = data.get("medications", [])

    if not lab_text:
        return jsonify({"error": "No lab text provided"}), 400

    context_parts = []
    if conditions:
        names = [c.get("name", "") for c in conditions if c.get("name")]
        if names:
            context_parts.append(f"Patient's medical conditions: {', '.join(names)}.")
    if medications:
        names = [m.get("name", "") for m in medications if m.get("name")]
        if names:
            context_parts.append(f"Current medications: {', '.join(names)}.")
    context_block = (" " + " ".join(context_parts)) if context_parts else ""

    prompt = (
        f"You are a helpful medical AI assistant explaining lab results in plain English to a patient.{context_block}\n\n"
        f"Lab report name: {test_name}\n"
        f"Lab report text:\n{lab_text}\n\n"
        "Please provide:\n"
        "1. A brief plain-English summary of what this test measures and what the results mean overall.\n"
        "2. A list of any values that are flagged HIGH or LOW — explain what each one means and why it matters.\n"
        "3. Any values that are within normal range that are worth noting.\n"
        "4. 2-3 practical questions the patient should ask their doctor at their next appointment.\n"
        "5. Any patterns worth noting if the patient's health context is relevant.\n\n"
        "Be clear, compassionate, and practical. Use simple language — no medical jargon without explanation. "
        "End with a brief reminder that this is for informational purposes and they should discuss results with their doctor."
    )

    try:
        ai_text = aivm_call(prompt)
        return jsonify({"success": True, "analysis": ai_text, "disclaimer": MEDICAL_DISCLAIMER})
    except Exception as e:
        print(f"  [analyze-labs] AIVM error: {e}")
        return jsonify({"error": "AI analysis unavailable right now. Please try again shortly.", "disclaimer": MEDICAL_DISCLAIMER}), 503


@app.route("/api/check-interactions", methods=["POST"])
def check_interactions():
    data        = request.get_json(silent=True) or {}
    medications = data.get("medications", [])
    conditions  = data.get("conditions", [])

    if not medications:
        return jsonify({"error": "No medications provided"}), 400

    med_list = []
    for m in medications:
        name   = m.get("name", "").strip()
        dosage = m.get("dosage", "").strip()
        route  = m.get("route", "").strip()
        if name:
            entry = name
            if dosage:
                entry += f" {dosage}"
            if route:
                entry += f" ({route})"
            med_list.append(entry)

    cond_list = [c.get("name", "") for c in conditions if c.get("name")]

    prompt = (
        "You are a helpful medical AI assistant checking for drug interactions and medication safety.\n\n"
        f"Medications being taken:\n" + "\n".join(f"- {m}" for m in med_list) + "\n\n"
        + (f"Patient's medical conditions: {', '.join(cond_list)}\n\n" if cond_list else "")
        + "Please check for:\n"
        "1. Any dangerous drug-drug interactions between these medications.\n"
        "2. Any medications that may worsen the listed conditions.\n"
        "3. Any important warnings (e.g. avoid alcohol, grapefruit, certain foods).\n"
        "4. Any duplicate medications or overlapping drug classes.\n"
        "5. Any dosage concerns worth flagging.\n\n"
        "Be specific — name which medications interact and explain what the risk is in plain English. "
        "If no significant interactions are found, say so clearly. "
        "End with a reminder to verify with a pharmacist."
    )

    try:
        ai_text = aivm_call(prompt)
        return jsonify({"success": True, "result": ai_text, "medications_checked": med_list, "disclaimer": MEDICAL_DISCLAIMER})
    except Exception as e:
        print(f"  [check-interactions] AIVM error: {e}")
        return jsonify({"error": "AI analysis unavailable right now. Please try again shortly.", "disclaimer": MEDICAL_DISCLAIMER}), 503


@app.route("/api/explain-medication", methods=["POST"])
def explain_medication():
    data     = request.get_json(silent=True) or {}
    med_name = data.get("name", "").strip()
    dosage   = data.get("dosage", "").strip()
    route    = data.get("route", "").strip()
    conditions = data.get("conditions", [])

    if not med_name:
        return jsonify({"error": "No medication name provided"}), 400

    cond_list = [c.get("name", "") for c in conditions if c.get("name")]

    prompt = (
        f"You are a helpful medical AI assistant explaining a medication to a patient in plain English.\n\n"
        f"Medication: {med_name}"
        + (f" {dosage}" if dosage else "")
        + (f" taken {route}" if route else "")
        + "\n"
        + (f"Patient conditions: {', '.join(cond_list)}\n" if cond_list else "")
        + "\nPlease explain:\n"
        "1. What this medication is used for — its main purpose in plain English.\n"
        "2. How it works in the body (brief, simple explanation).\n"
        "3. The most common side effects to watch for.\n"
        "4. Important warnings — foods, activities, or other things to avoid.\n"
        "5. What to do if a dose is missed.\n"
        "6. Any specific notes relevant to the patient's conditions if listed.\n\n"
        "Use simple, friendly language. No jargon without explanation. "
        "End with a reminder to follow the prescribing doctor's instructions."
    )

    try:
        ai_text = aivm_call(prompt)
        return jsonify({"success": True, "explanation": ai_text, "medication": med_name, "disclaimer": MEDICAL_DISCLAIMER})
    except Exception as e:
        print(f"  [explain-medication] AIVM error: {e}")
        return jsonify({"error": "AI analysis unavailable right now. Please try again shortly.", "disclaimer": MEDICAL_DISCLAIMER}), 503


@app.route("/api/analyze-document", methods=["POST"])
def analyze_document():
    data     = request.get_json(silent=True) or {}
    doc_text = data.get("text", "").strip()
    doc_name = data.get("name", "Medical Document")

    if not doc_text:
        return jsonify({"error": "No document text provided"}), 400

    prompt = (
        "You are a helpful medical AI assistant reading a patient's medical document.\n\n"
        f"Document name: {doc_name}\n"
        f"Document contents:\n{doc_text[:3000]}\n\n"
        "Please:\n"
        "1. Identify what type of document this is (lab result, doctor's note, discharge summary, prescription, imaging report, etc.).\n"
        "2. Suggest which section of a health app this should be filed under "
        "(Lab Results, Documents, Medications, Medical History, Appointments, etc.).\n"
        "3. Provide a plain-English summary of the key information in this document.\n"
        "4. Flag any urgent findings, abnormal values, or action items the patient should follow up on.\n"
        "5. List 2-3 questions the patient might want to ask their doctor about this document.\n\n"
        "Be clear and practical. Explain any medical terms in plain English."
    )

    try:
        ai_text = aivm_call(prompt)
        return jsonify({"success": True, "result": ai_text, "disclaimer": MEDICAL_DISCLAIMER})
    except Exception as e:
        print(f"  [analyze-document] AIVM error: {e}")
        return jsonify({"error": "AI analysis unavailable right now. Please try again shortly.", "disclaimer": MEDICAL_DISCLAIMER}), 503


@app.route("/api/chat", methods=["POST"])
def chat():
    data       = request.get_json(silent=True) or {}
    message    = data.get("message", "").strip()
    context    = data.get("context", {})

    if not message:
        return jsonify({"error": "No message provided"}), 400

    context_parts = []
    if context.get("conditions"):
        names = [c.get("name", "") for c in context["conditions"] if c.get("name")]
        if names:
            context_parts.append(f"Medical conditions: {', '.join(names)}.")
    if context.get("medications"):
        names = [m.get("name", "") for m in context["medications"] if m.get("name")]
        if names:
            context_parts.append(f"Current medications: {', '.join(names)}.")
    if context.get("allergies"):
        names = [a.get("name", "") for a in context["allergies"] if a.get("name")]
        if names:
            context_parts.append(f"Allergies: {', '.join(names)}.")

    context_block = ("\n\nPatient health context:\n" + " ".join(context_parts)) if context_parts else ""

    prompt = (
        "You are MyICE Health Assistant — a helpful, knowledgeable, and compassionate AI health companion. "
        "You help patients understand their health information, prepare for doctor visits, and make sense of medical documents. "
        "You do NOT diagnose conditions or prescribe treatments. You explain things clearly in plain English and always recommend "
        "consulting a healthcare provider for medical decisions."
        + context_block
        + f"\n\nPatient question: {message}\n\n"
        "Answer helpfully and clearly. If the question involves something that requires a doctor's assessment, "
        "say so kindly while still giving useful background information. Keep your response concise and practical."
    )

    try:
        ai_text = aivm_call(prompt)
        return jsonify({"success": True, "response": ai_text, "disclaimer": MEDICAL_DISCLAIMER})
    except Exception as e:
        print(f"  [chat] AIVM error: {e}")
        return jsonify({"error": "AI assistant unavailable right now. Please try again shortly.", "disclaimer": MEDICAL_DISCLAIMER}), 503


@app.route("/api/analyze-symptoms", methods=["POST"])
def analyze_symptoms():
    data     = request.get_json(silent=True) or {}
    symptoms = data.get("symptoms", [])
    conditions = data.get("conditions", [])
    medications = data.get("medications", [])

    if not symptoms:
        return jsonify({"error": "No symptoms provided"}), 400

    symptom_lines = []
    for s in symptoms[-30:]:  # last 30 entries
        date     = s.get("date", "")
        symptom  = s.get("symptom", "")
        severity = s.get("severity", "")
        note     = s.get("note", "")
        line = f"- {date}: {symptom}"
        if severity:
            line += f" (severity: {severity}/10)"
        if note:
            line += f" — {note}"
        symptom_lines.append(line)

    cond_list = [c.get("name", "") for c in conditions if c.get("name")]
    med_list  = [m.get("name", "") for m in medications if m.get("name")]

    prompt = (
        "You are a helpful medical AI assistant analyzing a patient's symptom journal.\n\n"
        "Symptom entries (most recent 30):\n"
        + "\n".join(symptom_lines)
        + "\n\n"
        + (f"Known conditions: {', '.join(cond_list)}\n" if cond_list else "")
        + (f"Current medications: {', '.join(med_list)}\n" if med_list else "")
        + "\nPlease:\n"
        "1. Identify any patterns — symptoms that recur, worsen over time, or cluster around certain days.\n"
        "2. Note any symptoms that may be related to listed conditions or medications (side effects, flares, etc.).\n"
        "3. Flag any symptom patterns that warrant prompt medical attention.\n"
        "4. Suggest 2-3 specific things the patient should mention at their next doctor's appointment.\n\n"
        "Be practical and specific. Use the actual symptom names and dates from the data."
    )

    try:
        ai_text = aivm_call(prompt)
        return jsonify({"success": True, "result": ai_text, "disclaimer": MEDICAL_DISCLAIMER})
    except Exception as e:
        print(f"  [analyze-symptoms] AIVM error: {e}")
        return jsonify({"error": "AI analysis unavailable right now. Please try again shortly.", "disclaimer": MEDICAL_DISCLAIMER}), 503


@app.route("/api/suggest-questions", methods=["POST"])
def suggest_questions():
    data        = request.get_json(silent=True) or {}
    conditions  = data.get("conditions", [])
    medications = data.get("medications", [])
    appointment = data.get("appointment", {})
    recent_labs = data.get("recentLabs", [])

    cond_list = [c.get("name", "") for c in conditions if c.get("name")]
    med_list  = [m.get("name", "") for m in medications if m.get("name")]
    appt_type = appointment.get("reason", "") or appointment.get("doctorName", "")
    lab_names = [l.get("name", "") for l in recent_labs if l.get("name")]

    prompt = (
        "You are a helpful medical AI assistant preparing a patient for a doctor's appointment.\n\n"
        + (f"Appointment reason / doctor: {appt_type}\n" if appt_type else "")
        + (f"Patient conditions: {', '.join(cond_list)}\n" if cond_list else "")
        + (f"Current medications: {', '.join(med_list)}\n" if med_list else "")
        + (f"Recent lab results on file: {', '.join(lab_names)}\n" if lab_names else "")
        + "\nGenerate 6-8 specific, practical questions this patient should ask their doctor at this appointment. "
        "Make the questions targeted to their conditions, medications, and any recent labs. "
        "Include at least one question about medication side effects or alternatives if they're on medications. "
        "Include one question about lifestyle or prevention if relevant. "
        "Format as a numbered list. Keep each question concise and natural — how a real patient would phrase it."
    )

    try:
        ai_text = aivm_call(prompt)
        return jsonify({"success": True, "questions": ai_text, "disclaimer": MEDICAL_DISCLAIMER})
    except Exception as e:
        print(f"  [suggest-questions] AIVM error: {e}")
        return jsonify({"error": "AI unavailable right now. Please try again shortly.", "disclaimer": MEDICAL_DISCLAIMER}), 503


# ════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print(f"MyICE ⚕️ API server starting on port {PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
