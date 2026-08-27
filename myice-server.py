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
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
# Scoped CORS — override with CORS_ORIGINS env (comma-separated)
_CORS_ORIGINS = [o.strip() for o in os.environ.get(
    "CORS_ORIGINS",
    "https://myice.win,http://localhost:5000,http://127.0.0.1:5000"
).split(",") if o.strip()]
CORS(app, origins=_CORS_ORIGINS)

# ════════════════════════════════════════════════════════════════════════
# CONVERSATION MEMORY (per-session, in-process)
# ════════════════════════════════════════════════════════════════════════

_sessions = {}

def get_conversation_context(session_id, max_messages=12):
    if not session_id or session_id not in _sessions:
        return ""
    history = _sessions[session_id][-max_messages:]
    if not history:
        return ""
    lines = ["[PRIOR CONVERSATION]"]
    for msg in history:
        lines.append(f"User: {msg['user']}")
        lines.append(f"Assistant: {msg['assistant']}")
    return "\n".join(lines)

def save_to_session(session_id, user_msg, ai_response):
    if session_id not in _sessions:
        _sessions[session_id] = []
    _sessions[session_id].append({"user": user_msg, "assistant": ai_response})
    _sessions[session_id] = _sessions[session_id][-50:]


# ════════════════════════════════════════════════════════════════════════
# ABUSE GUARDS (local hardening build — 2026-08-26)
# Rate limits + daily spend backstop. Signature/ownership proof for
# hash-derived MyICE addresses is documented in SECURITY-HARDENING-REVIEW.md
# (EOA migration needed for full ecrecover). These guards still stop drains.
# ════════════════════════════════════════════════════════════════════════
import threading as _threading
from collections import defaultdict as _defaultdict

_CHAT_RATE_PER_MIN = int(os.environ.get("CHAT_RATE_PER_MIN", "5"))
_CHAT_RATE_PER_DAY = int(os.environ.get("CHAT_RATE_PER_DAY", "30"))
_STORE_RATE_PER_5MIN = int(os.environ.get("STORE_RATE_PER_5MIN", "1"))
_IP_RATE_PER_MIN = int(os.environ.get("IP_RATE_PER_MIN", "30"))
_DAILY_LCAI_CAP = float(os.environ.get("DAILY_LCAI_CAP", "50"))
_LCAI_PER_AI_JOB = float(os.environ.get("LCAI_PER_JOB", "0.02"))
_MAX_CONCURRENT_AI = int(os.environ.get("MAX_CONCURRENT_JOBS", "8"))
_PAYMENT_WALLET = os.environ.get("PAYMENT_WALLET", "0x6518fD26a7aD2Fe1bA80De5f279Ee59F55C0A9bA").lower()
_PREMIUM_ENFORCE = os.environ.get("PREMIUM_ENFORCE", "false").lower() in ("1", "true", "yes")
_PREMIUM_WHITELIST = {
    w.strip().lower()
    for w in os.environ.get("PREMIUM_WHITELIST", "").split(",")
    if w.strip()
}

_guard_lock = _threading.Lock()
_ip_hits = _defaultdict(list)          # ip -> [ts,...]
_addr_ai_hits = _defaultdict(list)
_addr_store_hits = _defaultdict(list)
_spend_day = ""
_spend_jobs = 0
_active_ai = 0
_used_nonces = {}  # key -> expiry ts

def _client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"

def _prune(lst, window):
    now = time.time()
    return [t for t in lst if now - t < window]

def _rate_ok(bucket, key, limit, window):
    with _guard_lock:
        lst = _prune(bucket[key], window)
        if len(lst) >= limit:
            bucket[key] = lst
            return False
        lst.append(time.time())
        bucket[key] = lst
        return True

def _daily_cap_ok():
    global _spend_day, _spend_jobs
    day = time.strftime("%Y-%m-%d")
    with _guard_lock:
        if _spend_day != day:
            _spend_day = day
            _spend_jobs = 0
        return (_spend_jobs * _LCAI_PER_AI_JOB) < _DAILY_LCAI_CAP

def _record_ai_spend():
    global _spend_jobs
    with _guard_lock:
        _spend_jobs += 1

def _gate_ai(address: str = ""):
    """Return (ok, http_code, error_dict)."""
    ip = _client_ip()
    if not _daily_cap_ok():
        return False, 503, {"error": "Daily AI spend cap reached — try again tomorrow"}
    if not _rate_ok(_ip_hits, ip, _IP_RATE_PER_MIN, 60):
        return False, 429, {"error": "Too many requests from this IP"}
    if address:
        if not _rate_ok(_addr_ai_hits, address.lower(), _CHAT_RATE_PER_MIN, 60):
            return False, 429, {"error": "Too many AI requests for this address"}
        day_key = address.lower() + "|day"
        if not _rate_ok(_addr_ai_hits, day_key, _CHAT_RATE_PER_DAY, 86400):
            return False, 429, {"error": "Daily AI limit for this address"}
    with _guard_lock:
        global _active_ai
        if _active_ai >= _MAX_CONCURRENT_AI:
            return False, 503, {"error": "Server busy — try again shortly"}
        _active_ai += 1
    return True, 200, {}

def _ai_done():
    global _active_ai
    with _guard_lock:
        _active_ai = max(0, _active_ai - 1)

def _gate_store(address: str):
    ip = _client_ip()
    if not _rate_ok(_ip_hits, "store|" + ip, _IP_RATE_PER_MIN, 60):
        return False, 429, {"error": "Too many store requests from this IP"}
    if not _rate_ok(_addr_store_hits, address.lower(), _STORE_RATE_PER_5MIN, 300):
        return False, 429, {"error": "Store rate limit: 1 per address per 5 minutes"}
    return True, 200, {}

def _premium_ok(address: str) -> bool:
    """Server-side premium check (whitelist + optional on-chain payment scan stub)."""
    if not address:
        return False
    a = address.lower()
    if a in _PREMIUM_WHITELIST:
        return True
    # Client may pass verifiedTxHash; we only accept if it paid PAYMENT_WALLET (best-effort).
    # Full historical scan is expensive — premium is also re-checked at payment verify time
    # and can be mirrored via PREMIUM_WHITELIST / future DB.
    return False


PORT = int(os.environ.get("PORT", 5000))

@app.before_request
def _before_ai_paths():
    """Gate LCAI-spending AI routes. store-health has its own gate."""
    path = request.path or ""
    ai_prefixes = (
        "/api/chat", "/api/analyze-labs", "/api/check-interactions",
        "/api/explain-medication", "/api/analyze-document",
        "/api/analyze-symptoms", "/api/suggest-questions",
    )
    if not any(path.startswith(p) for p in ai_prefixes):
        return None
    data = request.get_json(silent=True) or {}
    addr = (data.get("address") or data.get("wallet") or "").strip()
    # Close the address-less hole — AI routes must name a wallet
    if not addr:
        return jsonify({"error": "address required for AI endpoints"}), 400
    ok, code, err = _gate_ai(addr)
    if not ok:
        return jsonify(err), code
    # Hard 402 premium gate OFF by default until a durable premium store exists.
    # Rate limits + daily LCAI cap still protect the sponsor wallet either way.
    if _PREMIUM_ENFORCE and not TEST_MODE and not _premium_ok(addr):
        _ai_done()
        return jsonify({"error": "Premium required — server-side check"}), 402
    request._myice_ai_gated = True
    return None


TEST_MODE = os.environ.get("MYICE_TEST_MODE", "").lower() in ("true", "1", "yes")

MEDICAL_DISCLAIMER = (
    "🔴 IMPORTANT: This AI output is for general informational awareness only — it is NOT medical advice, "
    "NOT a diagnosis, and NOT a treatment recommendation. AI can be wrong. "
    "Do NOT change, stop, or start any medication or treatment based on this information. "
    "Always consult your doctor or pharmacist before making any changes to your health care."
)

AI_FRAMING_RULE = (
    "CRITICAL INSTRUCTION: You must NEVER give definitive medical conclusions. "
    "NEVER say a medication combination 'is dangerous', 'is safe', 'should be stopped', or 'must be changed'. "
    "NEVER diagnose a condition. NEVER recommend starting, stopping, or changing any medication or treatment. "
    "Instead, use informational language: 'may be worth discussing with your doctor', "
    "'your pharmacist might want to review', 'some people find that...', 'research suggests...', "
    "'this is something to bring up at your next appointment'. "
    "Every response must end with: 'Please bring this information to your doctor or pharmacist "
    "before making any changes. They can review your full health picture and give you personalized guidance.' "
    "You are providing background information to help the patient have better conversations with their healthcare team — nothing more."
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
        f"{AI_FRAMING_RULE}\n\n"
        f"You are a helpful health information assistant helping a patient understand their lab results in plain English.{context_block}\n\n"
        f"Lab report name: {test_name}\n"
        f"Lab report text:\n{lab_text}\n\n"
        "Please provide:\n"
        "1. A plain-English explanation of what this test measures — background context only.\n"
        "2. For any values flagged HIGH or LOW: explain what that value generally measures in the body. "
        "Do NOT say values 'are a problem' — say 'your doctor may want to discuss this value with you'.\n"
        "3. 2-3 questions the patient could bring to their doctor about these results.\n"
        "4. Any context from the patient's conditions or medications that might be worth mentioning to their doctor.\n\n"
        "Use simple, friendly language. Frame everything as background information to help the patient "
        "have a more informed conversation with their healthcare provider — not as conclusions or diagnoses."
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
        f"{AI_FRAMING_RULE}\n\n"
        "You are a helpful health information assistant providing general background on medications.\n\n"
        f"Medications listed:\n" + "\n".join(f"- {m}" for m in med_list) + "\n\n"
        + (f"Patient's medical conditions: {', '.join(cond_list)}\n\n" if cond_list else "")
        + "Please provide general informational background on:\n"
        "1. Any combinations of these medications that are sometimes associated with interactions — "
        "describe what the interaction involves in plain English, framed as 'worth discussing with your pharmacist'.\n"
        "2. Any of these medications that are sometimes associated with worsening certain conditions — "
        "frame as 'your doctor may want to review this'.\n"
        "3. Any general precautions commonly mentioned for these medications (e.g. foods, activities) — "
        "frame as general awareness, not personal advice.\n"
        "4. Any medications in the list that belong to the same drug class — mention for awareness only.\n\n"
        "If nothing notable comes up, say so clearly. "
        "Never say any combination 'is dangerous' or 'must be changed' — only that it may be worth a conversation."
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
        f"{AI_FRAMING_RULE}\n\n"
        f"You are a helpful health information assistant providing general background on a medication.\n\n"
        f"Medication: {med_name}"
        + (f" {dosage}" if dosage else "")
        + (f" taken {route}" if route else "")
        + "\n"
        + (f"Patient conditions: {', '.join(cond_list)}\n" if cond_list else "")
        + "\nPlease provide general background information on:\n"
        "1. What this medication is commonly used for — general purpose in plain English.\n"
        "2. How it generally works in the body (brief, simple explanation).\n"
        "3. Common side effects that are generally associated with this medication — for awareness only.\n"
        "4. General precautions commonly mentioned (foods, activities) — for awareness only.\n"
        "5. General guidance on missed doses — frame as 'a common approach is...' not personal advice.\n\n"
        "Use simple, friendly language. Frame everything as general information, not personal medical advice. "
        "Remind the patient to always follow their prescribing doctor's specific instructions, "
        "which may differ from general information."
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
    session_id = data.get("session_id", '')

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
    if context.get("careTeam"):
        entries = []
        for p in context["careTeam"]:
            if p.get("name"):
                entry = f"{p.get('name')} ({p.get('role','Doctor')})"
                if p.get("phone"):
                    entry += f" phone: {p['phone']}"
                entries.append(entry)
        if entries:
            context_parts.append(f"Care team: {'; '.join(entries)}.")
    if context.get("emergencyContacts"):
        entries = []
        for c in context["emergencyContacts"]:
            if c.get("name"):
                entry = f"{c.get('name')} ({c.get('relationship','Contact')})"
                if c.get("phone"):
                    entry += f" phone: {c['phone']}"
                entries.append(entry)
        if entries:
            context_parts.append(f"Emergency contacts: {'; '.join(entries)}.")

    context_block = ("\n\nPatient health context:\n" + " ".join(context_parts)) if context_parts else ""

    prior_convo = get_conversation_context(session_id)
    prior_block = ("\n\n" + prior_convo) if prior_convo else ""

    prompt = (
        f"{AI_FRAMING_RULE}\n\n"
        "You are MyICE Health Assistant — a helpful, compassionate health information companion. "
        "You help patients understand general health information and prepare better questions for their doctor visits. "
        "You do NOT diagnose, prescribe, or give personalized medical advice — ever. "
        "You provide general background information only, always directing the patient to their healthcare provider for anything specific.\n\n"
        "IMPORTANT — Phone number formatting: If the patient asks for a phone number and it is available in their health context, "
        "respond with the name and number clearly, formatted like this: [CALL:name:number] — for example: [CALL:Dr. Jones:555-1234]. "
        "The app will convert this into a tap-to-call button automatically. "
        "If the number is not in their records, tell them politely and suggest they add it in the Care Team or Emergency Contacts section."
        + context_block
        + prior_block
        + f"\n\nPatient question: {message}\n\n"
        "Provide helpful general background information. If the question requires a personal medical assessment, "
        "acknowledge the question warmly, provide relevant general information, and clearly direct them to their doctor or pharmacist. "
        "Keep responses concise, friendly, and practical."
    )

    try:
        ai_text = aivm_call(prompt)
        if session_id:
            save_to_session(session_id, message, ai_text)
        return jsonify({"success": True, "response": ai_text, "disclaimer": MEDICAL_DISCLAIMER, "session_id": session_id})
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
        f"{AI_FRAMING_RULE}\n\n"
        "You are a helpful health information assistant helping a patient review their symptom journal.\n\n"
        "Symptom entries (most recent 30):\n"
        + "\n".join(symptom_lines)
        + "\n\n"
        + (f"Known conditions: {', '.join(cond_list)}\n" if cond_list else "")
        + (f"Current medications: {', '.join(med_list)}\n" if med_list else "")
        + "\nPlease:\n"
        "1. Identify any patterns — symptoms that appear to recur or cluster — for the patient's awareness.\n"
        "2. Note any symptoms that might be worth mentioning to their doctor in relation to listed conditions or medications.\n"
        "3. Suggest 3-4 specific observations from the journal the patient could share with their doctor — "
        "framed as 'you might want to mention to your doctor that...'.\n\n"
        "Do NOT suggest what might be wrong or what the symptoms mean medically. "
        "Focus on helping the patient describe their experience clearly to their healthcare provider. "
        "Use the actual symptom names and dates from the data."
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
# ON-CHAIN HEALTH VAULT (MyICEStore contract — gas sponsored by dApp wallet)
# ════════════════════════════════════════════════════════════════════════

MYICE_STORE_ADDRESS = "0x0089792c849C1c8313fCa17d34d46AA1de7849F1"
MYICE_STORE_ABI = [
    {"name":"storeFor","type":"function","stateMutability":"nonpayable",
     "inputs":[{"name":"user","type":"address"},{"name":"emergency","type":"bytes"},{"name":"priv","type":"bytes"}],"outputs":[]},
    {"name":"storeEmergencyFor","type":"function","stateMutability":"nonpayable",
     "inputs":[{"name":"user","type":"address"},{"name":"emergency","type":"bytes"}],"outputs":[]},
    {"name":"deleteFor","type":"function","stateMutability":"nonpayable",
     "inputs":[{"name":"user","type":"address"}],"outputs":[]},
    {"name":"deleteRecord","type":"function","stateMutability":"nonpayable",
     "inputs":[],"outputs":[]},
    {"name":"getEmergency","type":"function","stateMutability":"view",
     "inputs":[{"name":"user","type":"address"}],"outputs":[{"name":"","type":"bytes"}]},
    {"name":"getPrivate","type":"function","stateMutability":"view",
     "inputs":[{"name":"user","type":"address"}],"outputs":[{"name":"","type":"bytes"}]},
    {"name":"getUpdatedAt","type":"function","stateMutability":"view",
     "inputs":[{"name":"user","type":"address"}],"outputs":[{"name":"","type":"uint64"}]},
    {"name":"hasRecord","type":"function","stateMutability":"view",
     "inputs":[{"name":"user","type":"address"}],"outputs":[{"name":"","type":"bool"}]},
]

_store_contract = None

def get_store_contract():
    global _store_contract
    if _store_contract:
        return _store_contract
    try:
        from web3 import Web3
        pk = os.environ.get("LIGHTCHAIN_PRIVATE_KEY", "").strip()
        if not pk:
            return None
        w3 = Web3(Web3.HTTPProvider("https://rpc.mainnet.lightchain.ai"))
        _store_contract = {
            "w3": w3,
            "contract": w3.eth.contract(
                address=Web3.to_checksum_address(MYICE_STORE_ADDRESS),
                abi=MYICE_STORE_ABI
            ),
            "account": w3.eth.account.from_key(pk)
        }
        return _store_contract
    except Exception as e:
        print(f"  [store] contract init failed: {e}")
        return None


def send_store_tx(fn, extra_gas=300_000):
    """Execute a write function on MyICEStore, sponsored by dApp wallet."""
    ctx = get_store_contract()
    if not ctx:
        raise RuntimeError("Store contract unavailable — LIGHTCHAIN_PRIVATE_KEY not set")
    w3       = ctx["w3"]
    account  = ctx["account"]
    nonce    = w3.eth.get_transaction_count(account.address)
    gas_price = w3.eth.gas_price
    tx = fn.build_transaction({
        "from":     account.address,
        "nonce":    nonce,
        "gas":      extra_gas,
        "gasPrice": gas_price,
        "chainId":  9200,
    })
    signed  = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    if receipt.status != 1:
        raise RuntimeError("Transaction reverted")
    return tx_hash.hex()


@app.route("/api/store-health", methods=["POST"])
def store_health():
    """
    Gas-sponsored endpoint: stores emergency + encrypted private data on-chain.
    Body: { address, emergencyData (hex), privateData (hex, optional) }
    emergencyData / privateData must be hex strings (0x-prefixed or not).
    Rate-limited: 1 store per address per 5 minutes.
    """
    data          = request.get_json(silent=True) or {}
    user_address  = data.get("address", "").strip()
    emergency_hex = data.get("emergencyData", "").strip()
    private_hex   = data.get("privateData", "").strip()

    if not user_address or not emergency_hex:
        return jsonify({"error": "address and emergencyData required"}), 400

    ok, code, err = _gate_store(user_address)
    if not ok:
        return jsonify(err), code

    # Ownership proof (EOA path): optional signature fields for V2 contract migration.
    # Hash-derived MyICE addresses cannot ecrecover — see SECURITY-HARDENING-REVIEW.md.
    # Basic address validation
    try:
        from web3 import Web3
        user_address = Web3.to_checksum_address(user_address)
    except Exception:
        return jsonify({"error": "Invalid Ethereum address"}), 400

    # Convert hex strings to bytes
    def hex_to_bytes(h):
        h = h.replace("0x", "").replace("0X", "")
        return bytes.fromhex(h)

    try:
        em_bytes = hex_to_bytes(emergency_hex)
        pr_bytes = hex_to_bytes(private_hex) if private_hex else b""
    except Exception:
        return jsonify({"error": "Invalid hex data"}), 400

    try:
        ctx      = get_store_contract()
        contract = ctx["contract"]
        if pr_bytes:
            fn = contract.functions.storeFor(user_address, em_bytes, pr_bytes)
        else:
            fn = contract.functions.storeEmergencyFor(user_address, em_bytes)
        tx_hash = send_store_tx(fn, extra_gas=400_000)
        print(f"  [store-health] stored for {user_address} — tx: {tx_hash}")
        return jsonify({"success": True, "txHash": tx_hash})
    except Exception as e:
        print(f"  [store-health] error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/delete-health", methods=["POST"])
def delete_health():
    """
    Gas-sponsored delete: clears the current on-chain health record for `address`.
    Body: { address }
    Rate-limited like store-health (1 per address / 5 min + per-IP).
    Phase-1 tradeoff: trusts address in body (no user sig — hash-based accounts).
    """
    data         = request.get_json(silent=True) or {}
    user_address = data.get("address", "").strip()
    if not user_address:
        return jsonify({"error": "address required"}), 400

    ok, code, err = _gate_store(user_address)
    if not ok:
        return jsonify(err), code

    try:
        from web3 import Web3
        user_address = Web3.to_checksum_address(user_address)
    except Exception:
        return jsonify({"error": "Invalid Ethereum address"}), 400

    try:
        ctx = get_store_contract()
        if not ctx:
            return jsonify({"error": "Store contract unavailable"}), 503
        contract = ctx["contract"]
        # Phase-1 contract exposes deleteFor; fall back message if old ABI on-chain
        if not hasattr(contract.functions, "deleteFor"):
            return jsonify({"error": "deleteFor not available on deployed contract — deploy Phase1 first"}), 501
        fn = contract.functions.deleteFor(user_address)
        tx_hash = send_store_tx(fn, extra_gas=200_000)
        print(f"  [delete-health] deleted for {user_address} — tx: {tx_hash}")
        return jsonify({"success": True, "txHash": tx_hash})
    except Exception as e:
        print(f"  [delete-health] error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/get-health", methods=["GET"])
def get_health():
    """
    Public read: returns emergency data (and optionally encrypted private data) for an address.
    Query params: address=0x..., include_private=true/false
    """
    user_address    = request.args.get("address", "").strip()
    include_private = request.args.get("include_private", "false").lower() == "true"

    if not user_address:
        return jsonify({"error": "address required"}), 400

    try:
        from web3 import Web3
        ctx      = get_store_contract()
        if not ctx:
            return jsonify({"error": "Store contract unavailable"}), 503
        contract = ctx["contract"]
        addr     = Web3.to_checksum_address(user_address)

        has_record  = contract.functions.hasRecord(addr).call()
        updated_at  = contract.functions.getUpdatedAt(addr).call()
        em_bytes    = contract.functions.getEmergency(addr).call()
        em_hex      = "0x" + em_bytes.hex() if em_bytes else ""

        result = {
            "hasRecord":     has_record,
            "updatedAt":     updated_at,
            "emergencyData": em_hex,
        }

        if include_private:
            pr_bytes = contract.functions.getPrivate(addr).call()
            result["privateData"] = "0x" + pr_bytes.hex() if pr_bytes else ""

        return jsonify(result)
    except Exception as e:
        print(f"  [get-health] error: {e}")
        return jsonify({"error": str(e)}), 500




# ── Static / SPA helpers (emergency QR path /e) ───────────────────────────────
_STATIC_DIR = os.path.dirname(os.path.abspath(__file__))

@app.route("/e")
@app.route("/e/")
def serve_emergency_spa():
    """Serve the PWA shell for emergency QR links. Key stays in URL fragment (never POSTed)."""
    return send_from_directory(_STATIC_DIR, "index.html")

@app.route("/")
def serve_index():
    return send_from_directory(_STATIC_DIR, "index.html")


@app.route("/<path:asset>")
def serve_static_asset(asset):
    # Allow QR/lib-less local testing of icons/manifest/apk from same origin
    safe = os.path.basename(asset)
    path = os.path.join(_STATIC_DIR, safe)
    if os.path.isfile(path):
        return send_from_directory(_STATIC_DIR, safe)
    return jsonify({"error": "not found"}), 404


@app.after_request
def _after_ai_release(resp):
    if getattr(request, "_myice_ai_gated", False):
        if resp.status_code < 500:
            # count spend on successful-ish responses (2xx/4xx after work may vary)
            if 200 <= resp.status_code < 300:
                _record_ai_spend()
        _ai_done()
    return resp

# ════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print(f"MyICE ⚕️ API server starting on port {PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
