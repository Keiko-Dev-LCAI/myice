"""
MyICE ⚕️ — Railway Backend Server
Flask API for AI health analysis features (Premium tier)
Powered by Lightchain AIVM decentralized inference.

Set LIGHTCHAIN_PRIVATE_KEY env var (dApp wallet) on Railway.
"""

import hashlib
import ipaddress
import os
import json
import threading
import time
import urllib.request
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
# Scoped CORS — override with CORS_ORIGINS env (comma-separated). Never "*".
_CORS_ORIGINS = [o.strip() for o in os.environ.get(
    "CORS_ORIGINS",
    "https://myice.win,http://localhost:5000,http://127.0.0.1:5000"
).split(",") if o.strip()]
CORS(app, origins=_CORS_ORIGINS, allow_headers=[
    "Content-Type", "X-MyICE-Message", "X-MyICE-Signature", "X-MyICE-Proof",
])

# Vacation hard-gate. Restore: unset MAINTENANCE and redeploy.
_MAINTENANCE = os.environ.get("MAINTENANCE", "").strip().lower() in ("1", "true", "yes", "on")
_VACATION_DIR = os.path.dirname(os.path.abspath(__file__))

@app.before_request
def _vacation_gate():
    if not _MAINTENANCE:
        return None
    return send_from_directory(_VACATION_DIR, "maintenance.html")

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
# Public receive address already shown on myice.win. PAYMENT_WALLET overrides it.
_PAYMENT_WALLET_PUBLIC = "0x6518fd26a7ad2fe1ba80de5f279ee59f55c0a9ba"
_PREMIUM_WHITELIST = {
    w.strip().lower()
    for w in os.environ.get("PREMIUM_WHITELIST", "").split(",")
    if w.strip()
}
MAX_HTTP_BODY = int(os.environ.get("MAX_HTTP_BODY", str(1024 * 1024)))
MAX_PROMPT_CHARS = int(os.environ.get("MAX_PROMPT_CHARS", "12000"))
MYICE_AUTH_MAX_AGE = 600
PREMIUM_USD = 3.0
PREMIUM_SECONDS = 31 * 24 * 3600
LCAI_DEX_TOKEN = "0x9cA8530CA349c966Fe9ef903Df17a75B8A778927"
_AI_PREFIXES = (
    "/api/chat", "/api/analyze-labs", "/api/check-interactions",
    "/api/explain-medication", "/api/analyze-document",
    "/api/analyze-symptoms", "/api/suggest-questions",
)
_AI_AUTH_FIELDS = {"address", "wallet", "auth_message", "signature", "payment_tx"}

_guard_lock = _threading.Lock()
_ip_hits = _defaultdict(list)          # ip -> [ts,...]
_addr_ai_hits = _defaultdict(list)
_addr_store_hits = _defaultdict(list)
_spend_day = ""
_spend_jobs = 0
_active_ai = 0
_used_sigs = {}
_price_cache = {"usd": 0.0, "ts": 0.0}
_sub_cache = {}

def _payment_wallet():
    configured = os.environ.get("PAYMENT_WALLET", "").strip().lower()
    return configured or _PAYMENT_WALLET_PUBLIC

def _valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False

def _client_ip():
    """Cloudflare client, otherwise the last proxy hop. The first hop is caller-chosen."""
    cf = (request.headers.get("CF-Connecting-IP") or "").strip()
    if _valid_ip(cf):
        return cf
    hops = [p.strip() for p in (request.headers.get("X-Forwarded-For") or "").split(",") if p.strip()]
    for hop in reversed(hops):
        if _valid_ip(hop):
            return hop
    return request.remote_addr or ""

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

_WALLET_TX = __import__("re").compile(r"0x[0-9a-fA-F]{64}")

def _rpc(method, params):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        "https://rpc.mainnet.lightchain.ai",
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "MyICE/1.0"},
    )
    with urllib.request.urlopen(req, timeout=12) as resp:
        body = json.loads(resp.read().decode())
    if not isinstance(body, dict) or body.get("error"):
        raise RuntimeError("rpc")
    return body.get("result")

def _lcai_usd():
    now = time.time()
    cached = float(_price_cache.get("usd") or 0)
    if cached > 0 and now - float(_price_cache.get("ts") or 0) < 300:
        return cached
    price = 0.0
    try:
        req = urllib.request.Request(
            "https://api.coingecko.com/api/v3/simple/price?ids=lightchain-ai&vs_currencies=usd",
            headers={"Accept": "application/json", "User-Agent": "MyICE/1.0"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = json.loads(resp.read().decode())
        price = float((body.get("lightchain-ai") or {}).get("usd") or 0)
    except Exception:
        price = 0.0
    if price <= 0:
        try:
            req = urllib.request.Request(
                "https://api.dexscreener.com/latest/dex/tokens/" + LCAI_DEX_TOKEN,
                headers={"Accept": "application/json", "User-Agent": "MyICE/1.0"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                body = json.loads(resp.read().decode())
            for pair in body.get("pairs") or []:
                base = (pair or {}).get("baseToken") or {}
                if str(base.get("symbol") or "").upper() != "LCAI":
                    continue
                got = float(pair.get("priceUsd") or 0)
                if got > 0:
                    price = got
                    break
        except Exception:
            price = 0.0
    if price > 0:
        _price_cache["usd"] = price
        _price_cache["ts"] = now
    return price

def _subscription_ok(address, tx_hash):
    """Native LCAI transfer from the signer to the MyICE receive wallet. Fail closed."""
    address = (address or "").lower()
    tx_hash = (tx_hash or "").strip()
    if not _WALLET_TX.fullmatch(tx_hash):
        return False, "An active Premium payment is required.", 402
    key = (address, tx_hash.lower())
    now = time.time()
    hit = _sub_cache.get(key)
    if hit and hit[0] and now - hit[1] < 600:
        return True, "", 200
    try:
        tx = _rpc("eth_getTransactionByHash", [tx_hash])
    except Exception:
        return False, "Could not verify the payment. Try again.", 503
    if not isinstance(tx, dict) or not tx.get("blockNumber"):
        return False, "Payment transaction was not found or is not confirmed.", 402
    if str(tx.get("from") or "").lower() != address:
        return False, "That payment is not from this wallet.", 402
    if str(tx.get("to") or "").lower() != _payment_wallet():
        return False, "That payment was not sent to MyICE.", 402
    try:
        value = int(tx.get("value") or "0x0", 16)
        receipt = _rpc("eth_getTransactionReceipt", [tx_hash])
        block = _rpc("eth_getBlockByNumber", [tx.get("blockNumber"), False])
    except Exception:
        return False, "Could not verify the payment. Try again.", 503
    if not isinstance(receipt, dict) or int(str(receipt.get("status") or "0x0"), 16) != 1:
        return False, "Payment was not successful.", 402
    if not isinstance(block, dict):
        return False, "Could not verify the payment. Try again.", 503
    try:
        ts = int(str(block.get("timestamp") or "0x0"), 16)
    except ValueError:
        return False, "Could not verify the payment. Try again.", 503
    if ts > now + 300 or now - ts > PREMIUM_SECONDS:
        return False, "The Premium payment is older than 31 days.", 402
    price = _lcai_usd()
    if not price or price <= 0:
        return False, "Could not verify the Premium price. Try again.", 503
    required = int((PREMIUM_USD / price) * 10 ** 18)
    if value < (required * 95) // 100:
        return False, "The payment amount is below the Premium price.", 402
    _sub_cache[key] = (True, now)
    if len(_sub_cache) > 2000:
        oldest = sorted(_sub_cache.items(), key=lambda item: item[1][1])[:500]
        for old_key, _old in oldest:
            _sub_cache.pop(old_key, None)
    return True, "", 200

def _recover(message, signature):
    from eth_account import Account
    from eth_account.messages import encode_defunct
    return Account.recover_message(encode_defunct(text=message), signature=signature).lower()

def _consume_sig(signature):
    digest = hashlib.sha256(signature.encode("utf-8")).hexdigest()
    now = time.time()
    with _guard_lock:
        stale = [k for k, ts in _used_sigs.items() if now - ts > MYICE_AUTH_MAX_AGE]
        for k in stale:
            _used_sigs.pop(k, None)
        if digest in _used_sigs:
            return False
        _used_sigs[digest] = now
        return True

def _canonical_ai(data):
    clean = {k: v for k, v in data.items() if k not in _AI_AUTH_FIELDS}
    return json.dumps(clean, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _too_long(value):
    if isinstance(value, str):
        return len(value) > MAX_PROMPT_CHARS
    if isinstance(value, dict):
        return any(_too_long(v) for v in value.values())
    if isinstance(value, list):
        return any(_too_long(v) for v in value)
    return False

def _ai_authorized(data):
    message = data.get("auth_message") if isinstance(data.get("auth_message"), str) else ""
    signature = (data.get("signature") or "").strip()
    address = (data.get("address") or data.get("wallet") or "").strip().lower()
    if not message or not signature or not address:
        return False, "A wallet signature is required.", 401, ""
    parts = message.split("|")
    if len(parts) != 5 or parts[0] != "MyICE" or parts[1] != "ai" or parts[2] != address:
        return False, "A wallet signature is required.", 401, ""
    try:
        ts = int(parts[3])
    except ValueError:
        return False, "A wallet signature is required.", 401, ""
    if abs(int(time.time()) - ts) > MYICE_AUTH_MAX_AGE:
        return False, "Signature expired. Sign again.", 401, ""
    if parts[4] != hashlib.sha256(_canonical_ai(data).encode("utf-8")).hexdigest():
        return False, "Signature does not match this request.", 401, ""
    try:
        got = _recover(message, signature)
    except Exception:
        return False, "A wallet signature is required.", 401, ""
    if got != address:
        return False, "Signature does not match this wallet.", 401, ""
    if address in _PREMIUM_WHITELIST:
        return True, "", 200, address
    ok, err, code = _subscription_ok(address, data.get("payment_tx") or "")
    if not ok:
        return False, err, code, ""
    return True, "", 200, address

def _header_or_body(header, field):
    value = (request.headers.get(header) or "").strip()
    if value:
        return value
    data = request.get_json(silent=True) or {}
    got = data.get(field) or ""
    return got.strip() if isinstance(got, str) else ""

def _record_authorized(hash_addr, payload_text):
    """Prove the caller knows the password seed for this hash address. The seed is not stored."""
    message = _header_or_body("X-MyICE-Message", "auth_message")
    signature = _header_or_body("X-MyICE-Signature", "signature")
    proof = _header_or_body("X-MyICE-Proof", "proof")
    hash_addr = (hash_addr or "").strip().lower()
    if not message or not signature or not proof:
        return False, "A wallet signature is required."
    if not (hash_addr.startswith("0x") and len(hash_addr) == 42):
        return False, "A wallet signature is required."
    raw = proof[2:] if proof.startswith("0x") else proof
    if len(raw) != 64:
        return False, "A wallet signature is required."
    try:
        seed = bytes.fromhex(raw)
    except ValueError:
        return False, "A wallet signature is required."
    derived = "0x" + hashlib.sha256(seed).digest()[:20].hex()
    if derived != hash_addr:
        return False, "Signature does not match this record."
    parts = message.split("|")
    if len(parts) != 5 or parts[0] != "MyICE" or parts[1] != "record" or parts[2] != hash_addr:
        return False, "A wallet signature is required."
    try:
        ts = int(parts[3])
    except ValueError:
        return False, "A wallet signature is required."
    if abs(int(time.time()) - ts) > MYICE_AUTH_MAX_AGE:
        return False, "Signature expired. Sign again."
    if parts[4] != hashlib.sha256(payload_text.encode("utf-8")).hexdigest():
        return False, "Signature does not match this request."
    try:
        from eth_account import Account
        signer = Account.from_key(seed).address.lower()
        got = _recover(message, signature)
    except Exception:
        return False, "A wallet signature is required."
    finally:
        seed = b""
    if got != signer:
        return False, "Signature does not match this record."
    if not _consume_sig(signature):
        return False, "Signature already used. Sign again."
    return True, ""

PORT = int(os.environ.get("PORT", 5000))

@app.before_request
def _before_ai_paths():
    """Fail closed before any LCAI spend or gas-sponsored record change."""
    if request.method == "OPTIONS":
        return None
    if request.content_length is not None and request.content_length > MAX_HTTP_BODY:
        return jsonify({"error": "request is too large"}), 413
    path = request.path or ""
    if any(path.startswith(prefix) for prefix in _AI_PREFIXES):
        data = request.get_json(silent=True) or {}
        if _too_long(data):
            return jsonify({"error": "message is too long"}), 413
        ok, err, code, addr = _ai_authorized(data)
        if not ok:
            return jsonify({"error": err}), code
        gate_ok, gate_code, gate_err = _gate_ai(addr)
        if not gate_ok:
            return jsonify(gate_err), gate_code
        request._myice_ai_gated = True
        return None
    if path == "/api/store-health" and request.method == "POST":
        data = request.get_json(silent=True) or {}
        emergency = data.get("emergencyData") if isinstance(data.get("emergencyData"), str) else ""
        private = data.get("privateData") if isinstance(data.get("privateData"), str) else ""
        ok, err = _record_authorized((data.get("address") or ""), emergency + "|" + private)
        if not ok:
            return jsonify({"error": err}), 401
        return None
    if path == "/api/delete-health" and request.method == "POST":
        data = request.get_json(silent=True) or {}
        ok, err = _record_authorized((data.get("address") or ""), "delete")
        if not ok:
            return jsonify({"error": err}), 401
        return None
    if path == "/api/get-health" and request.args.get("include_private", "false").lower() == "true":
        ok, err = _record_authorized(request.args.get("address") or "", "private")
        if not ok:
            return jsonify({"error": err}), 401
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
# Sortition, prepaid balance, and answer collection live in aivm_client.py.
# The retired /api/sessions/select + /api/sessions/prepare handshake is not called.
# ════════════════════════════════════════════════════════════════════════

class AIVMClient:
    def __init__(self, private_key: str):
        if not private_key:
            raise RuntimeError("AIVM is not configured")

    def run_inference(self, prompt: str, timeout_secs: int = 360) -> str:
        import aivm_client as _aivm_sortition
        return _aivm_sortition.infer(prompt, timeout=timeout_secs)


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
    return jsonify({
        "status": "ok",
        "service": "MyICE",
        "version": "2.1.0",
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
        if not ctx:
            return jsonify({"error": "Store contract unavailable"}), 503
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


@app.route("/getlcai/<path:asset>")
def serve_getlcai_asset(asset):
    safe = os.path.basename(asset)
    gl_dir = os.path.join(_STATIC_DIR, "getlcai")
    if os.path.isfile(os.path.join(gl_dir, safe)):
        return send_from_directory(gl_dir, safe)
    return jsonify({"error": "not found"}), 404


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
            if 200 <= resp.status_code < 300:
                _record_ai_spend()
        _ai_done()
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp

# ════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print(f"MyICE ⚕️ API server starting on port {PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
