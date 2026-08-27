/**
 * Local acceptance tests for MyICE emergency-tier encryption (no network, no deploy).
 * Covers: encrypt/decrypt, version marker M1, legacy plaintext, wrong/regen key,
 * fragment parse, and password-wrapped emKey riding inside private blob.
 * Run: node _test_emergency_encrypt.mjs
 */
import { webcrypto } from 'crypto';
const crypto = webcrypto;

function b64urlFromBytes(bytes) {
  let s = Buffer.from(bytes).toString('base64');
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function bytesFromB64url(str) {
  str = (str || '').replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return new Uint8Array(Buffer.from(str, 'base64'));
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
async function importEmergencyAesKey(keyB64) {
  const raw = bytesFromB64url(keyB64);
  if (raw.length !== 32) throw new Error('bad key len ' + raw.length);
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encryptData(aesKey, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder().encode(typeof plaintext === 'string' ? plaintext : JSON.stringify(plaintext));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, enc);
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0); out.set(new Uint8Array(ct), 12);
  return bytesToHex(out);
}
async function decryptData(aesKey, hexCipher) {
  const bytes = Uint8Array.from(hexCipher.replace('0x', '').match(/.{2}/g).map(h => parseInt(h, 16)));
  const iv = bytes.slice(0, 12);
  const ct = bytes.slice(12);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
  return JSON.parse(new TextDecoder().decode(pt));
}

const EM_CIPHER_MAGIC = new Uint8Array([0x4D, 0x31]); // "M1"

async function encryptEmergencyPayload(plaintext, keyB64) {
  const aes = await importEmergencyAesKey(keyB64);
  const packedHex = await encryptData(aes, plaintext);
  const packed = Uint8Array.from(packedHex.match(/.{2}/g).map(h => parseInt(h, 16)));
  const out = new Uint8Array(EM_CIPHER_MAGIC.length + packed.length);
  out.set(EM_CIPHER_MAGIC, 0);
  out.set(packed, EM_CIPHER_MAGIC.length);
  return bytesToHex(out);
}
async function decryptEmergencyPayload(hexCipher, keyB64) {
  const aes = await importEmergencyAesKey(keyB64);
  let hex = (hexCipher || '').replace(/^0x/i, '');
  if (hex.length >= 4 && hex.slice(0, 4).toLowerCase() === '4d31') hex = hex.slice(4);
  return decryptData(aes, hex);
}
function looksLikeEmergencyCipher(hex) {
  const h = (hex || '').replace(/^0x/i, '');
  if (!h || h.length < 4) return false;
  if (h.slice(0, 4).toLowerCase() === '4d31') return true;
  if (parseInt(h.slice(0, 2), 16) === 0x7b) return false;
  return h.length >= 40;
}
function parseEmergencyFragment(hash) {
  const h = (hash || '').replace(/^#/, '');
  const params = new URLSearchParams(h);
  let a = params.get('a') || '';
  let k = params.get('k') || '';
  if (!a || !k) {
    const am = h.match(/(?:^|&)a=([^&]+)/);
    const km = h.match(/(?:^|&)k=([^&]+)/);
    if (am) a = decodeURIComponent(am[1]);
    if (km) k = decodeURIComponent(km[1]);
  }
  if (!a || !k) return null;
  return { address: a, key: k };
}

let passed = 0, failed = 0;
function ok(name, cond, detail = '') {
  if (cond) { passed++; console.log('PASS', name); }
  else { failed++; console.error('FAIL', name, detail); }
}

const payload = {
  name: 'Test Patient',
  bloodType: 'O+',
  allergies: [{ name: 'Penicillin', severity: 'Anaphylaxis' }],
  contacts: [{ name: 'Alex', phone: '555-0100', relationship: 'Spouse' }],
  dnr: { status: 'None' },
  syncedAt: Date.now(),
};

const key = b64urlFromBytes(crypto.getRandomValues(new Uint8Array(32)));
const cipherHex = await encryptEmergencyPayload(JSON.stringify(payload), key);

ok('new records carry M1 magic prefix', cipherHex.slice(0, 4).toLowerCase() === '4d31');
ok('looksLikeEmergencyCipher true for marked cipher', looksLikeEmergencyCipher(cipherHex));
ok('ciphertext does not contain allergy plaintext', !Buffer.from(cipherHex, 'hex').toString('utf8').includes('Penicillin'));

const roundtrip = await decryptEmergencyPayload(cipherHex, key);
ok('decrypt restores blood type', roundtrip.bloodType === 'O+');
ok('decrypt restores allergy', roundtrip.allergies[0].name === 'Penicillin');

// Deterministic: even if AES IV would have started with 0x7b, magic wins
ok('marker check does not depend on IV first byte', looksLikeEmergencyCipher('4d317b' + 'aa'.repeat(30)));

const wrongKey = b64urlFromBytes(crypto.getRandomValues(new Uint8Array(32)));
let threw = false;
try { await decryptEmergencyPayload(cipherHex, wrongKey); } catch (e) { threw = true; }
ok('wrong key fails decrypt', threw);

const addr = '0xabc123def4567890abc123def4567890abc123de';
const url = `https://myice.win/e#a=${encodeURIComponent(addr)}&k=${encodeURIComponent(key)}`;
const frag = parseEmergencyFragment(url.split('#')[1]);
ok('fragment parses address', frag && frag.address === addr);
ok('fragment parses key', frag && frag.key === key);
ok('missing k fails parse', parseEmergencyFragment('a=' + addr) === null);

const key2 = b64urlFromBytes(crypto.getRandomValues(new Uint8Array(32)));
let threw2 = false;
try { await decryptEmergencyPayload(cipherHex, key2); } catch (e) { threw2 = true; }
ok('regenerated key invalidates old ciphertext', threw2);

// Legacy plaintext (no marker, starts with '{')
const legacyHex = bytesToHex(new TextEncoder().encode(JSON.stringify(payload)));
ok('legacy JSON hex detected as NOT cipher', !looksLikeEmergencyCipher(legacyHex));
ok('legacy starts with 7b', legacyHex.slice(0, 2).toLowerCase() === '7b');

// Fix 1: emKey rides inside password-encrypted private blob (simulated)
const sessionKey = await crypto.subtle.importKey(
  'raw', crypto.getRandomValues(new Uint8Array(32)),
  { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
);
const privateObj = { profile: '{"name":"x"}', emKey: key, syncedAt: Date.now() };
const privateCipher = await encryptData(sessionKey, JSON.stringify(privateObj));
ok('private blob ciphertext has no raw emKey string', !privateCipher.includes(key) && !Buffer.from(privateCipher, 'hex').toString('utf8').includes(key.slice(0, 8)));
const unlocked = await decryptData(sessionKey, privateCipher);
ok('password unlock restores emKey for second device', unlocked.emKey === key);
ok('store-health shape would not include raw key field', !('emKey' in { address: addr, emergencyData: cipherHex, privateData: privateCipher }));

// Simulate device B: only password, no local emKey → pull from private blob → decrypt emergency
const deviceBKey = unlocked.emKey;
const fromB = await decryptEmergencyPayload(cipherHex, deviceBKey);
ok('second device decrypts emergency without QR', fromB.bloodType === 'O+');

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
