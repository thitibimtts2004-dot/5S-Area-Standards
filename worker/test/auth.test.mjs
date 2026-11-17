// ทดสอบ Worker ที่แก้ BUG-2 — ตรวจว่าการยืนยัน Firebase ID token ทำงานจริง
// รัน: cd worker && npm test
import crypto from 'node:crypto';
import worker from '../src/index.js';

const PROJECT = 'fir-area-standards';
const ISS = 'https://securetoken.google.com/' + PROJECT;

// ── คู่กุญแจจริง (ของ "Google" ปลอม) + คู่กุญแจของผู้โจมตี ──
const good = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const evil = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const KID = 'testkid1';
const goodJwk = good.publicKey.export({ format: 'jwk' });
const JWKS = { keys: [{ kid: KID, kty: 'RSA', alg: 'RS256', use: 'sig', n: goodJwk.n, e: goodJwk.e }] };

const b64u = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function makeToken(payload, { key = good.privateKey, kid = KID, alg = 'RS256' } = {}) {
  const h = b64u(JSON.stringify({ alg, kid, typ: 'JWT' }));
  const p = b64u(JSON.stringify(payload));
  const sig = crypto.sign('RSA-SHA256', Buffer.from(h + '.' + p), key);
  return h + '.' + p + '.' + b64u(sig);
}
const now = () => Math.floor(Date.now() / 1000);
const validPayload = (sub = 'uid-inspector') => ({ sub, aud: PROJECT, iss: ISS, iat: now() - 60, exp: now() + 3600 });

// ── stub fetch: ตอบ JWKS และ Firestore REST (users/{uid}) ──
const ROLES = {
  'uid-admin': { role: { stringValue: 'admin' }, active: { booleanValue: true } },
  'uid-inspector': { role: { stringValue: 'inspector' }, active: { booleanValue: true } },
  'uid-exadmin': { role: { stringValue: 'admin' }, active: { booleanValue: false } },
};
let firestoreCalls = 0;
globalThis.fetch = async (url, opts = {}) => {
  url = String(url);
  if (url.includes('/service_accounts/v1/jwk/')) {
    return new Response(JSON.stringify(JWKS), { headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=3600' } });
  }
  if (url.includes('firestore.googleapis.com')) {
    firestoreCalls++;
    if (!(opts.headers || {}).Authorization?.startsWith('Bearer ')) return new Response('no auth', { status: 401 });
    const uid = decodeURIComponent(url.split('/documents/users/')[1]);
    if (!ROLES[uid]) return new Response('{}', { status: 404 });
    return new Response(JSON.stringify({ fields: ROLES[uid] }), { headers: { 'content-type': 'application/json' } });
  }
  throw new Error('unexpected fetch: ' + url);
};

// ── stub R2 bucket ──
const stored = new Map();
const env = {
  FIREBASE_PROJECT_ID: PROJECT,
  BUCKET: {
    async put(k, v, o) { stored.set(k, { v, o }); },
    async get(k) { return stored.has(k) ? { body: 'x', writeHttpMetadata() {}, httpEtag: '"e"' } : null; },
    async list({ prefix }) { return { objects: [...stored.keys()].filter(k => k.startsWith(prefix)).map(k => ({ key: k })), truncated: false }; },
    async delete(keys) { for (const k of keys) stored.delete(k); },
  },
};

const PNG = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
const upload = (path, token) => worker.fetch(new Request('https://w.dev/upload', {
  method: 'POST', body: PNG,
  headers: { 'Content-Type': 'image/png', 'x-file-path': path, ...(token ? { Authorization: 'Bearer ' + token } : {}) },
}), env);
const del = (id, token) => worker.fetch(new Request('https://w.dev/inspection/' + id, {
  method: 'DELETE', headers: token ? { Authorization: 'Bearer ' + token } : {},
}), env);
const delFile = (key, token) => worker.fetch(new Request('https://w.dev/file/' + encodeURIComponent(key), {
  method: 'DELETE', headers: token ? { Authorization: 'Bearer ' + token } : {},
}), env);

// ── ชุดทดสอบ ──
let pass = 0, fail = 0;
async function check(name, got, want) {
  const r = await got;
  const s = r.status;
  if (s === want) { pass++; console.log(`  ✅ ${name} → ${s}`); }
  else { fail++; console.log(`  ❌ ${name} → ได้ ${s} ควรได้ ${want}`); }
}

console.log('\n── ปฏิเสธ token ที่ไม่ถูกต้อง (ควรได้ 401 ทุกข้อ) ──');
await check('ไม่ส่ง token มาเลย', upload('inspections/a1/1/x.jpg', null), 401);
await check('token ขยะ', upload('inspections/a1/1/x.jpg', 'not.a.token'), 401);
await check('เซ็นด้วยกุญแจของผู้โจมตี', upload('inspections/a1/1/x.jpg', makeToken(validPayload(), { key: evil.privateKey })), 401);
await check('kid ไม่ตรงกับ JWKS', upload('inspections/a1/1/x.jpg', makeToken(validPayload(), { kid: 'unknown' })), 401);
await check('alg=none (ตัดลายเซ็นทิ้ง)', upload('inspections/a1/1/x.jpg', b64u(JSON.stringify({ alg: 'none', kid: KID })) + '.' + b64u(JSON.stringify(validPayload())) + '.'), 401);
await check('หมดอายุแล้ว', upload('inspections/a1/1/x.jpg', makeToken({ ...validPayload(), exp: now() - 10 })), 401);
await check('aud เป็นโปรเจกต์อื่น', upload('inspections/a1/1/x.jpg', makeToken({ ...validPayload(), aud: 'other-project' })), 401);
await check('iss ปลอม', upload('inspections/a1/1/x.jpg', makeToken({ ...validPayload(), iss: 'https://evil.example/' + PROJECT })), 401);
await check('สลับ payload หลังเซ็น', (async () => {
  const t = makeToken(validPayload());
  const [h, , s] = t.split('.');
  return upload('inspections/a1/1/x.jpg', h + '.' + b64u(JSON.stringify(validPayload('uid-admin'))) + '.' + s);
})(), 401);

console.log('\n── อัปโหลดรูปหลักฐาน inspections/ (ผู้ใช้ที่ล็อกอินแล้วทำได้) ──');
await check('inspector อัปรูปหลักฐาน', upload('inspections/a1/1/x.jpg', makeToken(validPayload())), 200);
await check('path ผิดรูปแบบ ยังถูกปฏิเสธ', upload('../../etc/passwd', makeToken(validPayload())), 400);

console.log('\n── อัปรูปมาตรฐาน standards/ (เฉพาะแอดมิน) ──');
await check('inspector อัปรูปมาตรฐาน', upload('standards/Office/1/x.jpg', makeToken(validPayload('uid-inspector'))), 403);
await check('แอดมินอัปรูปมาตรฐาน', upload('standards/Office/1/x.jpg', makeToken(validPayload('uid-admin'))), 200);
await check('แอดมินที่ถูกปิดใช้งาน', upload('standards/Office/1/x.jpg', makeToken(validPayload('uid-exadmin'))), 403);
await check('บัญชีที่ไม่มี users doc', upload('standards/Office/1/x.jpg', makeToken(validPayload('uid-ghost'))), 403);

console.log('\n── ลบรูปทั้งการตรวจ (เฉพาะแอดมิน) ──');
await check('ไม่ส่ง token', del('a1', null), 401);
await check('inspector สั่งลบ', del('a1', makeToken(validPayload('uid-inspector'))), 403);
const before = stored.size;
await check('แอดมินสั่งลบ', del('a1', makeToken(validPayload('uid-admin'))), 200);
if (stored.size < before) { pass++; console.log('  ✅ ไฟล์ของ inspection a1 ถูกลบจริง'); }
else { fail++; console.log('  ❌ ไฟล์ไม่ถูกลบ'); }

console.log('\n── ลบรูปมาตรฐานทีละไฟล์ DELETE /file/ (เฉพาะแอดมิน · เฉพาะ standards/) ──');
await upload('standards/Office/9/del.jpg', makeToken(validPayload('uid-admin')));
await upload('inspections/keep1/1/keep.jpg', makeToken(validPayload()));
await check('ไม่ส่ง token', delFile('standards/Office/9/del.jpg', null), 401);
await check('inspector สั่งลบ', delFile('standards/Office/9/del.jpg', makeToken(validPayload('uid-inspector'))), 403);
await check('แอดมินลบรูปหลักฐาน inspections/ ไม่ได้', delFile('inspections/keep1/1/keep.jpg', makeToken(validPayload('uid-admin'))), 400);
await check('path ผิดรูปแบบ', delFile('../../etc/passwd', makeToken(validPayload('uid-admin'))), 400);
await check('แอดมินลบรูปมาตรฐาน', delFile('standards/Office/9/del.jpg', makeToken(validPayload('uid-admin'))), 200);
if (!stored.has('standards/Office/9/del.jpg')) { pass++; console.log('  ✅ ไฟล์ถูกลบออกจาก R2 จริง'); }
else { fail++; console.log('  ❌ ไฟล์ยังอยู่ใน R2'); }
if (stored.has('inspections/keep1/1/keep.jpg')) { pass++; console.log('  ✅ รูปหลักฐานของผลตรวจไม่ถูกแตะ'); }
else { fail++; console.log('  ❌ รูปหลักฐานหายไปด้วย'); }

console.log('\n── GET /file/ ยังเปิดอ่านได้โดยไม่ต้อง token (รูปในรายงาน) ──');
await check('อ่านรูป standards ที่มีอยู่', worker.fetch(new Request('https://w.dev/file/' + encodeURIComponent('standards/Office/1/x.jpg')), env), 200);

console.log(`\nสรุป: ผ่าน ${pass} · ไม่ผ่าน ${fail} · เรียก Firestore ${firestoreCalls} ครั้ง`);
process.exit(fail ? 1 : 0);
