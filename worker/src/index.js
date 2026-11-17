// ============================================================
// 5S Area Standards — Cloudflare Worker for photo storage (R2)
// ------------------------------------------------------------
// Routes:
//   OPTIONS *              -> CORS preflight
//   POST    /upload        -> store an image in R2, return its public URL
//   GET     /file/<key>    -> serve an image from R2
//   DELETE  /inspection/<id> -> delete every image of one inspection (admin only)
//   DELETE  /file/<key>    -> delete one reference image under standards/ (admin only)
//
// Security model:
//   The frontend is a public static page, so a shared secret baked into it is
//   readable by anyone (view-source) — that is why the old UPLOAD_TOKEN scheme
//   was replaced. Callers must now send the signed-in user's Firebase ID token:
//
//       Authorization: Bearer <idToken>
//
//   The Worker verifies the token's RS256 signature against Google's public
//   JWKS and checks iss/aud/exp, so it cannot be forged. Writes are then gated:
//
//       inspections/<id>/...  -> any signed-in user (evidence photos)
//       standards/<area>/...  -> admin only (reference images)
//       DELETE /inspection/   -> admin only
//       DELETE /file/         -> admin only, and only under standards/
//
//   The admin check reads users/{uid}.role through the Firestore REST API using
//   the caller's OWN token, so Firestore security rules still apply and this
//   Worker needs no service-account credentials.
//
//   Known limit: an authenticated inspector may upload into any inspections/<id>
//   prefix, because photos are uploaded before the inspection document exists,
//   so ownership cannot be checked at upload time.
// ============================================================

const ALLOWED_ORIGINS = [
  'https://thitibimtts2004-dot.github.io', // production (GitHub Pages)
  'http://localhost',                      // local testing
  'http://127.0.0.1',                      // local testing
  'null',                                  // file:// opened directly
];

const MAX_BYTES = 3 * 1024 * 1024;                 // 3 MB per image
const KEY_RE = /^(inspections|standards)\/[\w-]+\/[\w.-]+\/[\w.-]+$/; // inspections/<id>/<itemNo>/<file> OR standards/<area>/<itemNo>/<file>

const JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

function corsHeaders(origin) {
  // localhost / 127.0.0.1 on ANY port (dev servers like Vite use a port, which
  // makes http://localhost:5174 a different origin from the bare http://localhost).
  const isLocal = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
  const allow = (ALLOWED_ORIGINS.includes(origin) || isLocal) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization,Content-Type,x-file-path',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

// ── base64url helpers ──────────────────────────────────────────
function b64urlToBytes(s) {
  let t = s.replace(/-/g, '+').replace(/_/g, '/');
  while (t.length % 4) t += '=';
  const bin = atob(t);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
function b64urlToJson(s) {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));
}

// ── Google signing keys (cached per isolate, honouring Cache-Control) ──
let _jwks = null;
let _jwksExpiry = 0;
async function getSigningKeys() {
  const now = Date.now();
  if (_jwks && now < _jwksExpiry) return _jwks;
  const res = await fetch(JWKS_URL);
  if (!res.ok) throw new Error('JWKS fetch failed ' + res.status);
  const body = await res.json();
  const m = /max-age=(\d+)/.exec(res.headers.get('cache-control') || '');
  const ttl = m ? Math.min(parseInt(m[1], 10), 21600) : 3600; // cap at 6h
  _jwks = body.keys || [];
  _jwksExpiry = now + ttl * 1000;
  return _jwks;
}

// ── Verify a Firebase ID token. Returns its payload, or null if invalid. ──
async function verifyIdToken(token, projectId) {
  if (!token || !projectId) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  let header, payload;
  try {
    header = b64urlToJson(parts[0]);
    payload = b64urlToJson(parts[1]);
  } catch {
    return null;
  }
  if (header.alg !== 'RS256' || !header.kid) return null;

  let keys;
  try {
    keys = await getSigningKeys();
  } catch {
    return null;
  }
  const jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) return null;

  let ok = false;
  try {
    const key = await crypto.subtle.importKey(
      'jwk',
      { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    ok = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      key,
      b64urlToBytes(parts[2]),
      new TextEncoder().encode(parts[0] + '.' + parts[1]),
    );
  } catch {
    return null;
  }
  if (!ok) return null;

  const now = Math.floor(Date.now() / 1000);
  if (payload.aud !== projectId) return null;
  if (payload.iss !== 'https://securetoken.google.com/' + projectId) return null;
  if (typeof payload.exp !== 'number' || payload.exp <= now) return null;
  if (typeof payload.iat !== 'number' || payload.iat > now + 300) return null; // 5 min clock skew
  if (!payload.sub) return null;

  return payload;
}

// ── Is this caller an active admin? Reads users/{uid} with the caller's own
//    token, so Firestore rules still decide what is readable. ──
async function isAdmin(uid, idToken, projectId) {
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${encodeURIComponent(uid)}`;
  let res;
  try {
    res = await fetch(url, { headers: { Authorization: 'Bearer ' + idToken } });
  } catch {
    return false;
  }
  if (!res.ok) return false;
  const doc = await res.json();
  const f = doc.fields || {};
  if (f.active && f.active.booleanValue === false) return false;
  return (f.role && f.role.stringValue) === 'admin';
}

function bearer(request) {
  const h = request.headers.get('Authorization') || '';
  return h.startsWith('Bearer ') ? h.slice(7).trim() : '';
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const cors = corsHeaders(origin);
    const projectId = env.FIREBASE_PROJECT_ID;

    // --- CORS preflight ---
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    // --- Serve an image (public: URLs are unguessable and embedded in reports) ---
    if (request.method === 'GET' && url.pathname.startsWith('/file/')) {
      const key = decodeURIComponent(url.pathname.slice('/file/'.length));
      const obj = await env.BUCKET.get(key);
      if (!obj) return new Response('Not found', { status: 404, headers: cors });
      const h = new Headers(cors);
      obj.writeHttpMetadata(h);
      h.set('etag', obj.httpEtag);
      h.set('Cache-Control', 'public, max-age=31536000, immutable');
      return new Response(obj.body, { headers: h });
    }

    if (!projectId) {
      return new Response('Worker misconfigured: FIREBASE_PROJECT_ID is not set', { status: 500, headers: cors });
    }

    // --- Upload an image ---
    if (request.method === 'POST' && url.pathname === '/upload') {
      const token = bearer(request);
      const claims = await verifyIdToken(token, projectId);
      if (!claims) {
        return new Response('Unauthorized', { status: 401, headers: cors });
      }
      const ct = request.headers.get('content-type') || '';
      if (!ct.startsWith('image/')) {
        return new Response('Only images allowed', { status: 415, headers: cors });
      }
      const path = request.headers.get('x-file-path') || '';
      if (!KEY_RE.test(path)) {
        return new Response('Bad file path', { status: 400, headers: cors });
      }
      // Reference images (standards/) are an admin-only feature in the app.
      if (path.startsWith('standards/') && !(await isAdmin(claims.sub, token, projectId))) {
        return new Response('Admin only', { status: 403, headers: cors });
      }
      const buf = await request.arrayBuffer();
      if (buf.byteLength === 0) {
        return new Response('Empty body', { status: 400, headers: cors });
      }
      if (buf.byteLength > MAX_BYTES) {
        return new Response('Image too large', { status: 413, headers: cors });
      }
      await env.BUCKET.put(path, buf, { httpMetadata: { contentType: ct } });
      const fileUrl = `${url.origin}/file/${encodeURIComponent(path)}`;
      return new Response(JSON.stringify({ url: fileUrl }), {
        status: 200,
        headers: { ...cors, 'Content-Type': 'application/json' },
      });
    }

    // --- Delete one reference image (admin only, standards/ prefix only) ---
    // Evidence photos under inspections/ are deleted with DELETE /inspection/<id>,
    // so this route stays narrow: it can only remove standard reference images.
    if (request.method === 'DELETE' && url.pathname.startsWith('/file/')) {
      const token = bearer(request);
      const claims = await verifyIdToken(token, projectId);
      if (!claims) {
        return new Response('Unauthorized', { status: 401, headers: cors });
      }
      if (!(await isAdmin(claims.sub, token, projectId))) {
        return new Response('Admin only', { status: 403, headers: cors });
      }
      const key = decodeURIComponent(url.pathname.slice('/file/'.length));
      if (!KEY_RE.test(key) || !key.startsWith('standards/')) {
        return new Response('Bad file path', { status: 400, headers: cors });
      }
      await env.BUCKET.delete([key]);
      return new Response(JSON.stringify({ deleted: 1 }), {
        status: 200,
        headers: { ...cors, 'Content-Type': 'application/json' },
      });
    }

    // --- Delete all images for one inspection (admin only) ---
    if (request.method === 'DELETE' && url.pathname.startsWith('/inspection/')) {
      const token = bearer(request);
      const claims = await verifyIdToken(token, projectId);
      if (!claims) {
        return new Response('Unauthorized', { status: 401, headers: cors });
      }
      if (!(await isAdmin(claims.sub, token, projectId))) {
        return new Response('Admin only', { status: 403, headers: cors });
      }
      const id = decodeURIComponent(url.pathname.slice('/inspection/'.length));
      if (!/^[\w-]+$/.test(id)) {
        return new Response('Bad id', { status: 400, headers: cors });
      }
      const prefix = `inspections/${id}/`;
      let deleted = 0, cursor;
      do {
        const listing = await env.BUCKET.list({ prefix, cursor });
        if (listing.objects.length) {
          await env.BUCKET.delete(listing.objects.map(o => o.key));
          deleted += listing.objects.length;
        }
        cursor = listing.truncated ? listing.cursor : undefined;
      } while (cursor);
      return new Response(JSON.stringify({ deleted }), {
        status: 200,
        headers: { ...cors, 'Content-Type': 'application/json' },
      });
    }

    return new Response('Not found', { status: 404, headers: cors });
  },
};
