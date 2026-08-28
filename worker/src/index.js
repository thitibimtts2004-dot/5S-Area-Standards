// ============================================================
// 5S Area Standards — Cloudflare Worker for photo storage (R2)
// ------------------------------------------------------------
// Routes:
//   OPTIONS *              -> CORS preflight
//   POST    /upload        -> store an image in R2, return its public URL
//   GET     /file/<key>    -> serve an image from R2
//
// Security notes (read me):
//   The frontend is a public static page, so any token it sends is
//   visible in the page source. UPLOAD_TOKEN therefore only blocks
//   casual bots, not a determined attacker. Real protection would
//   require user authentication, which this app does not have (its
//   Firestore is already open). We additionally restrict uploads to
//   the app's own Origin and to small image files to limit abuse.
// ============================================================

const ALLOWED_ORIGINS = [
  'https://thitibimtts2004-dot.github.io', // production (GitHub Pages)
  'http://localhost',                      // local testing
  'http://127.0.0.1',                      // local testing
  'null',                                  // file:// opened directly
];

const MAX_BYTES = 3 * 1024 * 1024;                 // 3 MB per image
const KEY_RE = /^inspections\/[\w-]+\/[\w.-]+\/[\w.-]+$/; // inspections/<id>/<itemNo>/<file>

function corsHeaders(origin) {
  const allow = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,x-upload-token,x-file-path',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const cors = corsHeaders(origin);

    // --- CORS preflight ---
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    // --- Serve an image ---
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

    // --- Upload an image ---
    if (request.method === 'POST' && url.pathname === '/upload') {
      if (request.headers.get('x-upload-token') !== env.UPLOAD_TOKEN) {
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

    return new Response('Not found', { status: 404, headers: cors });
  },
};
