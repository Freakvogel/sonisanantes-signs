const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Zugang nur mit kurzlebigem, signiertem Token von sonisanantes.com (Mitglieder-Check passiert dort).
// Token-Format: <ablauf-unix-sekunden>.<hmac-sha256-hex>
function tokenOk(token) {
  const secret = process.env.SIGNS_SHARED_SECRET;
  if (!secret || typeof token !== 'string') return false;
  const [exp, sig] = token.split('.');
  if (!/^\d{9,12}$/.test(exp || '') || !/^[0-9a-f]{64}$/.test(sig || '')) return false;
  if (Number(exp) < Math.floor(Date.now() / 1000)) return false;
  const expected = crypto.createHmac('sha256', secret).update(exp).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}

const LOCKED = `<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Sonisanantes Signs</title>
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#050608;color:#F5ECD0;font-family:Inter,system-ui,sans-serif;text-align:center;padding:24px}
a{display:inline-block;margin-top:18px;padding:12px 26px;border-radius:30px;background:linear-gradient(90deg,#7B2D9E,#C4257A);color:#fff;text-decoration:none}</style></head>
<body><div><h1 style="font-weight:400;letter-spacing:.08em">Sonisanantes Signs</h1>
<p>Diese App ist für Mitglieder.<br>Bitte öffne sie über deinen Mitgliederbereich.</p>
<a href="https://sonisanantes.com/deine-apps/">Zum Mitgliederbereich</a></div></body></html>`;

module.exports = (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.setHeader('Content-Security-Policy', "frame-ancestors 'self' https://sonisanantes.com https://www.sonisanantes.com");
  const token = new URL(req.url, 'http://x').searchParams.get('t');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  if (!tokenOk(token)) {
    res.statusCode = 403;
    return res.end(LOCKED);
  }
  res.statusCode = 200;
  res.end(fs.readFileSync(path.join(process.cwd(), 'private', 'signs.html')));
};
