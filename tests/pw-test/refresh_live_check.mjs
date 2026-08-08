// Stage 10.1 live integration check — runs the REAL backend (no mocks) behind a
// local static+proxy origin and drives real browser tabs through login, refresh
// rotation, expiry recovery, simultaneous reload and logout revocation. This is
// the real-server evidence the mock rig cannot provide (AGENTS.md review
// protocol): genuine Set-Cookie rotation, the /auth cookie path, and bearer
// tokens minted by the actual Flask code. Requires tests/venv. Run directly:
//   node tests/pw-test/refresh_live_check.mjs
import { chromium } from 'playwright';
import { spawn } from 'child_process';
import http from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';

const ROOT = '/workspace/markervault';
const PUBLIC = path.join(ROOT, 'public');
const VENV_PY = path.join(ROOT, 'tests/venv/bin/python');
const MIME = { '.html':'text/html', '.js':'application/javascript', '.css':'text/css', '.png':'image/png', '.ico':'image/x-icon' };
const BACKEND_PORT = 5000 + 100 + Math.floor(Math.random() * 900);

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'mv-live-'));
const dbPath = path.join(scratch, 'spots.db');

// Seed the scratch DB with the canonical schema and one approved user.
const seedScript = `
import sqlite3, sys
import bcrypt
sys.path.insert(0, ${JSON.stringify(ROOT)})
from markervault_schema import initialize_schema
conn = sqlite3.connect(${JSON.stringify(dbPath)})
initialize_schema(conn)
conn.execute(
    "INSERT INTO users (user_id, username, password_hash, role, status, created,"
    " first_name, last_name, email, company, department)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ('11111111-1111-1111-1111-111111111111', 'liveuser',
     bcrypt.hashpw(b'Abcd1234!', bcrypt.gensalt(rounds=4)), 'user', 'approved',
     '2026-07-19T00:00:00', 'Live', 'User', 'live@markervault.test', '', ''))
conn.commit()
conn.close()
`;
await new Promise((resolve, reject) => {
    const p = spawn(VENV_PY, ['-'], { stdio: ['pipe', 'inherit', 'inherit'] });
    p.stdin.end(seedScript);
    p.on('exit', code => code === 0 ? resolve() : reject(new Error(`seed exited ${code}`)));
});

// Real backend on loopback: development trust, plain-HTTP cookies, 3-second access
// tokens so expiry recovery is testable without waiting out the 15-minute default.
// MV_LIVE_GUNICORN=1 swaps ONLY the spawn command for the production server, with the
// tracked unit's explicit one-sync-worker and 30-second timeout flags. The rate
// buckets depend on that single process. Seeding, environment,
// proxy and cleanup are identical in both modes and the rig still owns the process.
const liveGunicorn = process.env.MV_LIVE_GUNICORN === '1';
const backendBin = liveGunicorn ? path.join(ROOT, 'tests/venv/bin/gunicorn') : VENV_PY;
const backendArgs = liveGunicorn
    ? ['--workers', '1', '--worker-class', 'sync', '--timeout', '30', '--bind', `127.0.0.1:${BACKEND_PORT}`, 'backend:app', '--access-logfile', '-', '--error-logfile', '-', '--no-control-socket']
    : ['-c', `import backend; backend.app.run(host='127.0.0.1', port=${BACKEND_PORT}, threaded=True)`];
const backend = spawn(backendBin, backendArgs, {
    cwd: ROOT,
    env: {
        ...process.env,
        MARKERVAULT_ENVIRONMENT: 'development',
        MARKERVAULT_DB_PATH: dbPath,
        MARKERVAULT_PHOTOS_PATH: path.join(scratch, 'photos'),
        MARKERVAULT_THUMBS_PATH: path.join(scratch, 'thumbs'),
        MARKERVAULT_AVATARS_PATH: path.join(scratch, 'avatars'),
        MARKERVAULT_TEMP_PATH: path.join(scratch, 'temp'),
        MARKERVAULT_COOKIE_SECURE: 'false',
        MARKERVAULT_ACCESS_TOKEN_DURATION: '3'
    },
    stdio: ['ignore', liveGunicorn ? 'pipe' : 'ignore', 'pipe']
});
let backendErr = '';
let backendOut = '';
backend.stderr.on('data', d => { backendErr += d; });
if (liveGunicorn) {
    backend.stdout.on('data', d => { backendOut += d; });
}

// Same-origin front: static files from the checkout, everything else proxied to
// Flask so cookies and bearer headers flow exactly as they do behind nginx.
const front = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (req.method === 'GET') {
        const fp = u.pathname === '/' ? '/index.html' : u.pathname;
        const full = path.join(PUBLIC, fp);
        if (fs.existsSync(full) && fs.statSync(full).isFile()) {
            res.writeHead(200, {'Content-Type': MIME[path.extname(full)] || 'text/plain'});
            return res.end(fs.readFileSync(full));
        }
    }
    const preq = http.request({ host: '127.0.0.1', port: BACKEND_PORT, method: req.method, path: req.url, headers: req.headers }, pres => {
        res.writeHead(pres.statusCode, pres.headers);
        pres.pipe(res);
    });
    preq.on('error', () => { res.writeHead(502); res.end(); });
    req.pipe(preq);
});
await new Promise(r => front.listen(0, r));
const base = `http://127.0.0.1:${front.address().port}`;

// Wait for the backend to answer through the proxy (401 = up, no cookie).
let up = false;
for (let i = 0; i < 60 && !up; i++) {
    up = await fetch(`${base}/auth/refresh`, { method: 'POST' }).then(r => r.status === 401).catch(() => false);
    if (!up) await new Promise(r => setTimeout(r, 250));
}
if (!up) {
    console.log(`FAIL backend never came up\n${backendErr}`);
    process.exit(1);
}

let PASS = 0, FAIL = 0;
function check(cond, label) {
    if (cond) { PASS++; console.log(`  PASS  ${label}`); }
    else { FAIL++; console.log(`  FAIL  ${label}`); }
}

const browser = await chromium.launch();
const context = await browser.newContext();
const page1 = await context.newPage();
const pageErrors = [];
page1.on('pageerror', e => pageErrors.push('page1: ' + e));

const atLogin = (page) => page.evaluate(() => document.getElementById('authScreen').classList.contains('active'));
const callMaps = (page) => page.evaluate(() => apiFetch('/maps').then(r => r.status).catch(e => 'threw:' + e.status));

console.log('== Cold boot without a session ==');
await page1.goto(base, { waitUntil: 'networkidle' });
check(await atLogin(page1), 'no refresh cookie boots to the login screen');

console.log('== Real login ==');
await page1.fill('#authLoginUsername', 'liveuser');
await page1.fill('#authLoginPassword', 'Abcd1234!');
await page1.click('#authLoginForm button[type=submit]');
await page1.waitForFunction(() => !document.getElementById('authScreen').classList.contains('active'), null, { timeout: 10000 });
check(!(await atLogin(page1)), 'login sets the refresh cookie and enters the app');
check((await callMaps(page1)) === 200, 'the minted bearer token authorizes real API calls');

console.log('== Second tab boots from the rotated cookie ==');
const page2 = await context.newPage();
page2.on('pageerror', e => pageErrors.push('page2: ' + e));
await page2.goto(base, { waitUntil: 'networkidle' });
check(!(await atLogin(page2)), 'a second tab silently restores the session via /auth/refresh');
check((await callMaps(page2)) === 200, 'the second tab\'s token works against the real backend');

console.log('== Real expiry: both tabs recover concurrently ==');
await page1.waitForTimeout(4000);
const statuses = await Promise.all([callMaps(page1), callMaps(page2)]);
check(statuses.every(s => s === 200), `expired tokens refresh through the rotating cookie (saw ${statuses})`);
check(!(await atLogin(page1)) && !(await atLogin(page2)), 'expiry recovery never shows the login screen');

console.log('== Simultaneous reload with real rotation ==');
await Promise.all([
    page1.reload({ waitUntil: 'networkidle' }),
    page2.reload({ waitUntil: 'networkidle' })
]);
check(!(await atLogin(page1)) && !(await atLogin(page2)), 'both tabs restore their session through serialized real rotations');

console.log('== Logout revokes the real session ==');
await page1.evaluate(() => doLogout());
await page1.waitForFunction(() => document.getElementById('authScreen').classList.contains('active'), null, { timeout: 10000 });
check(await atLogin(page1), 'logout returns to the login screen');
await page2.reload({ waitUntil: 'networkidle' });
check(await atLogin(page2), 'the revoked cookie cannot restore the other tab');

check(pageErrors.length === 0, `no page errors (${pageErrors.join(' | ') || 'none'})`);

await browser.close();
front.close();
backend.kill();
fs.rmSync(scratch, { recursive: true, force: true });
// Knob-on only: surface what the production server actually logged, so the worker
// model and the access/error channels are observed rather than assumed.
if (liveGunicorn) {
    const logLines = (backendOut + backendErr).split('\n');
    console.log('\n-- gunicorn --');
    logLines.filter(line => /Starting gunicorn|Listening at|Using worker|Booting worker/.test(line)).forEach(line => console.log(`   ${line.trim()}`));
    console.log(`   workers booted: ${logLines.filter(line => line.includes('Booting worker')).length}`);
    console.log(`   access lines: ${logLines.filter(line => /"[A-Z]+ [^"]*" \d{3} /.test(line)).length}`);
    console.log(`   markervault.backend lines: ${logLines.filter(line => line.includes('markervault.backend')).length}`);
}
console.log(`\n==== ${PASS} passed, ${FAIL} failed ====`);
process.exit(FAIL ? 1 : 0);
