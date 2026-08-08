// Stage 11 live integration check — runs the REAL backend (no mocks) behind a
// local static+proxy origin and drives a real KML import end to end: genuine
// multipart upload with a real bearer token, the actual bounded worker, compact
// skip/photo-failure counts, owner-authorized status 404s, read-triggered
// retention, notification history, and marker arrival through normal map
// retrieval. This is the real-server evidence the mock rig cannot provide
// (AGENTS.md review protocol).
// Requires tests/venv. Run directly:
//   node tests/pw-test/kml_live_check.mjs
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

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'mv-kml-live-'));
const dbPath = path.join(scratch, 'spots.db');
const tempPath = path.join(scratch, 'temp');

// Seed the scratch DB with the canonical schema and two approved users.
const seedScript = `
import sqlite3, sys
import bcrypt
sys.path.insert(0, ${JSON.stringify(ROOT)})
from markervault_schema import initialize_schema
conn = sqlite3.connect(${JSON.stringify(dbPath)})
initialize_schema(conn)
for uid, name in (('11111111-1111-1111-1111-111111111111', 'liveuser'),
                  ('22222222-2222-2222-2222-222222222222', 'otheruser')):
    conn.execute(
        "INSERT INTO users (user_id, username, password_hash, role, status, created,"
        " first_name, last_name, email, company, department)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (uid, name, bcrypt.hashpw(b'Abcd1234!', bcrypt.gensalt(rounds=4)), 'user',
         'approved', '2026-07-20T00:00:00', 'Live', 'User', name + '@markervault.test', '', ''))
    conn.execute(
        "INSERT INTO maps (owner_id, name, is_base, created, description)"
        " VALUES (?, 'Base Map', 1, '2026-07-20T00:00:00',"
        " 'Your default map. This map cannot be deleted.')",
        (uid,))
conn.commit()
conn.close()
`;
await new Promise((resolve, reject) => {
    const p = spawn(VENV_PY, ['-'], { stdio: ['pipe', 'inherit', 'inherit'] });
    p.stdin.end(seedScript);
    p.on('exit', code => code === 0 ? resolve() : reject(new Error(`seed exited ${code}`)));
});

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
        MARKERVAULT_TEMP_PATH: tempPath,
        MARKERVAULT_COOKIE_SECURE: 'false'
    },
    stdio: ['ignore', liveGunicorn ? 'pipe' : 'ignore', 'pipe']
});
let backendErr = '';
let backendOut = '';
backend.stderr.on('data', d => { backendErr += d; });
if (liveGunicorn) {
    backend.stdout.on('data', d => { backendOut += d; });
}
// A failed check path must never leave an orphaned backend holding the port.
process.on('exit', () => backend.kill());

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

// The four-placemark import: two valid, one out-of-range, one point-less, and one
// photo URL the real SSRF guard rejects — exercising skip and failure counts.
const LIVE_KML = `<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2"><Document><name>Live</name>
<Placemark><name>live-a</name>
<description><![CDATA[<img src="http://127.0.0.1:9/blocked.jpg">]]></description>
<Point><coordinates>8.6,41.1,0</coordinates></Point></Placemark>
<Placemark><name>live-b</name><Point><coordinates>-8.6,-41.1</coordinates></Point></Placemark>
<Placemark><name>bad-coords</name><Point><coordinates>200,95</coordinates></Point></Placemark>
<Placemark><name>no-point</name></Placemark>
</Document></kml>`;
const TINY_KML = `<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2"><Document><name>Tiny</name>
<Placemark><name>tiny-a</name><Point><coordinates>1.5,2.5</coordinates></Point></Placemark>
</Document></kml>`;

async function uploadKml(page, content) {
    await page.evaluate(kmlText => {
        const originalClick = HTMLInputElement.prototype.click;
        HTMLInputElement.prototype.click = function() {
            if (this.accept === '.kml') {
                const transfer = new DataTransfer();
                transfer.items.add(new File(
                    [kmlText], 'live.kml', {type:'application/vnd.google-earth.kml+xml'}
                ));
                this.files = transfer.files;
                this.dispatchEvent(new Event('change'));
                return;
            }
            originalClick.call(this);
        };
        document.getElementById('sidebar-markers-importMarkers').click();
        HTMLInputElement.prototype.click = originalClick;
    }, content);
}

const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();
const pageErrors = [];
page.on('pageerror', e => pageErrors.push(String(e)));
const importRequests = [];
const statusJobIds = new Set();
page.on('request', req => {
    const u = new URL(req.url());
    if (u.pathname === '/import_kml') {
        importRequests.push({ authorization: req.headers()['authorization'] || '' });
    }
    if (u.pathname.startsWith('/import_kml_status/')) {
        statusJobIds.add(u.pathname.split('/').pop());
    }
});

console.log('== Real login and import ==');
await page.goto(base, { waitUntil: 'networkidle' });
await page.fill('#authLoginUsername', 'liveuser');
await page.fill('#authLoginPassword', 'Abcd1234!');
await page.click('#authLoginForm button[type=submit]');
await page.waitForFunction(() => !document.getElementById('authScreen').classList.contains('active'), null, { timeout: 10000 });
check(true, 'login enters the app against the real backend');
await page.waitForFunction(() => typeof selectedMapID !== 'undefined' && selectedMapID !== null);
check(true, 'the real map bootstrap selects an import target before the upload');

await uploadKml(page, LIVE_KML);
try {
    await page.waitForFunction(() =>
        document.querySelector('.progress-text')?.textContent
            === 'Imported 2 / 4 markers (2 skipped, 1 photos failed)',
    null, { timeout: 20000 });
} catch (err) {
    const state = await page.evaluate(() => ({
        progress: document.querySelector('.progress-text')?.textContent,
        notifications: Array.from(document.querySelectorAll('.notification')).map(n => n.textContent)
    }));
    console.log('DEBUG state:', JSON.stringify(state));
    console.log('DEBUG jobs:', [...statusJobIds], 'imports:', JSON.stringify(importRequests));
    console.log('DEBUG backendErr tail:', backendErr.slice(-2000));
    throw err;
}
check(true, 'the real worker reports compact skip and photo-failure counts');
check(
    importRequests.length === 1 && importRequests[0].authorization.startsWith('Bearer '),
    'the import upload carries a real bearer token'
);
check(statusJobIds.size === 1, 'polling sticks to the single returned job UUID');
const jobId = [...statusJobIds][0];
check(
    /^[0-9a-f-]{36}$/.test(jobId) && !`${jobId}/import_kml_status/`.includes('share'),
    'the outgoing job/progress URL is a bare UUID with no adblocker-triggering name'
);

console.log('== Durable notification through the real boundary ==');
await page.waitForFunction(() => {
    const badge = document.getElementById('notifHistoryBadge');
    return badge.textContent === '1' && !badge.hidden;
});
check(true, 'the terminal KML refresh exposes the exact unseen badge count');
const degradedHistory = await page.evaluate(() =>
    apiFetch('/notif_history').then(response => response.json())
);
const degradedRow = degradedHistory.notifications[0];
check(
    degradedHistory.unseen === 1
        && degradedHistory.through_id === degradedRow.id
        && degradedRow.event === 'kml.import_degraded'
        && degradedRow.target_type === 'kml_job'
        && degradedRow.target_id === [...statusJobIds][0],
    'the authenticated history API returns the worker-authored degraded row'
);
check(
    degradedRow.detail.imported === 2
        && degradedRow.detail.total === 4
        && degradedRow.detail.skipped === 2
        && degradedRow.detail.photos_failed === 1
        && degradedRow.detail.photos_budget_skipped === 0
        && degradedRow.detail.affected_spots.join(',') === 'live-a',
    'the durable row preserves terminal counters and the affected marker name'
);
await page.evaluate(() => document.getElementById('notifHistoryBtn').click());
await page.waitForFunction(() =>
    document.getElementById('notifHistoryOverlay').classList.contains('active')
        && document.querySelectorAll('#notifHistoryList .notif-history-row').length === 1
);
const durableUi = await page.evaluate(() => ({
    message: document.querySelector('#notifHistoryList .notif-history-message').textContent,
    unseen: document.querySelector('#notifHistoryList .notif-history-row').classList.contains('unseen')
}));
check(
    durableUi.unseen && durableUi.message.includes('Affected markers: live-a.'),
    'the panel renders the persisted degraded outcome and object name'
);
await page.click('#notifHistoryMarkSeenBtn');
await page.waitForFunction(() => document.getElementById('notifHistoryBadge').hidden);
const seenHistory = await page.evaluate(() =>
    apiFetch('/notif_history').then(response => response.json())
);
check(
    seenHistory.unseen === 0 && seenHistory.notifications[0].seen === true,
    'Mark all seen persists the rendered high-water through the real API'
);
await page.click('#notifHistoryList .notif-history-row');
await page.waitForFunction(() => document.getElementById('notifHistoryBadge').textContent === '1');
const unreadHistory = await page.evaluate(() =>
    apiFetch('/notif_history').then(response => response.json())
);
check(
    unreadHistory.unseen === 1 && unreadHistory.notifications[0].seen === false,
    'clicking a seen row persists unread state and restores the exact badge'
);
await page.click('#notifHistoryList .notif-history-row');
await page.waitForFunction(() => document.getElementById('notifHistoryBadge').hidden);
const rereadHistory = await page.evaluate(() =>
    apiFetch('/notif_history').then(response => response.json())
);
check(
    rereadHistory.unseen === 0 && rereadHistory.notifications[0].seen === true,
    'clicking the row again persists read state through the real API'
);
await page.click('#notifHistoryOverlay .overlay-close');

console.log('== Markers arrive through normal map retrieval ==');
await page.waitForFunction(() => typeof markers !== 'undefined' && markers.length === 2, null, { timeout: 10000 });
const names = await page.evaluate(() => markers.map(m => m.data.name).sort());
check(
    names.join(',') === 'live-a,live-b',
    `the two valid placemarks are on the map via /maps/:id/spots (${names})`
);

console.log('== Owner-authorized status against the real backend ==');
const ownPoll = await page.evaluate(id => apiFetch(`/import_kml_status/${id}`).then(r => r.status), jobId);
check(ownPoll === 200, 'the uploader can still read the finished job');
const rawPoll = await fetch(`${base}/import_kml_status/${jobId}`);
check(rawPoll.status === 401, 'an unauthenticated status read is a real 401');

const otherContext = await browser.newContext();
const otherPage = await otherContext.newPage();
await otherPage.goto(base, { waitUntil: 'networkidle' });
await otherPage.fill('#authLoginUsername', 'otheruser');
await otherPage.fill('#authLoginPassword', 'Abcd1234!');
await otherPage.click('#authLoginForm button[type=submit]');
await otherPage.waitForFunction(() => !document.getElementById('authScreen').classList.contains('active'), null, { timeout: 10000 });
const crossPoll = await otherPage.evaluate(id => apiFetch(`/import_kml_status/${id}`).then(r => r.status), jobId);
check(crossPoll === 404, "another authenticated user cannot read the job (404)");

console.log('== Read-triggered retention ==');
await uploadKml(page, TINY_KML);
await page.waitForFunction(() =>
    document.querySelector('.progress-text')?.textContent === 'Imported 1 / 1 markers',
null, { timeout: 20000 });
await page.waitForFunction(() => document.getElementById('notifHistoryBadge').textContent === '1');
const cleanHistory = await page.evaluate(() =>
    apiFetch('/notif_history').then(response => response.json())
);
check(
    cleanHistory.unseen === 1
        && cleanHistory.notifications[0].event === 'kml.import_done'
        && cleanHistory.notifications[0].detail.imported === 1,
    'a later clean import creates a new unseen completion row'
);
const oldPoll = await page.evaluate(id => apiFetch(`/import_kml_status/${id}`).then(r => r.status), jobId);
check(oldPoll === 404, 'a new admission clears the previous terminal job row');
check(
    !fs.existsSync(tempPath) || fs.readdirSync(tempPath).length === 0,
    'no temporary KML files survive on the real filesystem'
);

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
