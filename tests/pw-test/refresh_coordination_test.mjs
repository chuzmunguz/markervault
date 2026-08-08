// Stage 10.1/10.3 — client refresh coordination with memory-only access tokens.
// Verifies same-tab single-flight, Web-Lock cross-tab serialization (each tab
// spends its own rotation; tokens are never shared or persisted), 429/401/offline
// refresh failure handling and the required-Web-Locks capability gate against a mock backend
// that counts /auth/refresh hits and tracks their concurrency.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const MIME = { '.html':'text/html', '.js':'application/javascript', '.css':'text/css', '.png':'image/png', '.ico':'image/x-icon' };

// Mint a JWT-shaped token (unsigned — the client only reads exp, never verifies).
function mint(expiresInSec) {
    const payload = Buffer.from(JSON.stringify({ username: 'alice', exp: Math.floor(Date.now() / 1000) + expiresInSec })).toString('base64url');
    return `hdr.${payload}.sig-${Math.random().toString(36).slice(2)}`;
}

let refreshHits = 0;
let refreshConcurrent = 0;
let refreshMaxConcurrent = 0;
let refreshDelayMs = 0;
let refreshMode = 'ok';        // 'ok' | '429' | '401'
let loginMode = 'ok';          // 'ok' | '429'
const validTokens = new Set();

function sendJSON(res, obj, code=200, headers={}){ res.writeHead(code, {'Content-Type':'application/json', ...headers}); res.end(JSON.stringify(obj)); }

const server = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x');
    const p = u.pathname;

    if (p === '/auth/refresh') {
        refreshHits++;
        refreshConcurrent++;
        refreshMaxConcurrent = Math.max(refreshMaxConcurrent, refreshConcurrent);
        if (refreshDelayMs) await new Promise(r => setTimeout(r, refreshDelayMs));
        refreshConcurrent--;
        if (refreshMode === '429') return sendJSON(res, { error: 'Too Many Requests' }, 429);
        if (refreshMode === '401') return sendJSON(res, { error: 'Unauthorized' }, 401);
        const token = mint(900);
        validTokens.add(token);
        return sendJSON(res, { access_token: token, access_expires_in: 900, role: 'user', username: 'alice', first_name: 'Alice', last_name: 'A' },
                        200, { 'Set-Cookie': `refresh_token=r${refreshHits}; Path=/auth; HttpOnly` });
    }

    if (p === '/login' && req.method === 'POST') {
        if (loginMode === '429') return sendJSON(res, { error: 'Too Many Requests' }, 429);
        return sendJSON(res, { success: true }, 200,
                        { 'Set-Cookie': `refresh_token=login-${refreshHits}; Path=/auth; HttpOnly` });
    }

    // Static files (index, frontend.js, assets).
    let fp = p === '/' ? '/index.html' : p;
    const full = path.join(ROOT, fp);
    if (fs.existsSync(full) && fs.statSync(full).isFile()) {
        res.writeHead(200, {'Content-Type': MIME[path.extname(full)] || 'text/plain'});
        return res.end(fs.readFileSync(full));
    }

    // Everything else is API surface: bearer-checked so an invalidated token 401s
    // exactly like the real backend after expiry.
    const bearer = (req.headers.authorization || '').replace(/^Bearer /, '');
    if (!validTokens.has(bearer)) return sendJSON(res, { error: 'Unauthorized' }, 401);
    return sendJSON(res, []);
});

await new Promise(r => server.listen(0, r));
const base = `http://127.0.0.1:${server.address().port}`;

let PASS = 0, FAIL = 0;
function check(cond, label) {
    if (cond) { PASS++; console.log(`  PASS  ${label}`); }
    else { FAIL++; console.log(`  FAIL  ${label}`); }
}

const browser = await chromium.launch();
const context = await browser.newContext();
const pageErrors = [];
const page1 = await context.newPage();
page1.on('pageerror', e => pageErrors.push('page1: ' + e));

const atLogin = (page) => page.evaluate(() => document.getElementById('authScreen').classList.contains('active'));
const atLimit = (page) => page.evaluate(() => document.getElementById('limitScreen').classList.contains('active'));
const atUnsupported = (page) => page.evaluate(() => document.getElementById('unsupportedScreen').classList.contains('active'));
// apiFetch is a top-level function declaration in the classic script, so it is
// reachable from evaluate; errors are reported as 'threw:<status>' strings.
const callMaps = (page, parallel=1) => page.evaluate(async (n) => {
    const calls = Array.from({ length: n }, () => apiFetch('/maps').then(r => r.status).catch(e => 'threw:' + e.status));
    return Promise.all(calls);
}, parallel);

console.log('== Single-tab cold boot ==');
await page1.goto(base, { waitUntil: 'networkidle' }).catch(e => pageErrors.push('goto: ' + e));
await page1.waitForTimeout(500);
check(refreshHits === 1, `cold boot performs exactly one refresh (saw ${refreshHits})`);
check(!(await atLogin(page1)), 'cold boot lands in the app, not on the login screen');

console.log('== Single-tab reload ==');
await page1.reload({ waitUntil: 'networkidle' });
await page1.waitForTimeout(500);
check(refreshHits === 2, `reload costs exactly one refresh (saw ${refreshHits - 1} extra)`);
check(!(await atLogin(page1)), 'reload silently restores the session');

console.log('== Same-tab concurrent 401 collapse ==');
validTokens.clear();
refreshDelayMs = 150;
let before = refreshHits;
let statuses = await callMaps(page1, 4);
check(statuses.every(s => s === 200), `all four parallel calls recover to 200 (saw ${statuses})`);
check(refreshHits - before === 1, `four concurrent 401s share one refresh (saw ${refreshHits - before})`);
check(!(await atLogin(page1)), 'recovery never bounces through the login screen');

console.log('== Second-tab cold boot ==');
const page2 = await context.newPage();
page2.on('pageerror', e => pageErrors.push('page2: ' + e));
before = refreshHits;
await page2.goto(base, { waitUntil: 'networkidle' }).catch(e => pageErrors.push('page2 goto: ' + e));
await page2.waitForTimeout(500);
check(refreshHits - before === 1, `a second tab boots with its own single refresh (saw ${refreshHits - before})`);
check(!(await atLogin(page2)), 'second tab lands in the app');

console.log('== Both tabs\' tokens die concurrently: serialized per-tab rotations ==');
validTokens.clear();
before = refreshHits;
statuses = (await Promise.all([callMaps(page1), callMaps(page2)])).flat();
check(statuses.every(s => s === 200), `both tabs recover to 200 (saw ${statuses})`);
check(refreshHits - before === 2, `each tab spends its own rotation — tokens are never shared (saw ${refreshHits - before})`);
check(refreshMaxConcurrent === 1, 'no two refresh requests ever overlapped (Web Lock serialization)');

console.log('== Two-tab simultaneous reload ==');
before = refreshHits;
await Promise.all([
    page1.reload({ waitUntil: 'networkidle' }),
    page2.reload({ waitUntil: 'networkidle' })
]);
await page1.waitForTimeout(500);
check(refreshHits - before === 2, `two-tab reload costs one refresh per tab (saw ${refreshHits - before})`);
check(!(await atLogin(page1)) && !(await atLogin(page2)), 'both tabs restore their session on simultaneous reload');
check(refreshMaxConcurrent === 1, 'simultaneous reloads still serialize their refreshes');
refreshDelayMs = 0;

console.log('== 429 on refresh: transient, never a logout ==');
validTokens.clear();
refreshMode = '429';
statuses = await callMaps(page1);
check(statuses[0] === 'threw:429', `rate-limited refresh surfaces the 429 to the caller (saw ${statuses})`);
check(!(await atLogin(page1)), 'a 429 refresh does NOT dump the session to the login screen');
refreshMode = 'ok';
before = refreshHits;
statuses = await callMaps(page1);
check(statuses[0] === 200, `next user action retries and recovers (saw ${statuses})`);
check(refreshHits - before === 1, 'recovery cost exactly one refresh');

console.log('== 401 on refresh: session over, login screen ==');
validTokens.clear();
refreshMode = '401';
statuses = await callMaps(page1);
check(statuses[0] === 'threw:401', `dead refresh cookie surfaces the 401 (saw ${statuses})`);
check(await atLogin(page1), 'a 401 refresh shows the login screen');
refreshMode = 'ok';

console.log('== Re-login after a mid-session kick starts from a clean slate ==');
// Leave visible leftover UI state from the killed session, then log back in: the
// login handler must reload the document instead of booting in place, so nothing
// (open overlays, filters, selected map) carries into the new session.
await page1.evaluate(() => { document.getElementById('profileOverlay').style.display = 'flex'; });
const navigation = page1.waitForNavigation({ waitUntil: 'networkidle' });
await page1.fill('#authLoginUsername', 'alice');
await page1.fill('#authLoginPassword', 'Whatever1!');
await page1.click('#authLoginForm button[type=submit]');
await navigation;
await page1.waitForTimeout(500);
check(!(await atLogin(page1)), 're-login lands back in the app');
check(
    await page1.evaluate(() => document.getElementById('profileOverlay').style.display !== 'flex'),
    'the killed session\'s open overlay did not survive into the new session'
);

console.log('== No login flash during silent restore ==');
refreshDelayMs = 400;
await page1.goto(base, { waitUntil: 'commit' });
await page1.waitForTimeout(150);
check(!(await atLogin(page1)), 'the login screen never shows while the silent refresh is in flight');
await page1.waitForLoadState('networkidle');
await page1.waitForTimeout(300);
check(!(await atLogin(page1)), 'and the session restores without any flash');
refreshDelayMs = 0;

console.log('== Missing Web Locks capability gate ==');
const context2 = await browser.newContext();
await context2.addInitScript(() => Object.defineProperty(navigator, 'locks', { value: undefined }));
const page3 = await context2.newPage();
page3.on('pageerror', e => pageErrors.push('page3: ' + e));
before = refreshHits;
await page3.goto(base, { waitUntil: 'networkidle' }).catch(e => pageErrors.push('page3 goto: ' + e));
await page3.waitForTimeout(500);
check(refreshHits - before === 0, `boot without Web Locks sends no refresh request (saw ${refreshHits - before})`);
check(await atUnsupported(page3), 'no-Locks browser lands on the unsupported-capability screen');
check(!(await atLogin(page3)), 'no-Locks browser never shows a misleading login form');
await context2.close();

console.log('== S-06: no persistent bearer storage ==');
const context3 = await browser.newContext();
await context3.addInitScript(() => localStorage.setItem('mv_access_token', 'residue-from-old-build'));
const page4 = await context3.newPage();
page4.on('pageerror', e => pageErrors.push('page4: ' + e));
before = refreshHits;
await page4.goto(base, { waitUntil: 'networkidle' }).catch(e => pageErrors.push('page4 goto: ' + e));
await page4.waitForTimeout(500);
check(refreshHits - before === 1, `boot ignores storage residue and refreshes once (saw ${refreshHits - before})`);
check(!(await atLogin(page4)), 'the session restores from the cookie alone');
check(
    await page4.evaluate(() => localStorage.getItem('mv_access_token') === null),
    'the old build\'s persisted token is purged and nothing is written back'
);
await context3.close();

console.log('== Offline: transient failure, recovery when back ==');
validTokens.clear();
await context.setOffline(true);
statuses = await callMaps(page2);
check(String(statuses[0]).startsWith('threw:'), `an offline API action surfaces a network error (saw ${statuses})`);
check(!(await atLogin(page2)), 'going offline never dumps the session to the login screen');
await context.setOffline(false);
before = refreshHits;
statuses = await callMaps(page2);
check(statuses[0] === 200, `back online, the next action recovers (saw ${statuses})`);
check(refreshHits - before === 1, 'offline recovery cost exactly one refresh');

console.log('== 429 at boot: rate-limit landing page, click-driven recovery ==');
const context4 = await browser.newContext();
const page5 = await context4.newPage();
page5.on('pageerror', e => pageErrors.push('page5: ' + e));
refreshMode = '429';
await page5.goto(base, { waitUntil: 'networkidle' }).catch(e => pageErrors.push('page5 goto: ' + e));
await page5.waitForTimeout(300);
check(await atLimit(page5), 'boot under the rate limit shows the landing page');
check(!(await atLogin(page5)), 'the misleading login form is NOT shown');
await page5.click('#limitRetryBtn');
await page5.waitForTimeout(300);
check((await atLimit(page5)) && !(await atLogin(page5)), 'retrying while still limited stays on the landing page');
refreshMode = 'ok';
before = refreshHits;
await page5.click('#limitRetryBtn');
await page5.waitForTimeout(500);
check(!(await atLimit(page5)) && !(await atLogin(page5)), 'retrying after the bucket refills boots into the app');
check(refreshHits - before === 1, 'the successful retry cost exactly one refresh');

console.log('== 429 on login: back-off message, not "invalid credentials" ==');
const page6 = await context4.newPage();
page6.on('pageerror', e => pageErrors.push('page6: ' + e));
refreshMode = '401';
await page6.goto(base, { waitUntil: 'networkidle' }).catch(e => pageErrors.push('page6 goto: ' + e));
refreshMode = 'ok';
loginMode = '429';
await page6.fill('#authLoginUsername', 'alice');
await page6.fill('#authLoginPassword', 'Whatever1!');
await page6.click('#authLoginForm button[type=submit]');
await page6.waitForTimeout(300);
check(
    (await page6.evaluate(() => document.getElementById('authError').textContent)).includes('Too many attempts'),
    'a rate-limited login explains the back-off instead of blaming the credentials'
);
loginMode = 'ok';
await context4.close();

console.log('== Static pins ==');
const src = fs.readFileSync(path.join(ROOT, 'frontend.js'), 'utf8');
const loginBlock = src.slice(src.indexOf('async function doLogin'), src.indexOf('async function doRegister'));
check(
    loginBlock.includes('clearAuthState()') && loginBlock.indexOf('clearAuthState()') < loginBlock.indexOf('await getAccessToken()'),
    'doLogin clears predecessor session state before minting its first token'
);
check(
    !src.includes("localStorage.setItem('mv_access_token'"),
    'no code path ever persists the bearer token (S-06)'
);
check(refreshMaxConcurrent === 1, `no refresh overlap anywhere in the run (max concurrent ${refreshMaxConcurrent})`);
check(pageErrors.length === 0, `no page errors (${pageErrors.join(' | ') || 'none'})`);

await browser.close();
server.close();
console.log(`\n==== ${PASS} passed, ${FAIL} failed ====`);
process.exit(FAIL ? 1 : 0);
