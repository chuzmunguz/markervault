// Regression (mobile): a touch tap synthesizes mouseover events; when a tap opens
// an overlay the browser re-fires mouseover on the element now under the finger,
// with no matching mouseout — so a hover tooltip it triggers would stick. The fix
// ignores hover events that follow a recent touch. This check asserts:
//   (A) mouse-only hover still shows a tooltip (desktop unaffected), and
//   (B) a hover right after a touch shows nothing.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const MIME = { '.html':'text/html', '.js':'application/javascript', '.css':'text/css', '.png':'image/png', '.ico':'image/x-icon' };
const MAPS = [{ id: 4, name: 'Base Map', created: '2026-07-11T09:00:00', description: 'x', notes: '', markers: 1, is_base: true, owned: true, role: 'owner', owner_username: 'dan', owner_name: 'Dan D' }];
const SPOTS = [{ id: 101, lat: 38.72, lng: -9.14, name: 'Marker Alpha', created: '2026-07-11T10:00:00', listing: '', subset: '', notes: '', photo_count: 0 }];

function sendJSON(res, obj){ res.writeHead(200, {'Content-Type':'application/json'}); res.end(JSON.stringify(obj)); }
const server = http.createServer((req, res) => {
    const p = new URL(req.url, 'http://x').pathname;
    if (p === '/auth/refresh') return sendJSON(res, { access_token:'faketoken', access_expires_in:900, role:'owner', username:'dan', first_name:'Dan', last_name:'D' });
    if (p === '/account-capabilities') return sendJSON(res, { role:'owner' });
    if (p === '/maps' && req.method === 'GET') return sendJSON(res, MAPS);
    if (/^\/maps\/\d+\/spots$/.test(p)) return sendJSON(res, SPOTS);
    if (['/users','/groups','/notif_history'].includes(p)) return sendJSON(res, []);
    const full = path.join(ROOT, p === '/' ? '/index.html' : p);
    if (fs.existsSync(full) && fs.statSync(full).isFile()) {
        res.writeHead(200, {'Content-Type': MIME[path.extname(full)] || 'text/plain'});
        return res.end(fs.readFileSync(full));
    }
    res.writeHead(200, {'Content-Type':'application/json'}); res.end('[]');
});

await new Promise(r => server.listen(0, r));
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true });
const page = await context.newPage();
const errors = [];
page.on('pageerror', e => errors.push(String(e)));
await page.goto(base, { waitUntil: 'networkidle' });
await page.waitForTimeout(1200);
await page.evaluate(() => document.getElementById('sidebar-toggle').click());
await page.waitForTimeout(600);

// Grab a visible data-tip element to hover.
const tipId = await page.evaluate(() => {
    const el = Array.from(document.querySelectorAll('[data-tip]')).find(e => e.offsetParent !== null);
    if (!el) return null;
    el.id = el.id || '__tip__';
    return el.id;
});
if (!tipId) { console.log('FAIL: no visible data-tip element'); process.exit(1); }

// (A) Mouse-only hover (no prior touch): tooltip SHOULD appear.
const aCount = await page.evaluate(async (id) => {
    document.getElementById(id).dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
    await new Promise(r => setTimeout(r, 900)); // past 750ms show delay
    return document.querySelectorAll('.tooltip').length;
}, tipId);
// Clear it before the next case.
await page.evaluate((id) => {
    document.getElementById(id).dispatchEvent(new MouseEvent('mouseout', { bubbles: true }));
}, tipId);
await page.waitForTimeout(400);

// (B) A real touch, then a hover on the tip element (the synthetic post-tap
// mouseover): tooltip must NOT appear.
await page.touchscreen.tap(200, 400);
const bCount = await page.evaluate(async (id) => {
    document.getElementById(id).dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
    await new Promise(r => setTimeout(r, 900));
    return document.querySelectorAll('.tooltip').length;
}, tipId);

const passA = aCount >= 1;   // mouse hover still works
const passB = bCount === 0;  // touch-driven hover suppressed
console.log(`A) mouse-only hover -> tooltips=${aCount} (want >=1) ${passA ? 'PASS' : 'FAIL'}`);
console.log(`B) hover after touch -> tooltips=${bCount} (want 0)  ${passB ? 'PASS' : 'FAIL'}`);
if (errors.length) { console.log('PAGE ERRORS:'); errors.forEach(e => console.log('  ' + e)); }

await browser.close();
server.close();
process.exit(passA && passB && !errors.length ? 0 : 1);
