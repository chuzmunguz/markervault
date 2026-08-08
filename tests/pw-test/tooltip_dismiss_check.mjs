// Regression: a tooltip must not linger after a click opens an overlay.
// Repro of the bug: hover a data-tip button, click it WITHIN the 750ms show
// delay (opening an overlay), then wait past the delay. The pending show-timer
// must have been cancelled, so no .tooltip is ever added to the DOM.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const MIME = { '.html':'text/html', '.js':'application/javascript', '.css':'text/css', '.png':'image/png', '.ico':'image/x-icon' };

const MAPS = [
    { id: 4, name: 'Base Map', created: '2026-07-11T09:00:00', description: 'x', notes: '', markers: 1, is_base: true, owned: true, role: 'owner', owner_username: 'dan', owner_name: 'Dan D' },
];
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
const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
const errors = [];
page.on('pageerror', e => errors.push(String(e)));
await page.goto(base, { waitUntil: 'networkidle' });
await page.waitForTimeout(1200);

// Open the sidebar so the per-map action buttons (which carry data-tip) render.
await page.evaluate(() => document.getElementById('sidebar-toggle').click());
await page.waitForTimeout(600);

// Pick any data-tip button that opens an overlay (e.g. "Edit Map"/"View Details").
const found = await page.evaluate(() => {
    const btns = Array.from(document.querySelectorAll('[data-tip]'))
        .filter(el => el.offsetParent !== null);
    if (!btns.length) return null;
    // Prefer one whose tip suggests it opens an overlay.
    const pref = btns.find(b => /details|edit|share/i.test(b.getAttribute('data-tip'))) || btns[0];
    pref.id = pref.id || '__tiprepro__';
    return { id: pref.id, tip: pref.getAttribute('data-tip') };
});
if (!found) { console.log('FAIL: no visible data-tip button to test'); process.exit(1); }

// Simulate the fast-click race: mouseover, then click ~150ms later (well under
// the 750ms show delay), then wait past the delay and check for a lingering tip.
const result = await page.evaluate(async (id) => {
    const el = document.getElementById(id);
    el.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
    await new Promise(r => setTimeout(r, 150));
    el.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await new Promise(r => setTimeout(r, 1000)); // past the 750ms show delay
    const tips = document.querySelectorAll('.tooltip');
    return { count: tips.length, shown: Array.from(tips).filter(t => t.classList.contains('show')).length };
}, found.id);

const pass = result.count === 0;
console.log(`tip="${found.tip}"  lingering .tooltip nodes=${result.count}  shown=${result.shown}  => ${pass ? 'PASS' : 'FAIL'}`);
if (errors.length) { console.log('PAGE ERRORS:'); errors.forEach(e => console.log('  ' + e)); }

await browser.close();
server.close();
process.exit(pass && !errors.length ? 0 : 1);
