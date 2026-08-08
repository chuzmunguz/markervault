// Verify the top search bar coordinates with the routing panel: when the panel opens
// and would overlap the normally-centred bar (phone), the bar slides up off-screen,
// and slides back when the route closes. On desktop there's no overlap, so the bar
// must not move.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const MIME = { '.html':'text/html', '.js':'application/javascript', '.css':'text/css', '.png':'image/png', '.ico':'image/x-icon' };
const MAPS = [{ id: 4, name: 'Base Map', created: '2026-07-11T09:00:00', description: '', notes: '', markers: 0, is_base: true, owned: true, role: 'owner', owner_username: 'dan', owner_name: 'Dan D' }];

function sendJSON(res, obj){ res.writeHead(200, {'Content-Type':'application/json'}); res.end(JSON.stringify(obj)); }
const server = http.createServer((req, res) => {
    const p = new URL(req.url, 'http://x').pathname;
    if (p === '/auth/refresh') return sendJSON(res, { access_token:'t', access_expires_in:900, role:'owner', username:'dan', first_name:'Dan', last_name:'D' });
    if (p === '/account-capabilities') return sendJSON(res, { role:'owner' });
    if (p === '/maps' && req.method === 'GET') return sendJSON(res, MAPS);
    if (/^\/maps\/\d+\/spots$/.test(p)) return sendJSON(res, []);
    if (['/users','/groups','/notif_history'].includes(p)) return sendJSON(res, []);
    const full = path.join(ROOT, p === '/' ? '/index.html' : p);
    if (fs.existsSync(full) && fs.statSync(full).isFile()) {
        res.writeHead(200, {'Content-Type': MIME[path.extname(full)] || 'text/plain'});
        return res.end(fs.readFileSync(full));
    }
    res.writeHead(200, {'Content-Type':'application/json'}); res.end('[]');
});

function encPoly(c){ let la=0,ln=0,o=''; const e=n=>{ n=n<0?~(n<<1):(n<<1); let s=''; while(n>=0x20){ s+=String.fromCharCode((0x20|(n&0x1f))+63); n>>=5; } s+=String.fromCharCode(n+63); return s; }; for (const [a,b] of c){ const A=Math.round(a*1e5),B=Math.round(b*1e5); o+=e(A-la)+e(B-ln); la=A; ln=B; } return o; }
const geom = encPoly([[38.72,-9.14],[38.75,-9.05]]);
const rt = (s,d,t) => ({ distance:d, duration:t, geometry:geom, weight:d, weight_name:'routability', legs:[{ summary:s, steps:[], distance:d, duration:t }] });
const osrmBody = JSON.stringify({ code:'Ok', waypoints:[{location:[-9.14,38.72],name:'',hint:''},{location:[-9.05,38.75],name:'',hint:''}], routes:[rt('A1',18000,1440), rt('A5',20000,1560), rt('N6',22000,1740)] });

await new Promise(r => server.listen(0, r));
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
const errors = [];

const bar = async page => page.evaluate(() => {
    const b = document.getElementById('topSearchBar').getBoundingClientRect();
    const panelEl = document.querySelector('.leaflet-routing-container.show');
    const panel = panelEl ? panelEl.getBoundingClientRect() : null;
    const tl = document.querySelector('.leaflet-top.leaflet-left').getBoundingClientRect();
    return { barL: Math.round(b.left), barR: Math.round(b.right), barW: Math.round(b.width),
             barT: Math.round(b.top), barB: Math.round(b.bottom),
             panelL: panel ? Math.round(panel.left) : null, ctrlR: Math.round(tl.right) };
});

async function run(width, height, label, expectHide) {
    const page = await browser.newPage({ viewport: { width, height } });
    page.on('pageerror', e => errors.push(`[${label}] ${e}`));
    await page.route(/tile\.openstreetmap|googleapis|gstatic|nominatim/i, r => r.abort());
    await page.route(/router\.project-osrm\.org/i, r => r.fulfill({ status:200, contentType:'application/json', body:osrmBody }));
    await page.goto(base, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(1500);

    const before = await bar(page);
    // Open a route (mirrors the generate flow: set waypoints + show).
    await page.evaluate(() => { routingControl.setWaypoints([L.latLng(38.72,-9.14), L.latLng(38.75,-9.05)]); routingContainer.classList.add('show'); });
    await page.waitForTimeout(700); // routes + width transition
    const during = await bar(page);
    // Close the route.
    await page.evaluate(() => document.querySelector('.close-route-btn').click());
    await page.waitForTimeout(700);
    const after = await bar(page);

    let pass, detail;
    if (expectHide) {
        // Panel overlaps → bar slides up off the top, then comes back on close.
        const slidUp = during.barB <= 2;                       // above the viewport top
        const restored = after.barB > 0 && Math.abs(after.barT - before.barT) <= 1;
        pass = slidUp && restored;
        detail = `slidUp=${slidUp}(barBottom ${before.barB}->${during.barB}) restored=${restored}(barTop ->${after.barT})`;
    } else {
        // No overlap → bar unchanged and still visible.
        const unchanged = during.barB > 0 && Math.abs(during.barL - before.barL) <= 1 && Math.abs(during.barW - before.barW) <= 1;
        const restored = Math.abs(after.barL - before.barL) <= 1;
        pass = unchanged && restored;
        detail = `unchanged=${unchanged}(L ${before.barL}->${during.barL}, visible barBottom ${during.barB}) restored=${restored}`;
    }
    console.log(`${label} ${width}x${height}: ${detail} => ${pass ? 'PASS' : 'FAIL'}`);
    await page.close();
    return pass;
}

const a = await run(390, 844, 'phone  ', true);
const b = await run(1280, 800, 'desktop', false);
if (errors.length) { console.log('PAGE ERRORS:'); errors.forEach(e => console.log('  ' + e)); }

await browser.close();
server.close();
process.exit(a && b && !errors.length ? 0 : 1);
