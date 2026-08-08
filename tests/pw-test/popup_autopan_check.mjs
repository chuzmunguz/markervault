// Verify marker popup auto-pan: a popup that opens CLIPPED by a map edge recenters
// on screen; a popup that opens FULLY VISIBLE moves nothing (the map — and every
// other marker on it — stays put). Runs on a phone-sized viewport.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const MIME = { '.html':'text/html', '.js':'application/javascript', '.css':'text/css', '.png':'image/png', '.ico':'image/x-icon' };
const MAPS = [{ id: 4, name: 'Base Map', created: '2026-07-11T09:00:00', description: 'x', notes: '', markers: 1, is_base: true, owned: true, role: 'owner', owner_username: 'dan', owner_name: 'Dan D' }];
const SPOTS = [{ id: 101, lat: 38.72, lng: -9.14, name: 'Edge Marker', created: '2026-07-11T10:00:00', listing: '', subset: '', notes: 'A marker near the edge', photo_count: 0 }];

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
await page.waitForTimeout(1500);

// (0) Real rendered marker must bind with autoPan disabled (relies on the handler).
const realAutoPan = await page.evaluate(() => {
    const opts = markers[0] && markers[0].getPopup() && markers[0].getPopup().options;
    return opts ? opts.autoPan : 'no-popup';
});
console.log('0) real marker popup autoPan option =', realAutoPan);

// (A) Clipped popup -> recenters on screen (and ends fully visible).
const A = await page.evaluate(async () => {
    map.closePopup();
    if (window.__p) { map.removeLayer(window.__p); window.__p = null; }
    const size = map.getSize();
    const m = L.marker(map.getCenter()).addTo(map);
    window.__p = m;
    m.bindPopup('<div style="width:220px">Clipped popup body to force an edge overflow.</div>', { autoPan: false });
    map.panBy([ -((size.x / 2) - 25), 0 ], { animate: false }); // shove marker ~25px inside the right edge
    m.openPopup();
    await new Promise(r => setTimeout(r, 800)); // pan animation
    const mapRect = map.getContainer().getBoundingClientRect();
    const pr = document.querySelector('.leaflet-popup').getBoundingClientRect();
    return {
        fullyInside: pr.left >= mapRect.left - 1 && pr.right <= mapRect.right + 1 && pr.top >= mapRect.top - 1 && pr.bottom <= mapRect.bottom + 1,
        offCenterX: Math.round((pr.left + pr.width / 2) - (mapRect.left + mapRect.width / 2)),
        offCenterY: Math.round((pr.top + pr.height / 2) - (mapRect.top + mapRect.height / 2)),
    };
});

// (B) Fully-visible popup -> map must not move at all.
const B = await page.evaluate(async () => {
    map.closePopup();
    if (window.__p) { map.removeLayer(window.__p); window.__p = null; }
    const before = map.getCenter();
    const m = L.marker(map.getCenter()).addTo(map);
    window.__p = m;
    m.bindPopup('<div style="width:180px">Small centered popup, fully visible.</div>', { autoPan: false });
    m.openPopup();
    await new Promise(r => setTimeout(r, 500));
    const after = map.getCenter();
    return { moved: Math.abs(after.lat - before.lat) > 1e-9 || Math.abs(after.lng - before.lng) > 1e-9 };
});
await page.evaluate(() => { if (window.__p) map.removeLayer(window.__p); map.closePopup(); });

const passA = A.fullyInside && Math.abs(A.offCenterX) <= 8 && Math.abs(A.offCenterY) <= 8;
const passB = !B.moved;
console.log(`A) clipped popup -> fullyInside=${A.fullyInside}  offCentre=(${A.offCenterX},${A.offCenterY})  ${passA ? 'PASS' : 'FAIL'}`);
console.log(`B) visible popup -> map moved=${B.moved}  ${passB ? 'PASS' : 'FAIL'}`);
if (errors.length) { console.log('PAGE ERRORS:'); errors.forEach(e => console.log('  ' + e)); }

// Visual: reopen the real marker's popup shoved against the right edge and shoot it.
await page.evaluate(async () => {
    map.closePopup();
    const m = markers[0];
    const size = map.getSize();
    map.setView(m.getLatLng(), map.getZoom(), { animate: false });
    map.panBy([ -((size.x / 2) - 25), 0 ], { animate: false });
    m.openPopup();
    await new Promise(r => setTimeout(r, 800));
});
await page.screenshot({ path: path.join(process.cwd(), 'autopan_phone_centered.png') });

await browser.close();
server.close();
process.exit(passA && passB && !errors.length ? 0 : 1);
