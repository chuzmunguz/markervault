// Verify the routing alternatives show short labels ("Route 1", "Route 2", …)
// instead of OSRM's run-together road names. Mocks the OSRM endpoint at the network
// level so the REAL router + the production rename wrapper + LRM's rendering all run,
// then asserts the alternative headers read "Route N" on phone and desktop.
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

// Minimal Google-polyline encoder (precision 5) — just needs to decode without error.
function encodePolyline(coords) {
    let lastLat = 0, lastLng = 0, out = '';
    const enc = num => { num = num < 0 ? ~(num << 1) : (num << 1); let s = ''; while (num >= 0x20) { s += String.fromCharCode((0x20 | (num & 0x1f)) + 63); num >>= 5; } s += String.fromCharCode(num + 63); return s; };
    for (const [lat, lng] of coords) {
        const la = Math.round(lat * 1e5), ln = Math.round(lng * 1e5);
        out += enc(la - lastLat) + enc(ln - lastLng);
        lastLat = la; lastLng = ln;
    }
    return out;
}
const geom = encodePolyline([[38.72, -9.14], [38.75, -9.05]]);
// legs with empty steps => LRM's _convertRoute skips step/instruction parsing.
const osrmRoute = (summary, dist, dur) => ({ distance: dist, duration: dur, geometry: geom, weight: dist, weight_name: 'routability', legs: [{ summary, steps: [], distance: dist, duration: dur }] });
const osrmBody = JSON.stringify({
    code: 'Ok',
    waypoints: [ { location: [-9.14, 38.72], name: '', hint: '' }, { location: [-9.05, 38.75], name: '', hint: '' } ],
    routes: [ osrmRoute('Highway A1', 18000, 1440), osrmRoute('IC19, A5', 20000, 1560), osrmRoute('N6', 22000, 1740) ],
});

const browser = await chromium.launch();
await new Promise(r => server.listen(0, r));
const base = `http://127.0.0.1:${server.address().port}`;
const errors = [];

async function check(width, height, label, screenshot) {
    const page = await browser.newPage({ viewport: { width, height } });
    page.on('pageerror', e => errors.push(`[${label}] ${e}`));
    await page.route(/tile\.openstreetmap|googleapis|gstatic|nominatim/i, r => r.abort());
    await page.route(/router\.project-osrm\.org/i, r => r.fulfill({ status: 200, contentType: 'application/json', body: osrmBody }));
    await page.goto(base, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(1500);
    await page.evaluate(() => {
        routingControl.setWaypoints([L.latLng(38.72, -9.14), L.latLng(38.75, -9.05)]);
        routingContainer.classList.add('show');
    });
    await page.waitForTimeout(1000);
    const names = await page.evaluate(() =>
        [...document.querySelectorAll('.leaflet-routing-alt h2')].map(h => h.textContent.trim()));
    const expected = ['Route 1', 'Route 2', 'Route 3'];
    const pass = names.length === 3 && names.every((n, i) => n === expected[i]);
    console.log(`${label} ${width}x${height}: headers=${JSON.stringify(names)} => ${pass ? 'PASS' : 'FAIL'}`);
    if (screenshot) await page.screenshot({ path: path.join(process.cwd(), screenshot) });
    await page.close();
    return pass;
}

const a = await check(390, 844, 'phone ', 'route_names_phone.png');
const b = await check(1280, 800, 'desktop', null);
if (errors.length) { console.log('PAGE ERRORS:'); errors.forEach(e => console.log('  ' + e)); }

await browser.close();
server.close();
process.exit(a && b && !errors.length ? 0 : 1);
