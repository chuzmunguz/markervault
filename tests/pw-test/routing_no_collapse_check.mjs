// Regression: Leaflet Routing Machine injects a bare "×" collapse button
// (.leaflet-routing-collapse-btn, CSS content:'\00d7') whenever the map is <=640px
// wide — i.e. on mobile. It's redundant with our "Close Route" button and looks
// out of place, so the control is created with collapsible:false. This renders the
// real LRM panel (via a mocked router) and asserts the collapse button is absent on
// both phone and desktop, while "Close Route" is present.
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

await new Promise(r => server.listen(0, r));
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
const errors = [];

async function check(width, height, label) {
    const page = await browser.newPage({ viewport: { width, height } });
    page.on('pageerror', e => errors.push(`[${label}] ${e}`));
    await page.route(/openstreetmap|project-osrm|nominatim|googleapis|gstatic/i, r => r.abort());
    await page.goto(base, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(1500);
    await page.evaluate(() => {
        const A = L.latLng(38.72, -9.14), M = L.latLng(38.735, -9.10), B = L.latLng(38.75, -9.05);
        const mk = (name, d, t) => ({ name, coordinates: [A, M, B], summary: { totalDistance: d, totalTime: t },
            instructions: [ { type:'Head', text:'Head north', distance:d*0.5, time:t*0.5, index:0 }, { type:'DestinationReached', text:'Arrive', distance:0, time:0, index:1 } ],
            inputWaypoints: [{ latLng: A }, { latLng: B }], waypoints: [{ latLng: A }, { latLng: B }], properties: { isSimplified: true } });
        routingControl.getRouter().route = (wps, cb, ctx) => cb.call(ctx, null, [mk('via A1', 18000, 1440), mk('via A2', 20000, 1560)]);
        routingControl.setWaypoints([A, B]);
        routingContainer.classList.add('show');
    });
    await page.waitForTimeout(700);
    const res = await page.evaluate(() => ({
        collapse: !!document.querySelector('.leaflet-routing-collapse-btn'),
        closeRoute: !!document.querySelector('.close-route-btn'),
        alts: document.querySelectorAll('.leaflet-routing-alt').length,
    }));
    const pass = !res.collapse && res.closeRoute && res.alts >= 2;
    console.log(`${label} ${width}x${height}: collapseBtn=${res.collapse} closeRoute=${res.closeRoute} alts=${res.alts} => ${pass ? 'PASS' : 'FAIL'}`);
    await page.close();
    return pass;
}

const a = await check(390, 844, 'phone ');
const b = await check(1280, 800, 'desktop');
if (errors.length) { console.log('PAGE ERRORS:'); errors.forEach(e => console.log('  ' + e)); }

await browser.close();
server.close();
process.exit(a && b && !errors.length ? 0 : 1);
