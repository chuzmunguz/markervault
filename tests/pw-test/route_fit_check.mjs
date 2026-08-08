// Verify route framing: after fitRouteInView, the whole route must be fully on
// screen at every viewport width (the mobile bug: fixed desktop padding was wider
// than the phone viewport, so fitBounds zoomed the route away). Checks phone,
// tablet and desktop; also runs the OLD fixed padding on a phone as a failing
// control to prove the difference.
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

// A wide-ish east–west route bounds (Lisbon area) — bigger than any test viewport
// at street zoom, so fitBounds must zoom to frame it (maxZoom won't bind).
const ROUTE = [[38.70, -9.22], [38.735, -9.05]];

// Reproduce the blend so the test can check the route lands inside the padded box.
function pad(width) {
    const t = Math.max(0, Math.min(1, (width - 520) / (1024 - 520)));
    const l = (a, b) => a + (b - a) * t;
    return { padL: l(30,500), padT: l(70,100), padR: l(30,250), padB: l(40,50) };
}

async function frame(page, useOldFixedPadding = false) {
    return await page.evaluate(async ({ ROUTE, useOldFixedPadding }) => {
        const b = L.latLngBounds(ROUTE);
        if (useOldFixedPadding) {
            map.fitBounds(b, { paddingTopLeft: [500,100], paddingBottomRight: [250,50], maxZoom: 16, animate: false });
        } else {
            // Call the real function but without animation so we can measure immediately.
            const orig = map.fitBounds.bind(map);
            map.fitBounds = (bounds, opts) => orig(bounds, { ...opts, animate: false });
            fitRouteInView(b);
            map.fitBounds = orig;
        }
        await new Promise(r => setTimeout(r, 150));
        const size = map.getSize();
        const corners = [b.getSouthWest(), b.getNorthWest(), b.getNorthEast(), b.getSouthEast()]
            .map(ll => map.latLngToContainerPoint(ll));
        const xs = corners.map(c => c.x), ys = corners.map(c => c.y);
        const minX = Math.min(...xs), maxX = Math.max(...xs), minY = Math.min(...ys), maxY = Math.max(...ys);
        return { sizeX: size.x, sizeY: size.y, minX, maxX, minY, maxY, zoom: map.getZoom() };
    }, { ROUTE, useOldFixedPadding });
}

async function run(width, height, label) {
    const page = await browser.newPage({ viewport: { width, height } });
    page.on('pageerror', e => errors.push(`[${label}] ${e}`));
    await page.goto(base, { waitUntil: 'networkidle' });
    await page.waitForTimeout(1200);
    const r = await frame(page);
    const p = pad(width);
    // Fully on screen (all corners within the map container).
    const onScreen = r.minX >= -1 && r.maxX <= r.sizeX + 1 && r.minY >= -1 && r.maxY <= r.sizeY + 1;
    // Inside the padded box (route clears the reserved overlay zones), ~2px tolerance.
    const inPadded = r.minX >= p.padL - 2 && r.maxX <= r.sizeX - p.padR + 2 && r.minY >= p.padT - 2 && r.maxY <= r.sizeY - p.padB + 2;
    // Actually framed (not zoomed away): route width fills most of the available box.
    const availW = r.sizeX - p.padL - p.padR;
    const framed = (r.maxX - r.minX) >= 0.6 * availW;
    const pass = onScreen && inPadded && framed;
    console.log(`${label} ${width}x${height}: onScreen=${onScreen} inPadded=${inPadded} framed=${framed} (routeW=${Math.round(r.maxX-r.minX)}/avail=${Math.round(availW)}, zoom=${r.zoom.toFixed(1)}) => ${pass ? 'PASS' : 'FAIL'}`);
    await page.close();
    return pass;
}

// Failing control: old fixed padding on a phone.
async function control() {
    const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
    await page.goto(base, { waitUntil: 'networkidle' });
    await page.waitForTimeout(1200);
    const r = await frame(page, true);
    const availW = 390 - 500 - 250; // negative — the whole bug in one number
    const onScreen = r.minX >= -1 && r.maxX <= r.sizeX + 1 && r.minY >= -1 && r.maxY <= r.sizeY + 1;
    console.log(`CONTROL old-padding 390x844: availW=${availW} routeW=${Math.round(r.maxX-r.minX)} zoom=${r.zoom.toFixed(1)} onScreen=${onScreen} (expect false — route overflows the screen)`);
    await page.close();
    return !onScreen; // control passes when the old behavior is demonstrably broken (route not fully visible)
}

const results = [];
results.push(await run(390, 844, 'phone '));
results.push(await run(768, 1024, 'tablet'));
results.push(await run(1280, 800, 'desktop'));
const ctl = await control();

// Visual: draw the route on a phone, frame it, and screenshot (tiles are gray
// offline; framing/position relative to the top bar and directions panel is the point).
const shot = await browser.newPage({ viewport: { width: 390, height: 844 } });
await shot.goto(base, { waitUntil: 'networkidle' });
await shot.waitForTimeout(1200);
await shot.evaluate(({ ROUTE }) => {
    const rc = document.querySelector('.leaflet-routing-container');
    if (rc) { rc.classList.add('show'); rc.innerHTML = '<div class="leaflet-routing-alt" style="padding:12px 16px"><h3>18 km, 24 min</h3></div>'; }
    const b = L.latLngBounds(ROUTE);
    L.polyline(ROUTE, { color: '#0077ff', weight: 5 }).addTo(map);
    const orig = map.fitBounds.bind(map);
    map.fitBounds = (bounds, opts) => orig(bounds, { ...opts, animate: false });
    fitRouteInView(b);
    map.fitBounds = orig;
}, { ROUTE });
await shot.waitForTimeout(300);
await shot.screenshot({ path: path.join(process.cwd(), 'route_fit_phone.png') });
await shot.close();

if (errors.length) { console.log('PAGE ERRORS:'); errors.forEach(e => console.log('  ' + e)); }
await browser.close();
server.close();
const ok = results.every(Boolean) && ctl && !errors.length;
console.log(`\n=> ${ok ? 'ALL PASS' : 'FAIL'}`);
process.exit(ok ? 0 : 1);
