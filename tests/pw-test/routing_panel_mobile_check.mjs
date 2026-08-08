// Regression: the routing directions panel must stay a tidy, fully-visible card on
// mobile. Leaflet Routing Machine's own stylesheet strips its margin/padding and
// forces width/height:100% under max-width:640px, which crammed it into the corner
// and clipped the alternatives. This asserts that on both phone and desktop the panel
// sits at the top-right, fits within the map, clears the left controls, and isn't
// clipped, with a content-sized width (not LRM's 320px). It no longer sits below the
// search bar — the search bar shrinks to clear it instead (see routing_searchbar_check).
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

const alt = (sel, km, min) => `<div class="leaflet-routing-alt${sel ? ' leaflet-routing-alt-selected' : ''}"><h2>via A1</h2><h3>${km} km, ${min} min</h3><table><tr><td>Turn right onto Rua Longa da Cidade Antiga</td><td>5 km</td></tr></table></div>`;

async function measure(width, height) {
    const page = await browser.newPage({ viewport: { width, height } });
    page.on('pageerror', e => errors.push(`[${width}] ${e}`));
    await page.goto(base, { waitUntil: 'networkidle' });
    await page.waitForTimeout(1200);
    const info = await page.evaluate(({ alts }) => {
        const rc = document.querySelector('.leaflet-routing-container');
        rc.innerHTML = '<div class="routing-button-row"><div class="close-route-btn">x</div></div>'
            + '<div class="leaflet-routing-alternatives-container">' + alts + '</div>';
        rc.classList.add('show');
        const r = el => { const b = el.getBoundingClientRect(); return { l: Math.round(b.left), t: Math.round(b.top), r: Math.round(b.right), b: Math.round(b.bottom), w: Math.round(b.width), h: Math.round(b.height) }; };
        const map = document.getElementById('map').getBoundingClientRect();
        const sb = document.getElementById('topSearchBar');
        const tl = document.querySelector('.leaflet-top.leaflet-left');
        return {
            rc: r(rc), map: { w: Math.round(map.width), h: Math.round(map.height) },
            sbBottom: sb ? Math.round(sb.getBoundingClientRect().bottom) : 0,
            tlRight: tl ? Math.round(tl.getBoundingClientRect().right) : 0,
            clipped: rc.scrollHeight > rc.clientHeight + 1,
        };
    }, { alts: alt(true, 18, 24) + alt(false, 20, 26) + alt(false, 22, 29) });
    await page.close();
    return info;
}

const phone = await measure(390, 844);
const desktop = await measure(1280, 800);

// Phone: at the top-right, fully within the map width, clear of the left controls,
// and not clipped.
const pAtTop = phone.rc.t <= 20;
const pInWidth = phone.rc.l >= 0 && phone.rc.r <= phone.map.w;
const pClearLeft = phone.rc.l >= phone.tlRight;
const pNotClipped = !phone.clipped;
const passPhone = pAtTop && pInWidth && pClearLeft && pNotClipped;

// Desktop: near the top-right, content-sized width (not the old fixed 320), within
// the map, not clipped.
const passDesktop = desktop.rc.t <= 20 && desktop.rc.w > 40 && desktop.rc.w <= 320 && desktop.rc.r <= desktop.map.w && !desktop.clipped;

console.log(`phone   ${JSON.stringify(phone.rc)} sbBottom=${phone.sbBottom} tlRight=${phone.tlRight} clipped=${phone.clipped}`);
console.log(`  atTop=${pAtTop} inWidth=${pInWidth} clearLeft=${pClearLeft} notClipped=${pNotClipped} => ${passPhone ? 'PASS' : 'FAIL'}`);
console.log(`desktop ${JSON.stringify(desktop.rc)} clipped=${desktop.clipped} => ${passDesktop ? 'PASS' : 'FAIL'}`);
if (errors.length) { console.log('PAGE ERRORS:'); errors.forEach(e => console.log('  ' + e)); }

await browser.close();
server.close();
process.exit(passPhone && passDesktop && !errors.length ? 0 : 1);
