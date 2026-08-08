// Diagnostic: render the app with a mock backend and screenshot the sidebar / top controls
// at phone and desktop sizes, sidebar collapsed and expanded, to eyeball layout.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const OUT = '/workspace/markervault/tests/pw-test';
const MIME = { '.html':'text/html', '.js':'application/javascript', '.css':'text/css', '.png':'image/png', '.ico':'image/x-icon' };

const MAPS = [
    { id: 4, name: 'Base Map', created: '2026-07-11T09:00:00', description: '', notes: '', markers: 3, is_base: true, owned: true, role: 'owner', owner_username: 'dan', owner_name: 'Dan D' },
    { id: 5, name: 'Fishing spots', created: '2026-07-12T09:00:00', description: '', notes: '', markers: 3, is_base: false, owned: true, role: 'owner', owner_username: 'dan', owner_name: 'Dan D' },
];
const SPOTS = [
    { id: 101, lat: 38.72, lng: -9.14, name: 'Marker Alpha', created: '2026-07-11T10:00:00', listing: '', subset: '', notes: '', photo_count: 0 },
    { id: 102, lat: 38.73, lng: -9.13, name: 'Marker Bravo', created: '2026-07-11T11:00:00', listing: '', subset: '', notes: '', photo_count: 0 },
    { id: 103, lat: 38.71, lng: -9.15, name: 'Marker Charlie', created: '2026-07-11T12:00:00', listing: '', subset: '', notes: '', photo_count: 0 },
];

function sendJSON(res, obj, code=200){ res.writeHead(code, {'Content-Type':'application/json'}); res.end(JSON.stringify(obj)); }

const server = http.createServer((req, res) => {
    const p = new URL(req.url, 'http://x').pathname;
    if (p === '/auth/refresh') return sendJSON(res, { access_token:'faketoken', access_expires_in:900, role:'owner', username:'dan', first_name:'Dan', last_name:'D' });
    if (p === '/account-capabilities') return sendJSON(res, { role:'owner' });
    if (p === '/maps' && req.method === 'GET') return sendJSON(res, MAPS);
    if (/^\/maps\/\d+\/spots$/.test(p)) return sendJSON(res, SPOTS);
    if (p === '/users') return sendJSON(res, []);
    if (p === '/groups') return sendJSON(res, []);
    if (p === '/notif_history') return sendJSON(res, []);
    let fp = p === '/' ? '/index.html' : p;
    const full = path.join(ROOT, fp);
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
async function shoot(name, viewport, expand) {
    const page = await browser.newPage({ viewport });
    page.on('pageerror', e => errors.push(`[${name}] ${e}`));
    await page.goto(base, { waitUntil: 'networkidle' }).catch(e => errors.push('goto '+e));
    await page.waitForTimeout(1500);
    if (expand) {
        // Sidebar starts collapsed; click the toggle to open it.
        await page.evaluate(() => document.getElementById('sidebar-toggle').click());
        await page.waitForTimeout(700);
    }
    const collapsed = await page.evaluate(() => document.getElementById('sidebar').classList.contains('collapsed'));
    await page.screenshot({ path: path.join(OUT, name) });
    console.log(`${name}  ${viewport.width}x${viewport.height}  sidebar collapsed=${collapsed}`);
    await page.close();
}

await shoot('dbg_phone_collapsed.png', { width: 390, height: 844 }, false);
await shoot('dbg_phone_expanded.png',  { width: 390, height: 844 }, true);
await shoot('dbg_desktop_expanded.png',{ width: 1280, height: 800 }, true);

await browser.close();
server.close();
if (errors.length) { console.log('\nPAGE ERRORS:'); errors.forEach(e => console.log('  '+e)); }
console.log('done');
