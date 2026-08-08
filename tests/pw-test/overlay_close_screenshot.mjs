// Diagnostic: force-open representative overlays and screenshot them at phone and
// desktop sizes to eyeball the shared top-right close (X) button placement.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const OUT = '/workspace/markervault/tests/pw-test';
const MIME = { '.html':'text/html', '.js':'application/javascript', '.css':'text/css', '.png':'image/png', '.ico':'image/x-icon' };

const MAPS = [
    { id: 4, name: 'Base Map', created: '2026-07-11T09:00:00', description: '', notes: '', markers: 3, is_base: true, owned: true, role: 'owner', owner_username: 'dan', owner_name: 'Dan D' },
];
const SPOTS = [
    { id: 101, lat: 38.72, lng: -9.14, name: 'Marker Alpha', created: '2026-07-11T10:00:00', listing: '', subset: '', notes: '', photo_count: 0 },
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

// Overlays picked for coverage: centered-title form, left-title panel, and a
// details overlay whose content sits at the very top of the card.
const OVERLAYS = ['addMapOverlay', 'notifHistoryOverlay', 'profileOverlay', 'deleteAccountOverlay'];

async function shoot(tag, viewport) {
    const page = await browser.newPage({ viewport });
    page.on('pageerror', e => errors.push(`[${tag}] ${e}`));
    await page.goto(base, { waitUntil: 'networkidle' }).catch(e => errors.push('goto '+e));
    await page.waitForTimeout(1200);
    for (const id of OVERLAYS) {
        const opened = await page.evaluate((oid) => {
            const el = document.getElementById(oid);
            if (!el) return false;
            el.style.display = 'flex';
            el.classList.add('active');
            return true;
        }, id);
        if (!opened) { errors.push(`[${tag}] ${id} not found`); continue; }
        await page.waitForTimeout(300);
        await page.screenshot({ path: path.join(OUT, `xbtn_${tag}_${id}.png`) });
        // Verify the X actually closes it via the delegated handler.
        const closed = await page.evaluate((oid) => {
            const el = document.getElementById(oid);
            el.querySelector('.overlay-close').click();
            return !el.classList.contains('active');
        }, id);
        console.log(`${tag}  ${id}  x-closes=${closed}`);
    }
    await page.close();
}

await shoot('phone', { width: 390, height: 844 });
await shoot('desktop', { width: 1280, height: 800 });

await browser.close();
server.close();
if (errors.length) { console.log('\nPAGE ERRORS:'); errors.forEach(e => console.log('  '+e)); }
console.log('done');
