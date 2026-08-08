// Render the branded status pages with the logo in place: the in-app 429 rate-limit
// screen (#limitScreen) and the standalone nginx 404 page (404.html). Saves PNGs so the
// cards can be eyeballed.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const OUT = '/workspace/markervault/tests/pw-test';
const MIME = { '.html':'text/html', '.js':'application/javascript', '.css':'text/css', '.png':'image/png', '.ico':'image/x-icon', '.webmanifest':'application/manifest+json' };

const server = http.createServer((req, res) => {
    const p = new URL(req.url, 'http://x').pathname;
    // Stub the app JS so boot logic can't toggle status screens out from under us.
    if (p === '/frontend.js') { res.writeHead(200, {'Content-Type':'application/javascript'}); return res.end(''); }
    const full = path.join(ROOT, p === '/' ? '/index.html' : p);
    if (fs.existsSync(full) && fs.statSync(full).isFile()) {
        res.writeHead(200, {'Content-Type': MIME[path.extname(full)] || 'text/plain'});
        return res.end(fs.readFileSync(full));
    }
    res.writeHead(404); res.end('');
});

await new Promise(r => server.listen(0, r));
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();

async function shoot(page, url, prep, sel, name) {
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    if (prep) await page.evaluate(prep);
    await page.waitForTimeout(300);
    await (await page.$(sel)).screenshot({ path: path.join(OUT, name) });
    console.log('wrote', name);
}

for (const [label, width] of [['desktop', 1280], ['phone', 390]]) {
    const page = await browser.newPage({ viewport: { width, height: 800 } });
    page.on('pageerror', () => {});
    await shoot(page, base + '/', () => document.getElementById('limitScreen').classList.add('active'), '#limitScreen .auth-card', `limit_screen_${label}.png`);
    await shoot(page, base + '/404.html', null, '.card', `notfound_${label}.png`);
    await page.close();
}

await browser.close();
server.close();
