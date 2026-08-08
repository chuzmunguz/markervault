// Render the "Browser not supported" screen (#unsupportedScreen) statically and save a
// screenshot, so the rarely-seen Web Locks capability-gate card can be eyeballed with
// the brand logo in place.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const OUT = '/workspace/markervault/tests/pw-test';
const MIME = { '.html':'text/html', '.js':'application/javascript', '.css':'text/css', '.png':'image/png', '.ico':'image/x-icon', '.webmanifest':'application/manifest+json' };

const server = http.createServer((req, res) => {
    const p = new URL(req.url, 'http://x').pathname;
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

for (const [label, width] of [['desktop', 1280], ['phone', 390]]) {
    const page = await browser.newPage({ viewport: { width, height: 800 } });
    page.on('pageerror', () => {});
    await page.goto(base + '/', { waitUntil: 'domcontentloaded' });
    await page.evaluate(() => document.getElementById('unsupportedScreen').classList.add('active'));
    await page.waitForTimeout(300);
    await page.$eval('#unsupportedScreen', el => el.scrollIntoView());
    const card = await page.$('#unsupportedScreen .auth-card');
    await card.screenshot({ path: path.join(OUT, `unsupported_screen_${label}.png`) });
    console.log('wrote', `unsupported_screen_${label}.png`);
    await page.close();
}

await browser.close();
server.close();
