// Diagnostic: render the auth/login card statically and screenshot it at desktop and
// phone widths to verify the brand logo (assets/brand/logo.png) renders undistorted
// after replacing the circular user-thumb placeholder.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const OUT = '/workspace/markervault/tests/pw-test';
const MIME = { '.html':'text/html', '.js':'application/javascript', '.css':'text/css', '.png':'image/png', '.ico':'image/x-icon', '.webmanifest':'application/manifest+json' };

const server = http.createServer((req, res) => {
    const p = new URL(req.url, 'http://x').pathname;
    let fp = p === '/' ? '/index.html' : p;
    const full = path.join(ROOT, fp);
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
    // frontend.js may throw without a real backend; ignore so the static DOM/CSS still render.
    page.on('pageerror', () => {});
    await page.goto(base + '/', { waitUntil: 'domcontentloaded' });
    await page.evaluate(() => {
        document.getElementById('authScreen').classList.add('active');
    });
    await page.waitForTimeout(300);
    const card = await page.$('#authScreen .auth-card');
    await card.screenshot({ path: path.join(OUT, `auth_logo_${label}.png`) });
    const box = await page.$eval('#authScreen .auth-logo', el => ({ w: el.clientWidth, h: el.clientHeight, natW: el.naturalWidth, natH: el.naturalHeight, radius: getComputedStyle(el).borderRadius }));
    console.log(label, JSON.stringify(box));
    await page.close();
}

await browser.close();
server.close();
