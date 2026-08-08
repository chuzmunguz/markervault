// Screenshot harness for the notif-history "Mark all seen" button styling.
// Boots the app against a minimal mock, opens the overlay, and captures the
// button enabled (unseen rows present) and disabled (after marking seen), at
// phone and desktop viewports. Not part of the npm-test suite; run by hand.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const MIME = { '.html':'text/html', '.js':'application/javascript', '.css':'text/css', '.png':'image/png', '.ico':'image/x-icon' };

let unseen = 2;
const rows = [
    { id:12, created:'2026-07-22T12:00:00Z', event:'map.deleted', target_type:'map', target_id:'5', target_label:'Survey', message:'Map “Survey” deleted.', detail:{markers:2, photos:1}, correlation_id:null, seen:false },
    { id:11, created:'2026-07-22T11:00:00Z', event:'server.error', target_type:'request', target_id:'/maps', target_label:'test', message:'Something went wrong. Reference abc123.', detail:{area:'test', method:'GET', route:'/maps'}, correlation_id:'abc123', seen:false }
];

function sendJSON(res, object, status=200) {
    res.writeHead(status, {'Content-Type':'application/json'});
    res.end(JSON.stringify(object));
}

const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    const pathname = url.pathname;
    if (pathname === '/auth/refresh') {
        return sendJSON(res, { access_token:'alice-token', access_expires_in:900, role:'super_admin', username:'alice', first_name:'Alice', last_name:'Tester', avatar_url:null });
    }
    if (pathname === '/maps' && req.method === 'GET') {
        return sendJSON(res, [{id:4, name:'Base Map', created:'2026-07-22T00:00:00Z', description:'', notes:'', markers:0, is_base:true, owned:true, role:'owner', shared:false}]);
    }
    if (/^\/maps\/\d+\/spots$/.test(pathname)) return sendJSON(res, []);
    if (pathname === '/notif_history' && url.searchParams.get('summary') === '1') return sendJSON(res, {unseen});
    if (pathname === '/notif_history' && req.method === 'GET') return sendJSON(res, {notifications:rows, unseen, through_id:12});
    if (pathname === '/notif_history/seen' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => { rows.forEach(n => { n.seen = true; }); unseen = 0; sendJSON(res, {marked:2, unseen:0}); });
        return;
    }
    const relative = pathname === '/' ? '/index.html' : pathname;
    const file = path.join(ROOT, relative);
    if (fs.existsSync(file) && fs.statSync(file).isFile()) {
        res.writeHead(200, {'Content-Type':MIME[path.extname(file)] || 'text/plain'});
        return res.end(fs.readFileSync(file));
    }
    res.writeHead(200, {'Content-Type':'application/javascript'});
    res.end('');
});

await new Promise(resolve => server.listen(0, resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();

async function shot(width, height, name, markSeen) {
    const page = await browser.newPage({viewport:{width, height}});
    await page.goto(base, {waitUntil:'networkidle'});
    await page.waitForFunction(() => document.getElementById('notifHistoryBadge').textContent === '2');
    await page.evaluate(() => document.getElementById('notifHistoryBtn').click());
    await page.waitForFunction(() => document.querySelectorAll('.notif-history-row').length === 2);
    if (markSeen) {
        await page.click('#notifHistoryMarkSeenBtn');
        await page.waitForFunction(() => document.getElementById('notifHistoryMarkSeenBtn').disabled);
    }
    const panel = await page.$('.notif-history-panel');
    await panel.screenshot({path:name});
    console.log(`wrote ${name}`);
    await page.close();
}

await shot(390, 844, 'notif_btn_phone_enabled.png', false);
await shot(1280, 900, 'notif_btn_desktop_enabled.png', false);
await shot(1280, 900, 'notif_btn_desktop_disabled.png', true);

await browser.close();
server.close();
