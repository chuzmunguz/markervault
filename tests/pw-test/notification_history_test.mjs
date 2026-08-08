// Notification-history UI: exact badge, explicit high-water seen action, bounded
// operation-driven refreshes, safe rendering, and cross-account state cleanup.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const MIME = {
    '.html':'text/html', '.js':'application/javascript', '.css':'text/css',
    '.png':'image/png', '.ico':'image/x-icon'
};

let account = 'alice';
let summaryCalls = 0;
let fullCalls = 0;
let summaryUnseen = 123;
let holdFullHistory = false;
const heldFullResponses = [];
const seenBodies = [];
const rowSeenBodies = [];
const notificationRequests = [];
const rows = [
    {
        id:12,
        created:'2026-07-22T12:00:00Z',
        event:'map.deleted',
        target_type:'map',
        target_id:'5',
        target_label:'Survey',
        message:'Map “<img src=x onerror=alert(1)>” deleted.',
        detail:{markers:2, photos:1},
        correlation_id:null,
        seen:false
    },
    {
        id:11,
        created:'2026-07-22T11:00:00Z',
        event:'server.error',
        target_type:'request',
        target_id:'/maps',
        target_label:'test',
        message:'Something went wrong. Reference abc123.',
        detail:{area:'test', method:'GET', route:'/maps'},
        correlation_id:'abc123',
        seen:false
    }
];

function sendJSON(res, object, status=200) {
    res.writeHead(status, {'Content-Type':'application/json'});
    res.end(JSON.stringify(object));
}

const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    const pathname = url.pathname;
    if (pathname === '/login' && req.method === 'POST') {
        account = 'bob';
        return sendJSON(res, {message:'ok'});
    }
    if (pathname === '/auth/refresh') {
        return sendJSON(res, {
            access_token:`${account}-token`,
            access_expires_in:900,
            role:'super_admin',
            username:account,
            first_name:account === 'alice' ? 'Alice' : 'Bob',
            last_name:'Tester',
            avatar_url:null
        });
    }
    if (pathname === '/maps' && req.method === 'GET') {
        return sendJSON(res, [
            {id:4, name:'Base Map', created:'2026-07-22T00:00:00Z', description:'', notes:'', markers:0, is_base:true, owned:true, role:'owner', shared:false},
            {id:5, name:'Survey', created:'2026-07-22T00:00:00Z', description:'', notes:'', markers:2, is_base:false, owned:true, role:'owner', shared:false}
        ]);
    }
    if (/^\/maps\/\d+\/spots$/.test(pathname)) return sendJSON(res, []);
    if (pathname === '/maps/5' && req.method === 'DELETE') {
        summaryUnseen = 8;
        return sendJSON(res, {success:true});
    }
    if (pathname === '/notif_history' && url.searchParams.get('summary') === '1') {
        summaryCalls += 1;
        notificationRequests.push('/notif_history?summary=1');
        return sendJSON(res, {unseen:summaryUnseen});
    }
    if (pathname === '/notif_history' && req.method === 'GET') {
        fullCalls += 1;
        notificationRequests.push('/notif_history');
        if (holdFullHistory) {
            heldFullResponses.push(res);
            return;
        }
        return sendJSON(res, {notifications:rows, unseen:2, through_id:12});
    }
    if (pathname === '/notif_history/seen' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            const parsed = JSON.parse(body);
            seenBodies.push(parsed);
            rows.forEach(notification => {
                if (notification.id <= parsed.through_id) notification.seen = true;
            });
            summaryUnseen = 1;
            notificationRequests.push('/notif_history/seen');
            sendJSON(res, {marked:2, unseen:1});
        });
        return;
    }
    if (/^\/notif_history\/\d+\/seen$/.test(pathname) && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            const parsed = JSON.parse(body);
            const id = Number(pathname.split('/')[2]);
            const notification = rows.find(row => row.id === id);
            notification.seen = parsed.seen;
            const unseen = rows.filter(row => !row.seen).length + 1;
            rowSeenBodies.push({id, ...parsed});
            notificationRequests.push(pathname);
            sendJSON(res, {id, seen:notification.seen, unseen});
        });
        return;
    }
    if (pathname === '/_test/500') {
        summaryUnseen = 7;
        return sendJSON(res, {error:'failed', correlation_id:'server500'}, 500);
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
const page = await browser.newPage({viewport:{width:390, height:844}});
const pageErrors = [];
page.on('pageerror', error => pageErrors.push(String(error)));

let PASS = 0;
let FAIL = 0;
function check(condition, label) {
    if (condition) {
        PASS += 1;
        console.log(`  PASS  ${label}`);
    } else {
        FAIL += 1;
        console.log(`  FAIL  ${label}`);
    }
}

await page.goto(base, {waitUntil:'networkidle'});
await page.waitForFunction(() => document.getElementById('notifHistoryBadge').textContent === '123');

console.log('\n== Boot badge and account-menu placement ==');
const menu = await page.evaluate(() => {
    const buttons = Array.from(document.querySelectorAll('#accountMenu > .account-menu-item'));
    const history = document.getElementById('notifHistoryBtn');
    const badge = document.getElementById('notifHistoryBadge');
    return {
        ids:buttons.map(button => button.id),
        labels:buttons.map(button => button.querySelector('span').textContent),
        badge:badge.textContent,
        badgeHidden:badge.hidden,
        bellViewBox:history.querySelector('svg').getAttribute('viewBox')
    };
});
check(
    JSON.stringify(menu.ids) === JSON.stringify([
        'accountProfileBtn', 'notifHistoryBtn', 'openAdminPanelBtn', 'logoutBtn'
    ]),
    `notification row sits between Profile and Administration (${JSON.stringify(menu.ids)})`
);
check(
    menu.labels.join('|') === 'Profile|Notifications|Administration|Logout'
    && menu.bellViewBox === '0 0 24 24',
    `the row has the Notifications label and bell artwork (${JSON.stringify(menu.labels)})`
);
check(
    menu.badge === '123' && !menu.badgeHidden,
    `boot badge shows the exact unseen count without abbreviation (${menu.badge})`
);
await page.waitForTimeout(800);
check(summaryCalls === 1, `idle time causes no notification polling (${summaryCalls} summary request)`);

console.log('\n== Snapshot rendering and explicit seen action ==');
await page.evaluate(() => document.getElementById('notifHistoryBtn').click());
await page.waitForFunction(() => document.querySelectorAll('.notif-history-row').length === 2);
let panel = await page.evaluate(() => ({
    active:document.getElementById('notifHistoryOverlay').classList.contains('active'),
    messages:Array.from(document.querySelectorAll('.notif-history-message')).map(node => node.textContent),
    eventLabels:Array.from(document.querySelectorAll('.notif-history-event')).map(node => node.textContent),
    rowTones:Array.from(document.querySelectorAll('.notif-history-row')).map(node => node.className),
    unseenRows:document.querySelectorAll('.notif-history-row.unseen').length,
    nestedImages:document.querySelectorAll('#notifHistoryList img').length,
    timestampTitles:Array.from(document.querySelectorAll('.notif-history-time')).map(node => node.title),
    badge:document.getElementById('notifHistoryBadge').textContent,
    markDisabled:document.getElementById('notifHistoryMarkSeenBtn').disabled,
    panelWidth:document.querySelector('.notif-history-panel').getBoundingClientRect().width,
    viewport:document.documentElement.clientWidth
}));
check(panel.active && fullCalls === 1, 'opening the panel fetches one current snapshot');
check(panel.panelWidth <= panel.viewport - 32, `history panel fits the narrow viewport (${panel.panelWidth}/${panel.viewport})`);
check(
    panel.messages[0] === 'Map “<img src=x onerror=alert(1)>” deleted.'
    && panel.nestedImages === 0,
    'server-authored messages render literally through textContent'
);
check(
    JSON.stringify(panel.eventLabels) === '["Map deleted","Application error"]'
    && panel.rowTones[0].includes('neutral')
    && panel.rowTones[1].includes('error'),
    `event keys become readable, visually distinct labels (${JSON.stringify(panel.eventLabels)})`
);
check(
    panel.unseenRows === 2 && panel.badge === '2' && !panel.markDisabled,
    `snapshot refreshes the exact badge and unseen styling (${JSON.stringify(panel)})`
);
check(panel.timestampTitles.every(Boolean), 'relative timestamps retain their absolute local-time title');

await page.click('#notifHistoryOverlay .overlay-close');
await page.waitForTimeout(300);
check(seenBodies.length === 0, 'closing the panel does not mark anything seen');
const secondSnapshot = page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.pathname === '/notif_history' && !url.search;
});
await page.evaluate(() => document.getElementById('notifHistoryBtn').click());
await secondSnapshot;
await page.click('#notifHistoryMarkSeenBtn');
await page.waitForFunction(() => document.getElementById('notifHistoryBadge').textContent === '1');
panel = await page.evaluate(() => ({
    unseenRows:document.querySelectorAll('.notif-history-row.unseen').length,
    markDisabled:document.getElementById('notifHistoryMarkSeenBtn').disabled,
    badge:document.getElementById('notifHistoryBadge').textContent
}));
check(
    JSON.stringify(seenBodies) === '[{"through_id":12}]',
    `Mark all seen posts the rendered high-water only (${JSON.stringify(seenBodies)})`
);
check(
    panel.unseenRows === 0 && panel.markDisabled && panel.badge === '1',
    'a concurrently inserted row keeps the exact badge while only rendered rows become seen'
);

await page.click('.notif-history-row[data-id="12"]');
await page.waitForFunction(() => document.getElementById('notifHistoryBadge').textContent === '2');
panel = await page.evaluate(() => ({
    unseenRows:document.querySelectorAll('.notif-history-row.unseen').length,
    markDisabled:document.getElementById('notifHistoryMarkSeenBtn').disabled,
    badge:document.getElementById('notifHistoryBadge').textContent,
    action:document.querySelector('.notif-history-row[data-id="12"]').getAttribute('aria-label')
}));
check(
    JSON.stringify(rowSeenBodies) === '[{"id":12,"seen":false}]'
    && panel.unseenRows === 1
    && !panel.markDisabled
    && panel.badge === '2'
    && panel.action.endsWith('Mark notification read.'),
    `clicking a seen row marks it unread and updates the exact badge (${JSON.stringify(panel)})`
);
await page.click('.notif-history-row[data-id="12"]');
await page.waitForFunction(() => document.getElementById('notifHistoryBadge').textContent === '1');
panel = await page.evaluate(() => ({
    unseenRows:document.querySelectorAll('.notif-history-row.unseen').length,
    markDisabled:document.getElementById('notifHistoryMarkSeenBtn').disabled,
    badge:document.getElementById('notifHistoryBadge').textContent,
    action:document.querySelector('.notif-history-row[data-id="12"]').getAttribute('aria-label')
}));
check(
    JSON.stringify(rowSeenBodies) === '[{"id":12,"seen":false},{"id":12,"seen":true}]'
    && panel.unseenRows === 0
    && panel.markDisabled
    && panel.badge === '1'
    && panel.action.endsWith('Mark notification unread.'),
    `clicking the row again marks it read without losing the concurrent count (${JSON.stringify(panel)})`
);

console.log('\n== Operation-driven refresh and account cleanup ==');
summaryCalls = 0;
await page.evaluate(() => document.querySelector('#notifHistoryOverlay .overlay-close').click());
await page.evaluate(() => deleteMap(5));
await page.locator('.confirmation-notif .btn-confirm').click();
await page.waitForFunction(() => document.getElementById('notifHistoryBadge').textContent === '8');
check(summaryCalls === 1, 'a committed deletion refreshes the summary once');

summaryCalls = 0;
await page.evaluate(() => apiFetch('/_test/500'));
await page.waitForFunction(() => document.getElementById('notifHistoryBadge').textContent === '7');
check(summaryCalls === 1, 'an authenticated 5xx response refreshes the summary once');

holdFullHistory = true;
const fullCallsBeforeRelogin = fullCalls;
await page.evaluate(() => openNotificationHistory());
while (fullCalls === fullCallsBeforeRelogin) {
    await new Promise(resolve => setTimeout(resolve, 10));
}
await page.evaluate(() => doLogin('bob', 'Abcd1234!'));
holdFullHistory = false;
heldFullResponses.splice(0).forEach(response => {
    sendJSON(response, {notifications:rows, unseen:2, through_id:12});
});
await page.waitForTimeout(50);
const reset = await page.evaluate(() => ({
    username:currentUser.username,
    overlay:document.getElementById('notifHistoryOverlay').style.display,
    badgeHidden:document.getElementById('notifHistoryBadge').hidden,
    badgeText:document.getElementById('notifHistoryBadge').textContent,
    listText:document.getElementById('notifHistoryList').textContent,
    rows:notificationHistoryRows.length,
    through:notificationHistoryThroughId
}));
check(
    reset.username === 'bob'
    && reset.overlay === 'none'
    && reset.badgeHidden
    && reset.badgeText === ''
    && reset.listText === ''
    && reset.rows === 0
    && reset.through === null,
    `re-login rejects a late prior-account snapshot and clears all history state (${JSON.stringify(reset)})`
);

await page.evaluate(() => updateNotificationHistoryBadge(0));
check(
    await page.evaluate(() => document.getElementById('notifHistoryBadge').hidden),
    'the badge is absent at zero'
);
check(
    notificationRequests.every(url => !url.includes('share')),
    `notification URLs preserve the adblocker-safe naming (${JSON.stringify(notificationRequests)})`
);
check(pageErrors.length === 0, `no page errors (${pageErrors.join(' | ') || 'none'})`);

console.log(`\n==== ${PASS} passed, ${FAIL} failed ====`);
await browser.close();
server.close();
process.exit(FAIL ? 1 : 0);
