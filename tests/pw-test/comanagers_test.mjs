// Regular-admin view (mock backend): co-managed user/group details name the OTHER
// controllers/owners without exposing editable delegation controls, and the Maps tab
// renders bare metadata from the relationship-key-omitting Addendum-4 wire contract.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const MIME = { '.html':'text/html', '.js':'application/javascript', '.css':'text/css', '.png':'image/png', '.ico':'image/x-icon' };

const MAPS = [
    { id: 4, name: 'Base Map', created: '2026-07-11T09:00:00', description: '', notes: '', markers: 0, is_base: true, owned: true, role: 'owner', owner_username: 'dan', owner_name: 'Dan D' },
];
const BOB_MAPS = [
    { id: 11, name: 'Base Map', created: '2026-07-02T09:10:00', is_base: true, markers: 0, photos: 0 },
    { id: 12, name: 'Fishing', created: '2026-07-05T09:00:00', is_base: false, markers: 7, photos: 3 },
];
// dan (the caller, a REGULAR admin) sees exactly the users he controls: bob is
// co-managed with erin, ted is dan's alone.
const USERS = [
    { user_id: 'u-bob', username: 'bob', role: 'user', status: 'approved', created: '2026-07-02T09:00:00', first_name: 'Bob', last_name: 'B', email: 'bob@x.eu', share_groups: [],
      managers: [
          { username: 'dan', first_name: 'Dan', last_name: 'D' },
          { username: 'erin', first_name: 'Erin', last_name: 'E' }
      ] },
    { user_id: 'u-ted', username: 'ted', role: 'user', status: 'approved', created: '2026-07-03T09:00:00', first_name: 'Ted', last_name: 'T', email: 'ted@x.eu',
      company: 'ACME', department: 'Ops', birth_date: '1985-02-03', sex: 'male', share_groups: [],
      managers: [ { username: 'dan', first_name: 'Dan', last_name: 'D' } ] },
];
const GROUPS = [
    { id: 1, name: 'TeamX', created: '2026-07-10T09:00:00', deletable: true, members: [],
      created_by_username: 'dan', created_by_first: 'Dan', created_by_last: 'D',
      owners: [
          { admin_id: 'u-dan', username: 'dan', first_name: 'Dan', last_name: 'D' },
          { admin_id: 'u-erin', username: 'erin', first_name: 'Erin', last_name: 'E' }
      ] },
    { id: 2, name: 'SoloG', created: '2026-07-10T10:00:00', deletable: true, members: [],
      created_by_username: 'dan', created_by_first: 'Dan', created_by_last: 'D',
      owners: [ { admin_id: 'u-dan', username: 'dan', first_name: 'Dan', last_name: 'D' } ] },
];
let adminShareRequests = 0;

function sendJSON(res, obj, code=200){ res.writeHead(code, {'Content-Type':'application/json'}); res.end(JSON.stringify(obj)); }

const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const p = u.pathname;

    if (p === '/auth/refresh') return sendJSON(res, { access_token:'faketoken', access_expires_in:900, role:'admin', username:'dan', first_name:'Dan', last_name:'D' });
    if (p === '/maps' && req.method === 'GET') return sendJSON(res, MAPS);
    if (/^\/maps\/\d+\/spots$/.test(p)) return sendJSON(res, []);
    if (p === '/users') return sendJSON(res, []);
    if (p === '/groups') return sendJSON(res, GROUPS.map(g => ({ id: g.id, name: g.name })));
    if (p === '/admin/users' && req.method === 'GET') return sendJSON(res, USERS);
    if (p === '/admin/users/u-bob/maps') return sendJSON(res, { owned: BOB_MAPS, sharing_visible: false });
    if (/^\/admin\/users\/[^/]+\/maps$/.test(p)) return sendJSON(res, { owned: [], sharing_visible: false });
    if (/^\/admin\/maps\/\d+\/collaborators/.test(p)) {
        adminShareRequests++;
        return sendJSON(res, { error: 'Forbidden' }, 403);
    }
    if (p === '/admin/groups' && req.method === 'GET') return sendJSON(res, GROUPS);

    let fp = p === '/' ? '/index.html' : p;
    const full = path.join(ROOT, fp);
    if (fs.existsSync(full) && fs.statSync(full).isFile()) {
        res.writeHead(200, {'Content-Type': MIME[path.extname(full)] || 'text/plain'});
        return res.end(fs.readFileSync(full));
    }
    res.writeHead(200, {'Content-Type':'application/javascript'}); res.end('');
});

await new Promise(r => server.listen(0, r));
const base = `http://127.0.0.1:${server.address().port}`;

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
const pageErrors = [];
const consoleErrors = [];
page.on('pageerror', e => pageErrors.push(String(e)));
page.on('console', msg => {
    // Chromium reports blocked optional external assets as "Failed to load resource"
    // in this network-isolated rig. Keep application console.error output load-bearing.
    if (msg.type() === 'error' && !msg.text().startsWith('Failed to load resource:')) {
        consoleErrors.push(msg.text());
    }
});

let PASS = 0, FAIL = 0;
function check(cond, label) {
    if (cond) { PASS++; console.log(`  PASS  ${label}`); }
    else { FAIL++; console.log(`  FAIL  ${label}`); }
}

await page.goto(base, { waitUntil: 'networkidle' }).catch(e => pageErrors.push('goto: '+e));
await page.waitForTimeout(1500);

console.log('== A. Co-managed user: Co-managers is the last normal detail fact ==');
await page.evaluate(() => document.getElementById('openAdminPanelBtn').click());
await page.waitForTimeout(800);
await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminUserList .admin-user-row'));
    rows.find(r => r.querySelector('.admin-user-name').textContent === 'Bob B').click();
});
await page.waitForTimeout(600);
const bobFacts = await page.evaluate(() => {
    const rows = {};
    const factRows = Array.from(document.querySelectorAll('#adminUserDetail .admin-detail-panel > .admin-facts > div'));
    factRows.forEach(d => {
        rows[d.querySelector('.admin-fact-label').textContent] = d.querySelector('span:last-child').textContent;
    });
    const header = document.querySelector('#adminUserDetail .admin-detail-title');
    return {
        rows,
        labels: factRows.map(d => d.querySelector('.admin-fact-label').textContent),
        managersSection: !!document.querySelector('#adminUserDetail .admin-managers-section'),
        hasEditor: !!document.querySelector('#adminUserDetail .admin-delegation-box'),
        headerName: (header.querySelector('.admin-detail-name') || {}).textContent,
        headerUsername: (header.querySelector('.admin-detail-realname') || {}).textContent
    };
});
check(bobFacts.headerName === 'Bob B' && bobFacts.headerUsername === 'bob',
      `detail header shows real name over username (got "${bobFacts.headerName}" / "${bobFacts.headerUsername}")`);
check(!bobFacts.managersSection && bobFacts.rows['Co-managers'] === 'Erin E'
      && bobFacts.labels.at(-1) === 'Co-managers',
      `Co-managers names the OTHER admin by real name (got ${JSON.stringify(bobFacts.rows)})`);
check(!bobFacts.hasEditor, 'no editable delegation chips for a regular admin');
check(!bobFacts.labels.includes('Direct Assignment') && !bobFacts.labels.includes('Group Assignment'),
      'regular-admin details expose no direct/group source labels');
check(USERS.every(u => !('controllers' in u) && !('group_managers' in u) && !('management_groups' in u))
      && !bobFacts.labels.includes('Management groups'),
      'regular-admin UI shows no management-group information (super-admin detail only)');

console.log('\n== A2. Regular-admin Maps tab is bare metadata only ==');
await page.evaluate(() => {
    Array.from(document.querySelectorAll('#adminUserDetail .admin-detail-tab'))
        .find(t => t.textContent === 'Maps').click();
});
await page.waitForTimeout(600);
const bobMaps = await page.evaluate(() => {
    const d = document.getElementById('adminUserDetail');
    return {
        maps: Array.from(d.querySelectorAll('.admin-map-name')).map(n => n.textContent),
        cards: d.querySelectorAll('.admin-maps-section .admin-maps-card').length,
        subheads: Array.from(d.querySelectorAll('.admin-maps-section .admin-maps-card-title')).map(n => n.textContent),
        meta: Array.from(d.querySelectorAll('.admin-map-meta')).map(n => n.textContent),
        shareButtons: d.querySelectorAll('.admin-map-head .icon-btn').length,
        chips: d.querySelectorAll('.collab-chip').length,
        collabRows: d.querySelectorAll('.admin-map-collabs').length
    };
});
check(JSON.stringify(bobMaps.maps) === '["Base Map","Fishing"]',
      `regular admin sees owned map names only (got ${JSON.stringify(bobMaps.maps)})`);
check(bobMaps.cards === 1 && JSON.stringify(bobMaps.subheads) === '["Owned"]',
      `no Shared-with card is created (got ${bobMaps.cards} / ${JSON.stringify(bobMaps.subheads)})`);
check(bobMaps.shareButtons === 0 && bobMaps.chips === 0 && bobMaps.collabRows === 0,
      `no share buttons or collaborator rows (got ${JSON.stringify(bobMaps)})`);
check(bobMaps.meta.some(m => m.includes('7 markers') && m.includes('3 photos')),
      `bare metadata retains marker/photo counts (got ${JSON.stringify(bobMaps.meta)})`);

await page.evaluate(() => openAdminShareOverlay(12, 'Fishing', 'bob'));
await page.waitForTimeout(200);
const guardedOverlay = await page.evaluate(() =>
    document.getElementById('collabOverlay').classList.contains('active'));
check(!guardedOverlay && adminShareRequests === 0,
      `direct non-super overlay call is inert (active=${guardedOverlay}, requests=${adminShareRequests})`);

console.log('\n== B. Sole-managed user: no Co-managers row ==');
await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminUserList .admin-user-row'));
    rows.find(r => r.querySelector('.admin-user-name').textContent === 'Ted T').click();
});
await page.waitForTimeout(600);
const tedManagers = await page.evaluate(() => ({
    section: !!document.querySelector('#adminUserDetail .admin-managers-section'),
    labels: Array.from(document.querySelectorAll('#adminUserDetail .admin-facts .admin-fact-label')).map(l => l.textContent)
}));
check(!tedManagers.section && !tedManagers.labels.includes('Co-managers'),
      `sole controller -> no Managers section (got ${JSON.stringify(tedManagers)})`);

console.log('\n== B2. Edit pencil + full profile facts (regular admin on a controlled user) ==');
const tedDetail = await page.evaluate(() => ({
    tips: Array.from(document.querySelectorAll('#adminUserDetail .admin-user-actions .icon-btn')).map(b => b.dataset.tip),
    labels: Array.from(document.querySelectorAll('#adminUserDetail .admin-facts .admin-fact-label')).map(l => l.textContent)
}));
check(JSON.stringify(tedDetail.tips) === '["Edit profile","Disable","Reset password"]',
      `admin sees edit/disable/resetpwd on a controlled user (got ${JSON.stringify(tedDetail.tips)})`);
check(['Company', 'Department', 'Birth date', 'Sex'].every(l => tedDetail.labels.includes(l)),
      `new profile facts render when populated (got ${JSON.stringify(tedDetail.labels)})`);

console.log('\n== C. Co-owned group: Co-managers row; sole-owned group: none ==');
await page.evaluate(() => document.querySelector('.admin-tab[data-admintab="groups"]').click());
await page.waitForTimeout(600);
await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminGroupList .admin-user-row'));
    rows.find(r => r.querySelector('.admin-user-name').textContent === 'TeamX').click();
});
await page.waitForTimeout(400);
const teamRow = await page.evaluate(() => {
    const d = document.getElementById('adminGroupDetail');
    const row = d.querySelector('.admin-group-owner-row');
    return {
        label: row ? row.querySelector('.admin-fact-label').textContent : null,
        value: row ? row.querySelector('span:last-child').textContent : null,
        hasEditor: !!d.querySelector('.admin-delegation-box'),
        listMeta: (document.querySelector('#adminGroupList .admin-user-row .admin-user-meta') || {}).textContent
    };
});
check(teamRow.label === 'Co-managers' && teamRow.value === 'Erin E',
      `co-owned group shows Co-managers by real name (got "${teamRow.label}: ${teamRow.value}")`);
check(!teamRow.hasEditor, 'no editable owner chips for a regular admin');
check(teamRow.listMeta === '0 members', `no owner suffix in the list meta for non-supers (got "${teamRow.listMeta}")`);
await page.screenshot({ path: '../ui_comanagers.png' });
await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminGroupList .admin-user-row'));
    rows.find(r => r.querySelector('.admin-user-name').textContent === 'SoloG').click();
});
await page.waitForTimeout(400);
const soloHasRow = await page.evaluate(() => !!document.querySelector('#adminGroupDetail .admin-group-owner-row'));
check(!soloHasRow, 'sole-owned group -> no Co-managers row');

console.log('\n== C-bis. personName partial-name fallback (admin-ui-names-batch shared helper) ==');
// The names-batch spec defines personName(first, last, username) as the single helper
// behind every "show a name" site. The full-name and both-blank->username cases are
// exercised by the rendered chips above and elsewhere; pin the PARTIAL cases (only one
// of first/last set) directly against the in-page helper — no mock covers a half-name.
const personNameCases = await page.evaluate(() => ({
    both: personName('Ada', 'Lovelace', 'ada'),
    firstOnly: personName('Ada', '', 'ada'),
    lastOnly: personName('', 'Lovelace', 'ada'),
    firstOnlyNullLast: personName('Ada', null, 'ada'),
    bothBlank: personName('', '', 'ada'),
    allEmpty: personName('', '', ''),
}));
check(personNameCases.both === 'Ada Lovelace', `both parts -> full name (got "${personNameCases.both}")`);
check(personNameCases.firstOnly === 'Ada', `first-only -> the first name, not the username (got "${personNameCases.firstOnly}")`);
check(personNameCases.lastOnly === 'Lovelace', `last-only -> the last name, not the username (got "${personNameCases.lastOnly}")`);
check(personNameCases.firstOnlyNullLast === 'Ada', `first set / last null -> first name (got "${personNameCases.firstOnlyNullLast}")`);
check(personNameCases.bothBlank === 'ada', `both parts blank -> username fallback (got "${personNameCases.bothBlank}")`);
check(personNameCases.allEmpty === '', `nothing set -> empty string, never undefined (got "${personNameCases.allEmpty}")`);

console.log('\n== D. No uncaught page errors ==');
check(pageErrors.length === 0, `no page errors${pageErrors.length ? ' (got ' + pageErrors.join('; ') + ')' : ''}`);
check(consoleErrors.length === 0, `no console errors from absent relationship keys${consoleErrors.length ? ' (got ' + consoleErrors.join('; ') + ')' : ''}`);

console.log(`\n==== ${PASS} passed, ${FAIL} failed ====`);
await browser.close();
server.close();
process.exit(FAIL ? 1 : 0);
