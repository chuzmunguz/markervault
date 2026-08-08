// Management Groups tab verification (mock backend) — Addendum 3.
// Covers: super-only tab visibility (hidden for regular admins), master list with
// manager meta, detail pane (facts + Managed-by delegation editor + rename/delete),
// members tab with regular-users-only candidates, the create/add/remove/delegate/
// revoke request wiring, and the user-detail Managers section (source-split for supers,
// unassigned marker honoring both controls() sources).
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const MIME = { '.html':'text/html', '.js':'application/javascript', '.css':'text/css', '.png':'image/png', '.ico':'image/x-icon' };

let CALLER = { role: 'super_admin', username: 'alice', first_name: 'Alice', last_name: 'A' };

// bob is controlled ONLY via the Ops group (dan manages it); ted is true nobody-land;
// pat is pending; dan+erin are admins (erin has no manager grant -> Add… candidate).
const USERS = [
    { user_id: 'u-alice', username: 'alice', role: 'super_admin', status: 'approved', created: '2026-07-01T09:00:00', first_name: 'Alice', last_name: 'A', email: 'alice@x.eu', share_groups: [], controllers: [], group_managers: [] },
    { user_id: 'u-bob',   username: 'bob',   role: 'user',  status: 'approved', created: '2026-07-02T09:00:00', first_name: 'Bob',  last_name: 'B', email: 'bob@x.eu', share_groups: [], management_groups: ['Ops'], controllers: [], group_managers: [ { admin_id: 'u-dan', username: 'dan', first_name: 'Dan', last_name: 'D' } ] },
    { user_id: 'u-ted',   username: 'ted',   role: 'user',  status: 'approved', created: '2026-07-03T09:00:00', first_name: 'Ted',  last_name: 'T', email: 'ted@x.eu', share_groups: [], controllers: [], group_managers: [] },
    { user_id: 'u-pat',   username: 'pat',   role: 'user',  status: 'pending',  created: '2026-07-04T09:00:00', first_name: 'Pat',  last_name: 'P', email: 'pat@x.eu', share_groups: [], controllers: [], group_managers: [] },
    { user_id: 'u-dan',   username: 'dan',   role: 'admin', status: 'approved', created: '2026-07-05T09:00:00', first_name: 'Dan',  last_name: 'D', email: 'dan@x.eu', share_groups: [], controllers: [], group_managers: [] },
    { user_id: 'u-erin',  username: 'erin',  role: 'admin', status: 'approved', created: '2026-07-06T09:00:00', first_name: 'Erin', last_name: 'E', email: 'erin@x.eu', share_groups: [], controllers: [], group_managers: [] },
];
let MGROUPS = [
    { id: 1, name: 'Ops', created: '2026-07-10T09:00:00', created_by_username: 'alice', created_by_first: 'Alice', created_by_last: 'A',
      managers: [ { admin_id: 'u-dan', username: 'dan', first_name: 'Dan', last_name: 'D' } ],
      members: [ { user_id: 'u-bob', username: 'bob', first_name: 'Bob', last_name: 'B' } ] },
    { id: 2, name: 'Orphaned', created: '2026-07-10T10:00:00', created_by_username: null, created_by_first: '', created_by_last: '',
      managers: [], members: [] },
];

let createBody = null;
let memberPutBody = null;
let memberDeleted = null;
let managerPutBody = null;
let managerDeleted = null;
let groupDeleted = null;

function sendJSON(res, obj, code=200){ res.writeHead(code, {'Content-Type':'application/json'}); res.end(JSON.stringify(obj)); }
function readBody(req, cb){ let b=''; req.on('data', d=>b+=d); req.on('end', ()=>cb(b?JSON.parse(b):{})); }

const server = http.createServer((req, res) => {
    const p = new URL(req.url, 'http://x').pathname;

    if (p === '/auth/refresh') return sendJSON(res, { access_token:'faketoken', access_expires_in:900, ...CALLER });
    if (p === '/maps' && req.method === 'GET') return sendJSON(res, []);
    if (/^\/maps\/\d+\/spots$/.test(p)) return sendJSON(res, []);
    if (p === '/users') return sendJSON(res, []);
    if (p === '/groups') return sendJSON(res, []);
    if (p === '/admin/users' && req.method === 'GET') return sendJSON(res, USERS);
    if (p === '/admin/groups' && req.method === 'GET') return sendJSON(res, []);
    if (p === '/admin/mgmt-groups' && req.method === 'GET') return sendJSON(res, MGROUPS);
    if (p === '/admin/mgmt-groups' && req.method === 'POST') return readBody(req, b => {
        createBody = b;
        const g9 = {
            id: 9, name: b.name, created: '2026-07-13T13:00:00',
            created_by_username: 'alice', created_by_first: 'Alice', created_by_last: 'A',
            managers: [], members: []
        };
        MGROUPS = MGROUPS.concat([g9]);
        sendJSON(res, g9);
    });
    if (p === '/admin/mgmt-groups/1/members' && req.method === 'PUT') return readBody(req, b => {
        memberPutBody = b;
        MGROUPS[0].members.push({ user_id: 'u-ted', username: 'ted', first_name: 'Ted', last_name: 'T' });
        sendJSON(res, { success: true });
    });
    if (p === '/admin/mgmt-groups/1/members/u-bob' && req.method === 'DELETE') {
        memberDeleted = true;
        MGROUPS[0].members = MGROUPS[0].members.filter(m => m.user_id !== 'u-bob');
        return sendJSON(res, { success: true });
    }
    if (p === '/admin/mgmt-groups/1/managers' && req.method === 'PUT') return readBody(req, b => {
        managerPutBody = b;
        MGROUPS[0].managers.push({
            admin_id: 'u-erin', username: 'erin', first_name: 'Erin', last_name: 'E'
        });
        sendJSON(res, { success: true });
    });
    if (p === '/admin/mgmt-groups/1/managers/u-dan' && req.method === 'DELETE') {
        managerDeleted = true;
        MGROUPS[0].managers = MGROUPS[0].managers.filter(m => m.admin_id !== 'u-dan');
        return sendJSON(res, { success: true });
    }
    if (p === '/admin/mgmt-groups/2' && req.method === 'DELETE') {
        groupDeleted = true;
        MGROUPS = MGROUPS.filter(g => g.id !== 2);
        return sendJSON(res, { success: true });
    }

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
page.on('pageerror', e => pageErrors.push(String(e)));

let PASS = 0, FAIL = 0;
function check(cond, label) {
    if (cond) { PASS++; console.log(`  PASS  ${label}`); }
    else { FAIL++; console.log(`  FAIL  ${label}`); }
}

await page.goto(base, { waitUntil: 'networkidle' }).catch(e => pageErrors.push('goto: '+e));
await page.waitForTimeout(1500);

console.log('== A. Super view: Management Groups tab visible, opens its panel ==');
await page.evaluate(() => document.getElementById('openAdminPanelBtn').click());
await page.waitForTimeout(800);
const tabState = await page.evaluate(() => ({
    mgmtVisible: document.getElementById('adminMgmtTabBtn').style.display !== 'none',
    labels: Array.from(document.querySelectorAll('.admin-tab')).map(t => t.textContent)
}));
check(tabState.mgmtVisible, 'Management Groups tab shown for a super-admin');
check(tabState.labels.includes('Share Groups') && tabState.labels.includes('Management Groups'),
      `both group tabs labeled (got ${JSON.stringify(tabState.labels)})`);

await page.evaluate(() => document.querySelector('.admin-tab[data-admintab="mgroups"]').click());
await page.waitForTimeout(700);
const listState = await page.evaluate(() => ({
    usersHidden: document.getElementById('adminUsersPanel').style.display === 'none',
    shareHidden: document.getElementById('adminGroupsPanel').style.display === 'none',
    rows: Array.from(document.querySelectorAll('#adminMgroupList .admin-user-name')).map(n => n.textContent),
    meta: (document.querySelector('#adminMgroupList .admin-user-meta') || {}).textContent
}));
check(listState.usersHidden && listState.shareHidden, 'users and share-groups panels hidden on the mgroups tab');
check(JSON.stringify(listState.rows) === '["Ops","Orphaned"]', `group list shows Ops+Orphaned (got ${JSON.stringify(listState.rows)})`);
check(listState.meta === '1 member · Dan D', `meta carries member count + manager real names (got "${listState.meta}")`);

console.log('\n== B. Detail pane: facts, Managed-by editor, rename+delete actions ==');
await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminMgroupList .admin-user-row'));
    rows.find(r => r.querySelector('.admin-user-name').textContent === 'Ops').click();
});
await page.waitForTimeout(500);
const opsDetail = await page.evaluate(() => {
    const d = document.getElementById('adminMgroupDetail');
    return {
        facts: Array.from(d.querySelectorAll('.admin-facts > div')).map(x => x.textContent),
        tips: Array.from(d.querySelectorAll('.icon-btn')).map(b => b.dataset.tip),
        managerChips: Array.from(d.querySelectorAll('.admin-delegation-chip')).map(c => c.textContent.replace('×','')),
        addOptions: Array.from(d.querySelectorAll('.admin-controller-select option')).map(o => o.textContent),
        managedByLabel: Array.from(d.querySelectorAll('.admin-fact-label')).some(l => l.textContent === 'Managed by')
    };
});
check(opsDetail.facts.includes('Created ByAlice A')
      && opsDetail.facts.includes('Creation Date7/10/2026'),
      `creation facts use separate creator/date rows (got ${JSON.stringify(opsDetail.facts)})`);
check(JSON.stringify(opsDetail.tips) === '["Rename group","Delete group"]', `rename+delete always offered (got ${JSON.stringify(opsDetail.tips)})`);
check(opsDetail.managedByLabel, 'delegation row is labeled Managed by');
check(JSON.stringify(opsDetail.managerChips) === '["Dan D"]', `manager chips show the real name (got ${JSON.stringify(opsDetail.managerChips)})`);
check(JSON.stringify(opsDetail.addOptions) === '["Add…","Erin E"]', `Add picker offers the remaining admin by real name (got ${JSON.stringify(opsDetail.addOptions)})`);

console.log('\n== C. Members tab: regular non-pending users only, all removable ==');
await page.evaluate(() => {
    const tabs = Array.from(document.querySelectorAll('#adminMgroupDetail .admin-detail-tab'));
    tabs.find(t => t.textContent === 'Members').click();
});
await page.waitForTimeout(400);
const memberLists = await page.evaluate(() => {
    const d = document.getElementById('adminMgroupDetail');
    const addList = d.querySelector('.admin-group-add-list');
    const memList = d.querySelector('.admin-group-members-list');
    return {
        candidates: Array.from(addList.querySelectorAll('.action-list-name')).map(n => n.textContent),
        members: Array.from(memList.querySelectorAll('.action-list-name')).map(n => n.textContent),
        removeBtns: memList.querySelectorAll('.action-list-btn').length
    };
});
check(JSON.stringify(memberLists.candidates) === '["Ted T"]',
      `candidates exclude admins, supers, pending and current members (got ${JSON.stringify(memberLists.candidates)})`);
check(JSON.stringify(memberLists.members) === '["Bob B"]', `member listed without a parenthesized username (got ${JSON.stringify(memberLists.members)})`);
check(memberLists.removeBtns === 1, 'every member row has a × (super view, no scope gating)');

console.log('\n== D. Request wiring: add/remove member, delegate/revoke manager, create ==');
await page.evaluate(() => {
    document.querySelector('#adminMgroupDetail .admin-group-add-list .action-list-btn').click();
});
await page.waitForTimeout(500);
check(memberPutBody && memberPutBody.username === 'ted', `member add PUT carries the username (got ${JSON.stringify(memberPutBody)})`);
await page.evaluate(() => {
    const memList = document.querySelector('#adminMgroupDetail .admin-group-members-list');
    const rows = Array.from(memList.querySelectorAll('.action-list-row'));
    rows.find(r => r.querySelector('.action-list-name').textContent === 'Bob B').querySelector('.action-list-btn').click();
});
await page.waitForTimeout(500);
check(memberDeleted === true, 'member × sends the DELETE');
await page.evaluate(() => {
    const tabs = Array.from(document.querySelectorAll('#adminMgroupDetail .admin-detail-tab'));
    tabs.find(t => t.textContent === 'Details').click();
});
await page.evaluate(() => {
    const sel = document.querySelector('#adminMgroupDetail .admin-controller-select');
    sel.value = 'u-erin';
    sel.dispatchEvent(new Event('change'));
});
await page.waitForTimeout(500);
check(managerPutBody && managerPutBody.admin_id === 'u-erin', `manager delegation PUT carries admin_id (got ${JSON.stringify(managerPutBody)})`);
await page.evaluate(() => {
    const chips = Array.from(document.querySelectorAll('#adminMgroupDetail .admin-delegation-chip'));
    chips.find(c => c.textContent.includes('Dan D')).querySelector('.admin-delegation-remove').click();
});
await page.waitForTimeout(500);
check(managerDeleted === true, 'manager chip × sends the targeted DELETE');
await page.evaluate(() => {
    document.getElementById('newMgroupName').value = 'Fresh';
    document.getElementById('adminCreateMgroupBtn').click();
});
await page.waitForTimeout(500);
check(createBody && createBody.name === 'Fresh', `create POST carries the name (got ${JSON.stringify(createBody)})`);
const afterCreate = await page.evaluate(() =>
    Array.from(document.querySelectorAll('#adminMgroupList .admin-user-name')).map(n => n.textContent));
check(afterCreate.includes('Fresh'), `new group appears in the list (got ${JSON.stringify(afterCreate)})`);

console.log('\n== E. Delete flows through the confirmation ==');
await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminMgroupList .admin-user-row'));
    rows.find(r => r.querySelector('.admin-user-name').textContent === 'Orphaned').click();
});
await page.waitForTimeout(400);
const orphanFacts = await page.evaluate(() =>
    Array.from(document.querySelectorAll('#adminMgroupDetail .admin-facts > div')).map(x => x.textContent));
check(orphanFacts.includes('Created ByAccount Deleted'),
      `null creator renders as Account Deleted (got ${JSON.stringify(orphanFacts)})`);
await page.evaluate(() => {
    Array.from(document.querySelectorAll('#adminMgroupDetail .icon-btn'))
        .find(b => b.dataset.tip === 'Delete group').click();
});
await page.waitForTimeout(400);
await page.evaluate(() => {
    const overlay = Array.from(document.querySelectorAll('button')).find(b =>
        b.offsetParent !== null && /^(yes|confirm|delete|ok)$/i.test(b.textContent.trim()));
    if (overlay) overlay.click();
});
await page.waitForTimeout(500);
check(groupDeleted === true, 'confirmed delete sends the DELETE');

console.log('\n== F. User detail: source split + unassigned marker uses BOTH sources ==');
await page.evaluate(() => selectAdminTab('active'));
await page.waitForTimeout(600);
const bobRow = await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminUserList .admin-user-row'));
    const row = rows.find(r => r.querySelector('.admin-user-name').textContent === 'Bob B');
    row.click();
    return row.querySelector('.admin-user-meta').textContent;
});
await page.waitForTimeout(500);
check(bobRow === 'User', `group-managed bob is NOT flagged Unassigned (got "${bobRow}")`);
const bobDetail = await page.evaluate(() => {
    const d = document.getElementById('adminUserDetail');
    const rows = {};
    d.querySelectorAll('.admin-managers-section .admin-manager-rows > div').forEach(x => {
        const l = x.querySelector('.admin-fact-label');
        if (l) rows[l.textContent] = x.textContent.slice(l.textContent.length);
    });
    return {
        rows,
        chips: Array.from(d.querySelectorAll('.admin-managers-section .admin-delegation-chip')).map(c => c.textContent.replace('×','')),
        emptyLabel: (d.querySelector('.admin-managers-section .admin-delegation-empty') || {}).textContent,
        nestedCard: !!d.querySelector('.admin-managers-section.admin-maps-card'),
        managementGroup: Array.from(d.querySelectorAll('.admin-detail-panel > .admin-facts > div'))
            .find(x => x.querySelector('.admin-fact-label').textContent === 'Management groups')?.querySelector('span:last-child').textContent
    };
});
check(bobDetail.rows['Group Assignment'] === 'Dan D' && 'Direct Assignment' in bobDetail.rows,
      `Managers section separates group assignment by real name (got ${JSON.stringify(bobDetail.rows)})`);
check(bobDetail.chips.length === 0 && bobDetail.emptyLabel === 'No direct assignment',
      `direct chips stay empty with the no-direct label (got chips=${JSON.stringify(bobDetail.chips)}, empty="${bobDetail.emptyLabel}")`);
check(!bobDetail.nestedCard && bobDetail.managementGroup === 'Ops',
      `Managers uses a separator and user details name the management group (got ${JSON.stringify(bobDetail)})`);
const tedState = await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminUserList .admin-user-row'));
    const row = rows.find(r => r.querySelector('.admin-user-name').textContent === 'Ted T');
    row.click();
    return row.querySelector('.admin-user-meta').textContent;
});
await page.waitForTimeout(400);
check(tedState === 'User · Unassigned', `true nobody-land ted IS flagged (got "${tedState}")`);
const tedDetail = await page.evaluate(() => {
    const d = document.getElementById('adminUserDetail');
    return {
        groupRow: Array.from(d.querySelectorAll('.admin-managers-section .admin-fact-label'))
            .some(l => l.textContent === 'Group Assignment'),
        emptyLabel: (d.querySelector('.admin-managers-section .admin-delegation-empty') || {}).textContent
    };
});
check(!tedDetail.groupRow && tedDetail.emptyLabel === 'Nobody (unassigned)',
      `no Group Assignment row and the unassigned label for ted (got group=${tedDetail.groupRow}, empty="${tedDetail.emptyLabel}")`);

console.log('\n== G. Regular admin: no Management Groups tab of any kind ==');
CALLER = { role: 'admin', username: 'dan', first_name: 'Dan', last_name: 'D' };
await page.goto(base, { waitUntil: 'networkidle' }).catch(e => pageErrors.push('goto2: '+e));
await page.waitForTimeout(1500);
await page.evaluate(() => document.getElementById('openAdminPanelBtn').click());
await page.waitForTimeout(700);
const adminView = await page.evaluate(() => ({
    mgmtHidden: document.getElementById('adminMgmtTabBtn').style.display === 'none',
    shareLabel: document.querySelector('.admin-tab[data-admintab="groups"]').textContent
}));
check(adminView.mgmtHidden, 'Management Groups tab hidden for a regular admin');
check(adminView.shareLabel === 'Share Groups', `admin still sees the renamed Share Groups tab (got "${adminView.shareLabel}")`);

console.log('\n== H. No uncaught page errors ==');
check(pageErrors.length === 0, pageErrors.length ? `page errors: ${pageErrors.join(' | ')}` : 'no page errors');

console.log(`\n==== ${PASS} passed, ${FAIL} failed ====`);
await browser.close();
server.close();
process.exit(FAIL ? 1 : 0);
