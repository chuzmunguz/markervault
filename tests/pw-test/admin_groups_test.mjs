// Admin-screen revamp + groups UI verification (mock backend).
// Covers: full-page admin screen with Users/Groups tabs, master-detail user pane with
// action buttons + maps metadata (+ 403 note), groups tab CRUD/membership UI, share
// overlay with user/group picker + group rows, sidebar dropdown-above-search order and
// the prefix-less owner line.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const MIME = { '.html':'text/html', '.js':'application/javascript', '.css':'text/css', '.png':'image/png', '.ico':'image/x-icon' };

const MAPS = [
    { id: 4, name: 'Base Map', created: '2026-07-11T09:00:00', description: '', notes: '', markers: 0, is_base: true,  owned: true,  role: 'owner',  owner_username: 'alice', owner_name: 'Alice A' },
    { id: 5, name: 'My Map',   created: '2026-07-11T10:00:00', description: '', notes: '', markers: 0, is_base: false, owned: true,  role: 'owner',  owner_username: 'alice', owner_name: 'Alice A' },
    { id: 7, name: 'ViewMap',  created: '2026-07-11T12:00:00', description: '', notes: '', markers: 0, is_base: false, owned: false, role: 'viewer', owner_username: 'zed', owner_name: 'Zed Z' },
];
// bob starts UNASSIGNED (nobody-land) so the delegation flow can assign him to dan.
const USERS = [
    { user_id: 'u-alice', username: 'alice', role: 'super_admin', status: 'approved', created: '2026-07-01T09:00:00', first_name: 'Alice', last_name: 'A', email: 'alice@x.eu', share_groups: [], management_groups: [], avatar_url: null, controllers: [], group_managers: [] },
    { user_id: 'u-bob',   username: 'bob',   role: 'user',  status: 'approved', created: '2026-07-02T09:00:00', first_name: 'Bob',   last_name: 'B', email: 'bob@x.eu',
      company: 'ACME', department: 'Ops', birth_date: '1990-05-01', sex: 'male', share_groups: ['Team'], management_groups: ['Ops'],
      avatar_url: 'assets/images/default-user-thumb.png?avatar=bob', controllers: [], group_managers: [] },
    { user_id: 'u-carol', username: 'carol', role: 'user',  status: 'pending',  created: '2026-07-03T09:00:00', first_name: '',      last_name: '',  email: 'carol@x.eu', share_groups: [], management_groups: [], avatar_url: 'assets/images/default-user-thumb.png?should-not-render=1', controllers: [], group_managers: [] },
    { user_id: 'u-dan',   username: 'dan',   role: 'admin', status: 'approved', created: '2026-07-04T09:00:00', first_name: 'Dan',   last_name: 'D', email: 'dan@x.eu', share_groups: [], management_groups: [], avatar_url: null, controllers: [], group_managers: [] },
];
const BOB_MAPS = [
    { id: 11, name: 'Base Map', created: '2026-07-02T09:10:00', is_base: true, markers: 0, photos: 0, collaborators: [] },
    { id: 12, name: 'Fishing', created: '2026-07-05T09:00:00', is_base: false, markers: 7, photos: 3,
      collaborators: [ { type: 'user', name: 'alice', role: 'editor' }, { type: 'group', name: 'Team', role: 'viewer' } ] },
];
// Maps shared WITH bob: one direct grant + one via his Team membership, same map.
const BOB_SHARED = [
    { id: 21, name: 'Harbours', owner: 'zed', owner_first: 'Zed', owner_last: 'Z',
      paths: [ { type: 'direct', role: 'editor' }, { type: 'group', group: 'Team', role: 'viewer' } ] },
];
let FISHING_SHARES = [
    { type: 'user', user_id: 'u-alice2', username: 'alice2', first_name: '', last_name: '', role: 'editor' },
    { type: 'group', group_id: 1, name: 'Team', role: 'viewer' },
];
// Team: owned by dan, deletable (caller is super). Frozen: superadmin-owned with an
// out-of-scope member — exercises the deletable=false and managed=false UI gating.
let GROUPS = [
    { id: 1, name: 'Team', created: '2026-07-10T09:00:00', created_by_username: 'dan', created_by_first: 'Dan', created_by_last: 'D',
      owners: [ { admin_id: 'u-dan', username: 'dan', first_name: 'Dan', last_name: 'D' } ], deletable: true,
      members: [ { user_id: 'u-bob', username: 'bob', first_name: 'Bob', last_name: 'B', avatar_url: 'assets/images/default-user-thumb.png?avatar=bob', managed: true } ] },
    { id: 2, name: 'Frozen', created: '2026-07-10T10:00:00', created_by_username: null, created_by_first: '', created_by_last: '', owners: [], deletable: false,
      members: [ { user_id: 'u-zed', username: 'zed', first_name: 'Zed', last_name: 'Z', managed: false } ] },
];
// Mutable: the remove flows below drain it so the sidebar green-state sync can be
// verified down to zero collaborators.
let SHARES5 = [
    { type: 'user', user_id: 'u-bob', username: 'bob', first_name: 'Bob', last_name: 'B', avatar_url: 'assets/images/default-user-thumb.png?avatar=bob', role: 'viewer' },
    { type: 'group', group_id: 1, name: 'Team', role: 'editor' },
];

let createGroupBody = null;
let addMemberBody = null;
let sharePutBody = null;
let groupShareDeleted = null;
let adminSharePutBody = null;
let adminGroupShareDeleted = null;
// Delegation captures (mutable mocks so reloads reflect the change)
let controllerPutBody = null;
let controllerDeleted = null;
let ownerDeleted = null;
let profilePutBody = null;

function sendJSON(res, obj, code=200){ res.writeHead(code, {'Content-Type':'application/json'}); res.end(JSON.stringify(obj)); }
function readBody(req, cb){ let b=''; req.on('data', d=>b+=d); req.on('end', ()=>cb(b?JSON.parse(b):{})); }

const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const p = u.pathname;

    if (p === '/auth/refresh') return sendJSON(res, { access_token:'faketoken', access_expires_in:900, role:'super_admin', username:'alice', first_name:'Alice', last_name:'A' });
    if (p === '/maps' && req.method === 'GET') return sendJSON(res, MAPS);
    if (/^\/maps\/\d+\/spots$/.test(p)) return sendJSON(res, []);
    if (p === '/maps/5/collaborators' && req.method === 'GET') return sendJSON(res, SHARES5);
    if (p === '/maps/5/collaborators' && req.method === 'PUT') return readBody(req, b => { sharePutBody = b; sendJSON(res, { success:true, ...b }); });
    if (p === '/maps/5/collaborators/group/1' && req.method === 'DELETE') { groupShareDeleted = true; SHARES5 = SHARES5.filter(s => s.type !== 'group'); return sendJSON(res, { success:true }); }
    if (p === '/maps/5/collaborators/u-bob' && req.method === 'DELETE') { SHARES5 = SHARES5.filter(s => s.user_id !== 'u-bob'); return sendJSON(res, { success:true }); }
    if (p === '/users') return sendJSON(res, [
        {user_id:'u-bob',username:'bob',first_name:'Bob',last_name:'B',avatar_url:'assets/images/default-user-thumb.png?avatar=bob'},
        {user_id:'u-dave',username:'dave',first_name:'Dave',last_name:'V',avatar_url:null}
    ]);
    if (p === '/groups') return sendJSON(res, GROUPS.map(g => ({ id: g.id, name: g.name })));
    if (p === '/admin/users' && req.method === 'GET') return sendJSON(res, USERS);
    if (p === '/admin/users/u-bob/maps') return sendJSON(res, { owned: BOB_MAPS, shared: BOB_SHARED, sharing_visible: true });
    if (p === '/admin/maps/12/collaborators' && req.method === 'GET') return sendJSON(res, FISHING_SHARES);
    if (p === '/admin/maps/12/collaborators' && req.method === 'PUT') return readBody(req, b => {
        adminSharePutBody = b;
        FISHING_SHARES = FISHING_SHARES.concat([{ type: 'user', user_id: 'u-dave', username: b.username, role: b.role }]);
        BOB_MAPS[1].collaborators = BOB_MAPS[1].collaborators.concat([{ type: 'user', name: b.username, role: b.role }]);
        sendJSON(res, { success: true, ...b });
    });
    if (p === '/admin/maps/12/collaborators/group/1' && req.method === 'DELETE') {
        adminGroupShareDeleted = true;
        FISHING_SHARES = FISHING_SHARES.filter(s => s.type !== 'group');
        return sendJSON(res, { success: true });
    }
    if (p === '/admin/users/u-dan/maps') return sendJSON(res, { error: 'You do not manage this user' }, 403);
    if (p === '/admin/users/u-bob/profile' && req.method === 'PUT') return readBody(req, b => {
        profilePutBody = b;
        Object.assign(USERS.find(x => x.user_id === 'u-bob'), b);
        sendJSON(res, { success: true, user_id: 'u-bob', username: b.username });
    });
    if (p === '/admin/users/u-bob/controllers' && req.method === 'PUT') return readBody(req, b => {
        controllerPutBody = b;
        const bob = USERS.find(x => x.user_id === 'u-bob');
        bob.controllers = bob.controllers.concat([{
            admin_id: b.admin_id, username: 'dan', first_name: 'Dan', last_name: 'D'
        }]);
        sendJSON(res, { success: true, user_id: 'u-bob', admin_id: b.admin_id });
    });
    if (p === '/admin/users/u-bob/controllers/u-dan' && req.method === 'DELETE') {
        controllerDeleted = true;
        const bob = USERS.find(x => x.user_id === 'u-bob');
        bob.controllers = bob.controllers.filter(c => c.admin_id !== 'u-dan');
        return sendJSON(res, { success: true, user_id: 'u-bob', admin_id: 'u-dan' });
    }
    if (p === '/admin/groups/1/owners/u-dan' && req.method === 'DELETE') {
        ownerDeleted = true;
        GROUPS[0].owners = GROUPS[0].owners.filter(o => o.admin_id !== 'u-dan');
        return sendJSON(res, { success: true, group_id: 1, admin_id: 'u-dan' });
    }
    if (p === '/admin/groups' && req.method === 'GET') return sendJSON(res, GROUPS);
    if (p === '/admin/groups' && req.method === 'POST') return readBody(req, b => {
        createGroupBody = b;
        const g9 = {
            id: 9, name: b.name, created: '2026-07-11T13:00:00',
            created_by_username: 'alice', created_by_first: 'Alice', created_by_last: 'A',
            owners: [], deletable: true, members: []
        };
        GROUPS = GROUPS.concat([g9]);
        sendJSON(res, g9);
    });
    if (p === '/admin/groups/1/members' && req.method === 'PUT') return readBody(req, b => {
        addMemberBody = b;
        GROUPS[0].members.push({ user_id: 'u-dan', username: 'dan', first_name: 'Dan', last_name: 'D', managed: true });
        sendJSON(res, { success:true });
    });

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

console.log('== A. Sidebar: dropdown above search, owner line without prefix ==');
const sidebarChecks = await page.evaluate(() => {
    const dd = document.querySelector('.mapsGroupFilter');
    const search = document.getElementById('mapsSearchInputWrapper');
    const ddAboveSearch = !!(dd && search && (dd.compareDocumentPosition(search) & Node.DOCUMENT_POSITION_FOLLOWING));
    setMapGroupFilter('shared', 'Shared with Me');
    const ownerLine = document.querySelector('.map-item[data-id="7"] .map-owner-line');
    return { ddAboveSearch, ownerText: ownerLine ? ownerLine.textContent : null };
});
check(sidebarChecks.ddAboveSearch, 'group dropdown sits above the search field');
check(sidebarChecks.ownerText === 'Zed Z', `owner line is just the name (got "${sidebarChecks.ownerText}")`);
await page.evaluate(() => setMapGroupFilter('mine', 'My Maps'));

console.log('\n== A2. Map details attribution ==');
const mapAttribution = await page.evaluate(() => {
    openMapDetailsOverlay(5);
    const text = document.querySelector('.map-details-date').textContent;
    closeMapDetailsOverlay();
    return text;
});
check(mapAttribution.startsWith('Alice A • ') && !mapAttribution.includes(':'),
      `map details show creator and date without a time (got "${mapAttribution}")`);

console.log('\n== A3. Account menu icons ==');
await page.evaluate(() => document.getElementById('accountToggle').click());
await page.waitForTimeout(400);
const accountMenuIcons = await page.evaluate(() => {
    const buttons = Array.from(document.querySelectorAll('#accountMenu .account-menu-item'));
    const icons = buttons.map(button => button.querySelector('svg'));
    return {
        labels: buttons.map(button => button.querySelector('span').textContent),
        visible: buttons.every(button => button.offsetParent !== null),
        iconCount: icons.filter(Boolean).length,
        uniqueIcons: new Set(icons.map(icon => icon.innerHTML)).size,
        iconSizes: icons.map(icon => {
            const rect = icon.getBoundingClientRect();
            return [Math.round(rect.width), Math.round(rect.height)];
        }),
        iconLefts: icons.map(icon => Math.round(icon.getBoundingClientRect().left)),
        labelLefts: buttons.map(button => Math.round(button.querySelector('span').getBoundingClientRect().left))
    };
});
check(JSON.stringify(accountMenuIcons.labels) === '["Profile","Notifications","Administration","Logout"]'
      && accountMenuIcons.visible,
      `account menu keeps all four labeled entries visible (got ${JSON.stringify(accountMenuIcons.labels)})`);
check(accountMenuIcons.iconCount === 4 && accountMenuIcons.uniqueIcons === 4,
      'Profile, Notifications, Administration, and Logout each use a distinct SVG');
check(accountMenuIcons.iconSizes.every(([width, height]) => width === 20 && height === 20),
      `account-menu artwork uses the normalized 20px size (got ${JSON.stringify(accountMenuIcons.iconSizes)})`);
check(new Set(accountMenuIcons.iconLefts).size === 1 && new Set(accountMenuIcons.labelLefts).size === 1,
      `account-menu icons and labels align in columns (got ${JSON.stringify(accountMenuIcons)})`);
await page.evaluate(() => document.getElementById('accountToggle').click());
await page.waitForTimeout(350);

console.log('\n== B. Admin screen opens full-page with tabs ==');
await page.evaluate(() => document.getElementById('openAdminPanelBtn').click());
await page.waitForTimeout(800);
const screenState = await page.evaluate(() => ({
    active: document.getElementById('adminScreen').classList.contains('active'),
    tabs: Array.from(document.querySelectorAll('.admin-tab')).map(t => t.textContent),
    rows: document.querySelectorAll('#adminUserList .admin-user-row').length,
    avatars: document.querySelectorAll('#adminUserList .admin-user-avatar').length,
    bobAvatar: (Array.from(document.querySelectorAll('#adminUserList .admin-user-row'))
        .find(r => r.querySelector('.admin-user-name').textContent === 'Bob B')
        ?.querySelector('.admin-user-avatar') || {}).src,
    aliceAvatar: (Array.from(document.querySelectorAll('#adminUserList .admin-user-row'))
        .find(r => r.querySelector('.admin-user-name').textContent === 'Alice A')
        ?.querySelector('.admin-user-avatar') || {}).src,
    firstRow: (document.querySelector('#adminUserList .admin-user-row .admin-user-name') || {}).textContent,
    emptyDetail: !!document.querySelector('#adminUserDetail .admin-detail-empty')
}));
check(screenState.active, 'admin screen active');
check(JSON.stringify(screenState.tabs) === '["Active Users","Inactive Users","Pending Approval","Share Groups","Management Groups","Audit"]',
      `status tabs + Share Groups + Management Groups + Audit (got ${JSON.stringify(screenState.tabs)})`);
check(screenState.rows === 3, `Active tab shows the 3 approved users, pending carol hidden (got ${screenState.rows})`);
check(screenState.avatars === 3 && screenState.bobAvatar.includes('avatar=bob'),
      `active list shows every avatar and preserves bob's uploaded image (got ${screenState.avatars} / "${screenState.bobAvatar}")`);
check(screenState.aliceAvatar.endsWith('/assets/images/default-user-thumb.png'),
      `accounts without an avatar use the default image (got "${screenState.aliceAvatar}")`);
check(screenState.emptyDetail, 'detail pane starts with the empty hint');

console.log('\n== B2. Status tabs split by status + master-list filter ==');
const tabViews = await page.evaluate(async () => {
    const names = () => Array.from(document.querySelectorAll('#adminUserList .admin-user-name')).map(n => n.textContent);
    const wait = ms => new Promise(r => setTimeout(r, ms));
    selectAdminTab('pending');
    await wait(500);
    const pendingNames = names();
    const pendingMeta = (document.querySelector('#adminUserList .admin-user-meta') || {}).textContent;
    const pendingAvatars = document.querySelectorAll('#adminUserList .admin-user-avatar').length;
    selectAdminTab('inactive');
    await wait(500);
    const inactiveText = document.getElementById('adminUserList').textContent;
    selectAdminTab('active');
    await wait(500);
    return { pendingNames, pendingMeta, pendingAvatars, inactiveText, activeNames: names() };
});
check(JSON.stringify(tabViews.pendingNames) === '["carol"]', `Pending tab shows carol only (got ${JSON.stringify(tabViews.pendingNames)})`);
check(tabViews.pendingMeta === 'User', `row meta is role only — no status label, no capitalize (got "${tabViews.pendingMeta}")`);
check(tabViews.pendingAvatars === 0, 'pending self-registrations do not render avatars');
check(tabViews.inactiveText === 'No users.', `Inactive tab empty (got "${tabViews.inactiveText}")`);
check(JSON.stringify(tabViews.activeNames) === '["Alice A","Bob B","Dan D"]', `back on Active (got ${JSON.stringify(tabViews.activeNames)})`);

const userFilterCheck = await page.evaluate(() => {
    const inp = document.getElementById('adminUserFilter');
    const names = () => Array.from(document.querySelectorAll('#adminUserList .admin-user-name')).map(n => n.textContent);
    const type = v => { inp.value = v; inp.dispatchEvent(new Event('input')); };
    type('ali');
    const byUsername = names();
    type('dan d');
    const byFullName = names();
    type('zzz');
    const noMatch = document.getElementById('adminUserList').textContent;
    type('');
    return { byUsername, byFullName, noMatch, restored: names() };
});
check(JSON.stringify(userFilterCheck.byUsername) === '["Alice A"]', `filter matches username (got ${JSON.stringify(userFilterCheck.byUsername)})`);
check(JSON.stringify(userFilterCheck.byFullName) === '["Dan D"]', `filter matches full name (got ${JSON.stringify(userFilterCheck.byFullName)})`);
check(userFilterCheck.noMatch === 'No matching users.', `no-match text (got "${userFilterCheck.noMatch}")`);
check(JSON.stringify(userFilterCheck.restored) === '["Alice A","Bob B","Dan D"]', `clearing the filter restores the list (got ${JSON.stringify(userFilterCheck.restored)})`);

console.log('\n== C. Selecting a user: profile, actions, maps metadata ==');
await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminUserList .admin-user-row'));
    rows.find(r => r.querySelector('.admin-user-name').textContent === 'Bob B').click();
});
await page.waitForTimeout(800);
const bobDetail = await page.evaluate(() => {
    const d = document.getElementById('adminUserDetail');
    const tabs = Array.from(d.querySelectorAll('.admin-detail-tab'));
    const panels = Array.from(d.querySelectorAll('.admin-detail-panel'));
    return {
        name: (d.querySelector('.admin-detail-name') || {}).textContent,
        subtitle: (d.querySelector('.admin-detail-realname') || {}).textContent,
        facts: Array.from(d.querySelectorAll('.admin-facts > div span:last-child')).map(s => s.textContent),
        tips: Array.from(d.querySelectorAll('.admin-user-actions .icon-btn')).map(b => b.dataset.tip),
        tabLabels: tabs.map(t => t.textContent),
        activeTab: (tabs.find(t => t.classList.contains('active')) || {}).textContent,
        mapsPanelHidden: panels.length === 2 && panels[1].style.display === 'none',
        mapsLoaded: !!d.querySelector('.admin-maps-list') && d.querySelector('.admin-maps-list').textContent !== '',
        selectedRow: (document.querySelector('#adminUserList .admin-user-row.selected .admin-user-name') || {}).textContent
    };
});
check(bobDetail.name === 'Bob B' && bobDetail.subtitle === 'bob',
      `detail header shows real name over username (got "${bobDetail.name}" / "${bobDetail.subtitle}")`);
check(bobDetail.selectedRow === 'Bob B', 'master row highlighted');
check(bobDetail.facts.includes('bob@x.eu'), `email fact shown (got ${JSON.stringify(bobDetail.facts)})`);
check(bobDetail.facts.includes('Team'), `groups fact shows Team (got ${JSON.stringify(bobDetail.facts)})`);
check(bobDetail.facts.includes('Ops'), `management-group fact shows Ops (got ${JSON.stringify(bobDetail.facts)})`);
check(JSON.stringify(bobDetail.tips) === JSON.stringify(['Edit profile', 'Promote to admin', 'Disable', 'Reset password', 'Delete user']),
      `super sees edit/promote/disable/resetpwd/delete on a user (got ${JSON.stringify(bobDetail.tips)})`);
check(bobDetail.facts.includes('ACME') && bobDetail.facts.includes('Ops') && bobDetail.facts.includes('1990-05-01') && bobDetail.facts.includes('Male'),
      `company/department/birth date/sex facts shown, sex capitalized (got ${JSON.stringify(bobDetail.facts)})`);
check(bobDetail.facts.includes('User') && !bobDetail.facts.includes('Approved'),
      `role fact capitalized, status fact gone — the tab says it (got ${JSON.stringify(bobDetail.facts)})`);
check(JSON.stringify(bobDetail.tabLabels) === '["Details","Maps"]', `inner tabs Details|Maps (got ${JSON.stringify(bobDetail.tabLabels)})`);
check(bobDetail.activeTab === 'Details', `Details is the default tab (got "${bobDetail.activeTab}")`);
check(bobDetail.mapsPanelHidden && !bobDetail.mapsLoaded, 'Maps panel hidden AND not fetched before first activation');

// Activate the Maps tab — content loads on first click only.
await page.evaluate(() => {
    Array.from(document.querySelectorAll('#adminUserDetail .admin-detail-tab'))
        .find(t => t.textContent === 'Maps').click();
});
await page.waitForTimeout(800);
const bobMaps = await page.evaluate(() => {
    const d = document.getElementById('adminUserDetail');
    return {
        maps: Array.from(d.querySelectorAll('.admin-map-name')).map(n => n.textContent),
        cards: d.querySelectorAll('.admin-maps-section .admin-maps-card').length,
        subheads: Array.from(d.querySelectorAll('.admin-maps-section .admin-maps-card-title')).map(s => s.textContent),
        meta: Array.from(d.querySelectorAll('.admin-map-meta')).map(m => m.textContent),
        chips: Array.from(d.querySelectorAll('.collab-chip')).map(c => c.textContent),
        rowLabels: Array.from(d.querySelectorAll('.collab-row-label')).map(l => l.textContent),
        editorChips: d.querySelectorAll('.collab-chip.role-editor').length,
        viewerChips: d.querySelectorAll('.collab-chip.role-viewer').length,
        badges: d.querySelectorAll('.admin-map-badge').length
    };
});
check(JSON.stringify(bobMaps.maps) === '["Base Map","Fishing","Harbours"]',
      `owned maps then shared-with maps, no name badge (got ${JSON.stringify(bobMaps.maps)})`);
check(bobMaps.badges === 0, 'trailing "Shared" badge is gone');
check(bobMaps.cards === 2 && JSON.stringify(bobMaps.subheads) === '["Owned","Shared with this user"]',
      `Owned + Shared-with as two titled cards (got ${bobMaps.cards} cards, ${JSON.stringify(bobMaps.subheads)})`);
check(bobMaps.meta.some(m => m.includes('7 markers') && m.includes('3 photos')), `counts in meta line (got ${JSON.stringify(bobMaps.meta)})`);
check(bobMaps.meta.includes('Owner: Zed Z'), `shared-with row names the owner by real name (got ${JSON.stringify(bobMaps.meta)})`);
check(JSON.stringify(bobMaps.rowLabels) === '["Groups:","Users:","Groups:","Direct:"]',
      `labeled chip rows, groups on top (got ${JSON.stringify(bobMaps.rowLabels)})`);
check(JSON.stringify(bobMaps.chips) === '["Team · viewer","alice · editor","Team · viewer","editor"]',
      `chips grouped per row (got ${JSON.stringify(bobMaps.chips)})`);
check(bobMaps.editorChips === 2 && bobMaps.viewerChips === 2,
      `chips colored by ROLE (got ${bobMaps.editorChips} editor / ${bobMaps.viewerChips} viewer)`);

console.log('\n== C2. Nobody-land marker + Managers separator section (super view) ==');
const bobDelegation = await page.evaluate(() => {
    const row = Array.from(document.querySelectorAll('#adminUserList .admin-user-row'))
        .find(r => r.querySelector('.admin-user-name').textContent === 'Bob B');
    const card = document.querySelector('#adminUserDetail .admin-managers-section');
    const box = card ? card.querySelector('.admin-delegation-box') : null;
    const sel = box ? box.querySelector('.admin-controller-select') : null;
    const label = card ? card.querySelector('.admin-fact-label') : null;
    const labelRect = label ? label.getBoundingClientRect() : null;
    const selectRect = sel ? sel.getBoundingClientRect() : null;
    return {
        meta: row.querySelector('.admin-user-meta').textContent,
        title: card ? card.querySelector('.admin-managers-title').textContent : null,
        nestedCard: !!(card && card.classList.contains('admin-maps-card')),
        labels: card ? Array.from(card.querySelectorAll('.admin-fact-label')).map(l => l.textContent) : [],
        empty: box ? (box.querySelector('.admin-delegation-empty') || {}).textContent : null,
        chips: box ? Array.from(box.querySelectorAll('.admin-delegation-chip span:first-child')).map(c => c.textContent) : null,
        options: sel ? Array.from(sel.options).map(o => o.textContent) : [],
        dropdownAlignment: labelRect && selectRect
            ? Math.abs((labelRect.top + labelRect.height / 2) - (selectRect.top + selectRect.height / 2))
            : null
    };
});
check(bobDelegation.meta === 'User · Unassigned', `unassigned marker in list meta (got "${bobDelegation.meta}")`);
check(bobDelegation.title === 'Managers' && JSON.stringify(bobDelegation.labels) === '["Direct Assignment"]',
      `super section starts with Direct Assignment only (got ${JSON.stringify(bobDelegation)})`);
check(!bobDelegation.nestedCard, 'Managers section is separated inline, not a nested card');
check(bobDelegation.empty === 'Nobody (unassigned)' && bobDelegation.chips.length === 0,
      'Direct Assignment editor starts at unassigned (no chips)');
check(JSON.stringify(bobDelegation.options) === '["Add…","Dan D"]',
      `add picker offers approved admins only (got ${JSON.stringify(bobDelegation.options)})`);
check(bobDelegation.dropdownAlignment <= 1,
      `Direct Assignment aligns vertically with its dropdown (delta ${bobDelegation.dropdownAlignment}px)`);

// Source detail belongs in super tooling: temporarily add a group-derived manager,
// reload, and verify the section adds a read-only named row without changing the direct
// editor. Reset afterward so the nobody-land delegation flow below remains load-bearing.
USERS.find(x => x.user_id === 'u-bob').group_managers = [{
    admin_id: 'u-dan', username: 'dan', first_name: 'Dan', last_name: 'D'
}];
await page.evaluate(async () => {
    await loadAdminUsers();
    const rows = Array.from(document.querySelectorAll('#adminUserList .admin-user-row'));
    rows.find(r => r.querySelector('.admin-user-name').textContent === 'Bob B').click();
});
await page.waitForTimeout(500);
const groupAssignment = await page.evaluate(() => {
    const card = document.querySelector('#adminUserDetail .admin-managers-section');
    return Array.from(card.querySelectorAll('.admin-manager-rows > div')).map(row => ({
        label: row.querySelector('.admin-fact-label').textContent,
        value: row.querySelector('span:last-child') ? row.querySelector('span:last-child').textContent : ''
    }));
});
check(groupAssignment.some(r => r.label === 'Direct Assignment') &&
      groupAssignment.some(r => r.label === 'Group Assignment' && r.value === 'Dan D'),
      `super section separates direct and group assignment (got ${JSON.stringify(groupAssignment)})`);
USERS.find(x => x.user_id === 'u-bob').group_managers = [];
await page.evaluate(async () => {
    await loadAdminUsers();
    const rows = Array.from(document.querySelectorAll('#adminUserList .admin-user-row'));
    rows.find(r => r.querySelector('.admin-user-name').textContent === 'Bob B').click();
});
await page.waitForTimeout(500);

console.log('\n== C3. Edit profile overlay (super): prefill, save, facts refresh ==');
await page.evaluate(() => {
    const btns = Array.from(document.querySelectorAll('#adminUserDetail .admin-user-actions .icon-btn'));
    btns.find(b => b.dataset.tip === 'Edit profile').click();
});
await page.waitForTimeout(500);
const editPrefill = await page.evaluate(() => ({
    active: document.getElementById('editUserOverlay').classList.contains('active'),
    username: document.getElementById('editUserUsername').value,
    email: document.getElementById('editUserEmail').value,
    first: document.getElementById('editUserFirstName').value,
    last: document.getElementById('editUserLastName').value,
    company: document.getElementById('editUserCompany').value,
    department: document.getElementById('editUserDepartment').value,
    birth: document.getElementById('editUserBirthDate').value,
    sex: document.getElementById('editUserSex').value
}));
check(editPrefill.active, 'edit overlay opens from the pencil');
check(editPrefill.username === 'bob' && editPrefill.email === 'bob@x.eu' && editPrefill.first === 'Bob' && editPrefill.last === 'B',
      `identity fields prefilled (got ${JSON.stringify(editPrefill)})`);
check(editPrefill.company === 'ACME' && editPrefill.department === 'Ops' && editPrefill.birth === '1990-05-01' && editPrefill.sex === 'male',
      `profile fields prefilled (got ${JSON.stringify(editPrefill)})`);
await page.evaluate(() => {
    document.getElementById('editUserCompany').value = 'NewCo';
    document.getElementById('editUserForm').requestSubmit();
});
await page.waitForTimeout(800);
check(profilePutBody && profilePutBody.username === 'bob' && profilePutBody.company === 'NewCo'
      && ['first_name', 'last_name', 'email', 'department', 'birth_date', 'sex'].every(k => k in profilePutBody),
      `PUT profile body carries all 8 fields (got ${JSON.stringify(profilePutBody)})`);
const afterSave = await page.evaluate(() => ({
    overlayActive: document.getElementById('editUserOverlay').classList.contains('active'),
    facts: Array.from(document.querySelectorAll('#adminUserDetail .admin-facts > div span:last-child')).map(s => s.textContent),
    activeTab: (Array.from(document.querySelectorAll('#adminUserDetail .admin-detail-tab'))
        .find(t => t.classList.contains('active')) || {}).textContent
}));
check(!afterSave.overlayActive, 'overlay closes after save');
check(afterSave.facts.includes('NewCo'), `facts refreshed with the new company (got ${JSON.stringify(afterSave.facts)})`);
check(afterSave.activeTab === 'Maps', `active inner tab survives the re-render (got "${afterSave.activeTab}")`);

// The super's OWN row gets the pencil too (explicit decision) — and only the pencil.
await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminUserList .admin-user-row'));
    rows.find(r => r.querySelector('.admin-user-name').textContent === 'Alice A').click();
});
await page.waitForTimeout(500);
const aliceTips = await page.evaluate(() =>
    Array.from(document.querySelectorAll('#adminUserDetail .admin-user-actions .icon-btn')).map(b => b.dataset.tip));
check(JSON.stringify(aliceTips) === '["Edit profile"]', `own super row shows exactly the edit pencil (got ${JSON.stringify(aliceTips)})`);

console.log('\n== D. Admin target: maps not inspectable note (403) ==');
await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminUserList .admin-user-row'));
    rows.find(r => r.querySelector('.admin-user-name').textContent === 'Dan D').click();
});
await page.waitForTimeout(800);
const danDetail = await page.evaluate(() => ({
    maps: document.querySelector('#adminUserDetail .admin-maps-list').textContent,
    facts: Array.from(document.querySelectorAll('#adminUserDetail .admin-facts > div span:last-child')).map(s => s.textContent),
    hasEditor: !!document.querySelector('#adminUserDetail .admin-delegation-box')
}));
check(danDetail.maps === 'This account is outside your management scope.', `403 note shown (got "${danDetail.maps}")`);
check(danDetail.facts.includes('None'), `groups fact says None when memberless (got ${JSON.stringify(danDetail.facts)})`);
check(!danDetail.hasEditor, 'no Managed-by editor on an admin target (admins are never controlled)');

console.log('\n== E. Groups tab: list, members, picker ==');
await page.evaluate(() => document.querySelector('.admin-tab[data-admintab="groups"]').click());
await page.waitForTimeout(800);
const groupsState = await page.evaluate(() => ({
    usersHidden: document.getElementById('adminUsersPanel').style.display === 'none',
    rows: Array.from(document.querySelectorAll('#adminGroupList .admin-user-row .admin-user-name')).map(n => n.textContent),
    meta: (document.querySelector('#adminGroupList .admin-user-meta') || {}).textContent
}));
check(groupsState.usersHidden, 'users panel hidden on groups tab');
check(JSON.stringify(groupsState.rows) === '["Team","Frozen"]', `group list shows Team+Frozen (got ${JSON.stringify(groupsState.rows)})`);
check(groupsState.meta === '1 member · Dan D', `member count meta + owner real name (super view) (got "${groupsState.meta}")`);

const groupFilterCheck = await page.evaluate(() => {
    const inp = document.getElementById('adminGroupFilter');
    const names = () => Array.from(document.querySelectorAll('#adminGroupList .admin-user-name')).map(n => n.textContent);
    inp.value = 'fro'; inp.dispatchEvent(new Event('input'));
    const narrowed = names();
    inp.value = ''; inp.dispatchEvent(new Event('input'));
    return { narrowed, restored: names() };
});
check(JSON.stringify(groupFilterCheck.narrowed) === '["Frozen"]', `group filter narrows the list (got ${JSON.stringify(groupFilterCheck.narrowed)})`);
check(JSON.stringify(groupFilterCheck.restored) === '["Team","Frozen"]', `clearing restores the group list (got ${JSON.stringify(groupFilterCheck.restored)})`);

await page.evaluate(() => document.querySelector('#adminGroupList .admin-user-row').click());
await page.waitForTimeout(400);
const teamDetail = await page.evaluate(() => {
    const d = document.getElementById('adminGroupDetail');
    const ownBox = d.querySelector('.admin-group-owner-row .admin-delegation-box');
    const tabs = Array.from(d.querySelectorAll('.admin-detail-tab'));
    return {
        name: (d.querySelector('.admin-detail-name') || {}).textContent,
        tabLabels: tabs.map(t => t.textContent),
        activeTab: (tabs.find(t => t.classList.contains('active')) || {}).textContent,
        facts: Array.from(d.querySelectorAll('.admin-facts > div')).map(x => x.textContent),
        members: Array.from(d.querySelectorAll('.admin-group-members-list .action-list-name')).map(n => n.textContent),
        memberAvatars: d.querySelectorAll('.admin-group-lists .collab-list-avatar').length,
        removeBtns: d.querySelectorAll('.admin-group-members-list .action-list-btn').length,
        pickerItems: Array.from(d.querySelectorAll('.admin-group-add-list .action-list-name')).map(o => o.textContent),
        listFilters: d.querySelectorAll('.admin-group-lists .filter-picker input').length,
        tips: Array.from(d.querySelectorAll('.admin-user-actions .icon-btn')).map(b => b.dataset.tip),
        ownerChips: ownBox ? Array.from(ownBox.querySelectorAll('.admin-delegation-chip span:first-child')).map(c => c.textContent) : null,
        ownerAddPicker: !!(ownBox && ownBox.querySelector('select'))
    };
});
check(teamDetail.name === 'Team', `group detail shows Team (got "${teamDetail.name}")`);
check(JSON.stringify(teamDetail.tabLabels) === '["Details","Members"]' && teamDetail.activeTab === 'Details',
      `group pane has Details|Members tabs, Details default (got ${JSON.stringify(teamDetail.tabLabels)} / "${teamDetail.activeTab}")`);
check(JSON.stringify(teamDetail.facts) === '["Created ByDan D","Creation Date7/10/2026"]',
      `creator and creation date use separate rows (got ${JSON.stringify(teamDetail.facts)})`);
check(JSON.stringify(teamDetail.members) === '["Bob B"]', `member listed without username parentheses (got ${JSON.stringify(teamDetail.members)})`);
check(teamDetail.removeBtns === 1, 'managed member has a × button');
check(JSON.stringify(teamDetail.pickerItems) === '["Alice A","Dan D"]',
      `add list offers approved non-members only (got ${JSON.stringify(teamDetail.pickerItems)})`);
check(teamDetail.memberAvatars === 3,
      `share-group member and candidate rows all show avatars (got ${teamDetail.memberAvatars})`);
check(teamDetail.listFilters === 2, `both member lists have a filter input (got ${teamDetail.listFilters})`);
check(JSON.stringify(teamDetail.tips) === '["Rename group","Delete group"]', `rename+delete actions (got ${JSON.stringify(teamDetail.tips)})`);
check(JSON.stringify(teamDetail.ownerChips) === '["Dan D"]', `Owned-by chips show the real name (got ${JSON.stringify(teamDetail.ownerChips)})`);
check(!teamDetail.ownerAddPicker, 'no add picker when every admin already co-owns the group');

console.log('\n== E2. Out-of-scope gating: Frozen group ==');
await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminGroupList .admin-user-row'));
    rows.find(r => r.querySelector('.admin-user-name').textContent === 'Frozen').click();
});
await page.waitForTimeout(400);
const frozenDetail = await page.evaluate(() => {
    const d = document.getElementById('adminGroupDetail');
    return {
        tips: Array.from(d.querySelectorAll('.admin-user-actions .icon-btn')).map(b => b.dataset.tip),
        removeBtns: d.querySelectorAll('.admin-group-members-list .action-list-btn').length,
        ownerEmpty: ((d.querySelector('.admin-group-owner-row .admin-delegation-empty') || {}).textContent),
        ownerOptions: Array.from(d.querySelectorAll('.admin-group-owner-row .admin-delegation-box select option')).map(o => o.textContent),
        facts: Array.from(d.querySelectorAll('.admin-facts > div')).map(x => x.textContent)
    };
});
check(JSON.stringify(frozenDetail.facts) === '["Created ByAccount Deleted","Creation Date7/10/2026"]',
      `null creator keeps separate creator/date rows (got ${JSON.stringify(frozenDetail.facts)})`);
check(JSON.stringify(frozenDetail.tips) === '["Rename group"]', `deletable=false hides the delete action (got ${JSON.stringify(frozenDetail.tips)})`);
check(frozenDetail.removeBtns === 0, 'unmanaged member has NO Remove button');
check(frozenDetail.ownerEmpty === 'Super Admin' && JSON.stringify(frozenDetail.ownerOptions) === '["Add…","Dan D"]',
      `superadmin-owned group shows Super Admin + an add picker (got "${frozenDetail.ownerEmpty}" / ${JSON.stringify(frozenDetail.ownerOptions)})`);
await page.evaluate(() => {
    Array.from(document.querySelectorAll('#adminGroupDetail .admin-detail-tab'))
        .find(t => t.textContent === 'Members').click();
});
await page.waitForTimeout(200);
const unequalActionRows = await page.evaluate(() => {
    const addRow = document.querySelector('#adminGroupDetail .admin-group-add-list .action-list-row');
    const memberRow = document.querySelector('#adminGroupDetail .admin-group-members-list .action-list-row');
    return {
        addHeight: Math.round(addRow.getBoundingClientRect().height),
        memberHeight: Math.round(memberRow.getBoundingClientRect().height),
        addHasButton: !!addRow.querySelector('.action-list-btn'),
        memberHasButton: !!memberRow.querySelector('.action-list-btn')
    };
});
check(unequalActionRows.addHasButton && !unequalActionRows.memberHasButton &&
      unequalActionRows.addHeight === unequalActionRows.memberHeight,
      `button and no-button rows align at equal height (got ${JSON.stringify(unequalActionRows)})`);
await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminGroupList .admin-user-row'));
    rows.find(r => r.querySelector('.admin-user-name').textContent === 'Team').click();
});
await page.waitForTimeout(400);

console.log('\n== F. Add member (Members tab, action lists) + create group ==');
await page.evaluate(() => {
    Array.from(document.querySelectorAll('#adminGroupDetail .admin-detail-tab'))
        .find(t => t.textContent === 'Members').click();
});
await page.waitForTimeout(300);
// Geometry needs the panel visible, so the side-by-side check lives here.
const listsSideBySide = await page.evaluate(() => {
    const boxes = document.querySelectorAll('#adminGroupDetail .admin-group-lists .filter-picker');
    if (boxes.length !== 2) return false;
    const a = boxes[0].getBoundingClientRect(), b = boxes[1].getBoundingClientRect();
    return Math.abs(a.top - b.top) < 2 && b.left > a.right;
});
check(listsSideBySide, 'add + members lists render side by side');
const listWidths = await page.evaluate(() =>
    Array.from(document.querySelectorAll('#adminGroupDetail .admin-group-lists .filter-picker'))
        .map(b => Math.round(b.getBoundingClientRect().width)));
check(JSON.stringify(listWidths) === '[350,350]', `both lists fixed at 350px (got ${JSON.stringify(listWidths)})`);
// Type to narrow, then add straight from the row's + button.
const memberPick = await page.evaluate(() => {
    const d = document.getElementById('adminGroupDetail');
    const input = d.querySelector('.admin-group-add-list input');
    input.value = 'da';
    input.dispatchEvent(new Event('input'));
    const items = Array.from(d.querySelectorAll('.admin-group-add-list .action-list-name')).map(x => x.textContent);
    const danRow = Array.from(d.querySelectorAll('.admin-group-add-list .action-list-row'))
        .find(r => r.querySelector('.action-list-name').textContent === 'Dan D');
    danRow.querySelector('.action-list-btn').click();
    return { items };
});
await page.waitForTimeout(600);
check(JSON.stringify(memberPick.items) === '["Dan D"]', `typing narrows the add list (got ${JSON.stringify(memberPick.items)})`);
check(addMemberBody && addMemberBody.username === 'dan', `row + button PUTs members (got ${JSON.stringify(addMemberBody)})`);
const memberAfter = await page.evaluate(() => ({
    names: Array.from(document.querySelectorAll('#adminGroupDetail .admin-group-members-list .action-list-name')).map(n => n.textContent),
    pickerFilterKept: document.querySelector('#adminGroupDetail .admin-group-add-list input').value,
    activeTab: (Array.from(document.querySelectorAll('#adminGroupDetail .admin-detail-tab'))
        .find(t => t.classList.contains('active')) || {}).textContent
}));
check(memberAfter.names.length === 2 && memberAfter.names[1] === 'Dan D', `member list refreshed (got ${JSON.stringify(memberAfter.names)})`);
check(memberAfter.pickerFilterKept === 'da', `add-list filter text survives the reload (got "${memberAfter.pickerFilterKept}")`);
check(memberAfter.activeTab === 'Members', `Members tab stays active across the reload (got "${memberAfter.activeTab}")`);

await page.evaluate(() => {
    document.getElementById('newGroupName').value = 'Ops';
    document.getElementById('adminCreateGroupBtn').click();
});
await page.waitForTimeout(600);
check(createGroupBody && createGroupBody.name === 'Ops', `POST group body (got ${JSON.stringify(createGroupBody)})`);
const groupRowsAfter = await page.evaluate(() => Array.from(document.querySelectorAll('#adminGroupList .admin-user-row .admin-user-name')).map(n => n.textContent));
check(JSON.stringify(groupRowsAfter) === '["Team","Frozen","Ops"]', `new group in list + auto-selected (got ${JSON.stringify(groupRowsAfter)})`);

await page.screenshot({ path: '../ui_admin_groups_tab.png' });

console.log('\n== G. Share overlay: type dropdown + persistent filter list + group rows ==');
// The /maps fixture carries no shared flag for map 5, so its sidebar button starts
// plain; loading the overlay's live share data must turn it green.
const preGreen = await page.evaluate(() => !!document.querySelector('.map-item[data-id="5"] .map-collab-btn.has-collabs'));
await page.evaluate(() => { document.getElementById('adminBackBtn').click(); openShareOverlay(5, 'My Map'); });
await page.waitForTimeout(800);
const postOpenGreen = await page.evaluate(() => !!document.querySelector('.map-item[data-id="5"] .map-collab-btn.has-collabs'));
check(!preGreen && postOpenGreen, `sidebar share button syncs green from live share data (was ${preGreen}, now ${postOpenGreen})`);
const shareState = await page.evaluate(() => {
    const typeSel = document.getElementById('collabTypeSelect');
    const input = document.querySelector('#collabPickerBox .filter-picker input');
    const items = () => Array.from(document.querySelectorAll('#collabPickerBox .filter-picker-item')).map(l => l.textContent);
    const typeOptions = Array.from(typeSel.options).map(o => o.value);
    // The list is PERSISTENT — candidates are visible without focusing or typing.
    const userItems = items();
    const userAvatars = document.querySelectorAll('#collabPickerBox .collab-list-avatar').length;
    const userAvatarSrc = (document.querySelector('#collabPickerBox .collab-list-avatar') || {}).src;
    const userPlaceholder = input.placeholder;
    typeSel.value = 'group';
    typeSel.dispatchEvent(new Event('change'));
    const groupItems = items();
    const groupPlaceholder = input.placeholder;
    const rows = Array.from(document.querySelectorAll('#collabList .collab-row')).map(r => ({
        name: r.querySelector('.collab-name').firstChild.textContent,
        badge: (r.querySelector('.collab-type-badge') || {}).textContent || '',
        role: r.querySelector('.collab-role-select').value
    }));
    const rowAvatars = document.querySelectorAll('#collabList .collab-list-avatar').length;
    return { typeOptions, userItems, userAvatars, userAvatarSrc, userPlaceholder, groupItems, groupPlaceholder, rows, rowAvatars };
});
check(JSON.stringify(shareState.typeOptions) === '["user","group"]', `type dropdown offers user+group (got ${JSON.stringify(shareState.typeOptions)})`);
check(JSON.stringify(shareState.userItems) === '["Dave V"]', `user candidates visible WITHOUT typing, already-shared excluded (got ${JSON.stringify(shareState.userItems)})`);
check(shareState.userAvatars === 1 && shareState.rowAvatars === 1,
      `share picker and current user share render avatars (got ${shareState.userAvatars} / ${shareState.rowAvatars})`);
check(shareState.userAvatarSrc.endsWith('/assets/images/default-user-thumb.png'),
      `share picker uses the default image when no avatar exists (got "${shareState.userAvatarSrc}")`);
check(shareState.userPlaceholder === 'Type to find a user...', `user placeholder (got "${shareState.userPlaceholder}")`);
check(JSON.stringify(shareState.groupItems) === '["Frozen","Ops"]', `group candidates exclude already-shared Team (got ${JSON.stringify(shareState.groupItems)})`);
check(shareState.groupPlaceholder === 'Type to find a group...', `group placeholder (got "${shareState.groupPlaceholder}")`);
check(JSON.stringify(shareState.rows) === JSON.stringify([
    { name: 'Bob B', badge: '', role: 'viewer' },
    { name: 'Team', badge: 'group', role: 'editor' }
]), `share list rows incl. badged group (got ${JSON.stringify(shareState.rows)})`);

const filterState = await page.evaluate(() => {
    const input = document.querySelector('#collabPickerBox .filter-picker input');
    const items = () => Array.from(document.querySelectorAll('#collabPickerBox .filter-picker-item')).map(l => l.textContent);
    input.value = 'zzz';
    input.dispatchEvent(new Event('input'));
    const noMatch = items();
    const noMatchEmpty = (document.querySelector('#collabPickerBox .filter-picker-empty') || {}).textContent || '';
    input.value = 'op';
    input.dispatchEvent(new Event('input'));
    return { noMatch, noMatchEmpty, narrowed: items() };
});
check(filterState.noMatch.length === 0 && filterState.noMatchEmpty === 'No matches',
      `no-match state (got "${filterState.noMatchEmpty}")`);
check(JSON.stringify(filterState.narrowed) === '["Ops"]', `typing narrows the results (got ${JSON.stringify(filterState.narrowed)})`);

await page.screenshot({ path: '../ui_share_with_groups.png' });

const pickState = await page.evaluate(() => {
    const item = document.querySelector('#collabPickerBox .filter-picker-item');
    item.click();
    return { text: item.textContent, selected: item.classList.contains('selected') };
});
check(pickState.text === 'Ops' && pickState.selected, `clicking a row selects + highlights it (got ${JSON.stringify(pickState)})`);
await page.evaluate(() => {
    document.getElementById('collabAddRole').value = 'viewer';
    document.getElementById('collabAddBtn').click();
});
await page.waitForTimeout(600);
check(sharePutBody && sharePutBody.group === 'Ops' && sharePutBody.role === 'viewer' && !('username' in sharePutBody),
      `PUT collaborators body for group (got ${JSON.stringify(sharePutBody)})`);
const afterShareReset = await page.evaluate(() => document.querySelector('#collabPickerBox .filter-picker input').value);
check(afterShareReset === '', `search box cleared after the grant (got "${afterShareReset}")`);

await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#collabList .collab-row'));
    const team = rows.find(r => r.querySelector('.collab-name').textContent.startsWith('Team'));
    team.querySelector('.collab-remove-btn').click();
});
await page.waitForTimeout(600);
check(groupShareDeleted === true, 'Remove on group row DELETEs /collaborators/group/<id>');

// Removing the LAST collaborator clears the sidebar green state immediately.
await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#collabList .collab-row'));
    rows.find(r => r.querySelector('.collab-name').textContent.startsWith('Bob B')).querySelector('.collab-remove-btn').click();
});
await page.waitForTimeout(600);
const afterLastRemove = await page.evaluate(() => ({
    green: !!document.querySelector('.map-item[data-id="5"] .map-collab-btn.has-collabs'),
    empty: (document.querySelector('#collabList .collab-empty') || {}).textContent || ''
}));
check(!afterLastRemove.green && afterLastRemove.empty === 'Not shared with anyone yet.',
      `unsharing the last collaborator clears the green state live (got ${JSON.stringify(afterLastRemove)})`);

const overlayHeight = await page.evaluate(() =>
    Math.round(document.querySelector('#collabOverlay .overlay-content').getBoundingClientRect().height));
check(overlayHeight === 600, `share overlay fixed at 600px (got ${overlayHeight})`);
// Typed partial NAME (no click) must resolve through the label map to the bare username.
sharePutBody = null;
await page.evaluate(() => {
    const typeSel = document.getElementById('collabTypeSelect');
    typeSel.value = 'user';
    typeSel.dispatchEvent(new Event('change'));
    const input = document.querySelector('#collabPickerBox .filter-picker input');
    input.value = 'ave v';
    input.dispatchEvent(new Event('input'));
    document.getElementById('collabAddRole').value = 'viewer';
    document.getElementById('collabAddBtn').click();
});
await page.waitForTimeout(600);
check(sharePutBody && sharePutBody.username === 'dave' && !('group' in sharePutBody),
      `typed partial name resolves to the BARE username (got ${JSON.stringify(sharePutBody)})`);

console.log('\n== G2. Delegation controls (super view): controls() + owns_group ==');
await page.evaluate(() => { closeShareOverlay(); document.getElementById('openAdminPanelBtn').click(); selectAdminTab('active'); });
await page.waitForTimeout(600);
await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminUserList .admin-user-row'));
    rows.find(r => r.querySelector('.admin-user-name').textContent === 'Bob B').click();
});
await page.waitForTimeout(600);
// Assign bob -> dan through the Direct Assignment add picker (additive grant).
await page.evaluate(() => {
    const sel = document.querySelector('#adminUserDetail .admin-managers-section .admin-controller-select');
    sel.value = 'u-dan';
    sel.dispatchEvent(new Event('change'));
});
await page.waitForTimeout(800);
check(controllerPutBody && controllerPutBody.admin_id === 'u-dan',
      `PUT /controllers body (got ${JSON.stringify(controllerPutBody)})`);
const bobAfterAssign = await page.evaluate(() => {
    const row = Array.from(document.querySelectorAll('#adminUserList .admin-user-row'))
        .find(r => r.querySelector('.admin-user-name').textContent === 'Bob B');
    const box = document.querySelector('#adminUserDetail .admin-managers-section .admin-delegation-box');
    const labelRect = document.querySelector('#adminUserDetail .admin-manager-rows .admin-fact-label').getBoundingClientRect();
    const chipRect = box.querySelector('.admin-delegation-chip').getBoundingClientRect();
    return {
        meta: row.querySelector('.admin-user-meta').textContent,
        chips: Array.from(box.querySelectorAll('.admin-delegation-chip span:first-child')).map(c => c.textContent),
        addPicker: !!box.querySelector('select'),
        chipAlignment: Math.abs(
            (labelRect.top + labelRect.height / 2) - (chipRect.top + chipRect.height / 2)
        )
    };
});
check(bobAfterAssign.meta === 'User', `unassigned marker gone after assignment (got "${bobAfterAssign.meta}")`);
check(JSON.stringify(bobAfterAssign.chips) === '["Dan D"]', `controller chip uses the real name after reload (got ${JSON.stringify(bobAfterAssign.chips)})`);
check(bobAfterAssign.chipAlignment <= 1,
      `Direct Assignment aligns vertically with its chip (delta ${bobAfterAssign.chipAlignment}px)`);
check(!bobAfterAssign.addPicker, 'add picker disappears once every admin is a controller');
// Targeted revoke via the chip's × — removes just dan's grant.
await page.evaluate(() => document.querySelector('#adminUserDetail .admin-managers-section .admin-delegation-remove').click());
await page.waitForTimeout(800);
check(controllerDeleted === true, 'chip × DELETEs /controllers/<admin_id>');
const bobAfterRevoke = await page.evaluate(() => {
    const row = Array.from(document.querySelectorAll('#adminUserList .admin-user-row'))
        .find(r => r.querySelector('.admin-user-name').textContent === 'Bob B');
    return row.querySelector('.admin-user-meta').textContent;
});
check(bobAfterRevoke === 'User · Unassigned', `revoking the last grant shows unassigned again (got "${bobAfterRevoke}")`);
// Re-assign so the screenshot shows a populated editor.
await page.evaluate(() => {
    const sel = document.querySelector('#adminUserDetail .admin-managers-section .admin-controller-select');
    sel.value = 'u-dan';
    sel.dispatchEvent(new Event('change'));
});
await page.waitForTimeout(800);
await page.screenshot({ path: '../ui_admin_delegation.png' });

// No selector on a pending user — approval comes first (carol lives on the Pending tab).
await page.evaluate(() => selectAdminTab('pending'));
await page.waitForTimeout(600);
await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminUserList .admin-user-row'));
    rows.find(r => r.querySelector('.admin-user-name').textContent === 'carol').click();
});
await page.waitForTimeout(400);
const carolHasEditor = await page.evaluate(() => !!document.querySelector('#adminUserDetail .admin-delegation-box'));
check(!carolHasEditor, 'no Managed-by editor on a pending user');

// Group ownership: revoke dan's grant via the chip × — the group reverts to superadmin.
await page.evaluate(() => selectAdminTab('groups'));
await page.waitForTimeout(600);
await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminGroupList .admin-user-row'));
    rows.find(r => r.querySelector('.admin-user-name').textContent === 'Team').click();
});
await page.waitForTimeout(400);
await page.evaluate(() => document.querySelector('#adminGroupDetail .admin-group-owner-row .admin-delegation-remove').click());
await page.waitForTimeout(800);
check(ownerDeleted === true, 'chip × DELETEs /owners/<admin_id>');
const teamAfterRevert = await page.evaluate(() => {
    const row = Array.from(document.querySelectorAll('#adminGroupList .admin-user-row'))
        .find(r => r.querySelector('.admin-user-name').textContent === 'Team');
    return row.querySelector('.admin-user-meta').textContent;
});
check(/Super Admin$/.test(teamAfterRevert), `list meta shows Super Admin owner after the last revoke (got "${teamAfterRevert}")`);

console.log('\n== H. Admin screen screenshot (users tab) ==');
await page.evaluate(() => { closeShareOverlay(); document.getElementById('openAdminPanelBtn').click(); selectAdminTab('active'); });
await page.waitForTimeout(600);
await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminUserList .admin-user-row'));
    rows.find(r => r.querySelector('.admin-user-name').textContent === 'Bob B').click();
});
await page.waitForTimeout(800);
await page.screenshot({ path: '../ui_admin_users_tab.png' });

console.log('\n== I. Admin manages a map\'s shares from the Maps section ==');
const shareBtns = await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminUserDetail .admin-map-row'));
    return rows.map(r => ({
        name: r.querySelector('.admin-map-name').firstChild.textContent,
        hasShare: !!r.querySelector('.admin-map-head .icon-btn')
    }));
});
check(JSON.stringify(shareBtns) === JSON.stringify([
    { name: 'Base Map', hasShare: false },
    { name: 'Fishing', hasShare: true },
    { name: 'Harbours', hasShare: true }
]), `share button on non-base owned + shared-with rows (got ${JSON.stringify(shareBtns)})`);

await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#adminUserDetail .admin-map-row'));
    rows.find(r => r.querySelector('.admin-map-name').firstChild.textContent === 'Fishing')
        .querySelector('.admin-map-head .icon-btn').click();
});
await page.waitForTimeout(800);
const adminShareState = await page.evaluate(() => {
    const typeSel = document.getElementById('collabTypeSelect');
    const items = () => Array.from(document.querySelectorAll('#collabPickerBox .filter-picker-item')).map(l => l.textContent);
    const userItems = items();
    typeSel.value = 'group';
    typeSel.dispatchEvent(new Event('change'));
    const groupItems = items();
    typeSel.value = 'user';
    typeSel.dispatchEvent(new Event('change'));
    return {
        active: document.getElementById('collabOverlay').classList.contains('active'),
        title: document.getElementById('collabOverlayTitle').textContent,
        userItems, groupItems,
        rows: Array.from(document.querySelectorAll('#collabList .collab-row')).map(r => r.querySelector('.collab-name').firstChild.textContent)
    };
});
check(adminShareState.active && adminShareState.title === 'Share “Fishing”', `overlay opens in admin mode (got "${adminShareState.title}")`);
check(JSON.stringify(adminShareState.userItems) === '["Dave V"]' && JSON.stringify(adminShareState.groupItems) === '["Frozen","Ops"]',
      `picker excludes the owner bob + shared Team (got ${JSON.stringify(adminShareState.userItems)} / ${JSON.stringify(adminShareState.groupItems)})`);
check(JSON.stringify(adminShareState.rows) === '["alice2","Team"]', `existing shares listed (got ${JSON.stringify(adminShareState.rows)})`);

await page.evaluate(() => {
    const input = document.querySelector('#collabPickerBox .filter-picker input');
    input.value = 'dav';
    input.dispatchEvent(new Event('input'));
    document.querySelector('#collabPickerBox .filter-picker-item').click();
    document.getElementById('collabAddRole').value = 'viewer';
    document.getElementById('collabAddBtn').click();
});
await page.waitForTimeout(600);
check(adminSharePutBody && adminSharePutBody.username === 'dave' && adminSharePutBody.role === 'viewer',
      `PUT went to /admin/maps/12/collaborators (got ${JSON.stringify(adminSharePutBody)})`);

await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#collabList .collab-row'));
    rows.find(r => r.querySelector('.collab-name').textContent.startsWith('Team')).querySelector('.collab-remove-btn').click();
});
await page.waitForTimeout(600);
check(adminGroupShareDeleted === true, 'Remove on group row DELETEs the admin group route');

await page.evaluate(() => closeShareOverlay());
await page.waitForTimeout(600);
const chipsAfter = await page.evaluate(() => Array.from(document.querySelectorAll('#adminUserDetail .collab-chip')).map(c => c.textContent));
check(chipsAfter.includes('dave · viewer'), `detail pane chips refreshed on close (got ${JSON.stringify(chipsAfter)})`);

console.log('\n== J. No uncaught page errors ==');
check(pageErrors.length === 0, `no page errors${pageErrors.length ? ' (got ' + pageErrors.join('; ') + ')' : ''}`);

console.log(`\n==== ${PASS} passed, ${FAIL} failed ====`);
await browser.close();
server.close();
process.exit(FAIL ? 1 : 0);
