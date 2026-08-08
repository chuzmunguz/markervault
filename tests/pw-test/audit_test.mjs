// Super-only Audit tab: visibility, readable log rendering, metadata, refetch and paging.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const MIME = { '.html':'text/html', '.js':'application/javascript', '.css':'text/css', '.png':'image/png', '.ico':'image/x-icon' };
let callerRole = 'super_admin';
let auditRequests = [];

const firstPage = {
    entries: [
        { id: 5, ts: '2026-07-16T12:00:00Z', actor_username: 'alice', action: 'auth.login_failed',
          actor_id: 'u-alice', actor_role: 'user', target_type: null, target_id: null,
          target_label: null, detail: { reason: 'bad_password' }, client_ip: '203.0.113.10' },
        { id: 4, ts: '2026-07-16T11:45:00Z', actor_username: 'boss', action: 'user.profile_edit',
          actor_id: 'u-boss', actor_role: 'super_admin', target_type: 'user', target_id: 'u-bob',
          target_label: 'bob', detail: {
              email: { old: 'old@example.com', new: 'new@example.com' },
              company: { old: 'Old Co', new: 'New Co' }
          }, client_ip: '192.0.2.4' },
        { id: 3, ts: '2026-07-16T11:30:00Z', actor_username: 'boss',
          action: 'map_share.group.change',
          actor_id: 'u-boss', actor_role: 'super_admin', target_type: 'map', target_id: '42',
          target_label: 'Survey map', detail: {
              group: 7, group_label: 'Field team', operation: 'role_changed',
              old_role: 'viewer', new_role: 'editor'
          }, client_ip: '192.0.2.4' },
        { id: 2, ts: '2026-07-16T11:00:00Z', actor_username: 'boss', action: 'user.disable',
          actor_id: 'u-boss', actor_role: 'super_admin', target_type: 'user', target_id: 'u-bob',
          target_label: 'bob', detail: null, client_ip: '192.0.2.4' }
    ],
    next_before: 2
};
const secondPage = {
    entries: [
        { id: 1, ts: '2026-07-16T10:00:00Z', actor_username: 'boss', action: 'user.create',
          actor_id: 'u-boss', actor_role: 'super_admin', target_type: 'user', target_id: 'u-carol',
          target_label: 'carol', detail: { role: 'user' }, client_ip: '192.0.2.4' }
    ],
    next_before: null
};
const filteredFirstPage = {
    entries: [firstPage.entries[3]],
    next_before: 2
};
const filteredSecondPage = {
    entries: [
        { id: 1, ts: '2026-07-15T10:00:00Z', actor_username: 'boss', action: 'user.disable',
          actor_id: 'u-boss', actor_role: 'super_admin', target_type: 'user', target_id: 'u-bob',
          target_label: 'bob', detail: { reason: 'policy review' }, client_ip: '192.0.2.4' }
    ],
    next_before: null
};

function sendJSON(res, obj, code=200) {
    res.writeHead(code, {'Content-Type':'application/json'});
    res.end(JSON.stringify(obj));
}

const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const p = u.pathname;
    if (p === '/auth/refresh') {
        return sendJSON(res, { access_token:'faketoken', access_expires_in:900, role:callerRole,
            username:callerRole === 'super_admin' ? 'boss' : 'dan', first_name:'Test', last_name:'Admin' });
    }
    if (p === '/maps') return sendJSON(res, []);
    if (p === '/users' || p === '/groups') return sendJSON(res, []);
    if (p === '/admin/users' || p === '/admin/groups' || p === '/admin/mgmt-groups') return sendJSON(res, []);
    if (p === '/admin/audit') {
        auditRequests.push(u.search);
        if (u.searchParams.get('event')) {
            return sendJSON(res, u.searchParams.get('before') === '2'
                ? filteredSecondPage : filteredFirstPage);
        }
        return sendJSON(res, u.searchParams.get('before') === '2' ? secondPage : firstPage);
    }
    let fp = p === '/' ? '/index.html' : p;
    const full = path.join(ROOT, fp);
    if (fs.existsSync(full) && fs.statSync(full).isFile()) {
        res.writeHead(200, {'Content-Type': MIME[path.extname(full)] || 'text/plain'});
        return res.end(fs.readFileSync(full));
    }
    res.writeHead(200, {'Content-Type':'application/javascript'});
    res.end('');
});

await new Promise(resolve => server.listen(0, resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
let PASS = 0, FAIL = 0;
function check(cond, label) {
    if (cond) { PASS++; console.log(`  PASS  ${label}`); }
    else { FAIL++; console.log(`  FAIL  ${label}`); }
}

// Fixed non-UTC zone: the local-day → UTC filter conversion and local timestamp
// rendering are asserted deterministically no matter which machine runs the suite.
const page = await browser.newPage({ viewport: { width: 1280, height: 800 }, timezoneId: 'Europe/Lisbon' });
const errors = [];
page.on('pageerror', error => errors.push(String(error)));
await page.goto(base, { waitUntil:'networkidle' });
await page.waitForTimeout(1200);
await page.evaluate(() => document.getElementById('openAdminPanelBtn').click());
await page.waitForTimeout(400);

console.log('== Super-admin Audit tab ==');
check(await page.isVisible('#adminAuditTabBtn'), 'Audit tab is visible for a super-admin');
check(auditRequests.length === 0, 'audit data is not requested before tab activation');
await page.click('#adminAuditTabBtn');
await page.waitForTimeout(500);
check(auditRequests.length === 1 && auditRequests[0] === '', `first activation fetches one page (got ${JSON.stringify(auditRequests)})`);

const first = await page.evaluate(() => ({
    timestamps: Array.from(document.querySelectorAll('.audit-log-timestamp')).map(x => ({
        text:x.textContent, datetime:x.dateTime
    })),
    actions: Array.from(document.querySelectorAll('.audit-log-action')).map(x => x.textContent),
    headings: Array.from(document.querySelectorAll('.audit-row-heading')).map(x => x.textContent),
    metadata: Array.from(document.querySelectorAll('.audit-row')).map(row =>
        Array.from(row.querySelectorAll('.audit-record-line')).map(x => x.textContent)),
    rawPreCount: document.querySelectorAll('.audit-row pre').length,
    font: getComputedStyle(document.getElementById('adminAuditList')).fontFamily,
    listBackground: getComputedStyle(document.getElementById('adminAuditList')).backgroundColor,
    rowBackground: getComputedStyle(document.querySelector('.audit-row')).backgroundColor,
    rowColor: getComputedStyle(document.querySelector('.audit-row')).color,
    more: !!document.querySelector('.audit-load-more')
}));
check(JSON.stringify(first.actions) ===
      '["[LOGIN FAILED]","[PROFILE UPDATED]","[GROUP MAP ACCESS CHANGED]","[USER DISABLED]"]',
      `action keys become readable CLI labels (got ${JSON.stringify(first.actions)})`);
check(first.headings[0] === 'Login failed for “alice”: incorrect password.'
      && first.headings[1].includes('Email “old@example.com” → “new@example.com”')
      && first.headings[1].includes('Company “Old Co” → “New Co”')
      && first.headings[2] ===
          'boss changed group “Field team” access to map “Survey map” from viewer to editor.'
      && first.headings[3] === 'boss disabled user “bob”.',
      `events render as human-readable narratives (got ${JSON.stringify(first.headings)})`);
check(first.timestamps[0].text === '[2026-07-16 13:00:00]'
      && first.timestamps[0].datetime === '2026-07-16T12:00:00Z',
      `timestamp is local (WEST) CLI text while preserving UTC (got ${JSON.stringify(first.timestamps[0])})`);
check(first.metadata[0].includes('Action key:auth.login_failed')
      && first.metadata[0].includes('Actor ID:u-alice')
      && first.metadata[0].includes('Source IP:203.0.113.10')
      && first.metadata[0].includes('Detail · Reason:incorrect password [bad_password]')
      && first.metadata[1].includes('Detail · Email:old@example.com → new@example.com'),
      'expandable record details preserve exact IDs, keys, IP, enums and field changes');
check(first.rawPreCount === 0 && first.font.toLowerCase().includes('mono'),
      'audit presentation is log-like and no longer exposes raw JSON blocks');
check(first.listBackground === 'rgb(255, 255, 255)'
      && first.rowBackground === 'rgb(255, 255, 255)'
      && first.rowColor !== 'rgb(255, 255, 255)',
      `audit log uses a light palette (got ${first.listBackground}, ${first.rowBackground}, ${first.rowColor})`);
check(first.more, 'Load more button appears when next_before is present');

const taxonomy = await page.evaluate(() => {
    const actions = [
        'auth.login', 'auth.login_failed', 'auth.logout', 'account.changepwd',
        'account.delete', 'user.approve', 'user.reject', 'user.role', 'user.disable',
        'user.enable', 'user.resetpwd', 'user.profile_edit', 'user.delete', 'user.create',
        'user.controller.add', 'user.controller.remove', 'share_group.create',
        'share_group.rename', 'share_group.delete', 'share_group.member.add',
        'share_group.member.remove', 'share_group.owner.add', 'share_group.owner.remove',
        'mgmt_group.create', 'mgmt_group.rename', 'mgmt_group.delete',
        'mgmt_group.member.add', 'mgmt_group.member.remove', 'mgmt_group.manager.add',
        'mgmt_group.manager.remove', 'map_share.direct.grant', 'map_share.direct.change',
        'map_share.direct.remove', 'map_share.group.grant', 'map_share.group.change',
        'map_share.group.remove'
    ];
    return actions.map(action => {
        const entry = {
            action, actor_username:'boss', target_label:'target',
            detail:{
                old:'user', new:'admin', role:'user', old_name:'old', new_name:'new',
                admin_id:'a1', admin_label:'admin', user_id:'u1', user_label:'user',
                recipient:'u1', recipient_label:'user', group:1, group_label:'group',
                operation:'created', old_role:null, new_role:'viewer', reason:'bad_password'
            }
        };
        return { action, label:formatAuditAction(entry), message:formatAuditMessage(entry) };
    });
});
check(taxonomy.length === 36
      && taxonomy.every(x => !/[._]/.test(x.label) && !x.message.includes('undefined')
          && !x.message.includes(x.action)),
      'every persisted action has a polished label and readable message fallback');
const loginFailureReasons = await page.evaluate(() => [
    'bad_password', 'unknown_user', 'approval_pending', 'account_disabled',
    'email_unverified', 'not_approved'
].map(reason => formatAuditMessage({
    action:'auth.login_failed',
    actor_username:'sample-user',
    detail:{reason}
})));
check(
    JSON.stringify(loginFailureReasons) === JSON.stringify([
        'Login failed for “sample-user”: incorrect password.',
        'Login failed for “sample-user”: unknown username.',
        'Login failed for “sample-user”: administrator approval pending.',
        'Login failed for “sample-user”: account disabled.',
        'Login failed for “sample-user”: email address not verified.',
        'Login failed for “sample-user”: account not approved.'
    ]),
    `login failure reasons are readable without raw enums (${JSON.stringify(loginFailureReasons)})`
);

await page.click('.audit-load-more');
await page.waitForTimeout(400);
const paged = await page.evaluate(() => ({
    headings: Array.from(document.querySelectorAll('.audit-row-heading')).map(x => x.textContent),
    more: !!document.querySelector('.audit-load-more')
}));
check(JSON.stringify(auditRequests) === '["","?before=2"]', `paging is explicit and keyset-based (got ${JSON.stringify(auditRequests)})`);
check(paged.headings.length === 5
      && paged.headings[4] === 'boss created user “carol” with the user role.',
      'older human-readable entries append after existing rows');
check(!paged.more, 'Load more disappears at the final page');

await page.click('.admin-tab[data-admintab="active"]');
await page.waitForTimeout(250);
await page.click('#adminAuditTabBtn');
await page.waitForTimeout(500);
const reactivated = await page.evaluate(() => ({
    headings: Array.from(document.querySelectorAll('.audit-row-heading')).map(x => x.textContent),
    more: !!document.querySelector('.audit-load-more')
}));
check(JSON.stringify(auditRequests) === '["","?before=2",""]',
      `returning to Audit refetches the first page (got ${JSON.stringify(auditRequests)})`);
check(reactivated.headings.length === 4
      && reactivated.headings[0] === 'Login failed for “alice”: incorrect password.'
      && reactivated.more,
      'reactivation replaces stale/paged rows with a fresh first page');

console.log('\n== Audit filters ==');
const controls = await page.evaluate(() => ({
    labels: Array.from(document.querySelectorAll('#adminAuditFilters label > span'))
        .map(label => label.textContent.trim()),
    events: Array.from(document.getElementById('adminAuditEvent').options)
        .map(option => option.value),
    eventLabels: Object.fromEntries(
        Array.from(document.getElementById('adminAuditEvent').options)
            .map(option => [option.value, option.textContent])),
    searchType: document.getElementById('adminAuditSearch').type,
    beginType: document.getElementById('adminAuditBegin').type,
    endType: document.getElementById('adminAuditEnd').type
}));
check(JSON.stringify(controls.labels) === '["Begin","End","Event","Search"]'
      && controls.searchType === 'search'
      && controls.beginType === 'date'
      && controls.endType === 'date',
      `filter controls use the requested labels and input types (got ${JSON.stringify(controls)})`);
check(controls.events.length === 40
      && controls.events[0] === ''
      && taxonomy.every(item => controls.events.includes(item.action))
      && new Set(Object.values(controls.eventLabels)).size === 40
      && controls.eventLabels['user.controller.add'] === 'Direct Manager Assigned'
      && controls.eventLabels['user.controller.remove'] === 'Direct Manager Removed'
      && controls.eventLabels['share_group.member.add'] === 'Share Group Member Added'
      && controls.eventLabels['mgmt_group.member.add'] === 'Management Group Member Added'
      && controls.eventLabels['share_group.owner.add'] === 'Share Group Manager Added'
      && controls.eventLabels['mgmt_group.manager.add'] === 'Management Group Manager Added'
      && controls.eventLabels['map_share.direct.grant'] === 'Direct Map Access Granted'
      && controls.eventLabels['map_share.direct.change'] === 'Direct Map Access Changed'
      && controls.eventLabels['map_share.direct.remove'] === 'Direct Map Access Removed'
      && controls.eventLabels['map_share.group.grant'] === 'Group Map Access Granted'
      && controls.eventLabels['map_share.group.change'] === 'Group Map Access Changed'
      && controls.eventLabels['map_share.group.remove'] === 'Group Map Access Removed'
      && controls.eventLabels['account.email_verified'] === 'Email Verified'
      && controls.eventLabels['account.password_reset_requested'] === 'Password Reset Requested'
      && controls.eventLabels['account.password_reset'] === 'Email Password Reset'
      && controls.eventLabels['user.resetpwd'] === 'Admin Password Reset',
      'Event dropdown includes every action with an unambiguous label');

await page.selectOption('#adminAuditEvent', 'user.disable');
await page.fill('#adminAuditBegin', '2026-07-01');
await page.fill('#adminAuditEnd', '2026-07-16');
await page.fill('#adminAuditSearch', 'bob');
await page.click('.audit-filter-apply');
await page.waitForTimeout(400);
const filteredQuery = new URL(auditRequests.at(-1), 'http://x').searchParams;
const filtered = await page.evaluate(() => ({
    headings: Array.from(document.querySelectorAll('.audit-row-heading')).map(x => x.textContent),
    more: !!document.querySelector('.audit-load-more')
}));
check(filteredQuery.get('event') === 'user.disable'
      && filteredQuery.get('search') === 'bob'
      && filteredQuery.get('begin') === '2026-06-30T23:00:00.000Z'
      && filteredQuery.get('end') === '2026-07-16T23:00:00.000Z',
      `Apply converts the inclusive local (WEST) date-range to UTC bounds (got ${auditRequests.at(-1)})`);
check(filtered.headings.length === 1
      && filtered.headings[0] === 'boss disabled user “bob”.'
      && filtered.more,
      'filtered results replace the current log and remain human-readable');

await page.click('.audit-load-more');
await page.waitForTimeout(350);
const filteredPageQuery = new URL(auditRequests.at(-1), 'http://x').searchParams;
check(filteredPageQuery.get('event') === 'user.disable'
      && filteredPageQuery.get('search') === 'bob'
      && filteredPageQuery.get('before') === '2',
      `Load more retains active filters (got ${auditRequests.at(-1)})`);
check((await page.locator('.audit-row-heading').allTextContents()).length === 2,
      'filtered pagination appends older matching records');

await page.selectOption('#adminAuditEvent', 'map_share.group.change');
await page.click('.audit-filter-apply');
await page.waitForTimeout(300);
check(new URL(auditRequests.at(-1), 'http://x').searchParams.get('event') === 'map_collab.group.change'
      && !auditRequests.at(-1).includes('share'),
      `share-bearing event filters travel collab-aliased in the URL (got ${auditRequests.at(-1)})`);

const requestsBeforeInvalidRange = auditRequests.length;
await page.fill('#adminAuditBegin', '2026-07-20');
await page.fill('#adminAuditEnd', '2026-07-19');
await page.click('.audit-filter-apply');
await page.waitForTimeout(100);
check(auditRequests.length === requestsBeforeInvalidRange
      && (await page.textContent('#adminAuditFilterError')).includes('on or before'),
      'an invalid date range is explained without issuing a request');

await page.click('#adminAuditClear');
await page.waitForTimeout(400);
const cleared = await page.evaluate(() => ({
    event: document.getElementById('adminAuditEvent').value,
    begin: document.getElementById('adminAuditBegin').value,
    end: document.getElementById('adminAuditEnd').value,
    search: document.getElementById('adminAuditSearch').value,
    headings: document.querySelectorAll('.audit-row-heading').length
}));
check(auditRequests.at(-1) === ''
      && !cleared.event && !cleared.begin && !cleared.end && !cleared.search
      && cleared.headings === 4,
      `Clear resets every filter and reloads the unfiltered log (got ${JSON.stringify(cleared)})`);

console.log('\n== Regular-admin visibility ==');
callerRole = 'admin';
const regular = await browser.newPage({ viewport: { width: 1280, height: 800 } });
await regular.goto(base, { waitUntil:'networkidle' });
await regular.waitForTimeout(1200);
await regular.evaluate(() => document.getElementById('openAdminPanelBtn').click());
await regular.waitForTimeout(300);
check(!(await regular.isVisible('#adminAuditTabBtn')), 'Audit tab is hidden for a regular admin');
check(errors.length === 0, `no page errors (got ${JSON.stringify(errors)})`);

console.log(`\n==== ${PASS} passed, ${FAIL} failed ====`);
await browser.close();
server.close();
process.exit(FAIL ? 1 : 0);
