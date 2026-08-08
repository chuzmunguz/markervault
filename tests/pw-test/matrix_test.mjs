// Per-bullet verification of the viewer/editor permission matrix + bulk share UI.
// Mock backend serves an owned map, an editor-shared map and a viewer-shared map.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const MIME = { '.html':'text/html', '.js':'application/javascript', '.css':'text/css', '.png':'image/png', '.ico':'image/x-icon' };

const MAPS = [
    { id: 4, name: 'Base Map', created: '2026-07-11T09:00:00', description: '', notes: '', markers: 0, is_base: true,  owned: true,  role: 'owner',  owner_username: 'alice', owner_name: 'Alice A', shared: false },
    { id: 5, name: 'My Map',   created: '2026-07-11T10:00:00', description: '', notes: '', markers: 1, is_base: false, owned: true,  role: 'owner',  owner_username: 'alice', owner_name: 'Alice A', shared: true },
    { id: 6, name: 'EdMap',    created: '2026-07-11T11:00:00', description: '', notes: '', markers: 0, is_base: false, owned: false, role: 'editor', owner_username: 'zed', owner_name: 'Zed Z', shared: true },
    { id: 7, name: 'ViewMap',  created: '2026-07-11T12:00:00', description: '', notes: '', markers: 1, is_base: false, owned: false, role: 'viewer', owner_username: 'zed', owner_name: 'Zed Z', shared: true },
    { id: 8, name: 'Plain',    created: '2026-07-11T13:00:00', description: '', notes: '', markers: 0, is_base: false, owned: true,  role: 'owner',  owner_username: 'alice', owner_name: 'Alice A', shared: false },
    { id: 9, name: 'Archive',  created: '2026-07-11T14:00:00', description: '', notes: '', markers: 0, is_base: false, owned: true,  role: 'owner',  owner_username: 'alice', owner_name: 'Alice A', shared: false },
];
const OSPOT = { id: 51, mapID: 5, name: 'OSpot', lat: 39, lng: -2, listing: 'poi', subset: 'a', notes: '', created: '2026-07-11T10:00:00', photo_count: 0 };
const VSPOT = { id: 71, mapID: 7, name: 'VSpot', lat: 40, lng: -3, listing: 'poi', subset: 'a', notes: '', created: '2026-07-11T10:00:00', photo_count: 0 };

let bulkBody = null;
let mapDeleteRequests = [];
let mapSpotReads = [];
let spotDeleteRequests = [];
let createdMapBodies = [];

function sendJSON(res, obj, code=200){ res.writeHead(code, {'Content-Type':'application/json'}); res.end(JSON.stringify(obj)); }

const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const p = u.pathname;

    if (p === '/auth/refresh') return sendJSON(res, { access_token:'faketoken', access_expires_in:900, role:'user', username:'alice', first_name:'Alice', last_name:'A' });
    if (p === '/maps' && req.method === 'GET') return sendJSON(res, MAPS);
    if (p === '/maps' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            const parsed = JSON.parse(body);
            createdMapBodies.push(parsed);
            sendJSON(res, {
                id:10,
                name:parsed.name,
                created:parsed.created || '2026-07-23T00:00:00',
                description:parsed.description || '',
                notes:parsed.notes || '',
                markers:0,
                is_base:false,
                owned:true,
                role:'owner'
            });
        });
        return;
    }
    if (p === '/maps/collaborators' && req.method === 'PUT') {
        let body = '';
        req.on('data', d => body += d);
        req.on('end', () => {
            bulkBody = JSON.parse(body);
            sendJSON(res, { success: true, shared: bulkBody.map_ids.length, username: bulkBody.username, role: bulkBody.role });
        });
        return;
    }
    if (/^\/maps\/\d+\/spots$/.test(p)) {
        mapSpotReads.push(p);
        if (p === '/maps/5/spots') return sendJSON(res, [OSPOT]);
        if (p === '/maps/7/spots') return sendJSON(res, [VSPOT]);
        return sendJSON(res, []);
    }
    if (/^\/maps\/\d+$/.test(p) && req.method === 'DELETE') {
        mapDeleteRequests.push(p);
        return sendJSON(res, { success: true });
    }
    if (/^\/spots\/\d+$/.test(p) && req.method === 'DELETE') {
        spotDeleteRequests.push(p);
        return sendJSON(res, { success: true });
    }
    if (/^\/maps\/\d+\/collaborators$/.test(p) && req.method === 'GET') return sendJSON(res, []);
    if (p === '/users') return sendJSON(res, [{user_id:'u-bob',username:'bob'},{user_id:'u-dave',username:'dave'}]);

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
const page = await browser.newPage();
const pageErrors = [];
page.on('pageerror', e => pageErrors.push(String(e)));

let PASS = 0, FAIL = 0;
function check(cond, label) {
    if (cond) { PASS++; console.log(`  PASS  ${label}`); }
    else { FAIL++; console.log(`  FAIL  ${label}`); }
}

await page.goto(base, { waitUntil: 'networkidle' }).catch(e => pageErrors.push('goto: '+e));
await page.waitForTimeout(1500);

// Helpers usable inside evaluate: expand a map card and list its action-button tips.
const cardTips = (id) => page.evaluate((id) => {
    const item = document.querySelector(`.map-item[data-id="${id}"]`);
    if (!item) return null;
    const t = item.querySelector('.map-toggle');
    if (t && t.dataset.state === 'closed') t.click();
    return Array.from(item.querySelectorAll('button.icon-btn')).map(b => b.dataset.tip);
}, id);

const ctxMenuVisibility = (id) => page.evaluate((id) => {
    const item = document.querySelector(`.map-item[data-id="${id}"]`);
    if (!item) return null;
    item.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, clientX: 420, clientY: 300 }));
    const menu = document.getElementById('sidebarMapContextMenu');
    const vis = {};
    ['details','share','edit','delete'].forEach(k => {
        const el = menu.querySelector(`[data-action="sidebar-map-${k}"]`);
        vis[k] = el ? el.style.display !== 'none' : null;
    });
    document.body.dispatchEvent(new MouseEvent('click', { bubbles: true }));  // close it
    return vis;
}, id);

console.log('\n== A. My Maps group: owner card + 3-dot menu ==');
let tips = await cardTips(5);
check(tips && tips.includes('Share Map') && tips.includes('Edit Map') && tips.includes('Delete Map') && tips.includes('View Details'),
      `owner card shows Info+Share+Edit+Delete (got ${JSON.stringify(tips)})`);
await cardTips(8);   // expand Plain so its buttons exist too
const greenIcons = await page.evaluate(() => ({
    sharedMap: !!document.querySelector('.map-item[data-id="5"] .icon-btn.has-collabs'),
    plainMap: !!document.querySelector('.map-item[data-id="8"] .icon-btn.has-collabs')
}));
check(greenIcons.sharedMap, 'share icon flagged green on an owned map WITH collaborators');
check(!greenIcons.plainMap, 'share icon stays neutral on an owned map WITHOUT collaborators');
let vis = await ctxMenuVisibility(5);
check(vis && vis.details && vis.share && vis.edit && vis.delete, `owner ctx menu: all items (got ${JSON.stringify(vis)})`);
let menuVis = await page.evaluate(() => ({
    create: document.getElementById('sidebar-maps-createMap').style.display !== 'none',
    share:  document.getElementById('sidebar-maps-collabSelected').style.display !== 'none',
    del:    document.getElementById('sidebar-maps-deleteSelected').style.display !== 'none',
    shareLabel: document.getElementById('sidebar-maps-collabSelected').textContent.trim()
}));
check(menuVis.create && menuVis.share && menuVis.del, `3-dot shows Create/Share/Delete in My Maps (got ${JSON.stringify(menuVis)})`);
check(menuVis.shareLabel === 'Share', `bulk item labelled "Share" (got "${menuVis.shareLabel}")`);

console.log('\n== B. Shared with Me group ==');
await page.evaluate(() => setMapGroupFilter('shared', 'Shared with Me'));
await page.waitForTimeout(300);
let ids = await page.evaluate(() => Array.from(document.querySelectorAll('.map-item')).map(i => i.dataset.id));
check(JSON.stringify(ids.sort()) === JSON.stringify(['6','7']), `shared group lists exactly maps 6+7 (got ${ids})`);
menuVis = await page.evaluate(() => ({
    create: document.getElementById('sidebar-maps-createMap').style.display !== 'none',
    share:  document.getElementById('sidebar-maps-collabSelected').style.display !== 'none',
    del:    document.getElementById('sidebar-maps-deleteSelected').style.display !== 'none',
    selectAll: document.getElementById('sidebar-maps-selectAll').style.display !== 'none',
    expand: document.getElementById('sidebar-maps-expandSelected').style.display !== 'none'
}));
check(!menuVis.create && !menuVis.share && !menuVis.del, `3-dot hides Create/Share/Delete in shared group (got ${JSON.stringify(menuVis)})`);
check(menuVis.selectAll && menuVis.expand, '3-dot keeps Select all/Expand in shared group');

tips = await cardTips(6);
check(tips && tips.includes('Edit Map') && tips.includes('View Details') && !tips.includes('Share Map') && !tips.includes('Delete Map'),
      `editor card: Info+Edit only (got ${JSON.stringify(tips)})`);
tips = await cardTips(7);
check(tips && tips.includes('View Details') && !tips.includes('Edit Map') && !tips.includes('Share Map') && !tips.includes('Delete Map'),
      `viewer card: Info only (got ${JSON.stringify(tips)})`);

vis = await ctxMenuVisibility(6);
check(vis && vis.details && !vis.share && vis.edit && !vis.delete, `editor ctx menu: Details+Edit, no Share/Delete (got ${JSON.stringify(vis)})`);
vis = await ctxMenuVisibility(7);
check(vis && vis.details && !vis.share && !vis.edit && !vis.delete, `viewer ctx menu: Details only (got ${JSON.stringify(vis)})`);

console.log('\n== C. Viewer mode marker gating (select ViewMap) ==');
await page.evaluate(() => document.querySelector('.map-item[data-id="7"]').click());
await page.waitForTimeout(800);
let mk = await page.evaluate(() => {
    if (!markers.length) return null;
    const m = markers[0];
    const content = m.getPopup().getContent();
    const tips = Array.from(content.querySelectorAll('button')).map(b => b.dataset.tip);
    return { dragEnabled: m.dragging ? m.dragging.enabled() : 'n/a', tips };
});
check(mk && mk.dragEnabled === false, `stored marker drag disabled for viewer (got ${mk && mk.dragEnabled})`);
check(mk && !mk.tips.includes('Edit Marker') && !mk.tips.includes('Delete Marker') && mk.tips.includes('View Details') && mk.tips.includes('Hide Marker'),
      `stored popup: no Edit/Delete, keeps Copy/Info/Hide (got ${JSON.stringify(mk && mk.tips)})`);

let mvis = await page.evaluate(() => {
    showStoredMarkerContextMenu(markers[0], { clientX: 420, clientY: 300 });
    const menu = document.getElementById('storedMarkerContextMenu');
    const g = a => menu.querySelector(`[data-action="${a}"]`).style.display !== 'none';
    const out = { edit: g('edit-stored-marker'), move: g('move-stored-marker'), del: g('delete-stored-marker'),
                  copy: g('copy-stored-marker'), details: g('view-stored-marker-details') };
    hideStoredMarkerContextMenu();
    return out;
});
check(!mvis.edit && !mvis.move && !mvis.del && mvis.copy && mvis.details,
      `stored ctx menu viewer: no Edit/Move/Delete, keeps Details/Copy (got ${JSON.stringify(mvis)})`);

mvis = await page.evaluate(() => {
    showSidebarMarkerContextMenu({ dataset: { id: '71' }, markerObject: markers[0].data }, { clientX: 420, clientY: 300 });
    const menu = document.getElementById('sidebarMarkerContextMenu');
    const g = a => menu.querySelector(`[data-action="${a}"]`).style.display !== 'none';
    const out = { edit: g('sidebar-marker-edit'), move: g('sidebar-marker-move'), del: g('sidebar-marker-delete'), copy: g('sidebar-marker-copy') };
    hideSidebarMarkerContextMenu();
    return out;
});
check(!mvis.edit && !mvis.move && !mvis.del && mvis.copy,
      `sidebar marker ctx menu viewer: no Edit/Move/Delete (got ${JSON.stringify(mvis)})`);

mvis = await page.evaluate(() => {
    showTempMarkerContextMenu({}, { clientX: 420, clientY: 300 });
    const t = document.querySelector('#tempMarkerContextMenu [data-action="save-temp-marker"]').style.display !== 'none';
    hideTempMarkerContextMenu();
    showSearchMarkerContextMenu({}, { clientX: 420, clientY: 300 });
    const s = document.querySelector('#searchMarkerContextMenu [data-action="save-search-marker"]').style.display !== 'none';
    hideSearchMarkerContextMenu();
    const popup = buildTempPopupHTML('x');
    const saveHidden = popup.querySelector('.save-btn').style.display === 'none';
    return { tempSave: t, searchSave: s, popupSaveHidden: saveHidden };
});
check(!mvis.tempSave, 'temp ctx menu viewer: Save hidden');
check(!mvis.searchSave, 'search ctx menu viewer: Save hidden');
check(mvis.popupSaveHidden, 'temp/search popup viewer: Save hidden');

const markersMenuViewer = await page.evaluate(() => {
    const g = id => document.getElementById(id).style.display !== 'none';
    return { importKml: g('sidebar-markers-importMarkers'), importGml: g('sidebar-markers-importGoogleMapsLink'),
             move: g('sidebar-markers-moveSelected'), del: g('sidebar-markers-deleteSelected'),
             copy: g('sidebar-markers-copySelected'), show: g('sidebar-markers-showSelected'),
             hide: g('sidebar-markers-hideSelected'), selectAll: g('sidebar-markers-selectAll') };
});
check(!markersMenuViewer.importKml && !markersMenuViewer.importGml && !markersMenuViewer.move && !markersMenuViewer.del,
      `markers 3-dot viewer: Import x2/Move/Delete hidden (got ${JSON.stringify(markersMenuViewer)})`);
check(markersMenuViewer.copy && markersMenuViewer.show && markersMenuViewer.hide && markersMenuViewer.selectAll,
      'markers 3-dot viewer: Copy/Show/Hide/Select-all stay');

console.log('\n== D. Owner mode: everything back ==');
await page.evaluate(() => setMapGroupFilter('mine', 'My Maps'));
await page.waitForTimeout(300);
await page.evaluate(() => document.querySelector('.map-item[data-id="5"]').click());
await page.waitForTimeout(500);
mvis = await page.evaluate(() => {
    showStoredMarkerContextMenu({}, { clientX: 420, clientY: 300 });
    const menu = document.getElementById('storedMarkerContextMenu');
    const g = a => menu.querySelector(`[data-action="${a}"]`).style.display !== 'none';
    const out = { edit: g('edit-stored-marker'), move: g('move-stored-marker'), del: g('delete-stored-marker') };
    hideStoredMarkerContextMenu();
    showTempMarkerContextMenu({}, { clientX: 420, clientY: 300 });
    out.tempSave = document.querySelector('#tempMarkerContextMenu [data-action="save-temp-marker"]').style.display !== 'none';
    hideTempMarkerContextMenu();
    const popup = buildTempPopupHTML('x');
    out.popupSaveShown = popup.querySelector('.save-btn').style.display !== 'none';
    const stored = buildMarkerPopupHTML({ data: { id: 1, name: 'x', lat: 1, lng: 1, created: '2026-07-11T10:00:00', photo_count: 0 } });
    const tips = Array.from(stored.querySelectorAll('button')).map(b => b.dataset.tip);
    out.storedEditDelete = tips.includes('Edit Marker') && tips.includes('Delete Marker');
    return out;
});
check(mvis.edit && mvis.move && mvis.del, `owner: stored ctx menu items back (got ${JSON.stringify(mvis)})`);
check(mvis.tempSave && mvis.popupSaveShown, 'owner: Save back in temp ctx menu + popup');
check(mvis.storedEditDelete, 'owner: stored popup has Edit+Delete again');

const markersMenuOwner = await page.evaluate(() => {
    const g = id => document.getElementById(id).style.display !== 'none';
    return g('sidebar-markers-importMarkers') && g('sidebar-markers-importGoogleMapsLink')
        && g('sidebar-markers-moveSelected') && g('sidebar-markers-deleteSelected');
});
check(markersMenuOwner, 'markers 3-dot owner: Import x2/Move/Delete back');

console.log('\n== E. Bulk share flow ==');
const bulk = await page.evaluate(async () => {
    openBulkShareOverlay([5]);
    await new Promise(r => setTimeout(r, 500));
    const out = {
        title: document.getElementById('collabOverlayTitle').textContent,
        list: document.getElementById('collabList').textContent,
        active: document.getElementById('collabOverlay').classList.contains('active')
    };
    // exact typed text resolves without clicking a result (the fallback path)
    document.getElementById('collabTypeSelect').value = 'user';
    const input = document.querySelector('#collabPickerBox .filter-picker input');
    input.value = 'bob';
    input.dispatchEvent(new Event('input'));
    document.getElementById('collabAddRole').value = 'editor';
    document.getElementById('collabAddBtn').click();
    await new Promise(r => setTimeout(r, 500));
    return out;
});
check(bulk.active && bulk.title === 'Share 1 map', `bulk overlay opens with title (got "${bulk.title}")`);
check(bulk.list.startsWith('Applies to: My Map'), `bulk overlay names the maps (got "${bulk.list}")`);
check(bulkBody && JSON.stringify(bulkBody.map_ids) === '[5]' && bulkBody.username === 'bob' && bulkBody.role === 'editor',
      `PUT /maps/collaborators got {map_ids:[5], bob, editor} (got ${JSON.stringify(bulkBody)})`);

console.log('\n== G. Open popup closes when switching maps ==');
const popupClosed = await page.evaluate(async () => {
    closeShareOverlay();
    const tm = L.marker([40, -3]).addTo(map).bindPopup('stale-popup').openPopup();
    await new Promise(r => setTimeout(r, 200));
    const openBefore = tm.isPopupOpen();
    setMapGroupFilter('shared', 'Shared with Me');
    await new Promise(r => setTimeout(r, 200));
    document.querySelector('.map-item[data-id="7"]').click();
    await new Promise(r => setTimeout(r, 600));
    const openAfter = tm.isPopupOpen();
    map.removeLayer(tm);
    return { openBefore, openAfter };
});
check(popupClosed.openBefore === true && popupClosed.openAfter === false,
      `popup open before map switch, closed after (got ${JSON.stringify(popupClosed)})`);

console.log('\n== H. Bulk share filters out the Base Map ==');
const bulkFilter = await page.evaluate(async () => {
    setMapGroupFilter('mine', 'My Maps');
    await new Promise(r => setTimeout(r, 200));
    // Check the base map (4) AND an owned map (5), like a select-all would.
    document.querySelectorAll('.map-item').forEach(item => {
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.className = 'map-checkbox';
        cb.dataset.id = item.dataset.id;
        cb.checked = ['4', '5'].includes(item.dataset.id);
        item.querySelector('.map-card').prepend(cb);
    });
    document.getElementById('sidebar-maps-collabSelected').click();
    await new Promise(r => setTimeout(r, 400));
    const out = {
        title: document.getElementById('collabOverlayTitle').textContent,
        list: document.getElementById('collabList').textContent
    };
    closeShareOverlay();
    return out;
});
check(bulkFilter.title === 'Share 1 map' && bulkFilter.list.startsWith('Applies to: My Map') && !bulkFilter.list.includes('Base Map'),
      `Base Map filtered from bulk selection (got ${JSON.stringify(bulkFilter)})`);

console.log('\n== H2. Map deletion leaves child cascades to the backend ==');
mapDeleteRequests = [];
mapSpotReads = [];
spotDeleteRequests = [];
await page.evaluate(() => {
    document.querySelectorAll('.map-checkbox').forEach(cb => {
        cb.checked = ['8', '9'].includes(cb.dataset.id);
    });
    document.getElementById('sidebar-maps-deleteSelected').click();
});
await page.locator('.confirmation-notif .btn-confirm').click();
await page.waitForTimeout(400);
check(
    JSON.stringify(mapDeleteRequests) === '["/maps/8","/maps/9"]'
    && !mapSpotReads.includes('/maps/8/spots')
    && !mapSpotReads.includes('/maps/9/spots')
    && spotDeleteRequests.length === 0,
    `bulk map delete sends one DELETE per map with no child reads/deletes (maps ${JSON.stringify(mapDeleteRequests)}, reads ${JSON.stringify(mapSpotReads)}, spots ${JSON.stringify(spotDeleteRequests)})`,
);

await page.evaluate(() => document.querySelector('.map-item[data-id="5"]').click());
await page.waitForTimeout(400);
mapDeleteRequests = [];
mapSpotReads = [];
spotDeleteRequests = [];
await page.evaluate(() => deleteMap(5));
await page.locator('.confirmation-notif .btn-confirm').click();
await page.waitForTimeout(400);
check(
    JSON.stringify(mapDeleteRequests) === '["/maps/5"]'
    && spotDeleteRequests.length === 0,
    `single map delete sends one map DELETE and no marker DELETEs (maps ${JSON.stringify(mapDeleteRequests)}, spots ${JSON.stringify(spotDeleteRequests)})`,
);
await page.evaluate(() => document.getElementById('sidebar-maps-createMap').click());
await page.fill('#addMapName', 'Replacement');
await page.click('#addMapForm button[type="submit"]');
await page.waitForFunction(() => !!document.querySelector('.map-item[data-id="10"]'));
const postCreateMaps = await page.evaluate(() => ({
    state:maps.map(map => map.id),
    sidebar:Array.from(document.querySelectorAll('.map-item')).map(item => Number(item.dataset.id))
}));
check(
    JSON.stringify(createdMapBodies.map(body => body.name)) === '["Replacement"]'
    && JSON.stringify(postCreateMaps.state) === '[4,6,7,10]'
    && JSON.stringify(postCreateMaps.sidebar) === '[4,10]',
    `creating after deletions cannot resurrect stale maps (${JSON.stringify(postCreateMaps)})`,
);

console.log('\n== I. Stale form state: boot reset + login autocomplete ==');
const staleReset = await page.evaluate(() => {
    const poi = document.getElementById('poiInput');
    const login = document.getElementById('authLoginUsername');
    poi.value = 'leftover search';
    login.value = 'previous-user';
    resetStaleFormState();
    return {
        poi: poi.value,
        login: login.value,
        autocomplete: login.getAttribute('autocomplete')
    };
});
check(staleReset.poi === '' && staleReset.login === '', `boot reset clears formless inputs + form fields (got ${JSON.stringify(staleReset)})`);
check(staleReset.autocomplete === 'off', `login username autocomplete=off (got "${staleReset.autocomplete}")`);

console.log('\n== F. No uncaught page errors ==');
check(pageErrors.length === 0, pageErrors.length ? `page errors: ${pageErrors.join(' | ')}` : 'no page errors');

console.log(`\n==== ${PASS} passed, ${FAIL} failed ====`);
await browser.close();
server.close();
process.exit(FAIL ? 1 : 0);
