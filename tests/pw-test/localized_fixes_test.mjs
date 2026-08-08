// Localized correctness checks: document layout, auth/KML wiring, and popup/gallery lifecycle.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const MIME = {
    '.html':'text/html', '.js':'application/javascript', '.css':'text/css',
    '.png':'image/png', '.jpg':'image/jpeg', '.ico':'image/x-icon'
};
const MAPS = [
    {
        id:4, name:'Base Map', created:'2026-07-19T00:00:00', description:'',
        notes:'', markers:0, is_base:true, owned:true, role:'owner',
        owner_username:'alice', owner_name:'Alice A', shared:false
    },
    {
        id:7, name:'Viewer Map', created:'2026-07-19T00:00:00', description:'',
        notes:'', markers:0, is_base:false, owned:false, role:'viewer',
        owner_username:'bob', owner_name:'Bob B', shared:true
    }
];
const GALLERY_PHOTOS = [1, 2, 3].map(index => ({
    filename:`gallery-${index}.jpg`,
    caption:`Gallery photo ${index}`,
    photo_url:`/assets/images/default-user-thumb.png?gallery=${index}`,
    thumb_url:`/assets/images/default-user-thumb.png?gallery=${index}`
}));

let parseMode = 'success';
let kmlMode = 'valid';
let queuedPolls = 0;
let logoutStatus = 503;
let documentRequests = 0;
const parseRequests = [];
const kmlRequests = [];
const kmlStatusRequests = [];
const logoutRequests = [];

function sendJSON(res, object, status=200) {
    res.writeHead(status, {'Content-Type':'application/json'});
    res.end(JSON.stringify(object));
}

function readBody(req, callback) {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => callback(body));
}

const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    const route = url.pathname;

    if (route === '/auth/refresh') {
        return sendJSON(res, {
            access_token:'faketoken',
            access_expires_in:900,
            role:'user',
            username:'alice',
            first_name:'Alice',
            last_name:'A'
        });
    }
    if (route === '/auth/logout') {
        logoutRequests.push({
            authorization:req.headers.authorization || '',
            method:req.method
        });
        return sendJSON(res, {error:'Temporary logout failure'}, logoutStatus);
    }
    if (route === '/maps' && req.method === 'GET') return sendJSON(res, MAPS);
    if (route === '/spots/401/photos') return sendJSON(res, GALLERY_PHOTOS);
    if (/^\/maps\/\d+\/spots$/.test(route)) return sendJSON(res, []);
    if (/^\/maps\/\d+\/collaborators$/.test(route)) return sendJSON(res, []);
    if (route === '/users') return sendJSON(res, []);

    if (route === '/parse-maps-link' && req.method === 'POST') {
        return readBody(req, body => {
            parseRequests.push({
                authorization:req.headers.authorization || '',
                body:JSON.parse(body)
            });
            if (parseMode === 'error') {
                return sendJSON(res, {error:'Unsupported test link'}, 400);
            }
            return sendJSON(res, {
                expanded_url:'https://maps.google.test/@40.1,-3.2,15z',
                latitude:40.1,
                longitude:-3.2
            });
        });
    }

    if (route === '/import_kml' && req.method === 'POST') {
        kmlRequests.push({
            authorization:req.headers.authorization || '',
            mode:kmlMode
        });
        req.resume();
        if (kmlMode === '400') return sendJSON(res, {error:'Rejected test KML'}, 400);
        if (kmlMode === '401') return sendJSON(res, {error:'Unauthorized'}, 401);
        if (kmlMode === '413') return sendJSON(res, {error:'oversized'}, 413);
        if (kmlMode === '429') return sendJSON(res, {error:'limited'}, 429);
        if (kmlMode === 'malformed') {
            res.writeHead(200, {'Content-Type':'application/json'});
            return res.end('{not-json');
        }
        if (kmlMode === 'skips') return sendJSON(res, {job_id:'job-skips', message:'KML import started'});
        if (kmlMode === 'queued') return sendJSON(res, {job_id:'job-queued', message:'KML import started'});
        if (kmlMode === 'gone') return sendJSON(res, {job_id:'job-gone', message:'KML import started'});
        if (kmlMode === 'weird') return sendJSON(res, {job_id:'job-weird', message:'KML import started'});
        return sendJSON(res, {job_id:'job-ok', message:'KML import started'});
    }
    if (route === '/import_kml_status/job-ok') {
        kmlStatusRequests.push({
            authorization:req.headers.authorization || '',
            route
        });
        return sendJSON(res, {
            imported:0,
            total:0,
            skipped:0,
            photos_failed:0,
            progress:100,
            status:'done',
            error:null
        });
    }
    if (route === '/import_kml_status/job-skips') {
        kmlStatusRequests.push({
            authorization:req.headers.authorization || '',
            route
        });
        return sendJSON(res, {
            imported:30,
            total:35,
            skipped:5,
            photos_failed:2,
            photos_budget_skipped:3,
            progress:100,
            status:'done',
            error:null
        });
    }
    if (route === '/import_kml_status/job-queued') {
        kmlStatusRequests.push({
            authorization:req.headers.authorization || '',
            route
        });
        queuedPolls += 1;
        if (queuedPolls === 1) {
            return sendJSON(res, {
                imported:0, total:0, skipped:0, photos_failed:0,
                progress:0, status:'queued', error:null
            });
        }
        return sendJSON(res, {
            imported:2, total:2, skipped:0, photos_failed:0,
            progress:100, status:'done', error:null
        });
    }
    if (route === '/import_kml_status/job-gone') {
        kmlStatusRequests.push({
            authorization:req.headers.authorization || '',
            route
        });
        return sendJSON(res, {error:'Job not found'}, 404);
    }
    if (route === '/import_kml_status/job-weird') {
        kmlStatusRequests.push({
            authorization:req.headers.authorization || '',
            route
        });
        return sendJSON(res, {status:'sideways'});
    }
    if (route.startsWith('/import_kml_status/')) {
        kmlStatusRequests.push({
            authorization:req.headers.authorization || '',
            route
        });
        return sendJSON(res, {error:'unexpected status route'}, 500);
    }

    const filePath = route === '/' ? '/index.html' : route;
    const fullPath = path.join(ROOT, filePath);
    if (route === '/') documentRequests += 1;
    if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
        res.writeHead(200, {
            'Content-Type':MIME[path.extname(fullPath)] || 'text/plain'
        });
        return res.end(fs.readFileSync(fullPath));
    }
    res.writeHead(200, {'Content-Type':'application/javascript'});
    res.end('');
});

await new Promise(resolve => server.listen(0, resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
const page = await browser.newPage({viewport:{width:1280, height:900}});
const pageErrors = [];
page.on('pageerror', error => pageErrors.push(String(error)));

await page.addInitScript(() => {
    Object.defineProperty(navigator, 'clipboard', {
        configurable:true,
        value:{
            readText:async () => 'https://maps.app.goo.gl/stage3'
        }
    });
});
await page.route('https://nominatim.openstreetmap.org/**', route => {
    route.fulfill({
        status:200,
        contentType:'application/json',
        body:JSON.stringify({
            name:'Stage Three',
            address:{city:'Test City'}
        })
    });
});

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

async function clearNotifications() {
    await page.evaluate(() => {
        document.getElementById('notification-container').replaceChildren();
    });
}

async function clickMapsImport() {
    await page.evaluate(() => {
        Object.defineProperty(navigator, 'clipboard', {
            configurable:true,
            value:{
                readText:async () => 'https://maps.app.goo.gl/stage3'
            }
        });
        document.getElementById('sidebar-markers-importGoogleMapsLink').click();
    });
}

async function uploadKml() {
    await page.evaluate(() => {
        const originalClick = HTMLInputElement.prototype.click;
        HTMLInputElement.prototype.click = function() {
            if (this.accept === '.kml') {
                const transfer = new DataTransfer();
                transfer.items.add(new File(
                    ['<?xml version="1.0"?><kml></kml>'],
                    'stage3.kml',
                    {type:'application/vnd.google-earth.kml+xml'}
                ));
                this.files = transfer.files;
                this.dispatchEvent(new Event('change'));
                return;
            }
            originalClick.call(this);
        };
        document.getElementById('sidebar-markers-importMarkers').click();
        HTMLInputElement.prototype.click = originalClick;
    });
}

async function expectKmlFailure(mode, message) {
    kmlMode = mode;
    const statusCount = kmlStatusRequests.length;
    await clearNotifications();
    await uploadKml();
    await page.waitForFunction(expected =>
        Array.from(document.querySelectorAll('.notification'))
            .some(notification => notification.textContent === expected),
    message);
    const state = await page.evaluate(() => ({
        notifications:Array.from(document.querySelectorAll('.notification'))
            .map(notification => notification.textContent),
        progress:document.querySelectorAll('.progress-notif').length
    }));
    return {
        messageShown:state.notifications.includes(message),
        progress:state.progress,
        statusDelta:kmlStatusRequests.length - statusCount
    };
}

await page.goto(base, {waitUntil:'networkidle'});
await page.waitForFunction(() => selectedMapID === 4);

const expectedBodyOrder = [
    'addMapOverlay',
    'editMapOverlay',
    'mapDetailsOverlay',
    'addMarkerOverlay',
    'editMarkerOverlay',
    'markerDetailsOverlay',
    'copyMarkersOverlay',
    'moveMarkersOverlay',
    'managePhotosOverlay',
    'busyOverlay',
    'authScreen',
    'limitScreen',
    'unsupportedScreen',
    'adminScreen',
    'createUserOverlay',
    'editUserOverlay',
    'resetPwdOverlay',
    'collabOverlay',
    'profileOverlay',
    'deleteAccountOverlay',
    'changePwdOverlay',
    'notifHistoryOverlay',
    'notification-container',
    'sidebarMapContextMenu',
    'sidebarMarkerContextMenu',
    'mapContextMenu',
    'storedMarkerContextMenu',
    'tempMarkerContextMenu',
    'searchMarkerContextMenu',
    'map',
    'script:assets/leaflet.js',
    'script:assets/Leaflet.PolylineMeasure.js',
    'script:assets/leaflet-routing-machine.js',
    'script:assets/swiper-bundle.min.js',
    'script:assets/glightbox.js',
    'script:frontend.js',
    'script:3p-layers.js'
];
const bodyOrder = await page.evaluate(() =>
    Array.from(document.body.children).map(element =>
        element.id || `script:${element.getAttribute('src')}`
    )
);
const viewportContent = await page.locator('meta[name="viewport"]').getAttribute('content');

console.log('\n== Valid document structure and viewport ==');
check(
    viewportContent === 'width=device-width, initial-scale=1',
    `responsive viewport metadata is exact (${viewportContent})`
);
check(
    JSON.stringify(bodyOrder) === JSON.stringify(expectedBodyOrder),
    'parser preserves the complete overlay, application, and script order'
);

const stackOrder = await page.evaluate(() => {
    const z = id => Number(getComputedStyle(document.getElementById(id)).zIndex);
    return {
        admin:z('adminScreen'),
        addMap:z('addMapOverlay'),
        createUser:z('createUserOverlay'),
        profile:z('profileOverlay'),
        changePassword:z('changePwdOverlay'),
        auth:z('authScreen'),
        photos:z('managePhotosOverlay'),
        busy:z('busyOverlay')
    };
});
check(
    JSON.stringify(stackOrder)
    === '{"admin":2500,"addMap":3000,"createUser":3100,"profile":3000,"changePassword":3100,"auth":4000,"photos":4000,"busy":5000}',
    `overlay stacking remains unchanged (${JSON.stringify(stackOrder)})`
);

await page.evaluate(() =>
    document.getElementById('sidebar-maps-createMap').click()
);
await page.waitForFunction(() =>
    document.getElementById('addMapOverlay').classList.contains('active')
);
check(
    await page.evaluate(() => document.activeElement?.id) === 'addMapName',
    'opening a moved overlay still focuses its intended first field'
);
await page.evaluate(() => closeAddMapOverlay());
await page.waitForFunction(() =>
    document.getElementById('addMapOverlay').style.display === 'none'
);

const mobileContext = await browser.newContext({
    viewport:{width:390, height:844},
    screen:{width:390, height:844},
    deviceScaleFactor:3,
    isMobile:true,
    hasTouch:true,
    javaScriptEnabled:false
});
const mobilePage = await mobileContext.newPage();
await mobilePage.goto(base, {waitUntil:'domcontentloaded'});
const mobileState = await mobilePage.evaluate(() => ({
    innerWidth,
    clientWidth:document.documentElement.clientWidth,
    visualWidth:visualViewport.width,
    screenWidth:screen.width,
    bodyOrder:Array.from(document.body.children).map(element =>
        element.id || `script:${element.getAttribute('src')}`
    )
}));
check(
    mobileState.innerWidth === 390
    && mobileState.clientWidth === 390
    && mobileState.visualWidth === 390
    && mobileState.screenWidth === 390,
    `mobile layout viewport uses device width (${JSON.stringify(mobileState)})`
);
check(
    JSON.stringify(mobileState.bodyOrder) === JSON.stringify(expectedBodyOrder),
    'mobile parsing preserves the same complete body order'
);
const mobileTabs = await mobilePage.evaluate(() => {
    const screen = document.getElementById('adminScreen');
    const strip = document.querySelector('.admin-tabs');
    const management = document.getElementById('adminMgmtTabBtn');
    const audit = document.getElementById('adminAuditTabBtn');
    screen.style.display = 'flex';
    management.style.display = '';
    audit.style.display = '';
    strip.scrollLeft = strip.scrollWidth;
    const stripRect = strip.getBoundingClientRect();
    const auditRect = audit.getBoundingClientRect();
    return {
        clientWidth:strip.clientWidth,
        scrollWidth:strip.scrollWidth,
        scrollLeft:strip.scrollLeft,
        stripLeft:stripRect.left,
        stripRight:stripRect.right,
        auditLeft:auditRect.left,
        auditRight:auditRect.right,
        auditVisible:auditRect.left >= stripRect.left
            && auditRect.right <= stripRect.right + 0.5
    };
});
check(
    mobileTabs.scrollWidth > mobileTabs.clientWidth
    && mobileTabs.scrollLeft > 0
    && mobileTabs.auditVisible,
    `mobile administrators can scroll the existing tab strip to Audit (${JSON.stringify(mobileTabs)})`
);
await mobileContext.close();

// The retired geocoder's own absence is asserted in "Routing without the retired
// geocoder" below, where the library rather than one of its elements is checked.
const routingState = await page.evaluate(() => ({
    active:Boolean(routingControl),
    closeButton:Boolean(document.querySelector('.close-route-btn')),
    collapseButton:Boolean(document.querySelector('.collapse-route-btn'))
}));
check(
    routingState.active
    && routingState.closeButton
    && !routingState.collapseButton,
    `routing keeps its active control without a hidden collapse control (${JSON.stringify(routingState)})`
);

console.log('\n== Authenticated Google Maps-link import ==');
const parseResponse = page.waitForResponse(
    response => response.url().endsWith('/parse-maps-link')
);
await clickMapsImport();
await parseResponse;
await page.waitForFunction(() => temporaryMarkers.length > 0);
check(
    parseRequests.length === 1
    && parseRequests[0].authorization === 'Bearer faketoken',
    `Maps-link request carries the access token (${JSON.stringify(parseRequests[0])})`
);
check(
    parseRequests[0]?.body?.url === 'https://maps.app.goo.gl/stage3',
    'Maps-link request preserves the clipboard URL'
);

parseMode = 'error';
await clearNotifications();
await clickMapsImport();
await page.waitForFunction(() =>
    Array.from(document.querySelectorAll('.notification'))
        .some(notification =>
            notification.textContent ===
            'Error importing Google Maps link: Unsupported test link'
        )
);
const parseError = await page.evaluate(() =>
    Array.from(document.querySelectorAll('.notification'))
        .map(notification => notification.textContent)
);
check(
    parseError.includes('Error importing Google Maps link: Unsupported test link'),
    'Maps-link failure shows the bounded server error'
);

console.log('\n== KML initial-response validation ==');
const kmlCases = [
    ['400', 'Rejected test KML'],
    ['401', 'Your session expired. Please sign in again.'],
    ['413', 'The KML file is too large.'],
    ['429', 'Too many KML imports. Please try again shortly.'],
    ['malformed', 'KML upload returned an invalid response.']
];
for (const [mode, message] of kmlCases) {
    const result = await expectKmlFailure(mode, message);
    check(
        result.messageShown && result.progress === 0 && result.statusDelta === 0,
        `${mode} response fails directly without progress polling (${JSON.stringify(result)})`
    );
}
check(
    kmlRequests.every(request => request.authorization === 'Bearer faketoken'),
    'every KML upload attempt carries the access token'
);
check(
    !kmlStatusRequests.some(request => request.route.includes('undefined')),
    'malformed starts never poll an undefined job'
);

kmlMode = 'valid';
const statusBefore = kmlStatusRequests.length;
await clearNotifications();
await uploadKml();
await page.waitForFunction(() =>
    document.querySelector('.progress-text')?.textContent === 'Imported 0 / 0 markers'
);
check(
    kmlStatusRequests.length === statusBefore + 1
    && kmlStatusRequests.at(-1).route === '/import_kml_status/job-ok'
    && kmlStatusRequests.at(-1).authorization === 'Bearer faketoken',
    'valid KML start polls only its validated job ID'
);

kmlMode = 'skips';
await clearNotifications();
await uploadKml();
await page.waitForFunction(() =>
    document.querySelector('.progress-text')?.textContent
        === 'Imported 30 / 35 markers (5 skipped, 2 photos failed, 3 photos skipped: download limit reached)'
);
check(
    kmlStatusRequests.at(-1).route === '/import_kml_status/job-skips',
    'a completed import surfaces its compact skip, photo-failure and budget-skip counts'
);
const sidebarSync = await page.evaluate(() => {
    const cached = maps.find(m => String(m.id) === '4');
    renderGroupedMaps();
    const rendered = document.querySelector(".map-item[data-id='4'] .marker-count");
    return {
        cached:cached ? cached.markers : null,
        rendered:rendered ? rendered.textContent : null
    };
});
check(
    sidebarSync.cached === 30 && sidebarSync.rendered === '30',
    `the imported count lands in the maps cache and survives a sidebar re-render (${JSON.stringify(sidebarSync)})`
);

console.log('\n== KML polling termination (S-09) ==');
kmlMode = 'queued';
await clearNotifications();
await uploadKml();
await page.waitForFunction(() =>
    document.querySelector('.progress-text')?.textContent === 'Waiting for an import slot...'
);
await page.waitForFunction(() =>
    document.querySelector('.progress-text')?.textContent === 'Imported 2 / 2 markers'
);
check(
    kmlStatusRequests.filter(request => request.route === '/import_kml_status/job-queued').length === 2,
    'a queued job shows the waiting text and polls through to completion'
);

kmlMode = 'gone';
await clearNotifications();
await uploadKml();
await page.waitForFunction(expected =>
    Array.from(document.querySelectorAll('.notification'))
        .some(notification => notification.textContent === expected),
'KML import failed');
await page.waitForFunction(() => document.querySelectorAll('.progress-notif').length === 0);
check(
    kmlStatusRequests.filter(request => request.route === '/import_kml_status/job-gone').length === 1,
    'a lost job stops immediately on 404 and removes its progress bar'
);

kmlMode = 'weird';
await clearNotifications();
await uploadKml();
await page.waitForFunction(expected =>
    Array.from(document.querySelectorAll('.notification'))
        .some(notification => notification.textContent === expected),
'KML import status unavailable');
check(
    kmlStatusRequests.filter(request => request.route === '/import_kml_status/job-weird').length === 5,
    'unknown status values stop after the bounded retry budget'
);

const settledPollCount = kmlStatusRequests.length;
await page.waitForTimeout(2500);
check(
    kmlStatusRequests.length === settledPollCount,
    'no KML polling survives after termination'
);

console.log('\n== Popup action lifecycle ==');
const tempCounts = await page.evaluate(async () => {
    temporaryMarkers.forEach(marker => marker.remove());
    temporaryMarkers = [];
    const counts = {copy:0, save:0, delete:0};
    copyCoordinates = () => counts.copy += 1;
    saveTempMarker = () => counts.save += 1;
    deleteTempMarker = () => counts.delete += 1;
    await addTempMarker(41.1, -8.6);
    const marker = temporaryMarkers[0];
    for (let index = 0; index < 3; index += 1) {
        marker.closePopup();
        marker.openPopup();
    }
    const popup = marker.getPopup().getContent();
    popup.querySelector('.copy-btn').click();
    popup.querySelector('.save-btn').click();
    popup.querySelector('.delete-btn').click();

    marker.closePopup();
    selectedMapID = 7;
    marker.openPopup();
    const viewerHidden = popup.querySelector('.save-btn').style.display === 'none';
    marker.closePopup();
    selectedMapID = 4;
    marker.openPopup();
    const ownerShown = popup.querySelector('.save-btn').style.display !== 'none';
    return {counts, viewerHidden, ownerShown, name:marker.name};
});
check(
    JSON.stringify(tempCounts.counts) === '{"copy":1,"save":1,"delete":1}',
    `temporary-marker actions fire once after repeated opens (${JSON.stringify(tempCounts)})`
);
check(
    tempCounts.viewerHidden && tempCounts.ownerShown,
    'temporary-marker save visibility is rechecked without rebinding actions'
);
check(
    tempCounts.name === 'Stage Three, Test City',
    `temporary-marker reverse-geocode label is preserved (${tempCounts.name})`
);

const searchCounts = await page.evaluate(async () => {
    const counts = {copy:0, save:0, delete:0};
    copyCoordinates = () => counts.copy += 1;
    saveSearchMarker = () => counts.save += 1;
    deleteSearchMarker = () => counts.delete += 1;
    await addSearchMarker('42.1, -7.6');
    const marker = searchMarkers[0];
    marker.openPopup();
    for (let index = 0; index < 3; index += 1) {
        marker.closePopup();
        marker.openPopup();
    }
    const popup = marker.getPopup().getContent();
    popup.querySelector('.copy-btn').click();
    popup.querySelector('.save-btn').click();
    popup.querySelector('.delete-btn').click();
    return {counts, name:marker.name};
});
check(
    JSON.stringify(searchCounts.counts) === '{"copy":1,"save":1,"delete":1}',
    `search-marker actions fire once after repeated opens (${JSON.stringify(searchCounts)})`
);
check(
    searchCounts.name === '42.100000, -7.600000',
    `coordinate-search label remains coordinate-only (${searchCounts.name})`
);

console.log('\n== Gallery/lightbox synchronization ==');
await page.evaluate(() => {
    markers.push({
        data:{
            id:401,
            name:'Gallery Marker',
            listing:'Test',
            subset:'Synchronization',
            created:'2026-07-19T00:00:00Z',
            lat:42.1,
            lng:-7.6,
            notes:''
        }
    });
    return openMarkerDetailsOverlay(401);
});
await page.waitForFunction(() =>
    window.spotSwiper?.slides?.length === 3
);
await page.locator('.mySwiper .swiper-slide').nth(0).locator('a.glightbox').click();
await page.evaluate(() => {
    document.querySelector('.gnext').click();
    document.querySelector('.gnext').click();
});
await page.waitForFunction(() => {
    const slides = Array.from(document.querySelectorAll('.gslide'));
    return slides.indexOf(document.querySelector('.gslide.current')) === 2;
});
await page.waitForTimeout(1000);
check(
    await page.evaluate(() => window.spotSwiper?.activeIndex) === 2,
    'rapid forward lightbox navigation synchronizes the last marker-details photo'
);

await page.evaluate(() => {
    document.querySelector('.gprev').click();
    document.querySelector('.gprev').click();
});
await page.waitForFunction(() => {
    const slides = Array.from(document.querySelectorAll('.gslide'));
    return slides.indexOf(document.querySelector('.gslide.current')) === 0;
});
await page.waitForTimeout(1000);
await page.locator('.gclose').click();
await page.waitForFunction(() => !document.body.classList.contains('glightbox-open'));
check(
    await page.evaluate(() => window.spotSwiper?.activeIndex) === 0,
    'rapid backward navigation and close still synchronize the first gallery photo'
);
await page.evaluate(() => closeDetailsOverlay());

console.log('\n== Routing without the retired geocoder ==');
// Control.Geocoder was retired because Routing Machine's callback API could never
// consume its promises. Routing itself never depended on it: waypoints arrive as
// coordinates from the app's own geocodeAddress(), and the route comes from OSRM.
await page.route('**/router.project-osrm.org/**', route => route.fulfill({
    status:200,
    contentType:'application/json',
    body:JSON.stringify({
        code:'Ok',
        waypoints:[{name:'A', location:[-8.6109, 41.1496], hint:''}, {name:'B', location:[-9.1393, 38.7223], hint:''}],
        routes:[{
            geometry:'ynb`Fj~qu@~xdEnb_R',
            legs:[{steps:[], summary:'A - B', distance:312000, duration:12500}],
            distance:312000,
            duration:12500,
            weight:12500,
            weight_name:'routability'
        }]
    })
}));
await page.evaluate(() =>
    routingControl.setWaypoints([L.latLng(41.1496, -8.6109), L.latLng(38.7223, -9.1393)])
);
await page.waitForFunction(() => Boolean(routingControl._line), null, { timeout:10000 });
const retiredGeocoderState = await page.evaluate(() => ({
    geocoderLibrary:typeof window.L.Control.Geocoder,
    geocoderOptionSet:'geocoder' in routingControl._plan.options,
    geocoderContainers:document.querySelectorAll('.leaflet-routing-geocoders').length,
    waypointInputs:document.querySelectorAll('.leaflet-routing-geocoder input').length,
    routeDrawn:Boolean(routingControl._line),
    alternatives:document.querySelectorAll('.leaflet-routing-alt').length
}));
check(
    retiredGeocoderState.geocoderLibrary === 'undefined' && retiredGeocoderState.geocoderOptionSet === false,
    'the retired geocoder is absent from the runtime and from the routing options'
);
check(
    retiredGeocoderState.geocoderContainers === 0 && retiredGeocoderState.waypointInputs === 0,
    'Routing Machine builds no waypoint-geocoder UI without a geocoder option'
);
check(
    retiredGeocoderState.routeDrawn && retiredGeocoderState.alternatives > 0,
    `routing still draws its line and alternatives (${JSON.stringify(retiredGeocoderState)})`
);

// The turn-by-turn steps are gated on PUBLIC_CONFIG.routingStepsVisible, which adds the
// class at boot; assert both sides of that switch against the shipped stylesheet.
const stepsVisibility = await page.evaluate(() => {
    const container = document.querySelector('.leaflet-routing-container');
    const table = document.querySelector('.leaflet-routing-alt table');
    const shipped = getComputedStyle(table).display;
    container.classList.add('routing-steps-visible');
    const toggled = getComputedStyle(table).display;
    container.classList.remove('routing-steps-visible');
    return {shipped, toggled, restored:getComputedStyle(table).display};
});
check(
    stepsVisibility.shipped === 'none' && stepsVisibility.restored === 'none',
    `turn-by-turn steps stay hidden with the shipped configuration (${JSON.stringify(stepsVisibility)})`
);
check(
    stepsVisibility.toggled === 'table',
    `the routing-steps-visible class reveals the steps table (${JSON.stringify(stepsVisibility)})`
);

console.log('\n== Recoverable frontend logout failure ==');
await clearNotifications();
const documentsBefore = documentRequests;
await page.evaluate(() => doLogout());
const logoutState = await page.evaluate(() => ({
    accessToken,
    stored:localStorage.getItem('mv_access_token'),
    notifications:Array.from(document.querySelectorAll('.notification'))
        .map(notification => notification.textContent)
}));
check(
    logoutRequests.length === 1
    && logoutRequests[0].method === 'POST'
    && logoutRequests[0].authorization === 'Bearer faketoken',
    `logout request keeps its current bearer context (${JSON.stringify(logoutRequests[0])})`
);
check(
    logoutState.accessToken === 'faketoken'
    && logoutState.stored === null
    && documentRequests === documentsBefore,
    'failed logout preserves the in-memory session (nothing persisted, S-06) and does not reload'
);
check(
    logoutState.notifications.includes('Unable to log out. Please try again.'),
    'failed logout shows a recoverable error'
);

console.log('\n== Runtime health ==');
check(
    pageErrors.length === 0,
    pageErrors.length ? `page errors: ${pageErrors.join(' | ')}` : 'no uncaught page errors'
);

console.log(`\n==== ${PASS} passed, ${FAIL} failed ====`);
await browser.close();
server.close();
process.exit(FAIL ? 1 : 0);
