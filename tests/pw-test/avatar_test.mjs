// Profile avatar UI: refresh bootstrap, upload, sidebar/preview sync, removal and fallback.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const MIME = {
    '.html':'text/html', '.js':'application/javascript', '.css':'text/css',
    '.png':'image/png', '.jpg':'image/jpeg', '.ico':'image/x-icon'
};
const AVATAR_BYTES = fs.readFileSync(path.join(ROOT, 'assets/images/default-user-thumb.png'));

let profileAvatar = '/avatars/original.jpg?exp=9999999999&uid=u-alice&sig=original';
const avatarRequests = [];

function sendJSON(res, obj, code=200) {
    res.writeHead(code, {'Content-Type':'application/json'});
    res.end(JSON.stringify(obj));
}

const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const p = u.pathname;

    if (p === '/auth/refresh') {
        return sendJSON(res, {
            access_token:'faketoken', access_expires_in:900, role:'user',
            username:'alice', first_name:'Alice', last_name:'Smith',
            avatar_url:profileAvatar
        });
    }
    if (p === '/maps') return sendJSON(res, []);
    if (p === '/profile' && req.method === 'GET') {
        return sendJSON(res, {
            username:'alice', role:'user', first_name:'Alice', last_name:'Smith',
            email:'alice@example.com', company:'', department:'',
            birth_date:'', sex:'', avatar_url:profileAvatar
        });
    }
    if (p === '/profile/avatar' && req.method === 'POST') {
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.on('end', () => {
            avatarRequests.push({
                method:req.method,
                authorization:req.headers.authorization || '',
                contentType:req.headers['content-type'] || '',
                body:Buffer.concat(chunks).toString('latin1')
            });
            profileAvatar = '/avatars/uploaded.jpg?exp=9999999999&uid=u-alice&sig=uploaded';
            sendJSON(res, {success:true, avatar_url:profileAvatar});
        });
        return;
    }
    if (p === '/profile/avatar' && req.method === 'DELETE') {
        avatarRequests.push({
            method:req.method,
            authorization:req.headers.authorization || '',
            contentType:req.headers['content-type'] || '',
            body:''
        });
        profileAvatar = null;
        return sendJSON(res, {success:true});
    }
    if (p.startsWith('/avatars/')) {
        res.writeHead(200, {'Content-Type':'image/png'});
        return res.end(AVATAR_BYTES);
    }

    const fp = p === '/' ? '/index.html' : p;
    const full = path.join(ROOT, fp);
    if (fs.existsSync(full) && fs.statSync(full).isFile()) {
        res.writeHead(200, {'Content-Type':MIME[path.extname(full)] || 'text/plain'});
        return res.end(fs.readFileSync(full));
    }
    res.writeHead(200, {'Content-Type':'application/javascript'});
    res.end('');
});

await new Promise(resolve => server.listen(0, resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
const page = await browser.newPage({viewport:{width:1280, height:900}});
const pageErrors = [];
const consoleErrors = [];
page.on('pageerror', error => pageErrors.push(String(error)));
page.on('console', msg => {
    if (msg.type() === 'error' && !msg.text().startsWith('Failed to load resource:')) {
        consoleErrors.push(msg.text());
    }
});

let PASS = 0, FAIL = 0;
function check(cond, label) {
    if (cond) {
        PASS++;
        console.log(`  PASS  ${label}`);
    } else {
        FAIL++;
        console.log(`  FAIL  ${label}`);
    }
}

await page.goto(base, {waitUntil:'networkidle'});
await page.waitForTimeout(1000);

console.log('\n== 1. Refresh bootstrap and profile preview ==');
let srcs = await page.evaluate(() => ({
    sidebar:document.querySelector('.user-profile-img').src,
    preview:document.getElementById('profileAvatarPreview').src
}));
check(srcs.sidebar.includes('/avatars/original.jpg?'),
      `auth refresh applies the avatar to the sidebar (${srcs.sidebar})`);

await page.evaluate(() => openProfileOverlay());
await page.waitForFunction(() => document.getElementById('profileUsername').textContent === 'alice');
srcs = await page.evaluate(() => {
    const preview = document.getElementById('profileAvatarPreview');
    const rect = preview.getBoundingClientRect();
    const uploadRect = document.getElementById('profileAvatarUploadBtn').getBoundingClientRect();
    return {
        sidebar:document.querySelector('.user-profile-img').src,
        preview:preview.src,
        width:Math.round(rect.width),
        height:Math.round(rect.height),
        uploadBelow:uploadRect.top >= rect.bottom,
        removeVisible:getComputedStyle(document.getElementById('profileAvatarRemoveBtn')).display !== 'none',
        inputHidden:document.getElementById('profileAvatarInput').hidden
    };
});
check(srcs.preview.includes('/avatars/original.jpg?') && srcs.preview === srcs.sidebar,
      'fresh profile data keeps preview and sidebar on the same signed URL');
check(srcs.width === 96 && srcs.height === 96,
      `profile preview is square and compact (${srcs.width}x${srcs.height})`);
check(srcs.uploadBelow, 'avatar Upload button is positioned below the preview');
check(srcs.removeVisible && srcs.inputHidden,
      'existing avatar shows Remove while the file input stays hidden');

console.log('\n== 2. Upload through the hidden file chooser ==');
const chooserPromise = page.waitForEvent('filechooser');
await page.click('#profileAvatarUploadBtn');
const chooser = await chooserPromise;
const uploadResponse = page.waitForResponse(response =>
    response.url().endsWith('/profile/avatar') && response.request().method() === 'POST'
);
await chooser.setFiles({
    name:'replacement.png',
    mimeType:'image/png',
    buffer:AVATAR_BYTES
});
await uploadResponse;
await page.waitForFunction(() =>
    document.querySelector('.user-profile-img').src.includes('/avatars/uploaded.jpg?')
);

const upload = avatarRequests.find(r => r.method === 'POST');
check(upload && upload.authorization === 'Bearer faketoken',
      'avatar POST carries the Bearer token');
check(upload && upload.contentType.startsWith('multipart/form-data; boundary=')
      && upload.body.includes('name="avatar"')
      && upload.body.includes('filename="replacement.png"'),
      'avatar POST is multipart with the expected field and filename');
srcs = await page.evaluate(() => ({
    sidebar:document.querySelector('.user-profile-img').src,
    preview:document.getElementById('profileAvatarPreview').src,
    inputValue:document.getElementById('profileAvatarInput').value,
    removeVisible:getComputedStyle(document.getElementById('profileAvatarRemoveBtn')).display !== 'none',
    toasts:Array.from(document.querySelectorAll('.notification')).map(x => x.textContent)
}));
check(srcs.sidebar.includes('/avatars/uploaded.jpg?') && srcs.preview === srcs.sidebar,
      'successful upload synchronizes preview and sidebar');
check(srcs.inputValue === '' && srcs.removeVisible,
      'upload resets the picker and keeps Remove available');
check(srcs.toasts.includes('Avatar updated'),
      `upload reports status by toast (${JSON.stringify(srcs.toasts)})`);

console.log('\n== 3. Removal and default fallback ==');
const deleteResponse = page.waitForResponse(response =>
    response.url().endsWith('/profile/avatar') && response.request().method() === 'DELETE'
);
await page.click('#profileAvatarRemoveBtn');
await deleteResponse;
await page.waitForFunction(() =>
    document.querySelector('.user-profile-img').src.includes('/assets/images/default-user-thumb.png')
);

const deletion = avatarRequests.find(r => r.method === 'DELETE');
check(deletion && deletion.authorization === 'Bearer faketoken',
      'avatar DELETE carries the Bearer token');
srcs = await page.evaluate(() => ({
    sidebar:document.querySelector('.user-profile-img').src,
    preview:document.getElementById('profileAvatarPreview').src,
    removeVisible:getComputedStyle(document.getElementById('profileAvatarRemoveBtn')).display !== 'none',
    toasts:Array.from(document.querySelectorAll('.notification')).map(x => x.textContent)
}));
check(srcs.sidebar.endsWith('/assets/images/default-user-thumb.png')
      && srcs.preview === srcs.sidebar,
      'remove synchronizes both images to the default fallback');
check(!srcs.removeVisible, 'Remove is hidden when no avatar exists');
check(srcs.toasts.includes('Avatar removed'),
      `removal reports status by toast (${JSON.stringify(srcs.toasts)})`);

console.log('\n== 4. Runtime health ==');
check(pageErrors.length === 0,
      `no page errors${pageErrors.length ? ` (got ${pageErrors.join('; ')})` : ''}`);
check(consoleErrors.length === 0,
      `no application console errors${consoleErrors.length ? ` (got ${consoleErrors.join('; ')})` : ''}`);

console.log(`\n==== ${PASS} passed, ${FAIL} failed ====`);
await browser.close();
server.close();
process.exit(FAIL ? 1 : 0);
