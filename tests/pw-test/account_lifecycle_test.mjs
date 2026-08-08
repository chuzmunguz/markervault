// Stage 12 UI: disabled/admin-managed mode and enabled email-assisted account flows.
// Presentation contract (2026-07-24 consistency pass): every pre-session pane owns one
// identical fixed-height .auth-feedback slot between its content and its navigation
// links; all interim/success/error text renders there, and no message ever moves the
// fields, the links, or the card edge.
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';

const ROOT = '/workspace/markervault/public';
const MIME = {
    '.html':'text/html', '.js':'application/javascript', '.css':'text/css',
    '.png':'image/png', '.jpg':'image/jpeg', '.ico':'image/x-icon'
};

let emailMode = false;
const requests = [];

function sendJSON(res, object, status=200) {
    res.writeHead(status, {'Content-Type':'application/json'});
    res.end(JSON.stringify(object));
}

function readJSON(req, callback) {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => callback(body ? JSON.parse(body) : {}));
}

const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    const route = url.pathname;

    if (route === '/account-capabilities') {
        return sendJSON(res, {email_account_flows:emailMode});
    }
    if (route === '/auth/refresh') {
        return sendJSON(res, {error:'No session'}, 401);
    }
    if (route === '/admin/users') return sendJSON(res, []);
    if (req.method === 'POST' && (
        route === '/register'
        || route === '/email-verification/confirm'
        || route === '/email-verification/resend'
        || route === '/password-recovery/request'
        || route === '/password-recovery/validate'
        || route === '/password-recovery/reset'
        || route.endsWith('/approve')
    )) {
        return readJSON(req, body => {
            requests.push({
                route,
                body,
                authorization:req.headers.authorization || ''
            });
            if (route === '/register') {
                return sendJSON(res, {
                    success:true,
                    email_sent:true,
                    message:'Registration received. Verify your email.'
                });
            }
            if (route === '/email-verification/confirm') {
                if (body.token === 'invalid-token') {
                    return sendJSON(res, {error:'Verification link is invalid or expired'}, 400);
                }
                return sendJSON(res, {success:true, message:'Email verified. Await administrator approval.'});
            }
            if (route === '/password-recovery/validate') {
                if (body.token === 'expired-token') {
                    return sendJSON(res, {error:'Reset link is invalid or expired'}, 400);
                }
                return sendJSON(res, {valid:true});
            }
            if (route === '/password-recovery/reset') {
                return setTimeout(() => {
                    sendJSON(res, {success:true, message:'Password reset. You can now log in.'});
                }, 300);
            }
            if (route.endsWith('/approve')) return sendJSON(res, {success:true});
            if (route === '/password-recovery/request') {
                return sendJSON(res, {
                    success:true,
                    message:'If that address belongs to an eligible account, a reset link will be sent.'
                });
            }
            return sendJSON(res, {
                success:true,
                message:'If verification is available for that address, a new link will be sent.'
            });
        });
    }

    const filePath = route === '/' ? '/index.html' : route;
    const full = path.join(ROOT, filePath);
    if (fs.existsSync(full) && fs.statSync(full).isFile()) {
        res.writeHead(200, {'Content-Type':MIME[path.extname(full)] || 'text/plain'});
        return res.end(fs.readFileSync(full));
    }
    res.writeHead(404);
    res.end();
});

await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
const page = await browser.newPage({viewport:{width:1280, height:900}});
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

// Computed presentation of one pane's feedback slot plus the geometry that must
// never move: the slot box, the pane's nav-link row, and the card itself.
async function slotPresentation(slotId) {
    return page.evaluate(id => {
        const slot = document.getElementById(id);
        const pane = slot.closest('#authLoginPane, #authSignupPane, #authRecoveryPane, '
            + '#authResendPane, #authVerifyPane, #authResetPane');
        const style = getComputedStyle(slot);
        const box = slot.getBoundingClientRect();
        const nav = pane.querySelector('.auth-switch');
        return {
            text:slot.textContent,
            classes:slot.className,
            display:style.display,
            fontSize:parseFloat(style.fontSize),
            fontWeight:style.fontWeight,
            lineHeight:style.lineHeight,
            aligned:style.textAlign,
            color:style.color,
            height:box.height,
            slotTop:box.top,
            linkGap:nav.getBoundingClientRect().top - box.bottom,
            beforeNav:Boolean(slot.compareDocumentPosition(nav)
                & Node.DOCUMENT_POSITION_FOLLOWING),
            cardHeight:document.querySelector('#authScreen .auth-card')
                .getBoundingClientRect().height
        };
    }, slotId);
}

// The uniform contract every slot must satisfy, relative to the login slot's spec.
function matchesSpec(slot, spec) {
    return slot.classes.includes('auth-feedback')
        && slot.display === 'flex'
        && slot.fontSize === spec.fontSize
        && slot.fontWeight === spec.fontWeight
        && slot.lineHeight === spec.lineHeight
        && slot.aligned === 'center'
        && slot.height === spec.height
        && slot.linkGap === spec.linkGap
        && slot.beforeNav;
}

console.log('\n== 1. Disabled admin-managed mode ==');
await page.goto(base, {waitUntil:'networkidle'});
const disabledState = await page.evaluate(() => ({
    loginText:document.getElementById('authLoginPane').textContent,
    modeHint:document.getElementById('authAccountModeHint'),
    globalMessage:document.getElementById('authMessage'),
    recovery:getComputedStyle(document.querySelector('.email-account-link')).display,
    resend:getComputedStyle(document.getElementById('authContextResend')).display,
    signup:document.getElementById('authSignupHint').textContent
}));
check(disabledState.modeHint === null
      && disabledState.globalMessage === null
      && !disabledState.loginText.includes('managed by an administrator'),
      'disabled login has no account-mode warning and no out-of-pane message element');
check(disabledState.recovery === 'none' && disabledState.resend === 'none',
      'disabled mode hides forgot-password and contextual resend controls');
check(disabledState.signup.includes('admin approval') && !disabledState.signup.includes('Verify your email'),
      'disabled signup retains the approval-only instructions');

console.log('\n== 2. Uniform reserved feedback slots ==');
emailMode = true;
await page.reload({waitUntil:'networkidle'});
const enabledState = await page.evaluate(() => ({
    loginText:document.getElementById('authLoginPane').textContent,
    modeHint:document.getElementById('authAccountModeHint'),
    recovery:getComputedStyle(document.querySelector('.email-account-link')).display,
    resend:getComputedStyle(document.getElementById('authContextResend')).display,
    signup:document.getElementById('authSignupHint').textContent
}));
check(enabledState.modeHint === null
      && !enabledState.loginText.includes('Email verification and password recovery'),
      'enabled login has no account-mode announcement');
check(enabledState.recovery !== 'none' && enabledState.resend === 'none'
      && enabledState.signup.includes('Verify your email'),
      'enabled mode shows recovery while keeping resend contextual');

const loginSpec = await slotPresentation('authError');
await page.click('#authToSignup');
const signupSlot = await slotPresentation('authSignupFeedback');
await page.click('#authSignupPane #authToLogin');
await page.click('#authToRecovery');
const recoverySlot = await slotPresentation('authRecoveryStatus');
await page.click('#authRecoveryPane .authBackToLogin');
// Verify/reset panes are link-entered; their slots are asserted inside those flows
// against this same spec.
check(
    loginSpec.classes.includes('auth-feedback')
    && loginSpec.display === 'flex'
    && loginSpec.aligned === 'center'
    && loginSpec.height === 54
    && loginSpec.text === ''
    && matchesSpec(signupSlot, loginSpec)
    && matchesSpec(recoverySlot, loginSpec),
    `every pane reserves the same fixed feedback slot between content and links (${JSON.stringify({loginSpec, signupSlot, recoverySlot})})`
);

console.log('\n== 3. Enabled recovery and contextual resend flows ==');
await page.click('#authToSignup');
await page.fill('#authSignupUsername', 'new-user');
await page.fill('#authSignupPassword', 'weak');
const signupBeforeError = await slotPresentation('authSignupFeedback');
await page.click('#authSignupForm button[type="submit"]');
const signupPolicyError = await slotPresentation('authSignupFeedback');
check(
    signupPolicyError.text.includes('Password must')
    && signupPolicyError.classes.includes('error')
    && signupPolicyError.slotTop === signupBeforeError.slotTop
    && signupPolicyError.cardHeight === signupBeforeError.cardHeight
    && matchesSpec(signupPolicyError, loginSpec),
    `signup validation renders in the signup slot without moving the card (${JSON.stringify(signupPolicyError)})`
);
await page.fill('#authSignupPassword', 'Signup123!');
await page.fill('#authSignupEmail', 'new-user@example.test');
await page.fill('#authSignupFirstName', 'New');
await page.fill('#authSignupLastName', 'User');
await page.click('#authSignupForm button[type="submit"]');
await page.waitForFunction(() =>
    getComputedStyle(document.getElementById('authContextResend')).display !== 'none'
);
const registrationResult = await slotPresentation('authError');
const loginPaneVisible = await page.evaluate(() =>
    getComputedStyle(document.getElementById('authLoginPane')).display !== 'none'
);
check(
    registrationResult.text === 'Registration received. Verify your email.'
    && !registrationResult.text.toLowerCase().includes('administrator')
    && registrationResult.classes.includes('success')
    && registrationResult.color === 'rgb(26, 127, 55)'
    && matchesSpec(registrationResult, loginSpec)
    && loginPaneVisible
    && requests.some(item => item.route === '/register'
        && item.body.email === 'new-user@example.test'),
    `registration success lands in the login slot and reveals contextual resend (${JSON.stringify(registrationResult)})`
);

await page.click('#authToResend');
const contextualEmail = await page.inputValue('#authResendEmail');
const resendBeforeMessage = await slotPresentation('authResendStatus');
await page.click('#authResendForm button[type="submit"]');
await page.waitForFunction(() =>
    document.getElementById('authResendStatus').textContent.includes('verification')
);
const resendResult = await slotPresentation('authResendStatus');
check(
    contextualEmail === 'new-user@example.test'
    && resendResult.classes.includes('success')
    && resendResult.slotTop === resendBeforeMessage.slotTop
    && resendResult.cardHeight === resendBeforeMessage.cardHeight
    && matchesSpec(resendResult, loginSpec)
    && !resendResult.text.includes('Use the address from your registration')
    && requests.some(item => item.route === '/email-verification/resend'
        && item.body.email === 'new-user@example.test'),
    `resend feedback fills its slot without resizing the card (${JSON.stringify(resendResult)})`
);

await page.click('#authResendPane .authBackToLogin');
await page.click('#authToRecovery');
await page.fill('#authRecoveryEmail', 'alice@example.test');
const recoveryBeforeMessage = await slotPresentation('authRecoveryStatus');
await page.click('#authRecoveryForm button[type="submit"]');
await page.waitForFunction(() => document.getElementById('authRecoveryStatus').textContent.includes('eligible'));
const recoveryResult = await slotPresentation('authRecoveryStatus');
const eligibleOccurrences = await page.evaluate(() =>
    (document.getElementById('authRecoveryPane').textContent.match(/eligible/g) || []).length
);
check(
    requests.some(item => item.route === '/password-recovery/request'
        && item.body.email === 'alice@example.test')
    && recoveryResult.text
        === 'If that address belongs to an eligible account, a reset link will be sent.'
    && eligibleOccurrences === 1
    && recoveryResult.classes.includes('success')
    && recoveryResult.color === 'rgb(26, 127, 55)'
    && recoveryResult.slotTop === recoveryBeforeMessage.slotTop
    && recoveryResult.cardHeight === recoveryBeforeMessage.cardHeight
    && matchesSpec(recoveryResult, loginSpec),
    `recovery shows one green response in its slot without resizing (${JSON.stringify(recoveryResult)})`
);

console.log('\n== 4. Verification and reset links ==');
await page.goto(`${base}/?link=verify#verify-email=verify-token`, {waitUntil:'networkidle'});
await page.waitForFunction(() => document.getElementById('authVerifyStatus').textContent.includes('Email verified'));
const verificationSuccess = await slotPresentation('authVerifyStatus');
check(
    requests.some(item => item.route === '/email-verification/confirm'
        && item.body.token === 'verify-token')
    && page.url() === `${base}/?link=verify`,
    'verification fragment is submitted once and removed from the browser URL'
);
check(
    verificationSuccess.classes.includes('success')
    && matchesSpec(verificationSuccess, loginSpec),
    `verification result uses the same slot spec as every other pane (${JSON.stringify(verificationSuccess)})`
);

await page.goto(`${base}/?link=verify-bad#verify-email=invalid-token`, {waitUntil:'networkidle'});
await page.waitForFunction(() =>
    document.getElementById('authVerifyStatus').textContent.includes('invalid or expired')
);
const verificationFailure = await slotPresentation('authVerifyStatus');
check(
    verificationFailure.classes.includes('error')
    && verificationFailure.slotTop === verificationSuccess.slotTop
    && verificationFailure.cardHeight === verificationSuccess.cardHeight
    && matchesSpec(verificationFailure, loginSpec),
    `invalid verification keeps the identical slot position (${JSON.stringify(verificationFailure)})`
);

await page.setViewportSize({width:320, height:900});
await page.goto(base, {waitUntil:'networkidle'});
const narrowLoginBaseline = await slotPresentation('authError');
await page.goto(`${base}/?link=reset#reset-password=reset-token`, {waitUntil:'networkidle'});
await page.waitForFunction(() => document.getElementById('authResetFields').classList.contains('active'));
const validReset = await slotPresentation('authResetStatus');
const validResetFields = await page.evaluate(() => ({
    fieldsDisplay:getComputedStyle(document.getElementById('authResetFields')).display,
    fieldsTop:document.getElementById('authResetFields').getBoundingClientRect().top,
    hintVisible:Boolean(document.getElementById('authResetHint').getClientRects().length)
}));
const resetRequestsBeforeSubmit = requests.filter(item =>
    item.route === '/password-recovery/reset'
).length;
await page.fill('#authResetPassword', 'Recovered1!');
await page.fill('#authResetRepeat', 'Different1!');
await page.click('#authResetForm button[type="submit"]');
const mismatchedReset = await slotPresentation('authResetStatus');
const mismatchedFieldsTop = await page.evaluate(() =>
    document.getElementById('authResetFields').getBoundingClientRect().top
);
await page.fill('#authResetPassword', 'short');
await page.fill('#authResetRepeat', 'short');
await page.click('#authResetForm button[type="submit"]');
const policyReset = await slotPresentation('authResetStatus');
const policyFieldsTop = await page.evaluate(() =>
    document.getElementById('authResetFields').getBoundingClientRect().top
);
const resetRequestsAfterValidation = requests.filter(item =>
    item.route === '/password-recovery/reset'
).length;
await page.fill('#authResetPassword', 'Recovered1!');
await page.fill('#authResetRepeat', 'Recovered1!');
await page.click('#authResetForm button[type="submit"]');
const pendingReset = await slotPresentation('authResetStatus');
const pendingFieldsTop = await page.evaluate(() =>
    document.getElementById('authResetFields').getBoundingClientRect().top
);
await page.waitForFunction(() => document.getElementById('authError').textContent.includes('Password reset'));
const resetCompletion = await slotPresentation('authError');
check(
    requests.some(item => item.route === '/password-recovery/validate'
        && item.body.token === 'reset-token')
    && requests.some(item => item.route === '/password-recovery/reset'
        && item.body.token === 'reset-token'
        && item.body.new_password === 'Recovered1!')
    && narrowLoginBaseline.height === 72
    && narrowLoginBaseline.text === ''
    && validReset.text === ''
    && validReset.height === 72
    && validResetFields.fieldsDisplay !== 'none'
    && validResetFields.hintVisible
    && mismatchedReset.text === 'New passwords do not match'
    && mismatchedReset.classes.includes('error')
    && mismatchedReset.slotTop === validReset.slotTop
    && mismatchedReset.cardHeight === validReset.cardHeight
    && mismatchedFieldsTop === validResetFields.fieldsTop
    && policyReset.text.includes('Password must')
    && policyReset.slotTop === validReset.slotTop
    && policyReset.cardHeight === validReset.cardHeight
    && policyFieldsTop === validResetFields.fieldsTop
    && resetRequestsAfterValidation === resetRequestsBeforeSubmit
    && pendingReset.text === ''
    && pendingReset.slotTop === validReset.slotTop
    && pendingReset.cardHeight === validReset.cardHeight
    && pendingFieldsTop === validResetFields.fieldsTop
    && resetCompletion.text === 'Password reset. You can now log in.'
    && resetCompletion.classes.includes('success')
    && resetCompletion.height === narrowLoginBaseline.height
    && resetCompletion.cardHeight === narrowLoginBaseline.cardHeight
    && page.url() === `${base}/?link=reset`,
    `every reset state keeps the narrow card fully stationary (${JSON.stringify({
        narrowLoginBaseline, validReset, validResetFields, mismatchedReset,
        policyReset, pendingReset, resetCompletion
    })})`
);

const resetRequestsBeforeExpiry = requests.filter(item =>
    item.route === '/password-recovery/reset'
).length;
await page.goto(`${base}/?link=expired#reset-password=expired-token`, {waitUntil:'networkidle'});
await page.waitForFunction(() =>
    document.getElementById('authResetStatus').textContent.includes('invalid or expired')
);
const expiredReset = await slotPresentation('authResetStatus');
const expiredFields = await page.evaluate(() => ({
    fieldsDisplay:getComputedStyle(document.getElementById('authResetFields')).display,
    fieldsHeight:document.getElementById('authResetFields').getBoundingClientRect().height,
    hintVisible:Boolean(document.getElementById('authResetHint').getClientRects().length),
    inert:document.getElementById('authResetFields').inert,
    url:location.href
}));
check(
    expiredFields.fieldsDisplay === 'none'
    && expiredFields.fieldsHeight === 0
    && !expiredFields.hintVisible
    && expiredFields.inert
    && expiredReset.classes.includes('error')
    && expiredReset.beforeNav
    && expiredReset.cardHeight < validReset.cardHeight
    && expiredFields.url === `${base}/?link=expired`
    && requests.filter(item => item.route === '/password-recovery/reset').length
        === resetRequestsBeforeExpiry,
    `expired reset omits the form and explains the link in the shared slot (${JSON.stringify({expiredReset, expiredFields})})`
);

await page.setViewportSize({width:1280, height:900});
console.log('\n== 5. Admin bypass and pending-profile affordance ==');
await page.goto(base, {waitUntil:'networkidle'});
await page.evaluate(() => {
    accessToken = 'faketoken';
    hideAuthScreen();
    document.getElementById('adminScreen').classList.add('active');
    currentUser = {
        username:'rootadmin',
        role:'super_admin',
        first_name:'Root',
        last_name:'Admin',
        avatar_url:null
    };
    renderAdminUserDetail({
        user_id:'pending-id',
        username:'pending',
        role:'user',
        status:'pending',
        created:'2026-07-24T00:00:00Z',
        first_name:'Pending',
        last_name:'User',
        email:'pending@example.test',
        email_verified:false,
        company:'',
        department:'',
        birth_date:'',
        sex:'',
        controllers:[],
        group_managers:[],
        share_groups:[],
        management_groups:[]
    });
});
page.once('dialog', dialog => dialog.accept());
await page.getByRole('button', {name:'Approve and mark email verified'}).click();
await page.waitForFunction(() =>
    Array.from(document.querySelectorAll('.notification'))
        .some(item => item.textContent.includes('verification bypassed'))
);
check(
    requests.some(item => item.route === '/admin/users/pending-id/approve'
        && item.authorization === 'Bearer faketoken'
        && item.body.bypass_verification === true),
    'unverified admin approval requires confirmation and sends the explicit bypass'
);

const profileStatus = await page.evaluate(() => {
    const overlay = document.getElementById('profileOverlay');
    const email = document.getElementById('profileEmail');
    email.value = 'alice@example.test';
    overlay.style.display = 'flex';
    renderProfileEmailStatus({
        email:'alice@example.test',
        email_verified:true,
        pending_email:null
    });
    const emptyPanelHeight = overlay.querySelector('.overlay-content')
        .getBoundingClientRect().height;
    renderProfileEmailStatus({
        email:'alice@example.test',
        email_verified:true,
        pending_email:'alice-new@example.test',
        message:'Profile saved. Verify the new email address before it replaces your current address.'
    });
    const field = document.querySelector('.profile-email-field');
    const dates = document.querySelectorAll('#profileForm > .auth-field-row')[2];
    const status = document.getElementById('profileEmailStatus');
    const save = document.querySelector('#profileForm .buttons-container');
    const indicator = document.getElementById('profileEmailIndicator');
    const result = {
        text:status.textContent,
        pendingAddressShown:status.textContent.includes('alice-new@example.test'),
        emptyPanelHeight,
        pendingPanelHeight:overlay.querySelector('.overlay-content')
            .getBoundingClientRect().height,
        fontSize:parseFloat(getComputedStyle(status).fontSize),
        allFollowing:[
            field.compareDocumentPosition(dates),
            dates.compareDocumentPosition(status),
            status.compareDocumentPosition(save)
        ].every(value => Boolean(value & Node.DOCUMENT_POSITION_FOLLOWING)),
        indicator:indicator.textContent,
        indicatorClass:indicator.className,
        indicatorInsideField:field.contains(indicator),
        statusAligned:getComputedStyle(status).textAlign
    };
    overlay.style.display = 'none';
    return result;
});
check(
    profileStatus.text.includes(
        'Profile saved. Verify the new email address before it replaces your current address.'
    )
    && profileStatus.text.includes('Resend verification')
    && !profileStatus.pendingAddressShown
    && profileStatus.allFollowing
    && profileStatus.indicator === '✓'
    && profileStatus.indicatorClass.includes('verified')
    && profileStatus.indicatorInsideField
    && profileStatus.statusAligned === 'center'
    && profileStatus.fontSize < 14
    && profileStatus.emptyPanelHeight === profileStatus.pendingPanelHeight,
    `profile uses the clean email/status/resend/save layout (${JSON.stringify(profileStatus)})`
);

console.log('\n== 6. Runtime health ==');
check(pageErrors.length === 0,
      `no page errors${pageErrors.length ? ` (${pageErrors.join('; ')})` : ''}`);

console.log(`\n==== ${PASS} passed, ${FAIL} failed ====`);
await browser.close();
server.close();
process.exit(FAIL ? 1 : 0);
