const PUBLIC_CONFIG = Object.freeze({
    busyIndicatorDelayMs: 500,
    defaultAvatarSrc: 'assets/images/default-user-thumb.png',
    kmlProgressPollMs: 1000,
    kmlProgressRemovalDelayMs: 2000,
    kmlStatusRetryLimit: 5,
    // Turn-by-turn steps under each route summary. Off by default; there is no user
    // setting yet, so this is the only place that decides it.
    routingStepsVisible: false
});

// ===============================================================
// Authentication
// ===============================================================
// Access token lives ONLY in this module var (S-06): no persistent bearer storage, so
// origin script access can never read a stored credential. Reloads restore the session
// through the httpOnly refresh cookie (scoped to /auth), which the frontend never sees.
let accessToken = null;
let refreshInFlight = null;
// Purge the bearer token an earlier build persisted; harmless once wiped server-side,
// but residue credentials should not linger in storage.
localStorage.removeItem('mv_access_token');
const DEFAULT_AVATAR_SRC = PUBLIC_CONFIG.defaultAvatarSrc;
let currentUser = {
    username: null, role: null, first_name: '', last_name: '', avatar_url: null
};
let notificationHistoryRows = [];
let notificationHistoryThroughId = null;
let notificationHistoryGeneration = 0;
let emailAccountFlowsEnabled = false;

async function loadAccountCapabilities() {
    try {
        const response = await fetch('/account-capabilities', { credentials: 'same-origin' });
        if (!response.ok) return;
        const capabilities = await response.json();
        emailAccountFlowsEnabled = capabilities.email_account_flows === true;
    } catch (_) {
        // The safe fallback is the default admin-managed mode.
        emailAccountFlowsEnabled = false;
    }
}

async function publicAccountPost(path, body) {
    const response = await fetch(path, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
        const error = new Error(data.error || 'Request failed');
        error.status = response.status;
        throw error;
    }
    return data;
}

// Network half of the refresh: rotate the cookie, keep the minted access token in
// memory. Only ever called under getAccessToken's single-flight/lock — never call
// directly.
async function refreshAccessToken() {
    const res = await fetch('/auth/refresh', { method: 'POST', credentials: 'include' });
    if (!res.ok) {
        const err = new Error('Failed to get access token');
        err.status = res.status;
        throw err;
    }
    const data = await res.json();
    accessToken = data.access_token;
    if (data.username) currentUser.username = data.username;
    if (data.role) currentUser.role = data.role;
    if ('first_name' in data) currentUser.first_name = data.first_name || '';
    if ('last_name' in data) currentUser.last_name = data.last_name || '';
    if ('avatar_url' in data) currentUser.avatar_url = data.avatar_url || null;
    updateAvatarImages();
    return accessToken;
}

// Obtain a fresh access token using the refresh cookie. Throws (with .status) on failure.
// Same-tab callers share one in-flight refresh; a Web Lock serializes the rotation
// across tabs. Under strict rotation this lock is what keeps a second tab from
// presenting the same cookie concurrently — a race would look like replay and revoke
// the whole session family. Tokens are never shared between tabs: each tab spends its
// own serialized rotation. initAuthGate blocks unsupported environments without Web
// Locks, so this path never degrades to same-tab-only serialization (owner 2026-07-22).
async function getAccessToken() {
    if (refreshInFlight) return refreshInFlight;
    refreshInFlight = navigator.locks.request('mv_token_rotation', refreshAccessToken);
    try {
        return await refreshInFlight;
    } finally {
        refreshInFlight = null;
    }
}

// Central fetch wrapper: attaches the Bearer token, and on 401 refreshes once and retries.
// Use for ALL same-origin API calls (NOT external Nominatim). Returns the raw Response so
// callers keep using res.ok / res.json() exactly as before. Only a 401 from the refresh
// itself sends the user to the login screen — transient refresh failures (429, offline)
// surface to the caller so a valid session is never dumped to login by a rate limit;
// the next user action retries.
async function apiFetch(url, options = {}) {
    options.headers = options.headers || {};

    // If the body is FormData, let the browser set the multipart Content-Type boundary.
    if (options.body instanceof FormData) {
        delete options.headers['Content-Type'];
    }

    if (!accessToken) {
        try { await getAccessToken(); }
        catch (err) {
            if (err.status === 401) showAuthScreen();
            throw err;
        }
    }

    const sentWith = accessToken;
    options.headers['Authorization'] = `Bearer ${sentWith}`;
    let res = await fetch(url, options);

    if (res.status === 401) {
        // A parallel caller may have rotated the token while this request was in
        // flight; only refresh when the rejected token is still the current one.
        if (accessToken === sentWith) {
            try { await getAccessToken(); }
            catch (err) {
                if (err.status === 401) showAuthScreen();
                throw err;
            }
        }
        options.headers['Authorization'] = `Bearer ${accessToken}`;
        res = await fetch(url, options);
    }
    if (res.status >= 500 && !String(url).startsWith('/notif_history')) {
        void refreshNotificationHistorySummary();
    }
    return res;
}

function clearAuthState() {
    accessToken = null;
    notificationHistoryGeneration += 1;
    currentUser = {
        username: null, role: null, first_name: '', last_name: '', avatar_url: null
    };
    notificationHistoryRows = [];
    notificationHistoryThroughId = null;
    updateNotificationHistoryBadge(0);
    const historyList = document.getElementById('notifHistoryList');
    if (historyList) historyList.textContent = '';
    const historyOverlay = document.getElementById('notifHistoryOverlay');
    if (historyOverlay) {
        historyOverlay.classList.remove('active');
        historyOverlay.style.display = 'none';
    }
}

// Mirror the backend password policy for instant feedback (backend re-validates).
// Module-scoped so signup, admin-create, etc. can all use it. Contract-tested against
// request_validation.py through tests/password_contract_vectors.json.
function passwordPolicyError(pw) {
    if (pw.length < 8) return 'Password must be at least 8 characters';
    if (new TextEncoder().encode(pw).length > 72) return 'Password must be at most 72 bytes of UTF-8';
    if (!/[A-Z]/.test(pw)) return 'Password must include an uppercase letter';
    if (!/[a-z]/.test(pw)) return 'Password must include a lowercase letter';
    if (!/\d/.test(pw)) return 'Password must include a digit';
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(pw)) return 'Password must include a special character';
    return null;
}

// Display label for the account: "First Last" when set, else the username.
function accountDisplayName() {
    const full = [currentUser.first_name, currentUser.last_name].filter(Boolean).join(' ').trim();
    return full || currentUser.username || 'Account';
}

function personName(first, last, username) {
    const full = [first, last].filter(Boolean).join(' ').trim();
    return full || username || '';
}

// User-facing lists show the person's name without repeating their username in
// parentheses. Accounts without a profile name still fall back to the username.
function nameWithUsername(u) {
    return personName(u.first_name, u.last_name, u.username);
}

// Reflect the current user's name in the sidebar account header. One .name-part span
// per name: a first+last pair wraps first-over-last when one line can't fit both, and
// each part ellipsizes on its own when it alone overflows (CSS). The title carries
// the full name for when it truncates.
function updateAccountName() {
    const el = document.querySelector('.user-profile-name');
    if (!el) return;
    el.textContent = '';
    const parts = [currentUser.first_name, currentUser.last_name].filter(Boolean);
    if (!parts.length) parts.push(currentUser.username || 'Account');
    parts.forEach((p, i) => {
        if (i) el.appendChild(document.createTextNode(' '));
        const span = document.createElement('span');
        span.className = 'name-part';
        span.textContent = p;
        el.appendChild(span);
    });
    el.title = accountDisplayName();
}

function setAvatarImage(img, src) {
    if (!img) return;
    img.onerror = () => {
        img.onerror = null;
        img.src = DEFAULT_AVATAR_SRC;
    };
    img.src = src || DEFAULT_AVATAR_SRC;
}

function userAvatar(src, className, alt = '') {
    const img = document.createElement('img');
    img.className = className;
    img.alt = alt;
    setAvatarImage(img, src);
    return img;
}

function updateAvatarImages() {
    setAvatarImage(document.querySelector('.user-profile-img'), currentUser.avatar_url);
    setAvatarImage(document.getElementById('profileAvatarPreview'), currentUser.avatar_url);
    const removeBtn = document.getElementById('profileAvatarRemoveBtn');
    if (removeBtn) removeBtn.style.display = currentUser.avatar_url ? '' : 'none';
}

async function doLogin(username, password) {
    const res = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    if (!res.ok) {
        let msg = 'Login failed';
        try { msg = (await res.json()).error || msg; } catch {}
        const err = new Error(msg);
        err.status = res.status;
        throw err;
    }
    // /login only sets the refresh cookie; fetch the access token separately. Clear
    // any predecessor session's in-memory state first so nothing from the previous
    // account survives into the new session.
    clearAuthState();
    await getAccessToken();
}

async function doRegister(fields) {
    const res = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(fields)
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
        const err = new Error(data.error || 'Registration failed');
        err.status = res.status;
        throw err;
    }
    if (!data.message) data.message = 'Registration received.';
    return data;
}

async function doLogout() {
    try {
        const response = await fetch('/auth/logout', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${accessToken}` },
            credentials: 'include'
        });
        if (!response.ok) {
            throw new Error('Unable to log out. Please try again.');
        }
    } catch (err) {
        console.warn('Logout request failed', err);
        showNotification(err.message || 'Unable to log out. Please try again.');
        return;
    }
    clearAuthState();
    // Reload so the next user starts from a clean initial state (no carried-over open
    // sections, expanded sidebar, filters or selected map from the previous session).
    // The fresh page boots to the login screen since the refresh cookie was revoked.
    window.location.reload();
}


// ===============================================================
// Auth screen UI (login + signup) + admin panel visibility
// ===============================================================
function showAuthScreen() {
    const el = document.getElementById('authScreen');
    if (!el) return;
    el.classList.add('active');
    updateAdminUI();
}
function hideAuthScreen() {
    const el = document.getElementById('authScreen');
    if (!el) return;
    el.classList.remove('active');
}
function showLimitScreen() {
    const el = document.getElementById('limitScreen');
    if (el) el.classList.add('active');
}
function hideLimitScreen() {
    const el = document.getElementById('limitScreen');
    if (el) el.classList.remove('active');
}
function showUnsupportedScreen() {
    const el = document.getElementById('unsupportedScreen');
    if (el) el.classList.add('active');
}

// Role helpers. super_admin > admin > user; both admin roles have admin powers.
function isAdminRole(role) { return role === 'admin' || role === 'super_admin'; }

// Display labels for enum values ("super_admin" → "Super Admin", "approved" →
// "Approved"). Only fixed vocabularies get this — user-entered text never does.
function prettyRole(role) {
    if (role === 'super_admin') return 'Super Admin';
    return role ? role.charAt(0).toUpperCase() + role.slice(1) : '';
}
function prettyEnum(value) {
    return value ? value.charAt(0).toUpperCase() + value.slice(1) : '';
}
function currentUserIsAdmin() { return isAdminRole(currentUser.role); }
function currentUserIsSuper() { return currentUser.role === 'super_admin'; }

// Show/hide the admin-panel menu item based on the logged-in user's role.
// (Logout lives in the account menu and is always available once shown.)
function updateAdminUI() {
    const btn = document.getElementById('openAdminPanelBtn');
    if (btn) btn.style.display = currentUserIsAdmin() ? '' : 'none';
}

// Wire the auth screen once the DOM is present (frontend.js loads at end of body).
function setupAuthScreen() {
    const overlay = document.getElementById('authScreen');
    if (!overlay) return false;

    const loginForm = document.getElementById('authLoginForm');
    const signupForm = document.getElementById('authSignupForm');
    const recoveryForm = document.getElementById('authRecoveryForm');
    const resendForm = document.getElementById('authResendForm');
    const resetForm = document.getElementById('authResetForm');
    const resetFields = document.getElementById('authResetFields');
    const loginUser = document.getElementById('authLoginUsername');
    const loginPass = document.getElementById('authLoginPassword');
    const signupUser = document.getElementById('authSignupUsername');
    const signupPass = document.getElementById('authSignupPassword');
    const toLogin = document.getElementById('authToLogin');
    const toSignup = document.getElementById('authToSignup');
    const loginPane = document.getElementById('authLoginPane');
    const signupPane = document.getElementById('authSignupPane');
    const recoveryPane = document.getElementById('authRecoveryPane');
    const resendPane = document.getElementById('authResendPane');
    const verifyPane = document.getElementById('authVerifyPane');
    const resetPane = document.getElementById('authResetPane');
    const panes = [loginPane, signupPane, recoveryPane, resendPane, verifyPane, resetPane];
    const contextResend = document.getElementById('authContextResend');

    // Every pane owns one identical reserved .auth-feedback slot; all interim,
    // error and success text renders there and nowhere else.
    const feedbackSlots = new Map([
        [loginPane, document.getElementById('authError')],
        [signupPane, document.getElementById('authSignupFeedback')],
        [recoveryPane, document.getElementById('authRecoveryStatus')],
        [resendPane, document.getElementById('authResendStatus')],
        [verifyPane, document.getElementById('authVerifyStatus')],
        [resetPane, document.getElementById('authResetStatus')],
    ]);
    function setFeedback(pane, message, state = '') {
        const slot = feedbackSlots.get(pane);
        slot.textContent = message;
        slot.classList.toggle('success', state === 'success');
        slot.classList.toggle('error', state === 'error');
    }
    function showPane(pane) {
        feedbackSlots.forEach((slot, owner) => setFeedback(owner, ''));
        panes.forEach(item => { item.style.display = item === pane ? '' : 'none'; });
    }
    function clearAccountFragment() {
        if (window.location.hash) {
            history.replaceState(null, '', window.location.pathname + window.location.search);
        }
    }
    function showLoginPane() { clearAccountFragment(); showPane(loginPane); }
    function showSignupPane() { showPane(signupPane); }
    function showContextualResend(email = '') {
        if (!emailAccountFlowsEnabled) return;
        contextResend.style.display = '';
        document.getElementById('authResendEmail').value = email;
    }
    toSignup.addEventListener('click', e => { e.preventDefault(); showSignupPane(); });
    toLogin.addEventListener('click', e => { e.preventDefault(); showLoginPane(); });
    document.querySelectorAll('.authBackToLogin').forEach(link => {
        link.addEventListener('click', e => { e.preventDefault(); showLoginPane(); });
    });

    document.querySelectorAll('.email-account-link').forEach(element => {
        element.style.display = emailAccountFlowsEnabled ? '' : 'none';
    });
    const signupHint = document.getElementById('authSignupHint');
    if (emailAccountFlowsEnabled) {
        signupHint.textContent = 'Fields marked * are required. Password: 8+ chars with upper, lower, digit and a special character. Verify your email, then wait for admin approval.';
    } else {
        signupHint.textContent = 'Fields marked * are required. Password: 8+ chars with upper, lower, digit and a special character. New accounts need admin approval before first login.';
    }

    document.getElementById('authToRecovery').addEventListener('click', e => {
        e.preventDefault();
        if (emailAccountFlowsEnabled) showPane(recoveryPane);
    });
    document.getElementById('authToResend').addEventListener('click', e => {
        e.preventDefault();
        if (emailAccountFlowsEnabled) showPane(resendPane);
    });

    loginForm.addEventListener('submit', async e => {
        e.preventDefault();
        setFeedback(loginPane, '');
        try {
            await doLogin(loginUser.value.trim(), loginPass.value);
            loginPass.value = '';
            // If a session already ran in this page (the login screen came from a
            // mid-session revocation), reload for a clean slate — same reasoning as
            // logout: no carried-over overlays, filters or selected map may leak
            // from the previous session into the new one.
            if (appBooted) {
                window.location.reload();
                return;
            }
            bootApp();
        } catch (err) {
            setFeedback(loginPane, err.status === 429 ? 'Too many attempts — wait a few seconds and try again'
                : err.status === 403 ? err.message
                : 'Invalid username or password', 'error');
            if (err.status === 403 && err.message.toLowerCase().includes('verification')) {
                showContextualResend();
            }
        }
    });

    const signupEmail = document.getElementById('authSignupEmail');
    const signupFirst = document.getElementById('authSignupFirstName');
    const signupLast = document.getElementById('authSignupLastName');
    const signupCompany = document.getElementById('authSignupCompany');
    const signupDept = document.getElementById('authSignupDepartment');
    const signupBirth = document.getElementById('authSignupBirthDate');
    const signupSex = document.getElementById('authSignupSex');

    signupForm.addEventListener('submit', async e => {
        e.preventDefault();
        setFeedback(signupPane, '');
        const u = signupUser.value.trim();
        const p = signupPass.value;
        const first = signupFirst.value.trim();
        const last = signupLast.value.trim();
        const email = signupEmail.value.trim();
        if (!u) { setFeedback(signupPane, 'Username is required', 'error'); return; }
        const policyErr = passwordPolicyError(p);
        if (policyErr) { setFeedback(signupPane, policyErr, 'error'); return; }
        if (!first || !last) { setFeedback(signupPane, 'First name and last name are required', 'error'); return; }
        if (!email) { setFeedback(signupPane, 'Email is required', 'error'); return; }
        try {
            const data = await doRegister({
                username: u, password: p,
                first_name: first, last_name: last, email: email,
                company: signupCompany.value.trim(),
                department: signupDept.value.trim(),
                birth_date: signupBirth.value,
                sex: signupSex.value
            });
            signupForm.reset();
            showLoginPane();
            setFeedback(loginPane, data.message, 'success');
            if (emailAccountFlowsEnabled
                    && Object.prototype.hasOwnProperty.call(data, 'email_sent')) {
                showContextualResend(email);
            }
        } catch (err) {
            setFeedback(signupPane, err.message, 'error');
        }
    });

    recoveryForm.addEventListener('submit', async e => {
        e.preventDefault();
        setFeedback(recoveryPane, '');
        try {
            const data = await publicAccountPost('/password-recovery/request', {
                email: document.getElementById('authRecoveryEmail').value.trim()
            });
            recoveryForm.reset();
            setFeedback(recoveryPane, data.message, 'success');
        } catch (err) {
            setFeedback(recoveryPane, err.status === 429
                ? 'Too many attempts — wait a few seconds and try again'
                : err.message, 'error');
        }
    });

    resendForm.addEventListener('submit', async e => {
        e.preventDefault();
        setFeedback(resendPane, '');
        try {
            const data = await publicAccountPost('/email-verification/resend', {
                email: document.getElementById('authResendEmail').value.trim()
            });
            resendForm.reset();
            setFeedback(resendPane, data.message, 'success');
        } catch (err) {
            setFeedback(resendPane, err.status === 429
                ? 'Too many attempts — wait a few seconds and try again'
                : err.message, 'error');
        }
    });

    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const verificationToken = fragment.get('verify-email');
    const resetToken = fragment.get('reset-password');
    if (emailAccountFlowsEnabled && verificationToken) {
        showPane(verifyPane);
        setFeedback(verifyPane, 'Verifying your email address...');
        publicAccountPost('/email-verification/confirm', { token: verificationToken })
            .then(data => {
                setFeedback(verifyPane, data.message, 'success');
                clearAccountFragment();
            })
            .catch(err => {
                setFeedback(verifyPane, err.message, 'error');
            });
        return true;
    }
    if (emailAccountFlowsEnabled && resetToken) {
        showPane(resetPane);
        resetFields.classList.remove('active');
        resetFields.inert = true;
        setFeedback(resetPane, 'Checking reset link...');
        resetForm.addEventListener('submit', async e => {
            e.preventDefault();
            setFeedback(resetPane, '');
            const password = document.getElementById('authResetPassword').value;
            const repeat = document.getElementById('authResetRepeat').value;
            if (password !== repeat) {
                setFeedback(resetPane, 'New passwords do not match', 'error');
                return;
            }
            const policyErr = passwordPolicyError(password);
            if (policyErr) {
                setFeedback(resetPane, policyErr, 'error');
                return;
            }
            try {
                const data = await publicAccountPost('/password-recovery/reset', {
                    token: resetToken,
                    new_password: password
                });
                resetForm.reset();
                showLoginPane();
                setFeedback(loginPane, data.message, 'success');
            } catch (err) {
                resetFields.classList.remove('active');
                resetFields.inert = true;
                setFeedback(resetPane, err.message, 'error');
                clearAccountFragment();
            }
        });
        publicAccountPost('/password-recovery/validate', { token: resetToken })
            .then(() => {
                setFeedback(resetPane, '');
                resetFields.classList.add('active');
                resetFields.inert = false;
                document.getElementById('authResetPassword').focus();
            })
            .catch(err => {
                resetFields.classList.remove('active');
                resetFields.inert = true;
                setFeedback(resetPane, err.message, 'error');
                clearAccountFragment();
            });
        return true;
    }
    showLoginPane();
    return false;
}


// ===============================================================
// Account menu (sidebar accordion) + profile + change-password
// ===============================================================
function setupAccountMenu() {
    const toggle = document.getElementById('accountToggle');
    const menu = document.getElementById('accountMenu');
    if (!toggle || !menu) return;

    // Animate the height like the other sidebar sections (0 <-> scrollHeight -> auto).
    let isAnimating = false;
    function setOpen(open) {
        if (isAnimating) return;
        const isOpen = menu.classList.contains('open');
        if (open === isOpen) return;
        isAnimating = true;
        toggle.setAttribute('aria-expanded', open ? 'true' : 'false');

        if (open) {
            menu.classList.add('open');
            menu.style.height = '0';
            menu.offsetHeight;                 // force reflow (Firefox)
            menu.style.height = menu.scrollHeight + 'px';
        } else {
            menu.style.height = menu.scrollHeight + 'px';
            menu.offsetHeight;                 // force reflow
            menu.classList.remove('open');
            menu.style.height = '0';
        }

        const handler = () => {
            menu.style.height = open ? 'auto' : '0';
            isAnimating = false;
            menu.removeEventListener('transitionend', handler);
        };
        menu.addEventListener('transitionend', handler);
    }
    toggle.addEventListener('click', () => setOpen(!menu.classList.contains('open')));
    toggle.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setOpen(!menu.classList.contains('open')); }
    });

    const profileBtn = document.getElementById('accountProfileBtn');
    if (profileBtn) profileBtn.addEventListener('click', () => { setOpen(false); openProfileOverlay(); });
    const historyBtn = document.getElementById('notifHistoryBtn');
    if (historyBtn) historyBtn.addEventListener('click', () => {
        setOpen(false);
        openNotificationHistory();
    });
    // Change Password now lives inside the Profile overlay (see setupProfileOverlay).
    // #openAdminPanelBtn and #logoutBtn keep their own handlers (setupAdminPanel / initAuthGate).

    setupProfileOverlay();
    setupChangePwdOverlay();
}

function updateNotificationHistoryBadge(unseen) {
    const badge = document.getElementById('notifHistoryBadge');
    if (!badge) return;
    const count = Number.isInteger(unseen) && unseen > 0 ? unseen : 0;
    badge.textContent = count ? String(count) : '';
    badge.hidden = count === 0;
}

async function refreshNotificationHistorySummary() {
    if (!accessToken) return;
    const generation = notificationHistoryGeneration;
    try {
        const response = await apiFetch('/notif_history?summary=1');
        const data = await response.json().catch(() => ({}));
        if (generation !== notificationHistoryGeneration) return;
        if (!response.ok || !Number.isInteger(data.unseen) || data.unseen < 0) return;
        updateNotificationHistoryBadge(data.unseen);
    } catch {}
}

function notificationHistoryTime(created) {
    const date = new Date(created);
    if (Number.isNaN(date.getTime())) return { label: '', title: '' };
    const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
    let label = 'Just now';
    if (seconds >= 86400) label = `${Math.floor(seconds / 86400)}d ago`;
    else if (seconds >= 3600) label = `${Math.floor(seconds / 3600)}h ago`;
    else if (seconds >= 60) label = `${Math.floor(seconds / 60)}m ago`;
    return { label, title: date.toLocaleString() };
}

const NOTIFICATION_HISTORY_PRESENTATION = {
    'map.deleted': { label: 'Map deleted', tone: 'neutral' },
    'marker.deleted': { label: 'Marker deleted', tone: 'neutral' },
    'photo.deleted': { label: 'Photo deleted', tone: 'neutral' },
    'kml.import_done': { label: 'Import complete', tone: 'success' },
    'kml.import_degraded': { label: 'Import completed with issues', tone: 'warning' },
    'kml.import_error': { label: 'Import failed', tone: 'error' },
    'server.error': { label: 'Application error', tone: 'error' },
};

function renderNotificationHistory() {
    const list = document.getElementById('notifHistoryList');
    const markBtn = document.getElementById('notifHistoryMarkSeenBtn');
    if (!list || !markBtn) return;
    list.textContent = '';
    if (!notificationHistoryRows.length) {
        const empty = document.createElement('p');
        empty.className = 'notif-history-empty';
        empty.textContent = 'No notifications yet.';
        list.appendChild(empty);
        markBtn.disabled = true;
        return;
    }
    notificationHistoryRows.forEach(notification => {
        const presentation = NOTIFICATION_HISTORY_PRESENTATION[notification.event]
            || { label: 'Notification', tone: 'neutral' };
        const row = document.createElement('button');
        row.type = 'button';
        row.className = `notif-history-row ${presentation.tone}`;
        if (!notification.seen) row.classList.add('unseen');
        row.dataset.id = notification.id;
        row.title = notification.seen ? 'Mark notification unread' : 'Mark notification read';
        row.setAttribute(
            'aria-label',
            `${presentation.label}. ${notification.message || 'Notification'} ${row.title}.`
        );
        row.addEventListener('click', () => {
            void setNotificationHistorySeen(notification.id, !notification.seen, row);
        });

        const timestamp = document.createElement('time');
        const time = notificationHistoryTime(notification.created);
        timestamp.className = 'notif-history-time';
        timestamp.dateTime = notification.created || '';
        timestamp.textContent = time.label;
        timestamp.title = time.title;

        const header = document.createElement('div');
        header.className = 'notif-history-row-header';
        const event = document.createElement('span');
        event.className = 'notif-history-event';
        event.textContent = presentation.label;
        header.append(event, timestamp);

        const message = document.createElement('div');
        message.className = 'notif-history-message';
        message.textContent = notification.message || '';

        row.append(header, message);
        list.appendChild(row);
    });
    markBtn.disabled = !notificationHistoryRows.some(notification => !notification.seen);
}

async function setNotificationHistorySeen(notificationId, seen, row) {
    const generation = notificationHistoryGeneration;
    row.disabled = true;
    try {
        const response = await apiFetch(`/notif_history/${notificationId}/seen`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ seen })
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok
                || data.id !== notificationId
                || data.seen !== seen
                || !Number.isInteger(data.unseen)) {
            throw new Error('set seen failed');
        }
        if (generation !== notificationHistoryGeneration) return;
        const notification = notificationHistoryRows.find(item => item.id === notificationId);
        if (notification) notification.seen = seen;
        updateNotificationHistoryBadge(data.unseen);
        renderNotificationHistory();
    } catch {
        if (generation !== notificationHistoryGeneration) return;
        row.disabled = false;
        showNotification('Unable to update notification.');
    }
}

async function loadNotificationHistory() {
    const list = document.getElementById('notifHistoryList');
    const markBtn = document.getElementById('notifHistoryMarkSeenBtn');
    const generation = notificationHistoryGeneration;
    if (list) list.textContent = 'Loading…';
    if (markBtn) markBtn.disabled = true;
    try {
        const response = await apiFetch('/notif_history');
        const data = await response.json().catch(() => ({}));
        if (!response.ok || !Array.isArray(data.notifications)) {
            throw new Error('notification history unavailable');
        }
        if (generation !== notificationHistoryGeneration) return;
        notificationHistoryRows = data.notifications;
        notificationHistoryThroughId = Number.isInteger(data.through_id)
            ? data.through_id
            : null;
        updateNotificationHistoryBadge(data.unseen);
        renderNotificationHistory();
    } catch {
        if (generation !== notificationHistoryGeneration) return;
        notificationHistoryRows = [];
        notificationHistoryThroughId = null;
        if (list) list.textContent = 'Unable to load notifications.';
    }
}

function openNotificationHistory() {
    const overlay = document.getElementById('notifHistoryOverlay');
    if (!overlay) return;
    overlay.style.display = 'flex';
    requestAnimationFrame(() => overlay.classList.add('active'));
    void loadNotificationHistory();
}

function closeNotificationHistory() {
    const overlay = document.getElementById('notifHistoryOverlay');
    if (!overlay) return;
    overlay.classList.remove('active');
    setTimeout(() => {
        if (!overlay.classList.contains('active')) overlay.style.display = 'none';
    }, 250);
}

async function markNotificationHistorySeen() {
    if (!notificationHistoryThroughId) return;
    const throughId = notificationHistoryThroughId;
    const generation = notificationHistoryGeneration;
    try {
        const response = await apiFetch('/notif_history/seen', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ through_id: throughId })
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok || !Number.isInteger(data.unseen)) {
            throw new Error('mark seen failed');
        }
        if (generation !== notificationHistoryGeneration) return;
        notificationHistoryRows.forEach(notification => {
            if (notification.id <= throughId) notification.seen = true;
        });
        updateNotificationHistoryBadge(data.unseen);
        renderNotificationHistory();
    } catch {
        if (generation !== notificationHistoryGeneration) return;
        showNotification('Unable to mark notifications seen.');
    }
}

document.getElementById('notifHistoryMarkSeenBtn').addEventListener('click', () => {
    void markNotificationHistorySeen();
});
addBackdropClose('notifHistoryOverlay', closeNotificationHistory);

// Close an overlay when the user clicks its backdrop (outside the .overlay-content card).
function addBackdropClose(overlayId, closeFn) {
    const overlay = document.getElementById(overlayId);
    if (!overlay) return;
    overlay.addEventListener('mousedown', e => {
        if (e.target === overlay) closeFn();
    });
}

// Every .overlay-content carries a top-right close (X) button. Rather than wire each
// one to its own dialog's teardown, reuse the backdrop-close path: every overlay
// already closes on a mousedown whose target is the .overlay element itself, so we
// dispatch exactly that. Form resets, promise rejection, Swiper teardown and the
// display-toggle all run identically to a real click on the backdrop.
document.addEventListener('click', e => {
    const btn = e.target.closest('.overlay-close');
    if (!btn) return;
    const overlay = btn.closest('.overlay');
    if (!overlay) return;
    overlay.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
});

// ---- Profile overlay (view + edit own profile) ----
function renderProfileEmailStatus(profile) {
    const status = document.getElementById('profileEmailStatus');
    const indicator = document.getElementById('profileEmailIndicator');
    if (!status || !indicator) return;
    status.textContent = '';
    indicator.hidden = !emailAccountFlowsEnabled;
    if (!emailAccountFlowsEnabled) {
        return;
    }
    indicator.textContent = profile.email_verified ? '✓' : '!';
    indicator.className = 'profile-email-indicator '
        + (profile.email_verified ? 'verified' : 'unverified');
    indicator.title = profile.email_verified ? 'Verified email address' : 'Email not verified';
    indicator.setAttribute('aria-label', indicator.title);
    if (!profile.pending_email) {
        return;
    }
    const warning = document.createElement('p');
    warning.className = 'profile-email-warning';
    warning.textContent = profile.message
        || 'Profile saved. Verify the new email address before it replaces your current address.';
    const resend = document.createElement('button');
    resend.type = 'button';
    resend.className = 'account-action-link profile-email-resend';
    resend.textContent = 'Resend verification';
    resend.addEventListener('click', async () => {
        resend.disabled = true;
        try {
            const data = await publicAccountPost('/email-verification/resend', {
                email: profile.pending_email
            });
            showNotification(data.message);
        } catch (err) {
            showNotification(err.message || 'Resend failed');
        } finally {
            resend.disabled = false;
        }
    });
    status.appendChild(warning);
    status.appendChild(resend);
}

function openProfileOverlay() {
    const overlay = document.getElementById('profileOverlay');
    if (!overlay) return;
    const err = document.getElementById('profileError');
    const msg = document.getElementById('profileMessage');
    if (err) err.textContent = '';
    if (msg) msg.textContent = '';
    overlay.style.display = 'flex';
    requestAnimationFrame(() => overlay.classList.add('active'));
    // Load fresh values from the backend.
    apiFetch('/profile').then(async r => {
        const p = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(p.error || 'Failed to load profile');
        return p;
    }).then(p => {
        document.getElementById('profileUsername').textContent = p.username || '';
        document.getElementById('profileRole').textContent = prettyRole(p.role);
        document.getElementById('profileEmail').value = p.email || '';
        document.getElementById('profileFirstName').value = p.first_name || '';
        document.getElementById('profileLastName').value = p.last_name || '';
        document.getElementById('profileCompany').value = p.company || '';
        document.getElementById('profileDepartment').value = p.department || '';
        document.getElementById('profileBirthDate').value = p.birth_date || '';
        document.getElementById('profileSex').value = p.sex || '';
        renderProfileEmailStatus(p);
        currentUser.avatar_url = p.avatar_url || null;
        updateAvatarImages();
    }).catch(() => { if (err) err.textContent = 'Failed to load profile'; });
}

function closeProfileOverlay() {
    const overlay = document.getElementById('profileOverlay');
    if (!overlay) return;
    overlay.classList.remove('active');
    setTimeout(() => overlay.style.display = 'none', 250);
}

function setupProfileOverlay() {
    const form = document.getElementById('profileForm');
    addBackdropClose('profileOverlay', closeProfileOverlay);
    if (!form) return;

    const avatarInput = document.getElementById('profileAvatarInput');
    const avatarUploadBtn = document.getElementById('profileAvatarUploadBtn');
    const avatarRemoveBtn = document.getElementById('profileAvatarRemoveBtn');
    if (avatarUploadBtn && avatarInput) {
        avatarUploadBtn.addEventListener('click', () => avatarInput.click());
        avatarInput.addEventListener('change', async () => {
            const file = avatarInput.files && avatarInput.files[0];
            if (!file) return;
            avatarUploadBtn.disabled = true;
            const body = new FormData();
            body.append('avatar', file);
            try {
                const res = await apiFetch('/profile/avatar', { method: 'POST', body });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) throw new Error(data.error || 'Avatar upload failed');
                currentUser.avatar_url = data.avatar_url || null;
                updateAvatarImages();
                showNotification('Avatar updated');
            } catch (err) {
                showNotification(err.message || 'Avatar upload failed');
            } finally {
                avatarInput.value = '';
                avatarUploadBtn.disabled = false;
            }
        });
    }
    if (avatarRemoveBtn) {
        avatarRemoveBtn.addEventListener('click', async () => {
            avatarRemoveBtn.disabled = true;
            try {
                const res = await apiFetch('/profile/avatar', { method: 'DELETE' });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) throw new Error(data.error || 'Avatar removal failed');
                currentUser.avatar_url = null;
                updateAvatarImages();
                showNotification('Avatar removed');
            } catch (err) {
                showNotification(err.message || 'Avatar removal failed');
            } finally {
                avatarRemoveBtn.disabled = false;
            }
        });
    }
    updateAvatarImages();

    form.addEventListener('submit', async e => {
        e.preventDefault();
        const err = document.getElementById('profileError');
        const msg = document.getElementById('profileMessage');
        err.textContent = ''; msg.textContent = '';
        const first = document.getElementById('profileFirstName').value.trim();
        const last = document.getElementById('profileLastName').value.trim();
        const email = document.getElementById('profileEmail').value.trim();
        if (!first || !last) { err.textContent = 'First name and last name are required'; return; }
        if (!email) { err.textContent = 'Email is required'; return; }
        try {
            const res = await apiFetch('/profile', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    first_name: first, last_name: last, email: email,
                    company: document.getElementById('profileCompany').value.trim(),
                    department: document.getElementById('profileDepartment').value.trim(),
                    birth_date: document.getElementById('profileBirthDate').value,
                    sex: document.getElementById('profileSex').value
                })
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) { err.textContent = data.error || 'Save failed'; return; }
            // Reflect the new name in the sidebar immediately.
            currentUser.first_name = data.first_name || '';
            currentUser.last_name = data.last_name || '';
            if ('avatar_url' in data) currentUser.avatar_url = data.avatar_url || null;
            document.getElementById('profileEmail').value = data.email || '';
            renderProfileEmailStatus(data);
            updateAccountName();
            updateAvatarImages();
            msg.textContent = data.pending_email ? '' : data.message || 'Profile saved';
        } catch (e2) {
            err.textContent = 'Save failed';
        }
    });

    const pwdBtn = document.getElementById('profileChangePwdBtn');
    if (pwdBtn) pwdBtn.addEventListener('click', openChangePwdOverlay);
    const delBtn = document.getElementById('deleteAccountBtn');
    if (delBtn) delBtn.addEventListener('click', openDeleteAccountOverlay);
    setupDeleteAccountOverlay();
}

// ---- Delete-my-account overlay (type username to confirm) ----
function openDeleteAccountOverlay() {
    const overlay = document.getElementById('deleteAccountOverlay');
    if (!overlay) return;
    document.getElementById('deleteAccountForm').reset();
    document.getElementById('deleteAccountError').textContent = '';
    overlay.style.display = 'flex';
    requestAnimationFrame(() => overlay.classList.add('active'));
}

function closeDeleteAccountOverlay() {
    const overlay = document.getElementById('deleteAccountOverlay');
    if (!overlay) return;
    overlay.classList.remove('active');
    setTimeout(() => overlay.style.display = 'none', 250);
}

function setupDeleteAccountOverlay() {
    const form = document.getElementById('deleteAccountForm');
    const cancelBtn = document.getElementById('deleteAccountCancelBtn');
    if (cancelBtn) cancelBtn.addEventListener('click', closeDeleteAccountOverlay);
    addBackdropClose('deleteAccountOverlay', closeDeleteAccountOverlay);
    if (!form) return;
    form.addEventListener('submit', async e => {
        e.preventDefault();
        const err = document.getElementById('deleteAccountError');
        err.textContent = '';
        const confirmName = document.getElementById('deleteAccountConfirm').value.trim();
        if (!confirmName) { err.textContent = 'Type your username to confirm'; return; }
        try {
            const res = await apiFetch('/account', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ confirm_username: confirmName })
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) { err.textContent = data.error || 'Delete failed'; return; }
            // Account gone — clear state and reload to the fresh login screen.
            clearAuthState();
            window.location.reload();
        } catch (e2) {
            err.textContent = 'Delete failed';
        }
    });
}

// ---- Change password overlay ----
function openChangePwdOverlay() {
    const overlay = document.getElementById('changePwdOverlay');
    if (!overlay) return;
    document.getElementById('changePwdForm').reset();
    document.getElementById('changePwdError').textContent = '';
    document.getElementById('changePwdMessage').textContent = '';
    overlay.style.display = 'flex';
    requestAnimationFrame(() => overlay.classList.add('active'));
}

function closeChangePwdOverlay() {
    const overlay = document.getElementById('changePwdOverlay');
    if (!overlay) return;
    overlay.classList.remove('active');
    setTimeout(() => overlay.style.display = 'none', 250);
}

function setupChangePwdOverlay() {
    const form = document.getElementById('changePwdForm');
    addBackdropClose('changePwdOverlay', closeChangePwdOverlay);
    if (!form) return;
    form.addEventListener('submit', async e => {
        e.preventDefault();
        const err = document.getElementById('changePwdError');
        const msg = document.getElementById('changePwdMessage');
        err.textContent = ''; msg.textContent = '';
        const oldp = document.getElementById('changePwdOld').value;
        const newp = document.getElementById('changePwdNew').value;
        const rep = document.getElementById('changePwdRepeat').value;
        if (newp !== rep) { err.textContent = 'New passwords do not match'; return; }
        try {
            const res = await apiFetch('/changepwd', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ old_password: oldp, new_password: newp, repeat_password: rep })
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) { err.textContent = data.error || 'Change failed'; return; }
            // Backend revokes all sessions on password change; force a clean re-login.
            msg.textContent = 'Password changed. Please log in again.';
            setTimeout(() => { closeChangePwdOverlay(); clearAuthState(); showAuthScreen(); }, 1200);
        } catch (e2) {
            err.textContent = 'Change failed';
        }
    });
}


// ===============================================================
// Admin screen (user + group management) — admin role only.
// Full-page master-detail: user/group list on the left, the selected item's
// detail pane on the right. Create-user/reset-pwd overlays stack above it.
// ===============================================================
// The three user tabs are status views over the same users panel; the tab itself
// says the status, so rows and detail facts carry no status label.
const STATUS_BY_TAB = { active: 'approved', inactive: 'disabled', pending: 'pending' };
let activeAdminTab = 'active';

function setupAdminPanel() {
    const openBtn = document.getElementById('openAdminPanelBtn');
    const screen = document.getElementById('adminScreen');
    if (!openBtn || !screen) return;

    openBtn.addEventListener('click', () => {
        screen.classList.add('active');
        // Management Groups, Audit, and Pending Approval are super-admin only — a
        // regular admin has no controlled pending self-registrations and cannot
        // approve or reject them, so the tab would only ever show an empty list.
        // Resolve visibility at open time (the logged-in identity is known) and
        // never leave a non-super parked on one of those tabs from a previous session.
        const mgmtTab = document.getElementById('adminMgmtTabBtn');
        if (mgmtTab) mgmtTab.style.display = currentUserIsSuper() ? '' : 'none';
        const auditTab = document.getElementById('adminAuditTabBtn');
        if (auditTab) auditTab.style.display = currentUserIsSuper() ? '' : 'none';
        const pendingTab = document.getElementById('adminPendingTabBtn');
        if (pendingTab) pendingTab.style.display = currentUserIsSuper() ? '' : 'none';
        if ((activeAdminTab === 'mgroups' || activeAdminTab === 'audit' || activeAdminTab === 'pending') && !currentUserIsSuper()) {
            activeAdminTab = 'active';
        }
        selectAdminTab(activeAdminTab);
    });
    document.getElementById('adminBackBtn').addEventListener('click', () => screen.classList.remove('active'));

    document.querySelectorAll('.admin-tab').forEach(tab => {
        tab.addEventListener('click', () => selectAdminTab(tab.dataset.admintab));
    });

    // Master-list filters re-render from the cache as the admin types.
    const userFilter = document.getElementById('adminUserFilter');
    if (userFilter) userFilter.addEventListener('input', () => renderAdminUsers(adminUsersCache));
    const groupFilter = document.getElementById('adminGroupFilter');
    if (groupFilter) groupFilter.addEventListener('input', renderAdminShareGroups);
    const mgroupFilter = document.getElementById('adminMgroupFilter');
    if (mgroupFilter) mgroupFilter.addEventListener('input', renderAdminMgmtGroups);

    const createBtn = document.getElementById('adminCreateUserBtn');
    if (createBtn) createBtn.addEventListener('click', openCreateUserOverlay);
    setupCreateUserOverlay();
    setupEditUserOverlay();
    setupResetPwdOverlay();
    setupShareGroupsTab();
    setupMgmtGroupsTab();
    setupAuditFilters();
}

function selectAdminTab(name) {
    activeAdminTab = name;
    const groupTab = name === 'groups' || name === 'mgroups';
    const auditTab = name === 'audit';
    document.querySelectorAll('.admin-tab').forEach(t => t.classList.toggle('active', t.dataset.admintab === name));
    document.getElementById('adminUsersPanel').style.display = groupTab || auditTab ? 'none' : '';
    document.getElementById('adminGroupsPanel').style.display = name === 'groups' ? '' : 'none';
    document.getElementById('adminMgroupsPanel').style.display = name === 'mgroups' ? '' : 'none';
    document.getElementById('adminAuditPanel').style.display = auditTab ? '' : 'none';
    if (auditTab) {
        loadAuditLog();
        return;
    }
    // Always refetch on tab switch: edits made on one tab (e.g. group membership)
    // must show on the next without reopening the admin screen. The group tabs also
    // need the users cache (member picker + delegation editors) — fetch it first
    // when it's still empty (admin screen opened straight onto a group tab).
    if (groupTab) {
        const usersReady = adminUsersCache.length ? Promise.resolve() : loadAdminUsers();
        usersReady.then(name === 'groups' ? loadAdminShareGroups : loadAdminMgmtGroups);
    } else {
        loadAdminUsers();
    }
}

const AUDIT_ACTION_LABELS = {
    'auth.login': 'LOGIN',
    'auth.login_failed': 'LOGIN FAILED',
    'auth.logout': 'LOGOUT',
    'account.changepwd': 'PASSWORD CHANGED',
    'account.delete': 'ACCOUNT DELETED',
    'account.email_verified': 'EMAIL VERIFIED',
    'account.password_reset_requested': 'PASSWORD RESET REQUESTED',
    'account.password_reset': 'EMAIL PASSWORD RESET',
    'user.approve': 'USER APPROVED',
    'user.reject': 'REGISTRATION REJECTED',
    'user.role': 'ROLE CHANGED',
    'user.disable': 'USER DISABLED',
    'user.enable': 'USER ENABLED',
    'user.resetpwd': 'ADMIN PASSWORD RESET',
    'user.profile_edit': 'PROFILE UPDATED',
    'user.delete': 'USER DELETED',
    'user.create': 'USER CREATED',
    'user.controller.add': 'DIRECT MANAGER ASSIGNED',
    'user.controller.remove': 'DIRECT MANAGER REMOVED',
    'share_group.create': 'SHARE GROUP CREATED',
    'share_group.rename': 'SHARE GROUP RENAMED',
    'share_group.delete': 'SHARE GROUP DELETED',
    'share_group.member.add': 'SHARE GROUP MEMBER ADDED',
    'share_group.member.remove': 'SHARE GROUP MEMBER REMOVED',
    'share_group.owner.add': 'SHARE GROUP MANAGER ADDED',
    'share_group.owner.remove': 'SHARE GROUP MANAGER REMOVED',
    'mgmt_group.create': 'MANAGEMENT GROUP CREATED',
    'mgmt_group.rename': 'MANAGEMENT GROUP RENAMED',
    'mgmt_group.delete': 'MANAGEMENT GROUP DELETED',
    'mgmt_group.member.add': 'MANAGEMENT GROUP MEMBER ADDED',
    'mgmt_group.member.remove': 'MANAGEMENT GROUP MEMBER REMOVED',
    'mgmt_group.manager.add': 'MANAGEMENT GROUP MANAGER ADDED',
    'mgmt_group.manager.remove': 'MANAGEMENT GROUP MANAGER REMOVED',
    'map_share.direct.grant': 'DIRECT MAP ACCESS GRANTED',
    'map_share.direct.change': 'DIRECT MAP ACCESS CHANGED',
    'map_share.direct.remove': 'DIRECT MAP ACCESS REMOVED',
    'map_share.group.grant': 'GROUP MAP ACCESS GRANTED',
    'map_share.group.change': 'GROUP MAP ACCESS CHANGED',
    'map_share.group.remove': 'GROUP MAP ACCESS REMOVED',
};

const AUDIT_DETAIL_LABELS = {
    admin_id: 'Admin ID',
    admin_label: 'Admin',
    birth_date: 'Birth date',
    client_ip: 'Source IP',
    first_name: 'First name',
    group: 'Group ID',
    group_label: 'Group',
    last_name: 'Last name',
    new: 'New value',
    new_name: 'New name',
    new_role: 'New role',
    old: 'Previous value',
    old_name: 'Previous name',
    old_role: 'Previous role',
    operation: 'Operation',
    recipient: 'Recipient ID',
    recipient_label: 'Recipient',
    role: 'Role',
    user_id: 'User ID',
    user_label: 'User',
    verification_bypassed: 'Verification bypassed',
};

let activeAuditFilters = {
    event: '',
    begin: '',
    end: '',
    search: '',
};

function auditOptionLabel(value) {
    return value.toLowerCase().replace(/(^|[\s/])\S/g, match => match.toUpperCase());
}

function auditDateBoundary(value, includeFollowingDay = false) {
    const parts = String(value || '').split('-').map(Number);
    if (parts.length !== 3 || parts.some(part => !Number.isInteger(part))) return '';
    const date = new Date(parts[0], parts[1] - 1, parts[2] + (includeFollowingDay ? 1 : 0));
    return Number.isNaN(date.getTime()) ? '' : date.toISOString();
}

function setupAuditFilters() {
    const form = document.getElementById('adminAuditFilters');
    const event = document.getElementById('adminAuditEvent');
    const begin = document.getElementById('adminAuditBegin');
    const end = document.getElementById('adminAuditEnd');
    const search = document.getElementById('adminAuditSearch');
    const clear = document.getElementById('adminAuditClear');
    const error = document.getElementById('adminAuditFilterError');
    if (!form || !event || !begin || !end || !search || !clear || !error) return;

    Object.entries(AUDIT_ACTION_LABELS)
        .sort((a, b) => a[1].localeCompare(b[1]) || a[0].localeCompare(b[0]))
        .forEach(([value, label]) => {
            const option = document.createElement('option');
            option.value = value;
            option.textContent = auditOptionLabel(label);
            event.appendChild(option);
        });

    form.addEventListener('submit', submitEvent => {
        submitEvent.preventDefault();
        error.textContent = '';
        if (begin.value && end.value && begin.value > end.value) {
            error.textContent = 'Begin date must be on or before the end date.';
            return;
        }
        activeAuditFilters = {
            event: event.value,
            begin: auditDateBoundary(begin.value),
            end: auditDateBoundary(end.value, true),
            search: search.value.trim(),
        };
        loadAuditLog();
    });

    clear.addEventListener('click', () => {
        form.reset();
        error.textContent = '';
        activeAuditFilters = {
            event: '',
            begin: '',
            end: '',
            search: '',
        };
        loadAuditLog();
    });
}

function auditQueryString(before = null) {
    const parameters = new URLSearchParams();
    Object.entries(activeAuditFilters).forEach(([key, value]) => {
        // Adblocker naming rule: request URLs never carry "share" — action names
        // travel collab-aliased; the server restores the stored spelling.
        if (key === 'event' && value) value = value.replace('share', 'collab');
        if (value) parameters.set(key, value);
    });
    if (before !== null && before !== undefined) parameters.set('before', before);
    const query = parameters.toString();
    return query ? `?${query}` : '';
}

function formatAuditTimestamp(value) {
    const date = value ? new Date(value) : null;
    if (!date || Number.isNaN(date.getTime())) return value || 'unknown time';
    const pad = part => String(part).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} `
        + `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function auditWords(value) {
    return String(value || '')
        .replace(/[._]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
}

function auditDetailLabel(key) {
    const label = AUDIT_DETAIL_LABELS[key] || auditWords(key);
    return label ? label.charAt(0).toUpperCase() + label.slice(1) : 'Value';
}

function auditFriendlyValue(key, value) {
    const raw = String(value);
    const reasonLabels = {
        account_disabled: 'account disabled',
        approval_pending: 'administrator approval pending',
        bad_password: 'incorrect password',
        email_unverified: 'email address not verified',
        not_approved: 'account not approved',
        unknown_user: 'unknown username',
    };
    const operationLabels = {
        created: 'created',
        role_changed: 'role changed',
    };
    if (key === 'reason' && reasonLabels[raw]) return reasonLabels[raw];
    if (key === 'operation' && operationLabels[raw]) return operationLabels[raw];
    if (key === 'role' || key === 'old_role' || key === 'new_role') return auditWords(raw);
    return raw;
}

function auditNarrativeValue(key, value) {
    if (value === null || value === undefined || value === '') return 'empty';
    if (typeof value === 'boolean') return value ? 'yes' : 'no';
    return auditFriendlyValue(key, value);
}

function auditQuotedValue(key, value) {
    const formatted = auditNarrativeValue(key, value);
    return formatted === 'empty' ? formatted : `“${formatted}”`;
}

function auditMetadataValue(key, value) {
    if (value === null || value === undefined) return 'null';
    if (value === '') return '"" (empty string)';
    if (typeof value === 'object') return JSON.stringify(value);
    const raw = String(value);
    const friendly = auditFriendlyValue(key, value);
    return friendly === raw ? raw : `${friendly} [${raw}]`;
}

function formatAuditAction(entry) {
    return AUDIT_ACTION_LABELS[entry.action] || auditWords(entry.action).toUpperCase() || 'EVENT';
}

function auditTarget(entry) {
    return auditQuotedValue('target_label', entry.target_label || entry.target_id || 'unknown target');
}

function auditCounterparty(detail, labelKey, idKey) {
    return auditQuotedValue(labelKey, detail[labelKey] || detail[idKey] || 'unknown');
}

function auditChangeSummary(detail) {
    return Object.entries(detail).map(([key, value]) => {
        if (value && typeof value === 'object' && !Array.isArray(value)
                && Object.prototype.hasOwnProperty.call(value, 'old')
                && Object.prototype.hasOwnProperty.call(value, 'new')) {
            return `${auditDetailLabel(key)} ${auditQuotedValue(key, value.old)} → `
                + auditQuotedValue(key, value.new);
        }
        return `${auditDetailLabel(key)} ${auditQuotedValue(key, value)}`;
    }).join('; ');
}

function formatAuditMessage(entry) {
    const detail = entry.detail && typeof entry.detail === 'object' ? entry.detail : {};
    const actor = entry.actor_username || 'System';
    const target = auditTarget(entry);
    switch (entry.action) {
        case 'auth.login':
            return `${actor} signed in.`;
        case 'auth.login_failed':
            return `Login failed for ${auditQuotedValue('actor_username', entry.actor_username
                || 'unknown username')}: ${auditNarrativeValue('reason', detail.reason || 'unknown reason')}.`;
        case 'auth.logout':
            return `${actor} signed out.`;
        case 'account.changepwd':
            return `${actor} changed their password.`;
        case 'account.delete':
            return `${actor} deleted their account.`;
        case 'account.email_verified':
            return `${actor} verified their email address.`;
        case 'account.password_reset_requested':
            return `${actor} requested a password reset.`;
        case 'account.password_reset':
            return `${actor} reset their password using an email link.`;
        case 'user.approve':
            return `${actor} approved user ${target}.`;
        case 'user.reject':
            return `${actor} rejected the registration for ${target}.`;
        case 'user.role':
            return `${actor} changed ${target} from ${auditNarrativeValue('role', detail.old)} `
                + `to ${auditNarrativeValue('role', detail.new)}.`;
        case 'user.disable':
            return `${actor} disabled user ${target}.`;
        case 'user.enable':
            return `${actor} enabled user ${target}.`;
        case 'user.resetpwd':
            return `${actor} reset the password for ${target}.`;
        case 'user.profile_edit': {
            const changes = auditChangeSummary(detail);
            return `${actor} updated the profile for ${target}${changes ? `: ${changes}` : ''}.`;
        }
        case 'user.delete':
            return `${actor} deleted user ${target}.`;
        case 'user.create':
            return `${actor} created user ${target} with the `
                + `${auditNarrativeValue('role', detail.role)} role.`;
        case 'user.controller.add':
            return `${actor} assigned ${auditCounterparty(detail, 'admin_label', 'admin_id')} `
                + `as a manager of user ${target}.`;
        case 'user.controller.remove':
            return `${actor} removed ${auditCounterparty(detail, 'admin_label', 'admin_id')} `
                + `as a manager of user ${target}.`;
        case 'share_group.create':
            return `${actor} created share group ${target}.`;
        case 'share_group.rename':
            return `${actor} renamed share group ${auditQuotedValue('old_name', detail.old_name)} `
                + `to ${auditQuotedValue('new_name', detail.new_name)}.`;
        case 'share_group.delete':
            return `${actor} deleted share group ${target}.`;
        case 'share_group.member.add':
            return `${actor} added user ${auditCounterparty(detail, 'user_label', 'user_id')} `
                + `to share group ${target}.`;
        case 'share_group.member.remove':
            return `${actor} removed user ${auditCounterparty(detail, 'user_label', 'user_id')} `
                + `from share group ${target}.`;
        case 'share_group.owner.add':
            return `${actor} added ${auditCounterparty(detail, 'admin_label', 'admin_id')} `
                + `as a manager of share group ${target}.`;
        case 'share_group.owner.remove':
            return `${actor} removed ${auditCounterparty(detail, 'admin_label', 'admin_id')} `
                + `as a manager of share group ${target}.`;
        case 'mgmt_group.create':
            return `${actor} created management group ${target}.`;
        case 'mgmt_group.rename':
            return `${actor} renamed management group ${auditQuotedValue('old_name', detail.old_name)} `
                + `to ${auditQuotedValue('new_name', detail.new_name)}.`;
        case 'mgmt_group.delete':
            return `${actor} deleted management group ${target}.`;
        case 'mgmt_group.member.add':
            return `${actor} added user ${auditCounterparty(detail, 'user_label', 'user_id')} `
                + `to management group ${target}.`;
        case 'mgmt_group.member.remove':
            return `${actor} removed user ${auditCounterparty(detail, 'user_label', 'user_id')} `
                + `from management group ${target}.`;
        case 'mgmt_group.manager.add':
            return `${actor} assigned ${auditCounterparty(detail, 'admin_label', 'admin_id')} `
                + `to manage management group ${target}.`;
        case 'mgmt_group.manager.remove':
            return `${actor} stopped ${auditCounterparty(detail, 'admin_label', 'admin_id')} `
                + `from managing management group ${target}.`;
        case 'map_share.direct.grant':
        case 'map_share.direct.change':
        case 'map_share.group.grant':
        case 'map_share.group.change': {
            const isGroup = entry.action.startsWith('map_share.group.');
            const recipient = isGroup
                ? auditCounterparty(detail, 'group_label', 'group')
                : auditCounterparty(detail, 'recipient_label', 'recipient');
            const recipientType = isGroup ? 'group' : 'user';
            if (entry.action.endsWith('.change')) {
                return `${actor} changed ${recipientType} ${recipient} access to map ${target} `
                    + `from ${auditNarrativeValue('old_role', detail.old_role)} `
                    + `to ${auditNarrativeValue('new_role', detail.new_role)}.`;
            }
            return `${actor} granted ${recipientType} ${recipient} `
                + `${auditNarrativeValue('new_role', detail.new_role)} access to map ${target}.`;
        }
        case 'map_share.direct.remove':
            return `${actor} removed user ${auditCounterparty(detail, 'recipient_label', 'recipient')} `
                + `access to map ${target}.`;
        case 'map_share.group.remove':
            return `${actor} removed group ${auditCounterparty(detail, 'group_label', 'group')} `
                + `access to map ${target}.`;
        default: {
            const detailText = auditChangeSummary(detail);
            const targetText = entry.target_label || entry.target_id ? ` for ${target}` : '';
            return `${actor} recorded ${auditWords(entry.action) || 'an event'}${targetText}`
                + `${detailText ? `: ${detailText}` : ''}.`;
        }
    }
}

function appendAuditMetadata(container, label, value, valueKey = '') {
    const line = document.createElement('div');
    line.className = 'audit-record-line';
    const key = document.createElement('span');
    key.className = 'audit-record-key';
    key.textContent = `${label}:`;
    const output = document.createElement('span');
    output.className = 'audit-record-value';
    output.textContent = auditMetadataValue(valueKey, value);
    line.append(key, output);
    container.appendChild(line);
}

function appendAuditDetailMetadata(container, detail, prefix = 'Detail') {
    if (detail === null || detail === undefined) {
        appendAuditMetadata(container, prefix, null);
        return;
    }
    if (typeof detail !== 'object' || Array.isArray(detail)) {
        appendAuditMetadata(container, prefix, detail);
        return;
    }
    const entries = Object.entries(detail);
    if (!entries.length) {
        appendAuditMetadata(container, prefix, '{}');
        return;
    }
    entries.forEach(([key, value]) => {
        const label = `${prefix} · ${auditDetailLabel(key)}`;
        if (value && typeof value === 'object' && !Array.isArray(value)
                && Object.prototype.hasOwnProperty.call(value, 'old')
                && Object.prototype.hasOwnProperty.call(value, 'new')) {
            const change = `${auditMetadataValue(key, value.old)} → `
                + auditMetadataValue(key, value.new);
            appendAuditMetadata(container, label, change);
        } else if (value && typeof value === 'object') {
            appendAuditDetailMetadata(container, value, label);
        } else {
            appendAuditMetadata(container, label, value, key);
        }
    });
}

async function loadAuditLog(before = null) {
    const list = document.getElementById('adminAuditList');
    if (!list || !currentUserIsSuper()) return;
    if (before === null) {
        list.replaceChildren();
        const loading = document.createElement('p');
        loading.className = 'admin-detail-empty';
        loading.textContent = 'Loading audit events...';
        list.appendChild(loading);
    }
    try {
        const res = await apiFetch(`/admin/audit${auditQueryString(before)}`);
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || 'Could not load audit log');
        if (before === null) list.replaceChildren();
        (data.entries || []).forEach(entry => {
            const row = document.createElement('article');
            row.className = 'audit-row';

            const line = document.createElement('div');
            line.className = 'audit-log-line';

            const timestamp = document.createElement('time');
            timestamp.className = 'audit-log-timestamp';
            if (entry.ts) timestamp.dateTime = entry.ts;
            timestamp.textContent = `[${formatAuditTimestamp(entry.ts)}]`;

            const action = document.createElement('span');
            action.className = 'audit-log-action';
            action.textContent = `[${formatAuditAction(entry)}]`;

            const heading = document.createElement('span');
            heading.className = 'audit-row-heading audit-log-message';
            heading.textContent = formatAuditMessage(entry);

            line.append(timestamp, action, heading);
            row.appendChild(line);

            const details = document.createElement('details');
            details.className = 'audit-record-details';
            const summary = document.createElement('summary');
            summary.textContent = 'Record details';
            const metadata = document.createElement('div');
            metadata.className = 'audit-record-metadata';
            appendAuditMetadata(metadata, 'Event ID', entry.id);
            appendAuditMetadata(metadata, 'Stored timestamp', entry.ts);
            appendAuditMetadata(metadata, 'Action key', entry.action);
            appendAuditMetadata(metadata, 'Actor username', entry.actor_username);
            appendAuditMetadata(metadata, 'Actor role', entry.actor_role);
            appendAuditMetadata(metadata, 'Actor ID', entry.actor_id);
            appendAuditMetadata(metadata, 'Target label', entry.target_label);
            appendAuditMetadata(metadata, 'Target type', entry.target_type);
            appendAuditMetadata(metadata, 'Target ID', entry.target_id);
            appendAuditMetadata(metadata, 'Source IP', entry.client_ip);
            appendAuditDetailMetadata(metadata, entry.detail);
            details.append(summary, metadata);
            row.appendChild(details);
            list.appendChild(row);
        });
        if (!(data.entries || []).length && before === null) {
            const empty = document.createElement('p');
            empty.className = 'admin-detail-empty';
            empty.textContent = Object.values(activeAuditFilters).some(Boolean)
                ? 'No audit events match these filters.'
                : 'No audit events yet.';
            list.appendChild(empty);
        }
        if (data.next_before !== null && data.next_before !== undefined) {
            const more = document.createElement('button');
            more.type = 'button';
            more.className = 'audit-load-more';
            more.textContent = 'Load more';
            more.addEventListener('click', () => {
                more.remove();
                loadAuditLog(data.next_before);
            });
            list.appendChild(more);
        }
    } catch (error) {
        if (before === null) list.replaceChildren();
        const message = document.createElement('p');
        message.className = 'admin-detail-empty';
        message.textContent = error.message || 'Could not load audit log';
        list.appendChild(message);
    }
}

// ---- Create user overlay (admin) — stacks on top of User Management ----
function openCreateUserOverlay() {
    const overlay = document.getElementById('createUserOverlay');
    if (!overlay) return;
    document.getElementById('createUserForm').reset();
    document.getElementById('createUserError').textContent = '';
    document.getElementById('createUserMessage').textContent = '';
    // Only a super-admin can create admins; regular admins create regular users only.
    const roleField = document.getElementById('createUserRoleField');
    const roleSel = document.getElementById('createUserRole');
    if (roleField) roleField.style.display = currentUserIsSuper() ? '' : 'none';
    if (roleSel && !currentUserIsSuper()) roleSel.value = 'user';
    overlay.style.display = 'flex';
    requestAnimationFrame(() => overlay.classList.add('active'));
}

function closeCreateUserOverlay() {
    const overlay = document.getElementById('createUserOverlay');
    if (!overlay) return;
    overlay.classList.remove('active');
    setTimeout(() => overlay.style.display = 'none', 250);
}

function setupCreateUserOverlay() {
    const form = document.getElementById('createUserForm');
    addBackdropClose('createUserOverlay', closeCreateUserOverlay);
    if (!form) return;
    form.addEventListener('submit', async e => {
        e.preventDefault();
        const err = document.getElementById('createUserError');
        const msg = document.getElementById('createUserMessage');
        err.textContent = ''; msg.textContent = '';
        const username = document.getElementById('createUserUsername').value.trim();
        const password = document.getElementById('createUserPassword').value;
        const first = document.getElementById('createUserFirstName').value.trim();
        const last = document.getElementById('createUserLastName').value.trim();
        const email = document.getElementById('createUserEmail').value.trim();
        if (!username) { err.textContent = 'Username is required'; return; }
        const policyErr = passwordPolicyError(password);
        if (policyErr) { err.textContent = policyErr; return; }
        if (!first || !last) { err.textContent = 'First name and last name are required'; return; }
        if (!email) { err.textContent = 'Email is required'; return; }
        try {
            const res = await apiFetch('/admin/users/create', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username, password,
                    first_name: first, last_name: last, email: email,
                    company: document.getElementById('createUserCompany').value.trim(),
                    department: document.getElementById('createUserDepartment').value.trim(),
                    birth_date: document.getElementById('createUserBirthDate').value,
                    sex: document.getElementById('createUserSex').value,
                    role: document.getElementById('createUserRole').value
                })
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) { err.textContent = data.error || 'Create failed'; return; }
            showNotification(`User created: ${username}`);
            closeCreateUserOverlay();
            // Admin-created users are pre-approved — land on the tab they show in.
            selectAdminTab('active');
        } catch (e2) {
            err.textContent = 'Create failed';
        }
    });
}

// ---- Edit user profile overlay (admin/super) — same governance as resetpwd:
// controls() for regular admins, supers unscoped (own row and admin-level rows
// included). Username rides along; identity is user_id so no session churn.
let editUserTarget = null;

function openEditUserOverlay(u) {
    const overlay = document.getElementById('editUserOverlay');
    if (!overlay) return;
    editUserTarget = u;
    document.getElementById('editUserError').textContent = '';
    document.getElementById('editUserMessage').textContent = '';
    document.getElementById('editUserUsername').value = u.username || '';
    document.getElementById('editUserEmail').value = u.email || '';
    document.getElementById('editUserFirstName').value = u.first_name || '';
    document.getElementById('editUserLastName').value = u.last_name || '';
    document.getElementById('editUserCompany').value = u.company || '';
    document.getElementById('editUserDepartment').value = u.department || '';
    document.getElementById('editUserBirthDate').value = u.birth_date || '';
    document.getElementById('editUserSex').value = u.sex || '';
    overlay.style.display = 'flex';
    requestAnimationFrame(() => overlay.classList.add('active'));
}

function closeEditUserOverlay() {
    const overlay = document.getElementById('editUserOverlay');
    if (!overlay) return;
    overlay.classList.remove('active');
    setTimeout(() => overlay.style.display = 'none', 250);
}

function setupEditUserOverlay() {
    const form = document.getElementById('editUserForm');
    addBackdropClose('editUserOverlay', closeEditUserOverlay);
    if (!form) return;
    form.addEventListener('submit', async e => {
        e.preventDefault();
        if (!editUserTarget) return;
        const err = document.getElementById('editUserError');
        const msg = document.getElementById('editUserMessage');
        err.textContent = ''; msg.textContent = '';
        const username = document.getElementById('editUserUsername').value.trim();
        const first = document.getElementById('editUserFirstName').value.trim();
        const last = document.getElementById('editUserLastName').value.trim();
        const email = document.getElementById('editUserEmail').value.trim();
        if (!username) { err.textContent = 'Username is required'; return; }
        if (!first || !last) { err.textContent = 'First name and last name are required'; return; }
        if (!email) { err.textContent = 'Email is required'; return; }
        const bypassVerification = (
            emailAccountFlowsEnabled
            && (
                !editUserTarget.email_verified
                || email.toLowerCase() !== (editUserTarget.email || '').toLowerCase()
            )
        );
        if (bypassVerification
                && !window.confirm('Save this profile and mark the email address verified?')) {
            return;
        }
        try {
            const res = await apiFetch(`/admin/users/${editUserTarget.user_id}/profile`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username,
                    first_name: first, last_name: last, email: email,
                    company: document.getElementById('editUserCompany').value.trim(),
                    department: document.getElementById('editUserDepartment').value.trim(),
                    birth_date: document.getElementById('editUserBirthDate').value,
                    sex: document.getElementById('editUserSex').value,
                    bypass_verification: bypassVerification
                })
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) { err.textContent = data.error || 'Save failed'; return; }
            // Self-edit (supers only can reach their own row): several UI checks compare
            // against currentUser.username (isSelf, Co-managers filtering), so patch the
            // cached identity and the account header now — the access token still carries
            // the old username claim until the next refresh, which is accepted cosmetics.
            if (editUserTarget.username === currentUser.username) {
                currentUser.username = username;
                currentUser.first_name = first;
                currentUser.last_name = last;
                updateAccountName();
            }
            showNotification(`Profile updated: ${username}`);
            closeEditUserOverlay();
            loadAdminUsers();
        } catch (e2) {
            err.textContent = 'Save failed';
        }
    });
}

let adminUsersCache = [];
let selectedAdminUserId = null;

async function loadAdminUsers() {
    const list = document.getElementById('adminUserList');
    if (!list) return;
    list.textContent = 'Loading...';
    try {
        const res = await apiFetch('/admin/users');
        if (!res.ok) throw new Error('Failed to load users');
        adminUsersCache = await res.json();
        renderAdminUsers(adminUsersCache);
        // Keep the detail pane in sync: actions (approve/promote/...) reload the list, and
        // the selected user's row data may have changed under the open detail pane. A user
        // whose status left the current tab (just approved/disabled) clears the pane — the
        // admin stays in the queue they were working.
        if (selectedAdminUserId) {
            const u = adminUsersCache.find(x => x.user_id === selectedAdminUserId);
            if (u && u.status === STATUS_BY_TAB[activeAdminTab]) renderAdminUserDetail(u);
            else clearAdminUserDetail();   // deleted/rejected, or moved to another tab
        }
    } catch (err) {
        console.error(err);
        list.textContent = 'Failed to load users.';
    }
}

async function adminAction(path, label, body = null) {
    try {
        const options = { method: 'POST' };
        if (body !== null) {
            options.headers = { 'Content-Type': 'application/json' };
            options.body = JSON.stringify(body);
        }
        const res = await apiFetch(path, options);
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || 'Action failed');
        showNotification(label);
        loadAdminUsers();
    } catch (err) {
        showNotification(err.message || 'Action failed');
    }
}

async function adminSetRole(userId, role) {
    try {
        const res = await apiFetch(`/admin/users/${userId}/role`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ role })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || 'Action failed');
        showNotification(`Role set to ${role}`);
        loadAdminUsers();
    } catch (err) {
        showNotification(err.message || 'Action failed');
    }
}

// Delete is destructive and cascades (the user's maps/markers/photos go too), so confirm first.
function confirmDeleteUser(u) {
    const label = [u.first_name, u.last_name].filter(Boolean).join(' ').trim() || u.username;
    showConfirmation(
        `Delete ${label}? This permanently deletes the account and all their maps. This cannot be undone.`,
        () => adminDeleteUser(u.user_id),
        () => {},
        'admin-delete-user',
        u.user_id
    );
}

async function adminDeleteUser(userId) {
    try {
        const res = await apiFetch(`/admin/users/${userId}`, { method: 'DELETE' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || 'Delete failed');
        showNotification('User deleted');
        if (selectedAdminUserId === userId) selectedAdminUserId = null;
        loadAdminUsers();
    } catch (err) {
        showNotification(err.message || 'Delete failed');
    }
}

// ---- Reset password overlay (admin sets a user's password) ----
let resetPwdTargetId = null;

function openResetPwdOverlay(u) {
    const overlay = document.getElementById('resetPwdOverlay');
    if (!overlay) return;
    resetPwdTargetId = u.user_id;
    const label = [u.first_name, u.last_name].filter(Boolean).join(' ').trim() || u.username;
    document.getElementById('resetPwdTarget').textContent = label + ' (' + u.username + ')';
    document.getElementById('resetPwdForm').reset();
    document.getElementById('resetPwdError').textContent = '';
    document.getElementById('resetPwdMessage').textContent = '';
    overlay.style.display = 'flex';
    requestAnimationFrame(() => overlay.classList.add('active'));
}

function closeResetPwdOverlay() {
    const overlay = document.getElementById('resetPwdOverlay');
    if (!overlay) return;
    overlay.classList.remove('active');
    setTimeout(() => overlay.style.display = 'none', 250);
}

function setupResetPwdOverlay() {
    const form = document.getElementById('resetPwdForm');
    addBackdropClose('resetPwdOverlay', closeResetPwdOverlay);
    if (!form) return;
    form.addEventListener('submit', async e => {
        e.preventDefault();
        const err = document.getElementById('resetPwdError');
        const msg = document.getElementById('resetPwdMessage');
        err.textContent = ''; msg.textContent = '';
        const newp = document.getElementById('resetPwdNew').value;
        const rep = document.getElementById('resetPwdRepeat').value;
        if (newp !== rep) { err.textContent = 'Passwords do not match'; return; }
        const policyErr = passwordPolicyError(newp);
        if (policyErr) { err.textContent = policyErr; return; }
        try {
            const res = await apiFetch(`/admin/users/${resetPwdTargetId}/resetpwd`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ new_password: newp })
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) { err.textContent = data.error || 'Reset failed'; return; }
            showNotification('Password reset');
            closeResetPwdOverlay();
        } catch (e2) {
            err.textContent = 'Reset failed';
        }
    });
}

// Inline SVG icons for the User Management row actions (24x24 stroke, like the map icons).
const ADMIN_ICONS = {
    approve: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
    reject:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
    promote: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 12 9 15 12"/><line x1="12" y1="9" x2="12" y2="16"/></svg>',
    demote:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 12 15 15 12"/><line x1="12" y1="8" x2="12" y2="15"/></svg>',
    disable: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.9" y1="4.9" x2="19.1" y2="19.1"/></svg>',
    enable:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="8 12 11 15 16 9"/></svg>',
    resetpwd:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><line x1="10.85" y1="12.15" x2="19" y2="4"/><line x1="18" y1="5" x2="20" y2="7"/><line x1="15" y1="8" x2="17" y2="10"/></svg>',
    edit:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg>',
    delete:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>'
};

// Shared row builder for the master lists (users + groups): title, optional subtitle,
// meta line, click-to-select highlighting.
function addMasterRow(list, { title, subtitle, meta, selected, onSelect, showAvatar = false, avatarUrl = null }) {
    const row = document.createElement('div');
    row.className = 'admin-user-row' + (selected ? ' selected' : '');

    if (showAvatar) {
        row.appendChild(userAvatar(avatarUrl, 'admin-user-avatar', `${title} avatar`));
    }
    const info = document.createElement('div');
    info.className = 'admin-user-info';
    const name = document.createElement('span');
    name.className = 'admin-user-name';
    name.textContent = title;
    info.appendChild(name);
    if (subtitle) {
        const sub = document.createElement('span');
        sub.className = 'admin-user-realname';
        sub.textContent = subtitle;
        info.appendChild(sub);
    }
    if (meta) {
        const m = document.createElement('span');
        m.className = 'admin-user-meta';
        m.textContent = meta;
        info.appendChild(m);
    }
    row.appendChild(info);
    row.addEventListener('click', onSelect);
    list.appendChild(row);
}

// Inner tab bar for a detail pane ([Details | Maps] on users, [Details | Members] on
// groups). Panels show one at a time; a panel's onFirstShow runs once, on its first
// activation (click-driven loading, no preloading). `active` restores the tab across
// the constant re-renders (actions reload the list), `onChange` records it.
function buildDetailTabs(tabs, active, onChange) {
    const bar = document.createElement('div');
    bar.className = 'admin-detail-tabs';
    const activate = idx => {
        tabs.forEach((t, i) => {
            t._btn.classList.toggle('active', i === idx);
            t.el.style.display = i === idx ? '' : 'none';
        });
        const first = tabs[idx].onFirstShow;
        if (first) {
            tabs[idx].onFirstShow = null;
            first();
        }
        if (onChange) onChange(idx);
    };
    tabs.forEach((t, i) => {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'admin-detail-tab';
        b.textContent = t.label;
        b.addEventListener('click', () => activate(i));
        t._btn = b;
        bar.appendChild(b);
    });
    activate(active || 0);
    return bar;
}

// Active inner tab per pane, remembered across re-renders (list reloads re-render the
// detail; jumping back to Details mid-membership-edit would be maddening).
let adminUserDetailTab = 0;
let adminShareGroupDetailTab = 0;
// Members-tab list filters, kept while the same group stays selected (add/remove
// reloads re-render the pane and would otherwise wipe mid-flow filter text).
let adminShareGroupListFilters = { groupId: null, picker: '', members: '' };

// Filterable pick list: a search input above a PERSISTENT scrollable result list —
// the same interaction as the sidebar marker filters. Clicking a row selects it
// (highlighted); typing re-filters and clears the selection. resolve() is what the
// consuming button reads: the clicked row, else an exact text match, else the single
// remaining match.
function buildFilterPicker({ placeholder, candidates, onPick }) {
    let candidatesList = candidates || [];
    let picked = null;
    const labelOf = candidate => typeof candidate === 'string' ? candidate : candidate.label;
    const root = document.createElement('div');
    root.className = 'filter-picker';
    const input = document.createElement('input');
    input.type = 'text';
    input.placeholder = placeholder || 'Type to filter...';
    input.autocomplete = 'off';
    const list = document.createElement('div');
    list.className = 'filter-picker-list';
    const render = () => {
        const text = input.value.trim().toLowerCase();
        list.textContent = '';
        const matches = candidatesList.filter(candidate => labelOf(candidate).toLowerCase().includes(text));
        if (!matches.length) {
            const p = document.createElement('div');
            p.className = 'filter-picker-empty';
            p.textContent = 'No matches';
            list.appendChild(p);
            return;
        }
        matches.forEach(candidate => {
            const rowEl = document.createElement('div');
            rowEl.className = 'filter-picker-item' + (candidate === picked ? ' selected' : '');
            if (typeof candidate !== 'string' && candidate.showAvatar) {
                rowEl.appendChild(userAvatar(
                    candidate.avatar_url,
                    'collab-list-avatar',
                    `${labelOf(candidate)} avatar`
                ));
                const label = document.createElement('span');
                label.textContent = labelOf(candidate);
                rowEl.appendChild(label);
            } else {
                rowEl.textContent = labelOf(candidate);
            }
            rowEl.addEventListener('click', () => {
                picked = candidate;
                list.querySelectorAll('.filter-picker-item.selected').forEach(x => x.classList.remove('selected'));
                rowEl.classList.add('selected');
                if (onPick) onPick(candidate);
            });
            list.appendChild(rowEl);
        });
    };
    input.addEventListener('input', () => {
        picked = null;
        if (onPick) onPick(null);
        render();
    });
    root.appendChild(input);
    root.appendChild(list);
    render();
    return {
        el: root,
        input,
        refresh(newCandidates) { candidatesList = newCandidates || []; picked = null; render(); },
        clear() { input.value = ''; picked = null; render(); },
        picked: () => picked,
        resolve() {
            if (picked) return picked;
            const text = input.value.trim().toLowerCase();
            if (!text) return null;
            const exact = candidatesList.filter(candidate => labelOf(candidate).toLowerCase() === text);
            if (exact.length === 1) return exact[0];
            if (exact.length > 1) return null;
            const matches = candidatesList.filter(candidate => labelOf(candidate).toLowerCase().includes(text));
            return matches.length === 1 ? matches[0] : null;
        }
    };
}

// Action list: a labeled filter input over a fixed-height list where every row is a
// name with its own action button (+ add / × remove). The group Members tab uses one
// per side. Rows flagged noAction render name-only (e.g. members outside the caller's
// control scope). initialFilter/onFilter let the caller persist the filter text
// across the reload-driven re-renders.
function buildActionList({ label, placeholder, items, actionLabel, actionClass, onAction, emptyText, initialFilter, onFilter, extraClass }) {
    const root = document.createElement('div');
    root.className = 'filter-picker action-list' + (extraClass ? ' ' + extraClass : '');
    if (label) {
        const l = document.createElement('div');
        l.className = 'admin-group-list-label';
        l.textContent = label;
        root.appendChild(l);
    }
    const input = document.createElement('input');
    input.type = 'text';
    input.placeholder = placeholder || 'Type to filter...';
    input.autocomplete = 'off';
    input.value = initialFilter || '';
    const list = document.createElement('div');
    list.className = 'filter-picker-list';
    const render = () => {
        const text = input.value.trim().toLowerCase();
        list.textContent = '';
        const matches = items.filter(it => it.label.toLowerCase().includes(text));
        if (!matches.length) {
            const p = document.createElement('div');
            p.className = 'filter-picker-empty';
            p.textContent = text ? 'No matches' : (emptyText || 'No matches');
            list.appendChild(p);
            return;
        }
        matches.forEach(it => {
            const rowEl = document.createElement('div');
            rowEl.className = 'action-list-row';
            if (it.showAvatar) {
                rowEl.appendChild(userAvatar(it.avatar_url, 'collab-list-avatar', `${it.label} avatar`));
            }
            const nm = document.createElement('span');
            nm.className = 'action-list-name';
            nm.textContent = it.label;
            nm.title = it.label;
            rowEl.appendChild(nm);
            if (!it.noAction) {
                const b = document.createElement('button');
                b.type = 'button';
                b.className = 'action-list-btn' + (actionClass ? ' ' + actionClass : '');
                b.textContent = actionLabel;
                b.addEventListener('click', () => onAction(it));
                rowEl.appendChild(b);
            }
            list.appendChild(rowEl);
        });
    };
    input.addEventListener('input', () => {
        if (onFilter) onFilter(input.value);
        render();
    });
    root.appendChild(input);
    root.appendChild(list);
    render();
    return root;
}

// Shared editor for the many-to-many delegation lists (a user's controlling admins, a
// group's owning admins). Renders each current grant with a revoke button plus a picker
// of the remaining admins; assignment is ADDITIVE and revocation TARGETED — co-grants
// are never disturbed. Super-admin only (the call sites gate on that).
function buildDelegationEditor({ current, emptyLabel, addUrl, removeUrl, notifyAdd, notifyRemove, reload }) {
    const box = document.createElement('div');
    box.className = 'admin-delegation-box';
    if (!current.length) {
        const none = document.createElement('span');
        none.className = 'admin-delegation-empty';
        none.textContent = emptyLabel;
        box.appendChild(none);
    }
    current.forEach(a => {
        const chip = document.createElement('span');
        chip.className = 'admin-delegation-chip';
        const nm = document.createElement('span');
        nm.textContent = personName(a.first_name, a.last_name, a.username);
        chip.appendChild(nm);
        const rm = document.createElement('button');
        rm.type = 'button';
        rm.className = 'admin-delegation-remove';
        rm.dataset.tip = 'Revoke';
        rm.setAttribute('aria-label', `Revoke ${personName(a.first_name, a.last_name, a.username)}`);
        rm.textContent = '×';
        rm.addEventListener('click', async () => {
            try {
                const res = await apiFetch(removeUrl(a), { method: 'DELETE' });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) throw new Error(data.error || 'Revoke failed');
                showNotification(notifyRemove(a));
                reload();
            } catch (err) {
                showNotification(err.message || 'Revoke failed');
            }
        });
        chip.appendChild(rm);
        box.appendChild(chip);
    });
    const currentIds = new Set(current.map(a => a.admin_id));
    const candidates = adminUsersCache
        .filter(a => a.role === 'admin' && a.status === 'approved' && !currentIds.has(a.user_id));
    if (candidates.length) {
        const sel = document.createElement('select');
        sel.className = 'admin-controller-select';
        const ph = document.createElement('option');
        ph.value = '';
        ph.textContent = 'Add…';
        sel.appendChild(ph);
        candidates.forEach(a => {
            const opt = document.createElement('option');
            opt.value = a.user_id;
            opt.textContent = personName(a.first_name, a.last_name, a.username);
            sel.appendChild(opt);
        });
        sel.addEventListener('change', async () => {
            if (!sel.value) return;
            const name = sel.options[sel.selectedIndex].textContent;
            try {
                const res = await apiFetch(addUrl, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ admin_id: sel.value })
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) throw new Error(data.error || 'Assignment failed');
                showNotification(notifyAdd(name));
                reload();
            } catch (err) {
                showNotification(err.message || 'Assignment failed');
                sel.value = '';
            }
        });
        box.appendChild(sel);
    }
    return box;
}

// Master list: selection only — profile, actions and maps live in the detail pane.
function renderAdminUsers(users) {
    const list = document.getElementById('adminUserList');
    list.textContent = '';

    // Only the active tab's status bucket, narrowed by the master-list filter
    // (username or full name). Usernames render as stored — never capitalized.
    const filterEl = document.getElementById('adminUserFilter');
    const needle = filterEl ? filterEl.value.trim().toLowerCase() : '';
    const visible = users.filter(u => {
        if (u.status !== STATUS_BY_TAB[activeAdminTab]) return false;
        if (!needle) return true;
        const fullName = [u.first_name, u.last_name].filter(Boolean).join(' ').trim();
        return u.username.toLowerCase().includes(needle) || fullName.toLowerCase().includes(needle);
    });

    visible.forEach(u => {
        const fullName = [u.first_name, u.last_name].filter(Boolean).join(' ').trim();
        // Nobody-land marker (super view only): approved users with NO source of
        // control — neither a direct controller nor a management-group manager — are
        // assignable; flag them so the super can spot them in the list.
        let meta = prettyRole(u.role);
        if (currentUserIsSuper() && u.role === 'user' && u.status !== 'pending'
            && !(u.controllers && u.controllers.length) && !(u.group_managers && u.group_managers.length)) {
            meta += ' · Unassigned';
        }
        addMasterRow(list, {
            title: fullName || u.username,
            subtitle: fullName ? u.username : '',
            meta,
            showAvatar: u.status !== 'pending',
            avatarUrl: u.avatar_url,
            selected: u.user_id === selectedAdminUserId,
            onSelect: () => {
                selectedAdminUserId = u.user_id;
                renderAdminUsers(adminUsersCache);
                renderAdminUserDetail(u);
            }
        });
    });

    if (!visible.length) list.textContent = needle ? 'No matching users.' : 'No users.';
}

function clearAdminUserDetail() {
    selectedAdminUserId = null;
    const detail = document.getElementById('adminUserDetail');
    if (!detail) return;
    detail.textContent = '';
    const p = document.createElement('p');
    p.className = 'admin-detail-empty';
    p.textContent = 'Select a user to see their profile and maps.';
    detail.appendChild(p);
}

// Detail pane for the selected user: profile facts, the action icon buttons (same
// governance guards as before the revamp), and the maps-metadata section.
function renderAdminUserDetail(u) {
    const detail = document.getElementById('adminUserDetail');
    if (!detail) return;
    detail.textContent = '';

    const header = document.createElement('div');
    header.className = 'admin-detail-header';
    const titleBox = document.createElement('div');
    titleBox.className = 'admin-detail-title';
    const name = document.createElement('span');
    name.className = 'admin-detail-name';
    const displayName = personName(u.first_name, u.last_name, u.username);
    name.textContent = displayName;
    titleBox.appendChild(name);
    if (displayName !== u.username) {
        const real = document.createElement('span');
        real.className = 'admin-detail-realname';
        real.textContent = u.username;
        titleBox.appendChild(real);
    }
    header.appendChild(titleBox);

    const actions = document.createElement('div');
    actions.className = 'admin-user-actions';

    const addIconBtn = (iconKey, tip, handler, extraClass) => {
        const b = document.createElement('button');
        b.className = 'icon-btn' + (extraClass ? ' ' + extraClass : '');
        b.dataset.tip = tip;
        b.setAttribute('aria-label', tip);
        b.innerHTML = ADMIN_ICONS[iconKey];
        b.addEventListener('click', handler);
        actions.appendChild(b);
    };

    // Governance: only a super-admin may act on admin/super-admin accounts.
    // A regular admin sees admin/super accounts read-only (no action buttons).
    const targetIsAdmin = isAdminRole(u.role);
    const isSelf = u.username === currentUser.username;
    const canAct = currentUserIsSuper() || !targetIsAdmin;

    if (canAct) {
        // Edit profile (incl. username). Supers get this on EVERY row including their
        // own and other admin/super rows (explicit exception to the hide-self-actions
        // convention); regular admins get it on the users they control — which is
        // their whole visible list.
        addIconBtn('edit', 'Edit profile', () => openEditUserOverlay(u));
        if (u.status === 'pending') {
            const approve = () => {
                if (emailAccountFlowsEnabled && !u.email_verified) {
                    if (!window.confirm('This email is not verified. Approve the account and mark the email verified?')) return;
                    adminAction(
                        `/admin/users/${u.user_id}/approve`,
                        'User approved; email verification bypassed',
                        { bypass_verification: true }
                    );
                    return;
                }
                adminAction(`/admin/users/${u.user_id}/approve`, 'User approved');
            };
            addIconBtn(
                'approve',
                emailAccountFlowsEnabled && !u.email_verified
                    ? 'Approve and mark email verified'
                    : 'Approve',
                approve
            );
            addIconBtn('reject', 'Reject', () => adminAction(`/admin/users/${u.user_id}/reject`, 'User rejected'), 'danger');
        } else if (u.status === 'approved') {
            // Promote/demote is super-only. A super-admin's role is UI-immutable (CLI-only),
            // so never offer a role toggle on a super-admin account.
            if (currentUserIsSuper() && u.role !== 'super_admin' && !isSelf) {
                if (u.role === 'admin') {
                    addIconBtn('demote', 'Demote to user', () => adminSetRole(u.user_id, 'user'));
                } else {
                    addIconBtn('promote', 'Promote to admin', () => adminSetRole(u.user_id, 'admin'));
                }
            }
            if (!isSelf) {
                addIconBtn('disable', 'Disable', () => adminAction(`/admin/users/${u.user_id}/disable`, 'User disabled'));
            }
        } else if (u.status === 'disabled') {
            addIconBtn('enable', 'Enable', () => adminAction(`/admin/users/${u.user_id}/enable`, 'User enabled'));
        }

        // Reset password (not on your own account — use Change Password for that).
        if (!isSelf) {
            addIconBtn('resetpwd', 'Reset password', () => openResetPwdOverlay(u));
        }

        // Delete is super-only (cross-scope blast radius, per the permissions model).
        if (currentUserIsSuper() && !isSelf) {
            addIconBtn('delete', 'Delete user', () => confirmDeleteUser(u), 'danger');
        }
    }

    header.appendChild(actions);
    detail.appendChild(header);

    const facts = document.createElement('div');
    facts.className = 'admin-facts';
    const addFact = (label, value) => {
        if (!value) return;
        const rowEl = document.createElement('div');
        const l = document.createElement('span');
        l.className = 'admin-fact-label';
        l.textContent = label;
        const v = document.createElement('span');
        v.textContent = value;
        rowEl.appendChild(l);
        rowEl.appendChild(v);
        facts.appendChild(rowEl);
    };
    addFact('Email', u.email);
    if (emailAccountFlowsEnabled) {
        addFact('Email verification', u.email_verified ? 'Verified' : 'Not verified');
    }
    // No Status fact: the status tabs already say it.
    addFact('Role', prettyRole(u.role));
    addFact('Member since', u.created ? new Date(u.created).toLocaleDateString() : '');
    addFact('Company', u.company);
    addFact('Department', u.department);
    addFact('Birth date', u.birth_date);
    addFact('Sex', prettyEnum(u.sex));
    addFact('Share groups', (u.share_groups && u.share_groups.length) ? u.share_groups.join(', ') : 'None');
    // Management-group membership is super-admin detail (addendum-3 Visibility); the
    // backend omits the key for regular admins. Mirror the Share groups 'None' shape.
    if (currentUserIsSuper()) {
        addFact('Management groups', (u.management_groups && u.management_groups.length) ? u.management_groups.join(', ') : 'None');
    }

    const makeManagersSection = () => {
        const section = document.createElement('div');
        section.className = 'admin-managers-section';
        const title = document.createElement('div');
        title.className = 'admin-managers-title';
        title.textContent = 'Managers';
        section.appendChild(title);
        const rows = document.createElement('div');
        rows.className = 'admin-facts admin-manager-rows';
        section.appendChild(rows);
        return { section, rows };
    };
    const addManagerRow = (rows, label, value) => {
        const rowEl = document.createElement('div');
        const l = document.createElement('span');
        l.className = 'admin-fact-label';
        l.textContent = label;
        rowEl.appendChild(l);
        if (typeof value === 'string') {
            const v = document.createElement('span');
            v.textContent = value;
            rowEl.appendChild(v);
        } else {
            rowEl.appendChild(value);
        }
        rows.appendChild(rowEl);
    };

    let managersSection = null;
    // Regular admins get one source-agnostic, read-only list already deduplicated by
    // the backend. Their only extra fact is the co-managers line at the bottom of the
    // normal details, rather than a separate Managers section.
    if (!currentUserIsSuper()) {
        const others = (u.managers || [])
            .filter(c => c.username !== currentUser.username);
        if (others.length) {
            addFact(
                'Co-managers',
                others.map(c => personName(c.first_name, c.last_name, c.username)).join(', ')
            );
        }
    } else if (u.role === 'user' && u.status !== 'pending') {
        // Super-admin tooling preserves source detail: direct grants remain editable,
        // while group-derived managers are a separate read-only row.
        const viaGroup = u.group_managers || [];
        const built = makeManagersSection();
        addManagerRow(built.rows, 'Direct Assignment', buildDelegationEditor({
            current: u.controllers || [],
            emptyLabel: viaGroup.length ? 'No direct assignment' : 'Nobody (unassigned)',
            addUrl: `/admin/users/${u.user_id}/controllers`,
            removeUrl: a => `/admin/users/${u.user_id}/controllers/${a.admin_id}`,
            notifyAdd: name => `${u.username} assigned to ${name}`,
            notifyRemove: a => `${a.username} no longer manages ${u.username}`,
            reload: loadAdminUsers
        }));
        if (viaGroup.length) {
            addManagerRow(
                built.rows,
                'Group Assignment',
                viaGroup.map(c => personName(c.first_name, c.last_name, c.username)).join(', ')
            );
        }
        managersSection = built.section;
    }
    const detailsPanel = document.createElement('div');
    detailsPanel.className = 'admin-detail-panel';
    detailsPanel.appendChild(facts);
    if (managersSection) detailsPanel.appendChild(managersSection);

    const mapsPanel = document.createElement('div');
    mapsPanel.className = 'admin-detail-panel admin-maps-section';
    const mapsBox = document.createElement('div');
    mapsBox.className = 'admin-maps-list';
    mapsPanel.appendChild(mapsBox);

    detail.appendChild(buildDetailTabs([
        { label: 'Details', el: detailsPanel },
        { label: 'Maps', el: mapsPanel, onFirstShow: () => loadAdminUserMaps(u, mapsBox) }
    ], adminUserDetailTab, i => adminUserDetailTab = i));
    detail.appendChild(detailsPanel);
    detail.appendChild(mapsPanel);
}

// Share button on an admin maps row: only super-admins may inspect or manage another
// account's sharing connections. The caller's self-grant is blocked server-side.
function makeAdminShareBtn(mapId, mapName, ownerUsername) {
    const shareBtn = document.createElement('button');
    shareBtn.className = 'icon-btn';
    shareBtn.dataset.tip = 'Manage Sharing';
    shareBtn.setAttribute('aria-label', 'Manage Sharing');
    shareBtn.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="18" cy="5" r="3"/>
            <circle cx="6" cy="12" r="3"/>
            <circle cx="18" cy="19" r="3"/>
            <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
            <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
        </svg>
    `;
    shareBtn.addEventListener('click', () => openAdminShareOverlay(mapId, mapName, ownerUsername));
    return shareBtn;
}

// Maps-metadata section: contents (markers, photos, description/notes) are sealed
// server-side and never shown here. Regular admins get bare owned-map metadata; only
// super-admins get collaborator rosters and the maps shared WITH the selected user.
async function loadAdminUserMaps(u, box) {
    box.textContent = 'Loading...';
    try {
        const res = await apiFetch(`/admin/users/${u.user_id}/maps`);
        if (res.status === 403) {
            // Guard fallback: the target is outside the caller's management scope
            // (viewing maps needs controls() over the user). The scoped user list
            // makes this normally unreachable through the UI.
            box.textContent = 'This account is outside your management scope.';
            return;
        }
        const data = await safeJson(res, null);
        if (data === null) throw new Error('Unexpected response for maps');
        box.textContent = '';

        // Each subsection (Owned / Shared with this user) is its own card; rows and
        // empty lines go inside the card returned here.
        const addSection = label => {
            const card = document.createElement('div');
            card.className = 'admin-maps-card';
            const t = document.createElement('div');
            t.className = 'admin-maps-card-title';
            t.textContent = label;
            card.appendChild(t);
            box.appendChild(card);
            return card;
        };
        const addEmptyLine = (card, text) => {
            const p = document.createElement('p');
            p.className = 'admin-maps-empty';
            p.textContent = text;
            card.appendChild(p);
        };

        // Collaborator chips in labeled rows, groups on top; chips are colored by ROLE
        // (green editor / gray viewer, same tokens as the sidebar badge) — the row
        // label carries the type, so no per-type tint or tooltip.
        const buildCollabRows = rowsSpec => {
            const wrap = document.createElement('div');
            wrap.className = 'admin-map-collabs';
            rowsSpec.forEach(spec => {
                if (!spec.chips.length) return;
                const rowEl = document.createElement('div');
                rowEl.className = 'collab-chip-row';
                const lb = document.createElement('span');
                lb.className = 'collab-row-label';
                lb.textContent = spec.label;
                rowEl.appendChild(lb);
                spec.chips.forEach(ch => {
                    const chip = document.createElement('span');
                    chip.className = 'collab-chip role-' + ch.role;
                    chip.textContent = ch.text;
                    rowEl.appendChild(chip);
                });
                wrap.appendChild(rowEl);
            });
            return wrap.childNodes.length ? wrap : null;
        };

        const ownedCard = addSection('Owned');
        if (!data.owned.length) addEmptyLine(ownedCard, 'No maps.');
        data.owned.forEach(m => {
            const row = document.createElement('div');
            row.className = 'admin-map-row';

            // On the super-admin path, the share button sits right after the name and
            // the current relationships appear in chip rows below.
            const head = document.createElement('div');
            head.className = 'admin-map-head';
            const nameLine = document.createElement('div');
            nameLine.className = 'admin-map-name';
            nameLine.textContent = m.name;
            head.appendChild(nameLine);
            if (currentUserIsSuper() && !m.is_base) {
                // Base Maps are never shareable, so they get no share button.
                head.appendChild(makeAdminShareBtn(m.id, m.name, u.username));
            }
            row.appendChild(head);

            const meta = document.createElement('div');
            meta.className = 'admin-map-meta';
            const createdDate = m.created ? new Date(m.created).toLocaleDateString() : '';
            meta.textContent = `${createdDate} · ${m.markers} marker${m.markers === 1 ? '' : 's'} · ${m.photos} photo${m.photos === 1 ? '' : 's'}`;
            row.appendChild(meta);

            if (currentUserIsSuper()) {
                const collabRows = buildCollabRows([
                    { label: 'Groups:', chips: m.collaborators.filter(cb => cb.type === 'group').map(cb => ({ text: `${cb.name} · ${cb.role}`, role: cb.role })) },
                    { label: 'Users:', chips: m.collaborators.filter(cb => cb.type !== 'group').map(cb => ({ text: `${cb.name} · ${cb.role}`, role: cb.role })) }
                ]);
                if (collabRows) row.appendChild(collabRows);
            }
            ownedCard.appendChild(row);
        });

        if (currentUserIsSuper()) {
            const sharedCard = addSection('Shared with this user');
            if (!data.shared.length) addEmptyLine(sharedCard, 'None.');
            data.shared.forEach(m => {
                const row = document.createElement('div');
                row.className = 'admin-map-row';

                const head = document.createElement('div');
                head.className = 'admin-map-head';
                const nameLine = document.createElement('div');
                nameLine.className = 'admin-map-name';
                nameLine.textContent = m.name;
                head.appendChild(nameLine);
                head.appendChild(makeAdminShareBtn(m.id, m.name, m.owner));
                row.appendChild(head);

                const meta = document.createElement('div');
                meta.className = 'admin-map-meta';
                meta.textContent = `Owner: ${personName(m.owner_first, m.owner_last, m.owner)}`;
                row.appendChild(meta);

                // One chip per access path; the row labels say how the access arrives.
                const collabRows = buildCollabRows([
                    { label: 'Groups:', chips: m.paths.filter(pth => pth.type === 'group').map(pth => ({ text: `${pth.group} · ${pth.role}`, role: pth.role })) },
                    { label: 'Direct:', chips: m.paths.filter(pth => pth.type !== 'group').map(pth => ({ text: pth.role, role: pth.role })) }
                ]);
                if (collabRows) row.appendChild(collabRows);
                sharedCard.appendChild(row);
            });
        }
    } catch (err) {
        console.error(err);
        box.textContent = 'Failed to load maps.';
    }
}


// ===============================================================
// Share Groups tab (admin screen) — admin-managed sharing groups + their members.
// DOM ids and CSS classes keep the bare "group" naming (never "share..."): adblock
// filter lists match "share" substrings in element ids/classes and quietly hide them.
// ===============================================================
let adminShareGroupsCache = [];
let selectedAdminShareGroupId = null;

function setupShareGroupsTab() {
    const createBtn = document.getElementById('adminCreateGroupBtn');
    const nameInput = document.getElementById('newGroupName');
    if (!createBtn || !nameInput) return;

    async function createGroup() {
        const name = nameInput.value.trim();
        if (!name) { showNotification('Enter a group name'); return; }
        try {
            const res = await apiFetch('/admin/groups', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name })
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(data.error || 'Create failed');
            nameInput.value = '';
            selectedAdminShareGroupId = data.id;
            showNotification(`Group created: ${data.name}`);
            loadAdminShareGroups();
        } catch (err) {
            showNotification(err.message || 'Create failed');
        }
    }
    createBtn.addEventListener('click', createGroup);
    nameInput.addEventListener('keydown', e => {
        if (e.key === 'Enter') { e.preventDefault(); createGroup(); }
    });
}

async function loadAdminShareGroups() {
    const list = document.getElementById('adminGroupList');
    if (!list) return;
    list.textContent = 'Loading...';
    try {
        const res = await apiFetch('/admin/groups');
        if (!res.ok) throw new Error('Failed to load groups');
        adminShareGroupsCache = await res.json();
        renderAdminShareGroups();
    } catch (err) {
        console.error(err);
        list.textContent = 'Failed to load groups.';
    }
}

function renderAdminShareGroups() {
    const list = document.getElementById('adminGroupList');
    list.textContent = '';

    // Master-list filter on the group name; group names render as stored.
    const filterEl = document.getElementById('adminGroupFilter');
    const needle = filterEl ? filterEl.value.trim().toLowerCase() : '';
    const visible = adminShareGroupsCache.filter(gr => !needle || gr.name.toLowerCase().includes(needle));

    visible.forEach(gr => {
        // Super view: show who owns each group (owns_group, possibly several co-owners);
        // admins only list their own.
        const ownerNames = (gr.owners || [])
            .map(o => personName(o.first_name, o.last_name, o.username))
            .join(', ');
        const ownerSuffix = currentUserIsSuper() ? ` · ${ownerNames || 'Super Admin'}` : '';
        addMasterRow(list, {
            title: gr.name,
            meta: `${gr.members.length} member${gr.members.length === 1 ? '' : 's'}${ownerSuffix}`,
            selected: gr.id === selectedAdminShareGroupId,
            onSelect: () => {
                selectedAdminShareGroupId = gr.id;
                renderAdminShareGroups();
            }
        });
    });
    if (!visible.length) list.textContent = needle ? 'No matching groups.' : 'No groups yet.';

    const sel = adminShareGroupsCache.find(g => g.id === selectedAdminShareGroupId);
    if (sel) renderAdminShareGroupDetail(sel);
    else clearAdminShareGroupDetail();
}

function clearAdminShareGroupDetail() {
    selectedAdminShareGroupId = null;
    const detail = document.getElementById('adminGroupDetail');
    if (!detail) return;
    detail.textContent = '';
    const p = document.createElement('p');
    p.className = 'admin-detail-empty';
    p.textContent = 'Select a group to manage its members.';
    detail.appendChild(p);
}

function renderAdminShareGroupDetail(gr) {
    const detail = document.getElementById('adminGroupDetail');
    if (!detail) return;
    detail.textContent = '';

    const header = document.createElement('div');
    header.className = 'admin-detail-header';
    const titleBox = document.createElement('div');
    titleBox.className = 'admin-detail-title';
    const name = document.createElement('span');
    name.className = 'admin-detail-name';
    name.textContent = gr.name;
    titleBox.appendChild(name);
    header.appendChild(titleBox);

    const actions = document.createElement('div');
    actions.className = 'admin-user-actions';

    // Rename: swap the title for an inline input. Enter saves, Escape/blur cancels.
    const renameBtn = document.createElement('button');
    renameBtn.className = 'icon-btn';
    renameBtn.dataset.tip = 'Rename group';
    renameBtn.setAttribute('aria-label', 'Rename group');
    renameBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg>';
    renameBtn.addEventListener('click', () => {
        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'admin-group-rename-input';
        input.value = gr.name;
        titleBox.replaceChild(input, name);
        input.focus();
        input.select();
        let done = false;
        const finish = restore => {
            if (done) return;
            done = true;
            if (restore && input.parentNode) titleBox.replaceChild(name, input);
        };
        input.addEventListener('keydown', async e => {
            if (e.key === 'Escape') { finish(true); return; }
            if (e.key !== 'Enter') return;
            e.preventDefault();
            const newName = input.value.trim();
            if (!newName || newName === gr.name) { finish(true); return; }
            try {
                const res = await apiFetch(`/admin/groups/${gr.id}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: newName })
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) throw new Error(data.error || 'Rename failed');
                done = true;
                showNotification(`Group renamed to ${newName}`);
                loadAdminShareGroups();
            } catch (err) {
                showNotification(err.message || 'Rename failed');
                finish(true);
            }
        });
        input.addEventListener('blur', () => finish(true));
    });
    actions.appendChild(renameBtn);

    // Delete only where the backend would allow it: super always; an admin only for
    // self-created groups they still own with every member in their control list.
    if (gr.deletable) {
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'icon-btn danger';
        deleteBtn.dataset.tip = 'Delete group';
        deleteBtn.setAttribute('aria-label', 'Delete group');
        deleteBtn.innerHTML = ADMIN_ICONS.delete;
        deleteBtn.addEventListener('click', () => {
            showConfirmation(
                `Delete group ${gr.name}? Its members immediately lose access to every map shared with it.`,
                async () => {
                    try {
                        const res = await apiFetch(`/admin/groups/${gr.id}`, { method: 'DELETE' });
                        const data = await res.json().catch(() => ({}));
                        if (!res.ok) throw new Error(data.error || 'Delete failed');
                        showNotification('Group deleted');
                        selectedAdminShareGroupId = null;
                        loadAdminShareGroups();
                    } catch (err) {
                        showNotification(err.message || 'Delete failed');
                    }
                },
                () => {},
                'admin-delete-group',
                gr.id
            );
        });
        actions.appendChild(deleteBtn);
    }
    header.appendChild(actions);
    detail.appendChild(header);

    const detailsPanel = document.createElement('div');
    detailsPanel.className = 'admin-detail-panel';

    // Creation facts. created_by persists as a historical fact; a NULL resolution
    // means the creating account was deleted since.
    const facts = document.createElement('div');
    facts.className = 'admin-facts';
    const addFact = (label, value) => {
        if (!value) return;
        const rowEl = document.createElement('div');
        const l = document.createElement('span');
        l.className = 'admin-fact-label';
        l.textContent = label;
        const v = document.createElement('span');
        v.textContent = value;
        rowEl.appendChild(l);
        rowEl.appendChild(v);
        facts.appendChild(rowEl);
    };
    const createdDate = gr.created ? new Date(gr.created).toLocaleDateString() : '';
    const creatorName = personName(
        gr.created_by_first,
        gr.created_by_last,
        gr.created_by_username
    ) || 'Account Deleted';
    addFact('Created By', creatorName);
    addFact('Creation Date', createdDate);
    detailsPanel.appendChild(facts);

    // Ownership line — owns_group(admin, group), many-to-many. Super-admins get a live
    // editor: delegation adds a co-owner, revocation removes just that one grant; no
    // owners left = superadmin-owned (never a claimable pool).
    if (currentUserIsSuper()) {
        const ownRow = document.createElement('div');
        ownRow.className = 'admin-group-owner-row';
        const lbl = document.createElement('span');
        lbl.className = 'admin-fact-label';
        lbl.textContent = 'Owned by';
        ownRow.appendChild(lbl);
        ownRow.appendChild(buildDelegationEditor({
            current: gr.owners || [],
            emptyLabel: 'Super Admin',
            addUrl: `/admin/groups/${gr.id}/owners`,
            removeUrl: a => `/admin/groups/${gr.id}/owners/${a.admin_id}`,
            notifyAdd: name => `${gr.name} delegated to ${name}`,
            notifyRemove: a => `${a.username} no longer owns ${gr.name}`,
            reload: loadAdminShareGroups
        }));
        detailsPanel.appendChild(ownRow);
    }
    // Co-managers line (non-super view): the group's OTHER co-owners, by name,
    // read-only — mirrors the user detail's line.
    if (!currentUserIsSuper()) {
        const others = (gr.owners || []).filter(o => o.username !== currentUser.username);
        if (others.length) {
            const coRow = document.createElement('div');
            coRow.className = 'admin-group-owner-row';
            const lbl = document.createElement('span');
            lbl.className = 'admin-fact-label';
            lbl.textContent = 'Co-managers';
            const val = document.createElement('span');
            val.textContent = others
                .map(o => personName(o.first_name, o.last_name, o.username))
                .join(', ');
            coRow.appendChild(lbl);
            coRow.appendChild(val);
            detailsPanel.appendChild(coRow);
        }
    }

    const membersPanel = document.createElement('div');
    membersPanel.className = 'admin-detail-panel';

    // Members management: two side-by-side action lists — approved non-members with a
    // + per row, current members with a × per row — each with its own live filter.
    // Filter text survives the reload-driven re-renders while the same group stays
    // selected.
    if (adminShareGroupListFilters.groupId !== gr.id) {
        adminShareGroupListFilters = { groupId: gr.id, picker: '', members: '' };
    }
    const memberIds = new Set(gr.members.map(m => m.user_id));
    const lists = document.createElement('div');
    lists.className = 'admin-group-lists';
    lists.appendChild(buildActionList({
        label: 'Add users',
        placeholder: 'Filter users...',
        extraClass: 'admin-group-add-list',
        items: adminUsersCache
            .filter(u => u.status === 'approved' && !memberIds.has(u.user_id))
            .map(u => ({
                label: nameWithUsername(u),
                username: u.username,
                avatar_url: u.avatar_url,
                showAvatar: true
            })),
        actionLabel: '+',
        emptyText: 'No users to add.',
        initialFilter: adminShareGroupListFilters.picker,
        onFilter: v => adminShareGroupListFilters.picker = v,
        onAction: async it => {
            try {
                const res = await apiFetch(`/admin/groups/${gr.id}/members`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: it.username })
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) throw new Error(data.error || 'Add failed');
                showNotification(`${it.username} added to ${gr.name}`);
                loadAdminShareGroups();
            } catch (err) {
                showNotification(err.message || 'Add failed');
            }
        }
    }));
    lists.appendChild(buildActionList({
        label: 'Members',
        placeholder: 'Filter members...',
        extraClass: 'admin-group-members-list',
        // Removal needs controls() on the member ('managed' is server-computed for the
        // caller): out-of-scope members placed by a super-admin stay until a super
        // removes them — those rows render without the ×.
        items: gr.members.map(mb => ({
            label: nameWithUsername(mb),
            member: mb,
            avatar_url: mb.avatar_url,
            showAvatar: true,
            noAction: !mb.managed
        })),
        actionLabel: '×',
        actionClass: 'danger',
        emptyText: 'No members yet.',
        initialFilter: adminShareGroupListFilters.members,
        onFilter: v => adminShareGroupListFilters.members = v,
        onAction: async it => {
            const mb = it.member;
            try {
                const res = await apiFetch(`/admin/groups/${gr.id}/members/${mb.user_id}`, { method: 'DELETE' });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) throw new Error(data.error || 'Remove failed');
                showNotification(`${mb.username} removed from ${gr.name}`);
                loadAdminShareGroups();
            } catch (err) {
                showNotification(err.message || 'Remove failed');
            }
        }
    }));
    membersPanel.appendChild(lists);

    detail.appendChild(buildDetailTabs([
        { label: 'Details', el: detailsPanel },
        { label: 'Members', el: membersPanel }
    ], adminShareGroupDetailTab, i => adminShareGroupDetailTab = i));
    detail.appendChild(detailsPanel);
    detail.appendChild(membersPanel);
}


// ===============================================================
// Management Groups tab (admin screen) — Addendum 3, SUPER-ADMIN ONLY end to end
// (the tab button itself is hidden for regular admins and every route 403s them).
// A structural clone of the Share Groups tab wired to /admin/mgmt-groups: membership
// × delegated managers is the second source of controls(). Members are regular users
// only; "Managed by" delegates management, never ownership — the group always stays
// superadmin-owned, so there is no deletable flag and no creator-scoped delete rule.
// ===============================================================
let adminMgmtGroupsCache = [];
let selectedAdminMgmtGroupId = null;
let adminMgmtGroupDetailTab = 0;
let adminMgmtGroupListFilters = { groupId: null, picker: '', members: '' };

function setupMgmtGroupsTab() {
    const createBtn = document.getElementById('adminCreateMgroupBtn');
    const nameInput = document.getElementById('newMgroupName');
    if (!createBtn || !nameInput) return;

    async function createGroup() {
        const name = nameInput.value.trim();
        if (!name) { showNotification('Enter a group name'); return; }
        try {
            const res = await apiFetch('/admin/mgmt-groups', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name })
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(data.error || 'Create failed');
            nameInput.value = '';
            selectedAdminMgmtGroupId = data.id;
            showNotification(`Group created: ${data.name}`);
            loadAdminMgmtGroups();
        } catch (err) {
            showNotification(err.message || 'Create failed');
        }
    }
    createBtn.addEventListener('click', createGroup);
    nameInput.addEventListener('keydown', e => {
        if (e.key === 'Enter') { e.preventDefault(); createGroup(); }
    });
}

async function loadAdminMgmtGroups() {
    const list = document.getElementById('adminMgroupList');
    if (!list) return;
    list.textContent = 'Loading...';
    try {
        const res = await apiFetch('/admin/mgmt-groups');
        if (!res.ok) throw new Error('Failed to load groups');
        adminMgmtGroupsCache = await res.json();
        renderAdminMgmtGroups();
    } catch (err) {
        console.error(err);
        list.textContent = 'Failed to load groups.';
    }
}

function renderAdminMgmtGroups() {
    const list = document.getElementById('adminMgroupList');
    list.textContent = '';

    // Master-list filter on the group name; group names render as stored.
    const filterEl = document.getElementById('adminMgroupFilter');
    const needle = filterEl ? filterEl.value.trim().toLowerCase() : '';
    const visible = adminMgmtGroupsCache.filter(gr => !needle || gr.name.toLowerCase().includes(needle));

    visible.forEach(gr => {
        const managerNames = (gr.managers || [])
            .map(m => personName(m.first_name, m.last_name, m.username))
            .join(', ');
        addMasterRow(list, {
            title: gr.name,
            meta: `${gr.members.length} member${gr.members.length === 1 ? '' : 's'} · ${managerNames || 'No manager'}`,
            selected: gr.id === selectedAdminMgmtGroupId,
            onSelect: () => {
                selectedAdminMgmtGroupId = gr.id;
                renderAdminMgmtGroups();
            }
        });
    });
    if (!visible.length) list.textContent = needle ? 'No matching groups.' : 'No groups yet.';

    const sel = adminMgmtGroupsCache.find(g => g.id === selectedAdminMgmtGroupId);
    if (sel) renderAdminMgmtGroupDetail(sel);
    else clearAdminMgmtGroupDetail();
}

function clearAdminMgmtGroupDetail() {
    selectedAdminMgmtGroupId = null;
    const detail = document.getElementById('adminMgroupDetail');
    if (!detail) return;
    detail.textContent = '';
    const p = document.createElement('p');
    p.className = 'admin-detail-empty';
    p.textContent = 'Select a group to manage its members.';
    detail.appendChild(p);
}

function renderAdminMgmtGroupDetail(gr) {
    const detail = document.getElementById('adminMgroupDetail');
    if (!detail) return;
    detail.textContent = '';

    const header = document.createElement('div');
    header.className = 'admin-detail-header';
    const titleBox = document.createElement('div');
    titleBox.className = 'admin-detail-title';
    const name = document.createElement('span');
    name.className = 'admin-detail-name';
    name.textContent = gr.name;
    titleBox.appendChild(name);
    header.appendChild(titleBox);

    const actions = document.createElement('div');
    actions.className = 'admin-user-actions';

    // Rename: swap the title for an inline input. Enter saves, Escape/blur cancels.
    const renameBtn = document.createElement('button');
    renameBtn.className = 'icon-btn';
    renameBtn.dataset.tip = 'Rename group';
    renameBtn.setAttribute('aria-label', 'Rename group');
    renameBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg>';
    renameBtn.addEventListener('click', () => {
        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'admin-group-rename-input';
        input.value = gr.name;
        titleBox.replaceChild(input, name);
        input.focus();
        input.select();
        let done = false;
        const finish = restore => {
            if (done) return;
            done = true;
            if (restore && input.parentNode) titleBox.replaceChild(name, input);
        };
        input.addEventListener('keydown', async e => {
            if (e.key === 'Escape') { finish(true); return; }
            if (e.key !== 'Enter') return;
            e.preventDefault();
            const newName = input.value.trim();
            if (!newName || newName === gr.name) { finish(true); return; }
            try {
                const res = await apiFetch(`/admin/mgmt-groups/${gr.id}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: newName })
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) throw new Error(data.error || 'Rename failed');
                done = true;
                showNotification(`Group renamed to ${newName}`);
                loadAdminMgmtGroups();
            } catch (err) {
                showNotification(err.message || 'Rename failed');
                finish(true);
            }
        });
        input.addEventListener('blur', () => finish(true));
    });
    actions.appendChild(renameBtn);

    // Delete is superadmin bookkeeping — always offered here (the whole tab is
    // super-only), no creator-scoped rule like share groups have.
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'icon-btn danger';
    deleteBtn.dataset.tip = 'Delete group';
    deleteBtn.setAttribute('aria-label', 'Delete group');
    deleteBtn.innerHTML = ADMIN_ICONS.delete;
    deleteBtn.addEventListener('click', () => {
        showConfirmation(
            `Delete group ${gr.name}? Its delegated managers immediately lose management of its members.`,
            async () => {
                try {
                    const res = await apiFetch(`/admin/mgmt-groups/${gr.id}`, { method: 'DELETE' });
                    const data = await res.json().catch(() => ({}));
                    if (!res.ok) throw new Error(data.error || 'Delete failed');
                    showNotification('Group deleted');
                    selectedAdminMgmtGroupId = null;
                    loadAdminMgmtGroups();
                } catch (err) {
                    showNotification(err.message || 'Delete failed');
                }
            },
            () => {},
            'admin-delete-mgroup',
            gr.id
        );
    });
    actions.appendChild(deleteBtn);
    header.appendChild(actions);
    detail.appendChild(header);

    const detailsPanel = document.createElement('div');
    detailsPanel.className = 'admin-detail-panel';

    // Creation facts. created_by persists as a historical fact; a NULL resolution
    // means the creating account was deleted since.
    const facts = document.createElement('div');
    facts.className = 'admin-facts';
    const addFact = (label, value) => {
        if (!value) return;
        const rowEl = document.createElement('div');
        const l = document.createElement('span');
        l.className = 'admin-fact-label';
        l.textContent = label;
        const v = document.createElement('span');
        v.textContent = value;
        rowEl.appendChild(l);
        rowEl.appendChild(v);
        facts.appendChild(rowEl);
    };
    addFact(
        'Created By',
        personName(gr.created_by_first, gr.created_by_last, gr.created_by_username)
            || 'Account Deleted'
    );
    addFact('Creation Date', gr.created ? new Date(gr.created).toLocaleDateString() : '');
    detailsPanel.appendChild(facts);

    // Management line — manage_mgmt_group(admin, group), many-to-many: delegation
    // adds a co-manager, revocation removes just that one grant; no managers left =
    // only superadmins reach the members (the group is superadmin-owned either way).
    const mgRow = document.createElement('div');
    mgRow.className = 'admin-group-owner-row';
    const lbl = document.createElement('span');
    lbl.className = 'admin-fact-label';
    lbl.textContent = 'Managed by';
    mgRow.appendChild(lbl);
    mgRow.appendChild(buildDelegationEditor({
        current: gr.managers || [],
        emptyLabel: 'Nobody (no delegated manager)',
        addUrl: `/admin/mgmt-groups/${gr.id}/managers`,
        removeUrl: a => `/admin/mgmt-groups/${gr.id}/managers/${a.admin_id}`,
        notifyAdd: name => `${gr.name} delegated to ${name}`,
        notifyRemove: a => `${a.username} no longer manages ${gr.name}`,
        reload: loadAdminMgmtGroups
    }));
    detailsPanel.appendChild(mgRow);

    const membersPanel = document.createElement('div');
    membersPanel.className = 'admin-detail-panel';

    // Members management: same side-by-side action lists as share groups, but the
    // add candidates are REGULAR USERS only (never admin-level accounts — membership
    // plus a manager grant produces controls(), and admins are never controlled).
    // Pending accounts must be approved first; disabled ones stay addable/removable.
    if (adminMgmtGroupListFilters.groupId !== gr.id) {
        adminMgmtGroupListFilters = { groupId: gr.id, picker: '', members: '' };
    }
    const memberIds = new Set(gr.members.map(m => m.user_id));
    const lists = document.createElement('div');
    lists.className = 'admin-group-lists';
    lists.appendChild(buildActionList({
        label: 'Add users',
        placeholder: 'Filter users...',
        extraClass: 'admin-group-add-list',
        items: adminUsersCache
            .filter(u => u.role === 'user' && u.status !== 'pending' && !memberIds.has(u.user_id))
            .map(u => ({
                label: nameWithUsername(u),
                username: u.username,
                avatar_url: u.avatar_url,
                showAvatar: true
            })),
        actionLabel: '+',
        emptyText: 'No users to add.',
        initialFilter: adminMgmtGroupListFilters.picker,
        onFilter: v => adminMgmtGroupListFilters.picker = v,
        onAction: async it => {
            try {
                const res = await apiFetch(`/admin/mgmt-groups/${gr.id}/members`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: it.username })
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) throw new Error(data.error || 'Add failed');
                showNotification(`${it.username} added to ${gr.name}`);
                loadAdminMgmtGroups();
            } catch (err) {
                showNotification(err.message || 'Add failed');
            }
        }
    }));
    lists.appendChild(buildActionList({
        label: 'Members',
        placeholder: 'Filter members...',
        extraClass: 'admin-group-members-list',
        items: gr.members.map(mb => ({
            label: nameWithUsername(mb),
            member: mb,
            avatar_url: mb.avatar_url,
            showAvatar: true
        })),
        actionLabel: '×',
        actionClass: 'danger',
        emptyText: 'No members yet.',
        initialFilter: adminMgmtGroupListFilters.members,
        onFilter: v => adminMgmtGroupListFilters.members = v,
        onAction: async it => {
            const mb = it.member;
            try {
                const res = await apiFetch(`/admin/mgmt-groups/${gr.id}/members/${mb.user_id}`, { method: 'DELETE' });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) throw new Error(data.error || 'Remove failed');
                showNotification(`${mb.username} removed from ${gr.name}`);
                loadAdminMgmtGroups();
            } catch (err) {
                showNotification(err.message || 'Remove failed');
            }
        }
    }));
    membersPanel.appendChild(lists);

    detail.appendChild(buildDetailTabs([
        { label: 'Details', el: detailsPanel },
        { label: 'Members', el: membersPanel }
    ], adminMgmtGroupDetailTab, i => adminMgmtGroupDetailTab = i));
    detail.appendChild(detailsPanel);
    detail.appendChild(membersPanel);
}


// ===============================================================
// Share panel (the owner manages a map's viewer/editor shares)
// ===============================================================
let collabOverlayMapId = null;
let collabOverlayMapIds = null;      // bulk mode: share several owned maps in one go
let collabOverlayAdminMode = false;  // admin screen: manage another user's map via /admin/maps/...
let collabOverlayOwnerUsername = null;   // that map's owner (kept out of the picker)

// The same overlay serves the owner (their own maps) and the admin screen (any user's
// maps); admin mode swaps the API prefix — authorization differs server-side only.
function collabBasePath(mapId) {
    return (collabOverlayAdminMode ? '/admin/maps/' : '/maps/') + mapId + '/collaborators';
}

// Parse a response as JSON only when it's OK and actually JSON; otherwise return the
// fallback. Prevents an HTML error/index page (e.g. a missing nginx proxy) from throwing.
async function safeJson(res, fallback) {
    if (!res || !res.ok) return fallback;
    const ct = res.headers.get('content-type') || '';
    if (!ct.includes('application/json')) return fallback;
    try { return await res.json(); }
    catch { return fallback; }
}

function openShareOverlay(mapId, mapName) {
    collabOverlayMapId = mapId;
    collabOverlayMapIds = null;
    collabOverlayAdminMode = false;
    collabOverlayOwnerUsername = null;
    const overlay = document.getElementById('collabOverlay');
    if (!overlay) return;
    const title = document.getElementById('collabOverlayTitle');
    if (title) title.textContent = `Share “${mapName}”`;
    resetCollabPicker();
    overlay.style.display = 'flex';
    requestAnimationFrame(() => overlay.classList.add('active'));
    loadShareData(mapId);
}

// Super-admin mode: manage another account's map from the Administration screen.
// ownerUsername keeps the map's owner out of the picker (the backend rejects them too).
function openAdminShareOverlay(mapId, mapName, ownerUsername) {
    if (!currentUserIsSuper()) return;
    collabOverlayMapId = mapId;
    collabOverlayMapIds = null;
    collabOverlayAdminMode = true;
    collabOverlayOwnerUsername = ownerUsername;
    const overlay = document.getElementById('collabOverlay');
    if (!overlay) return;
    const title = document.getElementById('collabOverlayTitle');
    if (title) title.textContent = `Share “${mapName}”`;
    resetCollabPicker();
    overlay.style.display = 'flex';
    requestAnimationFrame(() => overlay.classList.add('active'));
    loadShareData(mapId);
}

// Bulk mode: same overlay, but the grant applies to every selected owned map. There is
// no per-map collaborator list here — the list area names the maps being shared instead.
function openBulkShareOverlay(mapIds) {
    collabOverlayMapId = null;
    collabOverlayMapIds = mapIds;
    const overlay = document.getElementById('collabOverlay');
    if (!overlay) return;
    const title = document.getElementById('collabOverlayTitle');
    if (title) title.textContent = `Share ${mapIds.length} map${mapIds.length === 1 ? '' : 's'}`;
    resetCollabPicker();
    overlay.style.display = 'flex';
    requestAnimationFrame(() => overlay.classList.add('active'));
    loadBulkShareData(mapIds);
}

function closeShareOverlay() {
    const overlay = document.getElementById('collabOverlay');
    if (!overlay) return;
    overlay.classList.remove('active');
    setTimeout(() => overlay.style.display = 'none', 250);
    // Leaving admin mode: refresh the detail pane so its collaborator chips reflect
    // whatever was just changed in the overlay.
    if (collabOverlayAdminMode && selectedAdminUserId) {
        const u = adminUsersCache.find(x => x.user_id === selectedAdminUserId);
        if (u) renderAdminUserDetail(u);
    }
    collabOverlayMapId = null;
    collabOverlayMapIds = null;
    collabOverlayAdminMode = false;
    collabOverlayOwnerUsername = null;
}

// The picker is a type dropdown (User/Group) + a filter-picker component: a search
// field over a persistent scrollable list of the active type's candidates (refreshed
// per overlay load, already-shared targets and the map's owner excluded upstream).
let collabCandidates = { user: [], group: [] };
let collabPicker = null;   // built once in setupSharePanel

function collabActiveType() {
    const sel = document.getElementById('collabTypeSelect');
    return (sel && sel.value) === 'group' ? 'group' : 'user';
}

function setCollabCandidates(users, groups) {
    collabCandidates = {
        user: users.map(u => ({
            label: nameWithUsername(u),
            username: u.username,
            avatar_url: u.avatar_url,
            showAvatar: true
        })),
        group: groups.map(gr => ({ label: gr.name, group: gr.name }))
    };
    resetCollabSearch();
}

// Clear the search + selection and show the active type's full candidate list.
function resetCollabSearch() {
    if (!collabPicker) return;
    collabPicker.input.placeholder = collabActiveType() === 'group' ? 'Type to find a group...' : 'Type to find a user...';
    collabPicker.clear();
    collabPicker.refresh(collabCandidates[collabActiveType()]);
}

// What the picker currently designates (clicked row / exact text / single match).
function collabPickedTarget() {
    const candidate = collabPicker && collabPicker.resolve();
    if (!candidate) return null;
    if (collabActiveType() === 'group') {
        return { group: typeof candidate === 'string' ? candidate : candidate.group };
    }
    return { username: typeof candidate === 'string' ? candidate : candidate.username };
}

// Fresh picker state on every overlay open (type back to User, search cleared).
function resetCollabPicker() {
    const typeSel = document.getElementById('collabTypeSelect');
    if (typeSel) typeSel.value = 'user';
    resetCollabSearch();
}

// Keep the sidebar's shared indicator in sync with share changes: update the cached
// flag and toggle the card's button in place (no re-render, card state untouched).
// Both lookups are guarded — in admin mode the map may not be in this sidebar at all.
function syncSidebarShared(mapId, shared) {
    const m = maps.find(x => x.id === mapId);
    if (m) m.shared = shared;
    const btn = document.querySelector(`#mapsList .map-item[data-id="${mapId}"] .map-collab-btn`);
    if (btn) btn.classList.toggle('has-collabs', shared);
}

async function loadShareData(mapId) {
    const list = document.getElementById('collabList');
    if (list) list.textContent = 'Loading...';
    try {
        const [sharesRes, usersRes, groupsRes] = await Promise.all([
            apiFetch(collabBasePath(mapId)),
            apiFetch('/users'),
            apiFetch('/groups')
        ]);
        if (!sharesRes.ok) throw new Error('Failed to load collaborators');
        // Guard against a non-JSON body (e.g. an HTML error/index page from a
        // misconfigured proxy) so the panel degrades instead of throwing.
        const shares = await safeJson(sharesRes, null);
        if (shares === null) throw new Error('Unexpected response for collaborators');
        const users = await safeJson(usersRes, []);
        const groups = await safeJson(groupsRes, []);

        // Offer only users/groups not already shared with — and never the map's owner
        // (relevant in admin mode; on own maps the caller is excluded by /users itself).
        const sharedIds = new Set(shares.filter(s => s.type !== 'group').map(s => s.user_id));
        const sharedGroupIds = new Set(shares.filter(s => s.type === 'group').map(s => s.group_id));
        setCollabCandidates(
            users.filter(u => !sharedIds.has(u.user_id) && u.username !== collabOverlayOwnerUsername),
            groups.filter(gr => !sharedGroupIds.has(gr.id)));
        renderShareList(shares);
        syncSidebarShared(mapId, shares.length > 0);
    } catch (err) {
        console.error(err);
        if (list) list.textContent = 'Failed to load shares.';
    }
}

// Bulk mode loader: every approved user and every group is offered (the upsert makes a
// re-share a role change), and the list area names the maps the grant will apply to.
async function loadBulkShareData(mapIds) {
    const list = document.getElementById('collabList');
    try {
        const [usersRes, groupsRes] = await Promise.all([apiFetch('/users'), apiFetch('/groups')]);
        setCollabCandidates(await safeJson(usersRes, []), await safeJson(groupsRes, []));
        if (list) {
            const names = mapIds.map(id => (maps.find(m => m.id === id) || {}).name).filter(Boolean);
            list.textContent = 'Applies to: ' + names.join(', ');
        }
    } catch (err) {
        console.error(err);
        if (list) list.textContent = 'Failed to load users.';
    }
}

function renderShareList(shares) {
    const list = document.getElementById('collabList');
    if (!list) return;
    list.textContent = '';
    if (!shares.length) {
        const p = document.createElement('p');
        p.className = 'collab-empty';
        p.textContent = 'Not shared with anyone yet.';
        list.appendChild(p);
        return;
    }
    shares.forEach(s => {
        const row = document.createElement('div');
        row.className = 'collab-row';
        const isGroup = s.type === 'group';

        if (!isGroup) {
            row.appendChild(userAvatar(
                s.avatar_url,
                'collab-list-avatar',
                `${nameWithUsername(s)} avatar`
            ));
        }
        const name = document.createElement('span');
        name.className = 'collab-name';
        name.textContent = isGroup ? s.name : nameWithUsername(s);
        if (isGroup) {
            const badge = document.createElement('span');
            badge.className = 'collab-type-badge';
            badge.textContent = 'group';
            name.appendChild(badge);
        }
        row.appendChild(name);

        const roleSelect = document.createElement('select');
        roleSelect.className = 'collab-role-select';
        ['viewer', 'editor'].forEach(r => {
            const opt = document.createElement('option');
            opt.value = r;
            opt.textContent = r;
            if (r === s.role) opt.selected = true;
            roleSelect.appendChild(opt);
        });
        const target = isGroup ? { group: s.name } : { username: s.username };
        roleSelect.addEventListener('change', () => addOrUpdateShare(target, roleSelect.value));
        row.appendChild(roleSelect);

        const removeBtn = document.createElement('button');
        removeBtn.textContent = 'Remove';
        removeBtn.className = 'collab-remove-btn';
        removeBtn.addEventListener('click', () => isGroup ? removeGroupShare(s.group_id) : removeShare(s.user_id));
        row.appendChild(removeBtn);

        list.appendChild(row);
    });
}

// target is { username } for a user grant or { group } for a group grant; the backend
// takes exactly one of the two alongside the role.
async function addOrUpdateShare(target, role) {
    const label = target.username || target.group;

    // Bulk mode: one grant across every selected map.
    if (collabOverlayMapIds) {
        try {
            const res = await apiFetch('/maps/collaborators', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ map_ids: collabOverlayMapIds, ...target, role })
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(data.error || 'Failed to share');
            showNotification(`Shared ${data.shared} map(s) with ${label} as ${role}`);
            // A bulk grant is an upsert: every targeted map is shared afterwards.
            collabOverlayMapIds.forEach(id => syncSidebarShared(id, true));
            resetCollabSearch();
        } catch (err) {
            showNotification(err.message || 'Failed to share');
        }
        return;
    }

    if (!collabOverlayMapId) return;
    try {
        const res = await apiFetch(collabBasePath(collabOverlayMapId), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ...target, role })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || 'Failed to share');
        showNotification(`Shared with ${label} as ${role}`);
        loadShareData(collabOverlayMapId);
    } catch (err) {
        showNotification(err.message || 'Failed to share');
    }
}

async function removeShare(userId) {
    if (!collabOverlayMapId) return;
    try {
        const res = await apiFetch(`${collabBasePath(collabOverlayMapId)}/${userId}`, { method: 'DELETE' });
        if (!res.ok) throw new Error('Failed to remove share');
        showNotification('Access removed');
        loadShareData(collabOverlayMapId);
    } catch (err) {
        showNotification(err.message || 'Failed to remove share');
    }
}

async function removeGroupShare(groupId) {
    if (!collabOverlayMapId) return;
    try {
        const res = await apiFetch(`${collabBasePath(collabOverlayMapId)}/group/${groupId}`, { method: 'DELETE' });
        if (!res.ok) throw new Error('Failed to remove share');
        showNotification('Group access removed');
        loadShareData(collabOverlayMapId);
    } catch (err) {
        showNotification(err.message || 'Failed to remove share');
    }
}

function setupSharePanel() {
    const overlay = document.getElementById('collabOverlay');
    if (!overlay) return;
    overlay.addEventListener('mousedown', e => { if (e.target === overlay) closeShareOverlay(); });
    const typeSel = document.getElementById('collabTypeSelect');
    const roleSel = document.getElementById('collabAddRole');
    const addBtn = document.getElementById('collabAddBtn');

    const pickBox = document.getElementById('collabPickerBox');
    if (pickBox) {
        collabPicker = buildFilterPicker({ placeholder: 'Type to find a user...', candidates: [] });
        pickBox.appendChild(collabPicker.el);
    }

    if (typeSel) typeSel.addEventListener('change', resetCollabSearch);
    if (addBtn) addBtn.addEventListener('click', () => {
        const target = collabPickedTarget();
        const role = (roleSel && roleSel.value) || 'viewer';
        if (!target) {
            showNotification(collabActiveType() === 'group' ? 'Pick a group from the list' : 'Pick a user from the list');
            return;
        }
        addOrUpdateShare(target, role);
    });
}


// ===============================================================
// Global state
// ===============================================================
let maps = [];          // stored maps from database
let markers = [];       // stored markers from database
let listings = [];      // stored listings of loaded markers
let searchMarkers = [];   // temporary POI search markers
let temporaryMarkers = [];   // temporary context menu markers
let markersVisible = true; // show/hide toggle state
let clickedLatLng = null;
let tipTimer = null;
let tooltip = null;
let selectedMapID = null;  // Set to the user's own Base Map id after maps load
let sidebarWidth = 0;

const topSearchBar = document.getElementById('topSearchBar');
const optionsToggle = document.querySelector('.options-toggle');
const optionsMenu = document.querySelector('.options-menu');
const poiInput = document.getElementById('poiInput');
const searchPOIButton = document.getElementById('searchPOIButton')
const clearPOIButton = document.getElementById('clearPOIButton');
const sidebar = document.getElementById('sidebar');
const toggleMarkersVisibility = document.getElementById('toggleMarkersVisibility');


// ===============================================================
// Tooltips helpers
// ===============================================================

// Tooltips are a mouse-hover affordance. On touch there is no hover: a tap
// synthesizes mouseover/mouseout events, and when a tap opens an overlay the
// browser re-fires mouseover on whatever element now sits under the finger — with
// no matching mouseout, so any tooltip it triggers would stick. Record the last
// touch so the show-path can ignore hover events that a touch produced.
let lastTouchAt = 0;
document.addEventListener("touchstart", () => { lastTouchAt = Date.now(); }, { passive: true, capture: true });
function hoverCameFromTouch() { return Date.now() - lastTouchAt < 1000; }

// Show tooltip after hover delay in any element of the page
document.addEventListener("mouseover", e => {

    // Skip hover events synthesized by a recent touch (see note above).
    if (hoverCameFromTouch()) return;

    // e.target is the element currently under the mouse.
    // closest("[data-tip]") checks that element first; if it doesn't have a data-tip
    // attribute, it moves up through its parent elements until it finds one.
    // tipTarget will be the matching element, or null if none exists.
    const tipTarget = e.target.closest("[data-tip]");

    // Exit if tipTarget is null
    if (!tipTarget) return;

    // Read the tooltip text stored in the element's data-tip attribute
    const text = tipTarget.getAttribute("data-tip");

    // setTimeout schedules a function to run after a delay (here 750ms)
    // tipTimer stores the ID of this timer so it can be cleared later if the mouse moves away before the delay ends
    tipTimer = setTimeout(() => {

        // Create tooltip element
        tooltip = document.createElement("div");  // creates a new <div> in memory
        tooltip.className = "tooltip";            // adds the class so CSS styles and animations can apply
        tooltip.textContent = text;               // sets the content of the tooltip to whatever was in data-tip
        document.body.appendChild(tooltip);       // actually inserts the <div> into the page so it’s visible

        // getBoundingClientRect() returns the position and size of the hovered element relative to the viewport
        const rect = tipTarget.getBoundingClientRect();

        // Place tooltip centered above the element
        tooltip.style.left = rect.left + rect.width / 2 + "px";     // sets the horizontal position at the center of the element
        tooltip.style.top = rect.top - 30 + window.scrollY + "px";  // sets vertical position 30px above the element (rect.top - 30), and adds window.scrollY in case the page is scrolled
        tooltip.style.transform = "translateX(-50%)";               // shifts the tooltip left by half its width so it’s properly centered

        // Trigger fade-in animation
        requestAnimationFrame(() => tooltip.classList.add("show")); // Without requestAnimationFrame, the browser might skip the transition and the tooltip would appear instantly
    }, 750); // hover delay before tooltip appears
});

// Listen for when the mouse leaves any element in the document
document.addEventListener("mouseout", e => {

    // Find the nearest element the mouse left that has a `data-tip` attribute
    // If no tooltip target is found, exit early
    const tipTarget = e.target.closest("[data-tip]");
    if (!tipTarget) return;

    // Cancel any pending tooltip show timer (prevents it from appearing if still in delay)
    clearTimeout(tipTimer);

    // If a tooltip is currently visible
    if (tooltip) {

        // Start hiding the tooltip by removing the "show" class (triggers fade-out)
        tooltip.classList.remove("show");

        // After the fade-out animation (~180ms), remove the tooltip element from the DOM
        // If tooltip exists (not null or undefined), call its remove() method to delete it from the DOM.
        // If tooltip does not exist, do nothing (avoids errors).
        setTimeout(() => {
            tooltip?.remove();
            tooltip = null;
        }, 300);
    }
});

// Dismiss any tooltip the moment the user clicks — on every click, and always
// clearing the pending show-timer. Both matter: clicking within the 750ms hover
// delay must cancel the timer (otherwise the tooltip pops up *after* the click's
// overlay has opened), and when a click opens an overlay the source element never
// gets a mouseout (it's covered or removed), so a shown tooltip would otherwise
// linger on top of the overlay with no way to dismiss it.
document.addEventListener("click", () => {
    clearTimeout(tipTimer);
    if (tooltip) {
        tooltip.remove();
        tooltip = null;
    }
});


// ===============================================================
// Notifications helpers
// ===============================================================
function showNotification(message, duration = 3000) {
    const container = document.getElementById('notification-container');

    // Create notification element
    const notif = document.createElement('div');
    notif.className = 'notification';
    notif.textContent = message;
    container.appendChild(notif);

    // Force reflow so transition triggers
    void notif.offsetWidth;

    // Trigger slide-in
    notif.classList.add('show');

    // Remove after duration
    setTimeout(() => {
        // Listen for transition end before removing
        const onEnd = () => {
            notif.remove();
            notif.removeEventListener('transitionend', onEnd);
        };
        notif.addEventListener('transitionend', onEnd);

        // Trigger slide-out
        notif.classList.remove('show');
    }, duration);
}

function showProgressNotification(message) {
    const container = document.getElementById('notification-container');

    const progress = document.createElement('div');
    progress.className = 'notification progress-notif';

    const text = document.createElement('div');
    text.className = 'progress-text';
    text.textContent = message;
    progress.appendChild(text);

    const barContainer = document.createElement('div');
    barContainer.className = 'progress-bar-container';
    const bar = document.createElement('div');
    bar.className = 'progress-bar';
    barContainer.appendChild(bar);
    progress.appendChild(barContainer);

    container.appendChild(progress);

    void progress.offsetWidth;
    progress.classList.add('show');

    return {
        update: (percent) => { bar.style.width = percent + '%'; },
        updateText: (msg) => { text.textContent = msg; },
        remove: () => {
            const onEnd = () => {
                progress.remove();
                progress.removeEventListener('transitionend', onEnd);
            };
            progress.addEventListener('transitionend', onEnd);
            progress.classList.remove('show');
        }
    };
}

let activeConfirmation = null;
function showConfirmation(message, onConfirm, onCancel, callerId, markerId) {
    const container = document.getElementById('notification-container');

    if (activeConfirmation) {
        if (activeConfirmation.callerId === callerId && activeConfirmation.markerId === markerId) {
            // same caller/marker → replace silently
            activeConfirmation.el.remove();
        } else {
            // different caller/marker → immediately remove and trigger No without transition
            activeConfirmation.el.remove();
            activeConfirmation.cancel();
        }
        activeConfirmation = null;
    }

    const confirmation = document.createElement('div');
    confirmation.className = 'notification confirmation-notif';

    const content = document.createElement('div');
    content.className = 'notification-content';

    const text = document.createElement('div');
    text.className = 'notification-text';
    text.textContent = message;

    const buttons = document.createElement('div');
    buttons.className = 'notification-buttons';

    const confirmBtn = document.createElement('button');
    confirmBtn.className = 'btn-confirm';
    confirmBtn.textContent = 'Yes';

    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn-cancel';
    cancelBtn.textContent = 'No';

    buttons.append(confirmBtn, cancelBtn);
    content.append(text, buttons);
    confirmation.appendChild(content);
    container.appendChild(confirmation);

    requestAnimationFrame(() => confirmation.classList.add('show'));

    const destroy = () => {
        confirmation.remove();
        if (activeConfirmation?.el === confirmation) activeConfirmation = null;
    };

    const cancel = () => {
        onCancel && onCancel();
        confirmation.classList.remove('show');
        confirmation.classList.add('hide');
        confirmation.addEventListener('transitionend', destroy, { once: true });
    };

    confirmBtn.onclick = () => {
        onConfirm && onConfirm();
        destroy();
    };
    cancelBtn.onclick = cancel;

    activeConfirmation = { el: confirmation, cancel, callerId, markerId };
}


// ===============================================================
// Marker note links helper
// ===============================================================
// GLightbox renders data-title as HTML (via innerHTML), so a photo caption could
// otherwise inject markup/script. Strip angle brackets before handing it over.
function sanitizeGlightboxTitle(text) {
    return String(text ?? '').replace(/[<>]/g, '');
}

function linkifyNotes(text) {
    if (!text) return document.createTextNode('');

    const container = document.createDocumentFragment();
    const urlRegex = /((https?:\/\/[^\s]+)|(maps\.app\.goo\.gl\/[^\s]+))/gi;

    let lastIndex = 0;
    let match;

    while ((match = urlRegex.exec(text)) !== null) {
        // Add text before match
        if (match.index > lastIndex) {
            container.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
        }

        // Add link
        const a = document.createElement('a');
        const href = match[0].startsWith('http') ? match[0] : `https://${match[0]}`;
        a.href = href;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.textContent = match[0];
        container.appendChild(a);

        lastIndex = urlRegex.lastIndex;
    }

    // Add remaining text
    if (lastIndex < text.length) {
        container.appendChild(document.createTextNode(text.slice(lastIndex)));
    }

    return container;
}


// ===============================================================
// Map initialization
// ===============================================================
const initialCenter = [39.69444, -8.13051];
const initialZoom = 7;
const map = L.map('map', {
    center: initialCenter,
    zoom: initialZoom,
    zoomSnap: 0.1,   // allows fractional zoom steps
    zoomDelta: 0.5   // optional: step when zooming with buttons or wheel
});

// Disable default double-click zoom first
map.doubleClickZoom.disable();

// Listen for double-click events
map.on('dblclick', (e) => {
    const targetZoom = 17;
    map.setZoomAround(e.latlng, targetZoom, { animate: true });
});

// Popup auto-pan: recenter a popup on screen only when it opens clipped by a map
// edge. A popup that opens fully visible triggers no pan, so markers already on
// screen — and the map itself — stay exactly where they are. (All marker popups
// bind with autoPan:false and rely on this single handler instead of Leaflet's
// built-in autoPan, which can only slide-to-edge, not center-when-clipped.)
map.on('popupopen', (e) => {
    const popupEl = e.popup.getElement();
    if (!popupEl) return;

    const mapRect = map.getContainer().getBoundingClientRect();
    const popRect = popupEl.getBoundingClientRect();

    // Clipped if any side spills past the map edge (1px tolerance avoids jitter on
    // a popup that sits flush against an edge but is still fully visible).
    const clipped = popRect.left < mapRect.left - 1
        || popRect.right > mapRect.right + 1
        || popRect.top < mapRect.top - 1
        || popRect.bottom > mapRect.bottom + 1;
    if (!clipped) return;

    // Pan so the popup's centre moves to the map's centre. panBy shifts the map view
    // by the given pixels, so the geo-anchored popup moves by the opposite amount —
    // hence (popup centre − map centre) lands the popup dead centre.
    const dx = (popRect.left + popRect.width / 2) - (mapRect.left + mapRect.width / 2);
    const dy = (popRect.top + popRect.height / 2) - (mapRect.top + mapRect.height / 2);
    map.panBy([dx, dy], { animate: true, duration: 0.5 }); // gentler than Leaflet's 0.25s default
});

// OpenStreetMap layer
var osm = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '© OpenStreetMap',
    maxZoom: 19
});

// Add default layer
osm.addTo(map);


// ===============================================================
// Map scale
// ===============================================================
const scaleWidth = 143;
const kmScale = L.control.scale({
    metric: true,
    imperial: false,
    maxWidth: scaleWidth,
});

// Override to show only km
kmScale.onAdd = function (map) {
    const container = L.DomUtil.create('div', 'leaflet-control-scale leaflet-control-scale-line');
    map.on('move', updateScale);
    updateScale();
    return container;

    function updateScale() {
        const center = map.getCenter();
        const y = center.lat;
        const metersPerPixel = 40075016.686 * Math.abs(Math.cos((y * Math.PI) / 180)) / Math.pow(2, map.getZoom() + 8);
        const maxWidthMeters = metersPerPixel * scaleWidth;
        const km = Math.round(maxWidthMeters / 1000);
        container.style.width = `${scaleWidth}px`;
        container.textContent = `${km} km`;
    }
};

// Add map scale
kmScale.addTo(map);


// ===============================================================
// Map ruler
// ===============================================================
L.control.polylineMeasure({
    position: 'topleft',
    unit: 'kilometres',
    clearMeasurementsOnStop: false,
    showClearControl: true,
    showUnitControl: true,
    showBearings: true,
}).addTo(map);


// ===============================================================
// Map routing engine
// ===============================================================
const startIcon = L.icon({
    iconUrl: 'assets/images/marker-icon-green.png',
    iconSize: [25, 41],
    iconAnchor: [12, 41],
    popupAnchor: [1, -34],
    shadowUrl: 'assets/images/marker-shadow.png',
    shadowSize: [41, 41]
});

const endIcon = L.icon({
    iconUrl: 'assets/images/marker-icon-red.png',
    iconSize: [25, 41],
    iconAnchor: [12, 41],
    popupAnchor: [1, -34],
    shadowUrl: 'assets/images/marker-shadow.png',
    shadowSize: [41, 41]
});

const viaIcon = L.icon({
    iconUrl: 'assets/images/marker-icon-yellow.png',
    iconSize: [25, 41],
    iconAnchor: [12, 41],
    popupAnchor: [1, -34],
    shadowUrl: 'assets/images/marker-shadow.png',
    shadowSize: [41, 41]
});

function createDeletableMarker(i, wp, nWps) {
    if (i === 0) {
        // Start marker
        return L.marker(wp.latLng, { icon: startIcon, draggable: true });
    } else if (i === nWps - 1) {
        // End marker
        return L.marker(wp.latLng, { icon: endIcon, draggable: true });
    } else {
        // Via-point marker
        const marker = L.marker(wp.latLng, { icon: viaIcon, draggable: true }).addTo(map);

        marker.on('click', () => {
            // Remove this waypoint
            routingControl.spliceWaypoints(i, 1);
        });

        return marker;
    }
}

// OSRM router, wrapped to relabel the alternatives with short, tidy names. LRM
// renders each alternative's header from route.name (its summaryTemplate is
// '<h2>{name}</h2>…'), and OSRM sets that name to a run-together list of road names.
// Rename to "Route 1", "Route 2", … in the order OSRM returns them (the same order
// LRM lists them) for a compact, readable panel.
const routeRouter = L.Routing.osrmv1({
    //serviceUrl: 'http://192.168.193.50:5001/route/v1',
    useHints: false
});
const _origRouterRoute = routeRouter.route.bind(routeRouter);
routeRouter.route = function(waypoints, callback, context, options) {
    return _origRouterRoute(waypoints, function(err, routes) {
        if (routes) routes.forEach((r, i) => { r.name = 'Route ' + (i + 1); });
        callback.call(context, err, routes);
    }, context, options);
};

const routingControl = L.Routing.control({
    waypoints: [],
    routeWhileDragging: true,
    fitSelectedRoutes: false,
    // Don't let LRM add its own collapse button (a bare "×" span it injects only when
    // the map is <=640px wide). It's mobile-only, redundant with our Close Route
    // button, and looks out of place. Off everywhere keeps mobile and desktop identical.
    collapsible: false,
    // Stack distance over time in each alternative (default template comma-joins them
    // on one line). Short lines also let the panel shrink to hug its content.
    summaryTemplate: '<h2>{name}</h2><h3>{distance}<br>{time}</h3>',
    createMarker: createDeletableMarker,
    lineOptions: {
        styles: [
            { color: 'white', opacity: 1, weight: 10 },
            { color: '#0077ff', opacity: 0.9, weight: 4 }
        ]
    },
    router: routeRouter
}).addTo(map);


async function geocodeAddress(address) {
    const res = await fetch(`https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(address)}&limit=1`);
    const data = await res.json();

    if (!data || data.length === 0) {
        throw new Error("Address not found: " + address);
    }

    return L.latLng(data[0].lat, data[0].lon);
}


const routingContainer = document.querySelector('.leaflet-routing-container');

if (PUBLIC_CONFIG.routingStepsVisible) {
    routingContainer.classList.add('routing-steps-visible');
}

// Wrap buttons in a row container
let buttonRow = routingContainer.querySelector('.routing-button-row');
if (!buttonRow) {
    buttonRow = document.createElement('div');
    buttonRow.className = 'routing-button-row';
    routingContainer.prepend(buttonRow); // insert at top
}

// Close Route Button
let closeRouteBtn = buttonRow.querySelector('.close-route-btn');
if (!closeRouteBtn) {
    closeRouteBtn = document.createElement('button');
    closeRouteBtn.innerText = 'Close Route';
    closeRouteBtn.className = 'close-route-btn';
    buttonRow.appendChild(closeRouteBtn);

    closeRouteBtn.addEventListener('click', () => {
        // Hide the routing container
        routingContainer.classList.remove('show');

        // Clear all waypoints from the map
        routingControl.setWaypoints([]);

        // Clear text in start and end fields and hide their clear buttons
        const inputsToClear = ['startAddress', 'endAddress'];
        inputsToClear.forEach(id => {
            const input = document.getElementById(id);
            if (input) input.value = '';

            const btn = document.querySelector(`.clear-waypoint-text-btn[data-for="${id}"]`);
            if (btn) btn.style.display = 'none';
        });
    });
}

// Frame a route so the whole line stays on screen at any viewport width. The fit
// padding keeps the route clear of the UI over the map (left sidebar, top-right
// directions panel, top search bar), but fixed desktop pixels were wider than a
// phone viewport, so fitBounds got a negative fit area and zoomed the route away.
// Blend the padding from compact/symmetric on phones to the fine-tuned desktop
// values, by map width — smooth, with no hard breakpoint, and identical to the old
// values at desktop widths (t reaches 1 by 1024px).
function fitRouteInView(routeBounds) {
    const size = map.getSize();
    const t = Math.max(0, Math.min(1, (size.x - 520) / (1024 - 520)));
    const lerp = (a, b) => a + (b - a) * t;
    map.fitBounds(routeBounds, {
        paddingTopLeft: [lerp(30, 500), lerp(70, 100)],
        paddingBottomRight: [lerp(30, 250), lerp(40, 50)],
        maxZoom: 16,
        animate: true,
        duration: 1.0
    });
}

// Show panel and generate route
let initialFitDone = false;
routingControl.on('routesfound', function(e) {
    if (initialFitDone) return;

    const routes = e.routes;
    if (!routes.length) return;

    const routeCoords = routes[0].coordinates;
    const routeBounds = L.latLngBounds(routeCoords);

    fitRouteInView(routeBounds);

    initialFitDone = true; // prevent further automatic fits
});

// Keep the search bar clear of the routing panel: re-layout it whenever the panel is
// shown or hidden (toggled from several places, so watch the class) and once more when
// routes arrive and the panel has its final width. On close it returns to normal.
new MutationObserver(() => positionSearchBar())
    .observe(routingContainer, { attributes: true, attributeFilter: ['class'] });
routingControl.on('routesfound', () => positionSearchBar());

// Button click just sets waypoints
document.getElementById('generate-route-btn').addEventListener('click', async () => {
    const start = document.getElementById('startAddress').value;
    const end = document.getElementById('endAddress').value;

    try {
        const startLatLng = await geocodeAddress(start);
        const endLatLng = await geocodeAddress(end);

        initialFitDone = false;
        routingControl.setWaypoints([startLatLng, endLatLng]);
        routingContainer.classList.add('show');
    } catch (err) {
        showNotification(err.message);
    }
});

// Trigger route generation when pressing Enter in either field
['startAddress', 'endAddress'].forEach(id => {
    const el = document.getElementById(id);

    el.addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            e.preventDefault();            // stops form submit / focus jumps
            document.getElementById('generate-route-btn').click();
        }
    });
});

// Reverse the route waypoints
document.getElementById('invert-route-btn').addEventListener('click', () => {
    const inputs = [document.getElementById('startAddress'), document.getElementById('endAddress')];
    const waypoints = routingControl.getWaypoints();

    if (waypoints.length > 1) {
        // Reverse map waypoints
        const reversedLatLngs = waypoints.map(wp => wp.latLng).reverse();
        routingControl.setWaypoints(reversedLatLngs);

        // Reverse input values
        const reversedValues = inputs.map(i => i.value).reverse();
        inputs.forEach((input, i) => input.value = reversedValues[i]);
    }
});

// Enable buttons only when there's text input on both fields
const startAddress = document.getElementById('startAddress')
const endAddress = document.getElementById('endAddress')
const generateRouteBtn = document.getElementById('generate-route-btn')
const invertRouteBtn = document.getElementById('invert-route-btn')
const routeHasText = (startAddress.value.trim() !== '' && endAddress.value.trim() !== '')
generateRouteBtn.classList.toggle('disabled', !routeHasText);
generateRouteBtn.disabled = !routeHasText;
invertRouteBtn.classList.toggle('disabled', !routeHasText);
invertRouteBtn.disabled = !routeHasText;

// Listen for input changes
startAddress.addEventListener('input', () => {
    const routeHasText = (startAddress.value.trim() !== '' && endAddress.value.trim() !== '');
    generateRouteBtn.classList.toggle('disabled', !routeHasText);
    generateRouteBtn.disabled = !routeHasText;
    invertRouteBtn.classList.toggle('disabled', !routeHasText);
    invertRouteBtn.disabled = !routeHasText;
});

endAddress.addEventListener('input', () => {
    const routeHasText = (startAddress.value.trim() !== '' && endAddress.value.trim() !== '');
    generateRouteBtn.classList.toggle('disabled', !routeHasText);
    generateRouteBtn.disabled = !routeHasText;
    invertRouteBtn.classList.toggle('disabled', !routeHasText);
    invertRouteBtn.disabled = !routeHasText;
});

// Route waypoints text clear button
function attachClearButton(inputId, btnSelector) {
    const input = document.getElementById(inputId);
    const btn = document.querySelector(`${btnSelector}[data-for="${inputId}"]`);

    input.addEventListener('input', () => {
        btn.style.display = input.value.trim() ? 'flex' : 'none';
    });

    btn.addEventListener('click', () => {
        input.value = '';
        btn.style.display = 'none';
        input.focus();
        routingContainer.classList.remove('show');
        routingControl.setWaypoints([]);
        generateRouteBtn.classList.add('disabled');
        invertRouteBtn.classList.add('disabled');
    });
}
attachClearButton('startAddress', '.clear-waypoint-text-btn');
attachClearButton('endAddress', '.clear-waypoint-text-btn');

// Set waypoints through context menu
function setWaypointInput(inputId, latlng) {
    const input = document.getElementById(inputId);

    // Set input value and trigger input event
    input.value = `${latlng.lat.toFixed(7)}, ${latlng.lng.toFixed(7)}`;
    input.dispatchEvent(new Event('input'));

    // Clear existing routes
    if (routingControl) {
        routingControl.setWaypoints([]);
    }

    // Hide the default Leaflet routing container if visible
    const routingContainerEl = document.querySelector('.leaflet-routing-container.show');
    if (routingContainerEl) {
        routingContainerEl.classList.remove('show');
        routingContainerEl.style.display = 'none';
    }

    // Ensure sidebar is expanded
    if (sidebar.classList.contains('collapsed')) {
        sidebar.classList.remove('collapsed');
        updateLeafletControls();
    }

    // Expand Route Planner section
    const routeSection = document.querySelector('.sidebar-section');
    const sectionContent = routeSection.querySelector('.section-content');

    if (!routeSection.classList.contains('open')) {
        routeSection.classList.add('open');
        const height = sectionContent.scrollHeight;
        sectionContent.style.height = '0';

        requestAnimationFrame(() => {
            sectionContent.style.height = height + 'px';
        });

        sectionContent.addEventListener('transitionend', function handler() {
            sectionContent.style.height = 'auto';
            sectionContent.removeEventListener('transitionend', handler);
        });
    }
}


// ===============================================================
// Helper: calculate adjusted longitude for sidebar
// ===============================================================
function getAdjustedLatLng(latlng, zoom = map.getZoom()) {
    if (!latlng) return latlng;

    let targetPoint = map.project([latlng.lat, latlng.lng], zoom);

    let sidebarWidth = 0;
    if (sidebar && !sidebar.classList.contains('collapsed')) {
        sidebarWidth = sidebar.offsetWidth;
    }

    // Shift center by half the sidebar width
    targetPoint.x -= sidebarWidth / 2;

    return map.unproject(targetPoint, zoom);
}

// ===============================================================
// Center map
// ===============================================================
function centerMap(latlng) {
    const adjustedLatLng = getAdjustedLatLng(latlng);
    map.setView(adjustedLatLng, map.getZoom(), { animate: true });
}

// ===============================================================
// Zoom to coordinates
// ===============================================================
function zoomMap(latlng, zoomLevel = 19) {
    const adjustedLatLng = getAdjustedLatLng(latlng, zoomLevel);
    map.setView(adjustedLatLng, zoomLevel, { animate: true });
}


// ===============================================================
// Reset map
// ===============================================================
function resetMap() {
    map.flyTo(initialCenter, initialZoom, {
        animate: true,
        duration: 1.5 // seconds
    });
}


// ===============================================================
// Disable map clicks and scroll on certain elements
// ===============================================================

// Routing panel
if (routingContainer) {
    routingContainer.addEventListener('mouseenter', () => {
        map.scrollWheelZoom.disable();
    });

    routingContainer.addEventListener('mouseleave', () => {
        map.scrollWheelZoom.enable();
    });
}

// Search bar
L.DomEvent.disableClickPropagation(topSearchBar);
L.DomEvent.disableScrollPropagation(topSearchBar);

// Sidebar
L.DomEvent.disableClickPropagation(sidebar);
L.DomEvent.disableScrollPropagation(sidebar);

// Context menu in UI elements
function preventContextMenuInContainer(containerSelector) {
    const container = document.querySelector(containerSelector);
    if (!container) return;

    // Prevent context menu on container itself
    container.addEventListener('contextmenu', e => {
        e.preventDefault();
        e.stopPropagation();
    });

    // Prevent context menu on all child elements
    container.querySelectorAll('*').forEach(el => {
        el.addEventListener('contextmenu', e => {
            e.preventDefault();
            e.stopPropagation();
        });
    });
}
preventContextMenuInContainer('.leaflet-top.leaflet-left');
preventContextMenuInContainer('.leaflet-top.leaflet-right');
preventContextMenuInContainer('.leaflet-bottom.leaflet-left');
preventContextMenuInContainer('.leaflet-bottom.leaflet-right');


// ===============================================================
// Sidebar menus autoscroll helper
// ===============================================================
function setupSidebarMenuDropdown(btn, menu, sidebar, otherMenus = []) {

    function getDistanceToSidebar(element, sidebar) {
        let distance = 0;
        let el = element;

        while (el && el !== sidebar) {
            distance += el.offsetTop;
            el = el.offsetParent;
        }

        return distance;
    }

    btn.addEventListener("click", e => {
        e.stopPropagation();

        // Toggle current menu
        menu.classList.toggle("show");

        // Close other menus
        otherMenus.forEach(m => m.classList.remove("show"));

        if (!menu.classList.contains("show")) return;

        // Check visibility
        const menuRect = menu.getBoundingClientRect();
        const sidebarRect = sidebar.getBoundingClientRect();

        const fullyVisible =
            menuRect.top >= sidebarRect.top &&
            menuRect.bottom <= sidebarRect.bottom;

        if (fullyVisible) return;

        // Align button to top
        const distance = getDistanceToSidebar(btn, sidebar);

        sidebar.scrollTo({
            top: distance - 10,
            behavior: "smooth"
        });
    });
}

// ===============================================================
// Sidebar
// ===============================================================
const toggle = document.getElementById('sidebar-toggle');
const leftControls = document.querySelectorAll(
    '.leaflet-top.leaflet-left, .leaflet-bottom.leaflet-left'
);
const rightControls = document.querySelectorAll('.leaflet-top.leaflet-right');

// Position the top search bar, centred in the clear "lane" between the right edge of
// the top-left controls and the map's right edge. Slide it up out of the way when
// there's no room for it: the sidebar is open on a phone, or the routing panel is open
// at the top-right and would overlap the centred bar. It returns to normal otherwise.
function positionSearchBar() {
    if (!topSearchBar) return;
    const collapsed = sidebar.classList.contains('collapsed');
    const offset = collapsed ? 0 : sidebar.offsetWidth + 10;
    const gap = 16;
    const topLeftControls = document.querySelector('.leaflet-top.leaflet-left');
    const buttonsWidth = topLeftControls ? topLeftControls.offsetWidth : 0;
    const controlsRight = offset + buttonsWidth;
    const laneLeft = controlsRight + gap;
    const laneRight = window.innerWidth - gap;
    const laneCenter = (laneLeft + laneRight) / 2;

    // Slide up when the sidebar leaves no room beside the controls (phone)...
    let hide = !collapsed && (laneRight - laneLeft) < 140;

    // ...or when the open routing panel (top-right) would overlap the centred bar.
    if (!hide) {
        const panel = document.querySelector('.leaflet-routing-container.show');
        if (panel) {
            const pr = panel.getBoundingClientRect();
            if (pr.top < 70 && laneCenter + topSearchBar.offsetWidth / 2 + gap > pr.left) hide = true;
        }
    }

    if (hide) {
        topSearchBar.style.transform =
            `translateX(calc(-50% + ${buttonsWidth / 2}px)) translateY(calc(-100% - 20px))`;
    } else {
        topSearchBar.style.transform = `translateX(calc(-50% + ${laneCenter - window.innerWidth / 2}px))`;
    }
}

function updateLeafletControls() {
    sidebarWidth = sidebar.offsetWidth;
    const collapsed = sidebar.classList.contains('collapsed');
    // Controls slide with the sidebar (left is transitioned in CSS). On narrow (phone) screens
    // there's no room for them beside the sidebar, so they also fade out as they slide — and
    // fade back in on the way out when it closes.
    const hideControls = !collapsed && window.innerWidth - (sidebarWidth + 10) < 150;
    const offset = collapsed ? 0 : sidebarWidth + 10;
    const offset2 = collapsed ? 13 : sidebarWidth + 23;
    const sidebarOffset = collapsed ? -10 : sidebarWidth + 10;

    sidebar.style.transform = `translateX(calc(-100% + ${sidebarOffset}px))`;

    leftControls.forEach(ctrl => {
        ctrl.style.left = `${offset}px`;
        ctrl.classList.toggle('controls-hidden', hideControls);
    });

    rightControls.forEach(ctrl => {
        ctrl.style.left = `${offset2}px`;
        ctrl.classList.toggle('controls-hidden', hideControls);
    });

    toggle.style.left = collapsed ? '0px' : `${sidebarWidth + 10}px`;
    toggle.textContent = collapsed ? '▶' : '◀';

    // Position the top search bar (centred in its lane; shrinks to clear an open routing panel).
    positionSearchBar();

    // The map itself stays fixed on toggle — the sidebar overlays it. Panning it here fought
    // with the popup autoPan on phones (the sidebar covers most of the screen there).
}

// The toggle lives inside the Leaflet map container, so a tap on it bubbles to the map
// and the map's click closes any open popup — problematic on phones. Stop it, same as the
// sidebar and top search bar above.
L.DomEvent.disableClickPropagation(toggle);

// Initialize toggle icon and position without moving controls
toggle.textContent = sidebar.classList.contains('collapsed') ? '▶' : '◀';
toggle.style.left = sidebar.classList.contains('collapsed') ? '0px' : `${sidebar.offsetWidth}px`;

// Only update Leaflet controls when toggling
toggle.addEventListener('click', () => {
    sidebar.classList.toggle('collapsed');
    updateLeafletControls();
});

// Centre the search bar between the left controls and the map's right edge for the initial
// (collapsed) layout — updateLeafletControls only runs on toggle, so do it once here. Suppress
// the transform transition so the one-time positioning doesn't visibly slide on load.
if (topSearchBar) {
    topSearchBar.style.transition = 'none';
    positionSearchBar();
    topSearchBar.getBoundingClientRect();  // force reflow before restoring the transition
    topSearchBar.style.transition = '';
}

// Re-layout the search bar on resize (the routing panel's position and the amount of
// room beside the controls both depend on the viewport width).
window.addEventListener('resize', positionSearchBar);

// Keep the sidebar toggle vertically centred in the gap between the top-left and bottom-left
// control clusters. The top cluster (zoom/ruler/km) is taller than the bottom one (layers/scale),
// so that midpoint sits below the viewport centre — a plain top:50% doesn't match it. Recompute
// on resize since the bottom cluster is anchored to the map's bottom edge.
function centerSidebarToggle() {
    const topCtl = document.querySelector('.leaflet-top.leaflet-left');
    const botCtl = document.querySelector('.leaflet-bottom.leaflet-left');
    if (!topCtl || !botCtl) return;
    const mapTop = map.getContainer().getBoundingClientRect().top;
    const mid = (topCtl.getBoundingClientRect().bottom + botCtl.getBoundingClientRect().top) / 2 - mapTop;
    toggle.style.top = `${mid}px`;  // toggle keeps translateY(-50%), so `top` is its centre
}
centerSidebarToggle();
window.addEventListener('resize', centerSidebarToggle);

// Sidebar section toggles (accordion)
const toggles = document.querySelectorAll(".section-toggle");

toggles.forEach(toggle => {
    const section = toggle.parentElement;
    const content = toggle.nextElementSibling;
    let isAnimating = false;

    toggle.addEventListener("click", () => {
        if (isAnimating) return;
        if (sidebarMapsMenu.classList.contains("show") || sidebarMarkersMenu.classList.contains("show")) return;

        isAnimating = true;
        const isOpen = section.classList.contains("open");

        if (isOpen) {
            // Closing
            section.classList.remove("open");
            content.style.height = content.scrollHeight + "px";

            // Force reflow for Firefox
            content.offsetHeight;

            content.style.height = "0";

            // Scroll the previous visible section into view
            let prev = section.previousElementSibling;
            while (prev && !prev.classList.contains("sidebar-section")) {
                prev = prev.previousElementSibling;
            }
            if (prev) {
                prev.scrollIntoView({ behavior: "smooth", block: "start" });
            }

        } else {
            // Opening
            section.classList.add("open");
            const height = content.scrollHeight;
            content.style.height = "0";

            // Force reflow for Firefox
            content.offsetHeight;

            content.style.height = height + "px";
        }

        const handler = () => {
            content.style.height = isOpen ? "0" : "auto";
            isAnimating = false;
            content.removeEventListener("transitionend", handler);

            // Scroll section to top of sidebar **after animation**
            if (!isOpen) {
                const sidebarTop = sidebar.getBoundingClientRect().top;
                const sectionTop = section.getBoundingClientRect().top;
                const scrollOffset = sidebar.scrollTop + (sectionTop - sidebarTop);

                sidebar.scrollTo({
                    top: scrollOffset - 6,
                    behavior: "smooth"
                });
            }
        };

        content.addEventListener("transitionend", handler);
    });
});

// Prevent default browser context menu on sidebar elements
toggle.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    e.stopPropagation();
});

sidebar.addEventListener('contextmenu', (e) => {
    // Allow default context menu if the right-click is on an input or textarea
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
        return;
    }
    e.preventDefault(); // Otherwise, prevent default context menu
});


// ===============================================================
// Per-map role helpers (viewer/editor UI gating; backend enforces regardless)
// ===============================================================
// The current user's role on a map: 'owner', 'editor' or 'viewer'.
function mapRole(mapId) {
    const m = maps.find(mm => mm.id === mapId);
    return m ? m.role : 'owner';
}

// Show/hide a static context-menu entry by its data-action.
function setMenuItemVisible(menu, action, visible) {
    const item = menu.querySelector(`[data-action="${action}"]`);
    if (item) item.style.display = visible ? '' : 'none';
}


// ===============================================================
// Sidebar map context menu (right-click)
// ===============================================================
const sidebarMapContextMenu = document.getElementById('sidebarMapContextMenu');
let clickedSidebarMapItem = null; // store the item that was right-clicked

function showSidebarMapContextMenu(item, event) {
    hideAllContextMenus();
    clickedSidebarMapItem = item;

    // Owner: Share/Edit/Delete. Editor: Edit only. Viewer: none (Details always shows).
    const role = mapRole(parseInt(item.dataset.id, 10));
    setMenuItemVisible(sidebarMapContextMenu, 'sidebar-map-share', role === 'owner');
    setMenuItemVisible(sidebarMapContextMenu, 'sidebar-map-edit', role === 'owner' || role === 'editor');
    setMenuItemVisible(sidebarMapContextMenu, 'sidebar-map-delete', role === 'owner');

    const mapContainer = map.getContainer();
    const mapRect = mapContainer.getBoundingClientRect();

    // Show menu offscreen first to measure its size
    sidebarMapContextMenu.style.visibility = 'hidden';
    sidebarMapContextMenu.style.display = 'block';
    sidebarMapContextMenu.style.left = '0px';
    sidebarMapContextMenu.style.top = '0px';

    const menuWidth = sidebarMapContextMenu.offsetWidth;
    const menuHeight = sidebarMapContextMenu.offsetHeight;

    // Calculate click position relative to map container
    let left = event.clientX - mapRect.left;
    let top = event.clientY - mapRect.top;

    // Clamp to map bounds
    left = Math.min(left, mapRect.width - menuWidth - 5);
    top = Math.min(top, mapRect.height - menuHeight - 5);
    left = Math.max(5, left);
    top = Math.max(5, top);

    sidebarMapContextMenu.style.left = `${left}px`;
    sidebarMapContextMenu.style.top = `${top}px`;
    sidebarMapContextMenu.style.visibility = 'visible';
    sidebarMapContextMenu.classList.add('visible');
}

function hideSidebarMapContextMenu() {
    sidebarMapContextMenu.style.display = 'none';
    sidebarMapContextMenu.style.visibility = 'hidden';
    sidebarMapContextMenu.classList.remove('visible');
}

// Handle clicks on the sidebar menu
sidebarMapContextMenu.addEventListener('click', (e) => {
    const action = e.target.dataset.action;
    if (!action || !clickedSidebarMapItem) return;

    const mapId = parseInt(clickedSidebarMapItem.dataset.id, 10);

    switch(action) {
        case 'sidebar-map-details':
            openMapDetailsOverlay(mapId);
            break;
        case 'sidebar-map-share': {
            const shareMap = maps.find(m => m.id === mapId);
            openShareOverlay(mapId, shareMap ? shareMap.name : '');
            break;
        }
        case 'sidebar-map-edit':
            editMap(mapId);
            break;
        case 'sidebar-map-delete':
            deleteMap(mapId);
            break;
    }

    hideSidebarMapContextMenu();
});


// ===============================================================
// Sidebar marker context menu (right-click)
// ===============================================================
const sidebarMarkerContextMenu = document.getElementById('sidebarMarkerContextMenu');
let clickedSidebarMarkerItem = null; // store the marker that was right-clicked

function showSidebarMarkerContextMenu(item, event) {
    hideAllContextMenus();
    clickedSidebarMarkerItem = item; // must be set

    // Viewer on the selected map: read-only — no Edit/Move/Delete (Copy stays).
    const canEditMarkers = mapRole(selectedMapID) !== 'viewer';
    setMenuItemVisible(sidebarMarkerContextMenu, 'sidebar-marker-edit', canEditMarkers);
    setMenuItemVisible(sidebarMarkerContextMenu, 'sidebar-marker-move', canEditMarkers);
    setMenuItemVisible(sidebarMarkerContextMenu, 'sidebar-marker-delete', canEditMarkers);

    const menu = sidebarMarkerContextMenu;
    const mapContainer = map.getContainer();
    const mapRect = mapContainer.getBoundingClientRect();

    // Show menu offscreen first to measure its size
    menu.style.visibility = 'hidden';
    menu.style.display = 'block';
    menu.style.left = '0px';
    menu.style.top = '0px';

    const menuWidth = menu.offsetWidth;
    const menuHeight = menu.offsetHeight;

    // Calculate click position relative to map container
    let left = event.clientX - mapRect.left;
    let top = event.clientY - mapRect.top;

    // Clamp to map bounds
    left = Math.min(left, mapRect.width - menuWidth - 5);
    top = Math.min(top, mapRect.height - menuHeight - 5);
    left = Math.max(5, left);
    top = Math.max(5, top);

    menu.style.left = `${left}px`;
    menu.style.top = `${top}px`;
    menu.style.visibility = 'visible';
    menu.classList.add('visible');
}

function hideSidebarMarkerContextMenu() {
    sidebarMarkerContextMenu.style.display = 'none';
    sidebarMarkerContextMenu.style.visibility = 'hidden';
    sidebarMarkerContextMenu.classList.remove('visible');
}

// Handle clicks on the sidebar marker menu
sidebarMarkerContextMenu.addEventListener('click', (e) => {
    const action = e.target.dataset.action;
    if (!action || !clickedSidebarMarkerItem) return;

    // Use the attached marker object
    const markerObj = clickedSidebarMarkerItem.markerObject;
    if (!markerObj) return; // safety check

    const markerId = parseInt(clickedSidebarMarkerItem.dataset.id, 10);
    const latLng = L.latLng(markerObj.lat, markerObj.lng); // Leaflet LatLng object

    switch(action) {
        case 'sidebar-marker-details':
            openMarkerDetailsOverlay(markerId);
            break;
        case 'sidebar-marker-edit':
            editMarker(markerId);
            break;
        case 'sidebar-marker-show':
            showMarker(markerId);
            break;
        case 'sidebar-marker-hide':
            hideMarker(markerId);
            break;
        case 'sidebar-marker-copy':
            openCopyOverlay([{ dataset: { id: markerId }, closest: () => null }], selectedMapID);
            break;
        case 'sidebar-marker-move':
            openMoveOverlay([{ dataset: { id: markerId }, closest: () => null }], selectedMapID);
            break;
        case 'sidebar-marker-delete':
            deleteMarker(markerId);
            break;
        case 'sidebar-marker-copy-coords':
            copyCoordinates(markerObj.lat, markerObj.lng);
            break;
        case 'sidebar-marker-set-start':
            setWaypointInput('startAddress', latLng);
            break;
        case 'sidebar-marker-set-end':
            setWaypointInput('endAddress', latLng);
            break;
        case 'sidebar-marker-zoom-map':
            zoomMap(latLng);
            break;
        case 'sidebar-marker-center-map':
            centerMap(latLng);
            break;
    }

    hideSidebarMarkerContextMenu();
});


// ===============================================================
// Map context menu (right-click)
// ===============================================================
const mapContextMenu = document.getElementById('mapContextMenu');
function showMapContextMenu(latlng) {
    hideAllContextMenus();
    clickedLatLng = latlng;
    const point = map.latLngToContainerPoint(latlng);
    const mapRect = map.getContainer().getBoundingClientRect();

    // Temporarily show off-screen to measure
    mapContextMenu.style.visibility = 'hidden';
    mapContextMenu.style.display = 'block';
    mapContextMenu.style.left = '0px';
    mapContextMenu.style.top = '0px';

    const menuWidth = mapContextMenu.offsetWidth;
    const menuHeight = mapContextMenu.offsetHeight;
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;

    let left = mapRect.left + point.x;
    let top = mapRect.top + point.y;

    // Adjust left if overflowing
    if (left + menuWidth > viewportWidth) {
        left = viewportWidth - menuWidth - 5; // 5px padding
    }

    // Adjust top if overflowing
    if (top + menuHeight > viewportHeight) {
        top = viewportHeight - menuHeight - 5; // 5px padding
    }

    left = Math.max(5, left);
    top = Math.max(5, top);

    // Apply final position and make visible
    mapContextMenu.style.left = `${left}px`;
    mapContextMenu.style.top = `${top}px`;
    mapContextMenu.style.visibility = 'visible';
    mapContextMenu.classList.add('visible');
}

function hideMapContextMenu() {
    mapContextMenu.style.display = 'none';
    mapContextMenu.style.visibility = 'hidden';
    mapContextMenu.classList.remove('visible');
}

// Only one context menu at a time — every show() closes all six first, so opening any one
// (sidebar maps/markers, or an on-map map/stored/temp/search menu) dismisses the rest.
function hideAllContextMenus() {
    hideSidebarMapContextMenu();
    hideSidebarMarkerContextMenu();
    hideMapContextMenu();
    hideStoredMarkerContextMenu();
    hideTempMarkerContextMenu();
    hideSearchMarkerContextMenu();
}

map.on('contextmenu', (e) => {
    e.originalEvent.preventDefault();
    showMapContextMenu(e.latlng);
    sidebarMapsMenu.classList.remove("show");
    sidebarMarkersMenu.classList.remove("show");
});

// Delegate mapContextMenu clicks
mapContextMenu.addEventListener('click', (e) => {
    const action = e.target.dataset.action;
    if (!action) return;

    switch (action) {
        case 'add-marker-here':
            addTempMarker(clickedLatLng.lat, clickedLatLng.lng);
            break;
        case 'clear-temp':
            removeAllTemporaryMarkers();
            break;
        case 'copy-coords':
            copyCoordinates(clickedLatLng.lat, clickedLatLng.lng);
            break;
        case 'set-start':
            setWaypointInput('startAddress', clickedLatLng);
            break;
        case 'set-end':
            setWaypointInput('endAddress', clickedLatLng);
            break;
        case 'zoom-map':
            zoomMap(clickedLatLng);
            break;
        case 'center-map':
            centerMap(clickedLatLng);
            break;
        case 'reset-filters':
            clearMarkerFilters();
            break;
        case 'reset-map':
            resetMap();
            break;
    }

    hideMapContextMenu();
});

// ===============================================================
// Stored marker context menu (right-click)
// ===============================================================
const storedMarkerContextMenu = document.getElementById('storedMarkerContextMenu');
let clickedStoredMarker = null; // store the marker that was right-clicked

function showStoredMarkerContextMenu(marker, event) {
    hideAllContextMenus();
    clickedStoredMarker = marker;

    // Viewer on the selected map: read-only — no Edit/Move/Delete (Copy stays; it
    // writes to the target map the user picks, not to this one).
    const canEditMarkers = mapRole(selectedMapID) !== 'viewer';
    setMenuItemVisible(storedMarkerContextMenu, 'edit-stored-marker', canEditMarkers);
    setMenuItemVisible(storedMarkerContextMenu, 'move-stored-marker', canEditMarkers);
    setMenuItemVisible(storedMarkerContextMenu, 'delete-stored-marker', canEditMarkers);

    const mapContainer = map.getContainer();
    const mapRect = mapContainer.getBoundingClientRect();

    // Show menu offscreen first to measure its size
    storedMarkerContextMenu.style.visibility = 'hidden';
    storedMarkerContextMenu.style.display = 'block';
    storedMarkerContextMenu.style.left = '0px';
    storedMarkerContextMenu.style.top = '0px';

    const menuWidth = storedMarkerContextMenu.offsetWidth;
    const menuHeight = storedMarkerContextMenu.offsetHeight;

    // Calculate click position relative to map container
    let left = event.clientX - mapRect.left;
    let top = event.clientY - mapRect.top;

    // Clamp to map bounds
    left = Math.min(left, mapRect.width - menuWidth - 5);
    top = Math.min(top, mapRect.height - menuHeight - 5);
    left = Math.max(5, left);
    top = Math.max(5, top);

    storedMarkerContextMenu.style.left = `${left}px`;
    storedMarkerContextMenu.style.top = `${top}px`;
    storedMarkerContextMenu.style.visibility = 'visible';
    storedMarkerContextMenu.classList.add('visible');
}

function hideStoredMarkerContextMenu() {
    storedMarkerContextMenu.style.display = 'none';
    storedMarkerContextMenu.style.visibility = 'hidden';
    storedMarkerContextMenu.classList.remove('visible');
}

// Delegate storedMarkerContextMenu clicks
storedMarkerContextMenu.addEventListener('click', (e) => {
    const action = e.target.dataset.action;
    if (!action || !clickedStoredMarker) return;

    switch(action) {
        case 'view-stored-marker-details':
            openMarkerDetailsOverlay(clickedStoredMarker.data.id);
            break;
        case 'edit-stored-marker':
            editMarker(clickedStoredMarker.data.id);
            break;
        case 'hide-stored-marker':
            hideMarker(clickedStoredMarker.data.id);
            break;
        case 'copy-stored-marker':
            openCopyOverlay([{ dataset: { id: clickedStoredMarker.data.id }, closest: () => null }], selectedMapID);
            break;
        case 'move-stored-marker':
            openMoveOverlay([{ dataset: { id: clickedStoredMarker.data.id }, closest: () => null }], selectedMapID);
            break;
        case 'delete-stored-marker':
            deleteMarker(clickedStoredMarker.data.id);
            break;
        case 'copy-stored-marker-coords':
            copyCoordinates(clickedStoredMarker.data.lat, clickedStoredMarker.data.lng);
            break;
        case 'set-stored-marker-start':
            setWaypointInput('startAddress', clickedStoredMarker.getLatLng());
            break;
        case 'set-stored-marker-end':
            setWaypointInput('endAddress', clickedStoredMarker.getLatLng());
            break;
        case 'zoom-stored-marker-map':
            zoomMap(clickedStoredMarker.getLatLng());
            break;
        case 'center-stored-marker-map':
            centerMap(clickedStoredMarker.getLatLng());
            break;
    }

    hideStoredMarkerContextMenu();
});


// ===============================================================
// Temporary marker context menu (right-click)
// ===============================================================
const tempMarkerContextMenu = document.getElementById('tempMarkerContextMenu');
let clickedTempMarker = null; // store the marker that was right-clicked

function showTempMarkerContextMenu(marker, event) {
    hideAllContextMenus();
    clickedTempMarker = marker;

    // A viewer can't save into the selected map.
    setMenuItemVisible(tempMarkerContextMenu, 'save-temp-marker', mapRole(selectedMapID) !== 'viewer');

    const mapContainer = map.getContainer();
    const mapRect = mapContainer.getBoundingClientRect();

    // Show menu offscreen first to measure its size
    tempMarkerContextMenu.style.visibility = 'hidden';
    tempMarkerContextMenu.style.display = 'block';
    tempMarkerContextMenu.style.left = '0px';
    tempMarkerContextMenu.style.top = '0px';

    const menuWidth = tempMarkerContextMenu.offsetWidth;
    const menuHeight = tempMarkerContextMenu.offsetHeight;

    // Calculate click position relative to map container
    let left = event.clientX - mapRect.left;
    let top = event.clientY - mapRect.top;

    // Clamp to map bounds
    left = Math.min(left, mapRect.width - menuWidth - 5);
    top = Math.min(top, mapRect.height - menuHeight - 5);
    left = Math.max(5, left);
    top = Math.max(5, top);

    tempMarkerContextMenu.style.left = `${left}px`;
    tempMarkerContextMenu.style.top = `${top}px`;
    tempMarkerContextMenu.style.visibility = 'visible';
    tempMarkerContextMenu.classList.add('visible');
}

function hideTempMarkerContextMenu() {
    tempMarkerContextMenu.style.display = 'none';
    tempMarkerContextMenu.style.visibility = 'hidden';
    tempMarkerContextMenu.classList.remove('visible');
}

// Delegate tempMarkerContextMenu clicks
tempMarkerContextMenu.addEventListener('click', (e) => {
    const action = e.target.dataset.action;
    if (!action || !clickedTempMarker) return;

    switch(action) {
        case 'save-temp-marker':
            saveTempMarker(clickedTempMarker, clickedTempMarker._latlng.lat, clickedTempMarker._latlng.lng, clickedTempMarker.name)
            break;
        case 'delete-temp-marker':
            deleteTempMarker(clickedTempMarker);
            break;
        case 'copy-temp-marker-coords':
            copyCoordinates(clickedTempMarker._latlng.lat, clickedTempMarker._latlng.lng);
            break;
        case 'set-temp-marker-start':
            setWaypointInput('startAddress', clickedTempMarker.getLatLng());
            break;
        case 'set-temp-marker-end':
            setWaypointInput('endAddress', clickedTempMarker.getLatLng());
            break;
        case 'zoom-temp-marker-map':
            zoomMap(clickedTempMarker.getLatLng());
            break;
        case 'center-temp-marker-map':
            centerMap(clickedTempMarker.getLatLng());
            break;
    }

    hideTempMarkerContextMenu();
});


// ===============================================================
// Search marker context menu (right-click)
// ===============================================================
const searchMarkerContextMenu = document.getElementById('searchMarkerContextMenu');
let clickedSearchMarker = null; // store the marker that was right-clicked

function showSearchMarkerContextMenu(marker, event) {
    hideAllContextMenus();
    clickedSearchMarker = marker;

    // A viewer can't save into the selected map.
    setMenuItemVisible(searchMarkerContextMenu, 'save-search-marker', mapRole(selectedMapID) !== 'viewer');

    const mapContainer = map.getContainer();
    const mapRect = mapContainer.getBoundingClientRect();

    // Show menu offscreen first to measure its size
    searchMarkerContextMenu.style.visibility = 'hidden';
    searchMarkerContextMenu.style.display = 'block';
    searchMarkerContextMenu.style.left = '0px';
    searchMarkerContextMenu.style.top = '0px';

    const menuWidth = searchMarkerContextMenu.offsetWidth;
    const menuHeight = searchMarkerContextMenu.offsetHeight;

    // Calculate click position relative to map container
    let left = event.clientX - mapRect.left;
    let top = event.clientY - mapRect.top;

    // Clamp to map bounds
    left = Math.min(left, mapRect.width - menuWidth - 5);
    top = Math.min(top, mapRect.height - menuHeight - 5);
    left = Math.max(5, left);
    top = Math.max(5, top);

    searchMarkerContextMenu.style.left = `${left}px`;
    searchMarkerContextMenu.style.top = `${top}px`;
    searchMarkerContextMenu.style.visibility = 'visible';
    searchMarkerContextMenu.classList.add('visible');
}

function hideSearchMarkerContextMenu() {
    searchMarkerContextMenu.style.display = 'none';
    searchMarkerContextMenu.style.visibility = 'hidden';
    searchMarkerContextMenu.classList.remove('visible');
}

// Delegate searchMarkerContextMenu clicks
searchMarkerContextMenu.addEventListener('click', (e) => {
    const action = e.target.dataset.action;
    if (!action || !clickedSearchMarker) return;

    switch(action) {
        case 'save-search-marker':
            saveSearchMarker(clickedSearchMarker, clickedSearchMarker._latlng.lat, clickedSearchMarker._latlng.lng, clickedSearchMarker.name)
            break;
        case 'delete-search-marker':
            deleteSearchMarker(clickedSearchMarker);
            break;
        case 'copy-search-marker-coords':
            copyCoordinates(clickedSearchMarker._latlng.lat, clickedSearchMarker._latlng.lng);
            break;
        case 'set-search-marker-start':
            setWaypointInput('startAddress', clickedSearchMarker.getLatLng());
            break;
        case 'set-search-marker-end':
            setWaypointInput('endAddress', clickedSearchMarker.getLatLng());
            break;
        case 'zoom-search-marker-map':
            zoomMap(clickedSearchMarker.getLatLng());
            break;
        case 'center-search-marker-map':
            centerMap(clickedSearchMarker.getLatLng());
            break;
    }

    hideSearchMarkerContextMenu();
});

// Single dismissal path for all six context menus: a pointer-down or map move/zoom
// anywhere outside them closes whatever is open, and the browser's own menu is blocked
// on top of them. (Opening one already closes the rest via hideAllContextMenus.)
const allContextMenus = [
    sidebarMapContextMenu,
    sidebarMarkerContextMenu,
    mapContextMenu,
    storedMarkerContextMenu,
    tempMarkerContextMenu,
    searchMarkerContextMenu
];

document.addEventListener('mousedown', (e) => {
    if (!allContextMenus.some(menu => menu.contains(e.target))) hideAllContextMenus();
}, true);  // use capture phase

['movestart', 'zoomstart'].forEach(event => map.on(event, hideAllContextMenus));

allContextMenus.forEach(menu => {
    menu.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        e.stopPropagation();
    });
});






// ===============================================================
// Initial load — gated behind authentication
// ===============================================================
// Boot the app only after we hold a valid access token. On page load, try a silent
// refresh (the httpOnly refresh cookie survives reloads); if that fails, show the
// auth screen. bootApp() is also called after a successful login.
let appBooted = false;

async function bootApp() {
    appBooted = true;
    hideAuthScreen();
    updateAdminUI();
    updateAccountName();
    updateAvatarImages();
    loadMapsFromDB();
    void refreshNotificationHistorySummary();
}

// Browsers restore input values across soft reloads — and logout IS a reload — so
// without this the previous user's login name, searches and half-typed overlay fields
// reappear. Reset every form plus the standalone (formless) text inputs at boot.
// Known limit: a password manager that actively autofills can still repopulate the
// login fields; that's outside app control — this targets the browser's own restore.
function resetStaleFormState() {
    document.querySelectorAll('form').forEach(f => f.reset());
    ['newGroupName', 'startAddress', 'endAddress',
     'mapsSearchInput', 'markersSearchInput', 'poiInput'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
}

async function initAuthGate() {
    // Strict refresh rotation needs browser-managed cross-tab serialization. Without
    // Web Locks, a second tab can look like replay and revoke an otherwise valid family.
    if (!navigator.locks) {
        showUnsupportedScreen();
        return;
    }
    resetStaleFormState();
    await loadAccountCapabilities();
    const accountLinkActive = setupAuthScreen();
    setupAccountMenu();
    setupAdminPanel();
    setupSharePanel();
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) logoutBtn.addEventListener('click', doLogout);
    const retryBtn = document.getElementById('limitRetryBtn');
    if (retryBtn) retryBtn.addEventListener('click', attemptSessionRestore);
    if (accountLinkActive) {
        showAuthScreen();
        return;
    }
    await attemptSessionRestore();
}

// Boot-time silent restore; also re-run by the rate-limit landing page's retry
// button. A 429 means the edge told us to back off while the session is most
// likely still valid — show the landing page, never a misleading login form.
async function attemptSessionRestore() {
    try {
        await getAccessToken();   // silent refresh via the /auth cookie
        hideLimitScreen();
        bootApp();
    } catch (err) {
        if (err.status === 429) {
            showLimitScreen();
        } else {
            hideLimitScreen();
            showAuthScreen();
        }
    }
}
initAuthGate();

// ===============================================================
// Load maps from the backend
// ===============================================================
async function loadMapsFromDB() {
    try {

        // Reset sidebar + state first so re-running this (e.g. on re-login without a full
        // page reload) repopulates rather than appending duplicates.
        const mapsListEl = document.getElementById('mapsList');
        if (mapsListEl) mapsListEl.innerHTML = '';
        maps = [];

        // Fetch all maps from the backend
        const res = await apiFetch('/maps');
        maps = await res.json();  // parse the JSON response into a JavaScript object/array

        // Render the maps of the active group (My Maps / Shared with Me).
        // Honor any active search/group filter so a reload doesn't drop the user's view.
        renderGroupedMaps(mapsSearchInput ? mapsSearchInput.value.toLowerCase() : '', activeMapGroupFilter);

        // Select this user's own Base Map by default (its id is per-user, not a fixed 1).
        selectedMapID = getOwnBaseMapId();

        // Reflect the selection in the sidebar
        document.querySelectorAll('.map-item.selected').forEach(i => i.classList.remove('selected'));
        const sel = document.querySelector(`.map-item[data-id="${selectedMapID}"]`);
        if (sel) sel.classList.add('selected');

        // Load markers of the selected map
        if (selectedMapID != null) loadSpotsFromDB(selectedMapID);

    } catch (err) {
        console.error("Failed to load maps:", err);
    }
}

// Which group a map belongs to. Keyed the same as the filter dropdown values.
function mapGroupKey(m) {
    return m.owned ? 'mine' : 'shared';
}

// Render the maps of the active group (chosen in the dropdown) into #mapsList, as a flat
// list — the dropdown IS the group selector, so no subheaders. Honors the text search.
function renderGroupedMaps(textFilter = '', groupFilter = activeMapGroupFilter) {
    const container = document.getElementById('mapsList');
    if (!container) return;
    container.innerHTML = '';

    const q = (textFilter || '').toLowerCase();
    const items = maps.filter(m =>
        mapGroupKey(m) === groupFilter
        && (!q
            || (m.name || '').toLowerCase().includes(q)
            || (m.owner_name || '').toLowerCase().includes(q)
            || (m.owner_username || '').toLowerCase().includes(q))
    );

    items.forEach(map => addMapToSidebar(map));
}

// The current user's own Base Map id (falls back to the first owned map, then any map).
function getOwnBaseMapId() {
    const ownBase = maps.find(m => m.is_base && m.owned);
    if (ownBase) return ownBase.id;
    const owned = maps.find(m => m.owned);
    if (owned) return owned.id;
    return maps.length ? maps[0].id : null;
}


// ===============================
// Add map to sidebar
// ===============================
let longPressTimerMaps;
let selectedMaps = new Set();
let longPressModeMaps = false; // true if checkboxes are visible
let ignoreNextClickMaps = false; // skip click immediately after long press
let longPressTriggered = false;

function addMapToSidebar(map) {
    const container = document.getElementById('mapsList');
    const div = document.createElement('div');
    div.className = 'map-item';
    div.dataset.id = map.id;

    // Format created date
    let createdDate = '';
    let createdTime = '';
    if (map.created) {
        const created = new Date(map.created);
        createdDate = created.toLocaleDateString();
        createdTime = created.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    // Card container
    const card = document.createElement('div');
    card.className = 'map-card';
    if (map.is_base) card.classList.add('basemap-card');

    // Toggle arrow
    const toggle = document.createElement('div');
    toggle.className = 'map-toggle';
    toggle.dataset.state = 'open';
    toggle.textContent = '▾';
    card.appendChild(toggle);

    // Collapsed name with marker-count
    const nameCollapsed = document.createElement('div');
    nameCollapsed.className = 'map-name-collapsed';
    const collapsedText = document.createTextNode(map.name + ' (');
    nameCollapsed.appendChild(collapsedText);
    const collapsedCount = document.createElement('span');
    collapsedCount.className = 'marker-count';
    collapsedCount.textContent = map.markers;
    nameCollapsed.appendChild(collapsedCount);
    nameCollapsed.appendChild(document.createTextNode(')'));
    card.appendChild(nameCollapsed);

    // Details section
    const details = document.createElement('div');
    details.className = 'map-details';

    if (map.is_base) {
        const nameDetail = document.createElement('div');
        nameDetail.className = 'map-name';
        const detailText = document.createTextNode(map.name + ' (');
        nameDetail.appendChild(detailText);
        const detailCount = document.createElement('span');
        detailCount.className = 'marker-count';
        detailCount.textContent = map.markers;
        nameDetail.appendChild(detailCount);
        nameDetail.appendChild(document.createTextNode(')'));
        details.appendChild(nameDetail);

        const createdWrapper = document.createElement('div');
        createdWrapper.className = 'map-created-wrapper';
        const dateDiv = document.createElement('div');
        dateDiv.className = 'map-created-date';
        dateDiv.textContent = 'The default map';
        const timeDiv = document.createElement('div');
        timeDiv.className = 'map-created-time';
        timeDiv.textContent = 'This map cannot be edited or deleted';
        createdWrapper.appendChild(dateDiv);
        createdWrapper.appendChild(timeDiv);
        details.appendChild(createdWrapper);
    } else {
        const nameDetail = document.createElement('div');
        nameDetail.className = 'map-name';
        const detailText = document.createTextNode(map.name + ' (');
        nameDetail.appendChild(detailText);
        const detailCount = document.createElement('span');
        detailCount.className = 'marker-count';
        detailCount.textContent = map.markers;
        nameDetail.appendChild(detailCount);
        nameDetail.appendChild(document.createTextNode(')'));
        details.appendChild(nameDetail);

        const actionsWrapper = document.createElement('div');
        actionsWrapper.className = 'map-actions-wrapper';

        const createdWrapper = document.createElement('div');
        createdWrapper.className = 'map-created-wrapper';
        const dateDiv = document.createElement('div');
        dateDiv.className = 'map-created-date';
        // Single line: date then time with a bullet in the middle (like markers).
        dateDiv.textContent = (createdDate || createdTime) ? `${createdDate} • ${createdTime}` : '';
        createdWrapper.appendChild(dateDiv);
        actionsWrapper.appendChild(createdWrapper);

        // Owner: share/edit/delete. Editor: edit only. Viewer: info only.
        const isOwner = map.role === 'owner';
        const canEdit = isOwner || map.role === 'editor';

        const isShared = map.role && map.role !== 'owner';

        // For non-owned maps the owner label and the badge+buttons live in ONE row so they
        // share a baseline (owner left, badge+actions right) — no cross-column alignment.
        const owner = isShared ? (map.owner_name || map.owner_username) : '';
        if (isShared) actionsWrapper.classList.add('has-owner-row');

        const actions = document.createElement('div');
        actions.className = 'map-actions';

        // The role badge sits inline just before the info button, vertically centered.
        if (isShared) {
            const badge = document.createElement('span');
            badge.className = 'map-role-badge role-' + map.role;
            badge.textContent = 'shared: ' + map.role;
            actions.appendChild(badge);
        }

        // Info button (always available to anyone who can see the map)
        const infoBtn = document.createElement('button');
        infoBtn.className = 'icon-btn';
        infoBtn.dataset.tip = 'View Details';
        infoBtn.addEventListener('click', e => {
            e.stopPropagation();
            openMapDetailsOverlay(map.id);
        });
        infoBtn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" width="24" height="24">
                <circle cx="12" cy="12" r="10"/>
                <circle cx="12" cy="8" r="1.5" fill="currentColor" stroke="none"/>
                <path d="M12 12v6"/>
            </svg>
        `;
        actions.appendChild(infoBtn);

        if (isOwner) {
            // Share button — turns green once the map actually has collaborators.
            // (Class name deliberately avoids "share": adblocker cosmetic filters.)
            const shareBtn = document.createElement('button');
            shareBtn.className = 'icon-btn map-collab-btn' + (map.shared ? ' has-collabs' : '');
            shareBtn.dataset.tip = 'Share Map';
            shareBtn.addEventListener('click', e => {
                e.stopPropagation();
                openShareOverlay(map.id, map.name);
            });
            shareBtn.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="18" cy="5" r="3"/>
                    <circle cx="6" cy="12" r="3"/>
                    <circle cx="18" cy="19" r="3"/>
                    <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
                    <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
                </svg>
            `;
            actions.appendChild(shareBtn);
        }

        if (canEdit) {
            // Edit button
            const editBtn = document.createElement('button');
            editBtn.className = 'icon-btn';
            editBtn.dataset.tip = 'Edit Map';
            editBtn.addEventListener('click', e => {
                e.stopPropagation();
                editMap(map.id);
            });
            editBtn.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 20h9"/>
                    <path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/>
                </svg>
            `;
            actions.appendChild(editBtn);
        }

        if (isOwner) {
            // Delete button
            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'icon-btn danger';
            deleteBtn.dataset.tip = 'Delete Map';
            deleteBtn.addEventListener('click', e => {
                e.stopPropagation();
                deleteMap(map.id);
            });
            deleteBtn.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="3 6 5 6 21 6"/>
                    <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
                    <path d="M10 11v6"/>
                    <path d="M14 11v6"/>
                    <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
                </svg>
            `;
            actions.appendChild(deleteBtn);
        }

        if (isShared) {
            // Owner label and the badge+buttons share one baseline row.
            const ownerRow = document.createElement('div');
            ownerRow.className = 'map-owner-row';
            const ownerLabel = document.createElement('span');
            ownerLabel.className = 'map-owner-line';
            ownerLabel.textContent = owner || '';
            ownerRow.appendChild(ownerLabel);
            ownerRow.appendChild(actions);
            actionsWrapper.appendChild(ownerRow);
        } else {
            actionsWrapper.appendChild(actions);
        }
        details.appendChild(actionsWrapper);
    }

    card.appendChild(details);
    div.appendChild(card);

    if (map.id === selectedMapID) div.classList.add('selected');

    // Long press checkbox logic
    function showCheckboxes() {
        longPressModeMaps = true;
        ignoreNextClickMaps = true;

        document.querySelectorAll('.map-item').forEach(item => {
            if (!item.querySelector('input.map-checkbox')) {
                const input = document.createElement('input');
                input.type = 'checkbox';
                input.className = 'map-checkbox';
                input.dataset.id = item.dataset.id;

                if (item === div) input.checked = true;

                item.querySelector('.map-card').prepend(input);

                input.addEventListener('change', ev => {
                    const id = ev.target.dataset.id;
                    if (ev.target.checked) selectedMaps.add(id);
                    else selectedMaps.delete(id);

                    if (selectedMaps.size === 0) {
                        document.querySelectorAll('.map-item input.map-checkbox').forEach(cb => cb.remove());
                        longPressModeMaps = false;
                    }

                    updateMapsMenuButtons();
                });

                if (input.checked) selectedMaps.add(item.dataset.id);
            }
        });

        updateMapsMenuButtons();

        setTimeout(() => {
            ignoreNextClickMaps = false;
        }, 0);
    }

    div.addEventListener('mousedown', e => {
        if (e.target.tagName === 'INPUT') return;
        longPressTriggered = false;
        longPressTimerMaps = setTimeout(() => {
            longPressTriggered = true;
            showCheckboxes();
        }, 600);
    });

    div.addEventListener('mouseup', () => clearTimeout(longPressTimerMaps));
    div.addEventListener('mouseleave', () => clearTimeout(longPressTimerMaps));

    div.addEventListener('click', e => {
        if (longPressTriggered) {
            longPressTriggered = false;
            return;
        }

        if (e.target.tagName === 'INPUT') return;

        if (ignoreNextClickMaps) {
            ignoreNextClickMaps = false;
            return;
        }

        if (longPressModeMaps) {
            const checkbox = div.querySelector('.map-checkbox');
            if (!checkbox) return;

            checkbox.checked = !checkbox.checked;
            const id = checkbox.dataset.id;

            checkbox.checked ? selectedMaps.add(id) : selectedMaps.delete(id);

            if (selectedMaps.size === 0) {
                document.querySelectorAll('.map-checkbox').forEach(cb => cb.remove());
                longPressModeMaps = false;
            }

            updateMapsMenuButtons();
            return;
        }

        if (selectedMapID === map.id) return;

        document.querySelectorAll('.map-item.selected').forEach(item => item.classList.remove('selected'));

        div.classList.add('selected');
        selectedMapID = map.id;
        loadSpotsFromDB(selectedMapID);
        clearMarkerFilters();
        clearSelectedMarkers();
    });

    // Collapse/expand toggle
    nameCollapsed.style.display = '';
    details.style.display = 'none';
    toggle.dataset.state = 'closed';
    toggle.textContent = '▾';

    toggle.addEventListener('click', e => {
        e.stopPropagation();
        const open = toggle.dataset.state === 'open';
        toggle.dataset.state = open ? 'closed' : 'open';

        if (open) {
            details.style.display = 'none';
            nameCollapsed.style.display = '';
            toggle.textContent = '▾';
        } else {
            details.style.display = '';
            nameCollapsed.style.display = 'none';
            toggle.textContent = '▴';
        }
    });

    container.appendChild(div);

    // Right-click to show sidebar context menu (base maps get no context menu at all)
    div.addEventListener('contextmenu', e => {
        e.preventDefault();
        if (map.is_base) return;
        showSidebarMapContextMenu(div, e);
    });
}


// ===============================
// Sidebar maps hamburguer menu buttons
// ===============================
const sidebarMapsMenuBtn = document.querySelector(".sidebar-maps-menu-btn");
const sidebarMapsMenu = document.querySelector(".sidebar-maps-menu-dropdown");
const sidebarMarkersMenuBtn = document.querySelector(".sidebar-markers-menu-btn");
const sidebarMarkersMenu = document.querySelector(".sidebar-markers-menu-dropdown");
const expandMapsBtn = document.getElementById('sidebar-maps-expandSelected');
const collapseMapsBtn = document.getElementById('sidebar-maps-collapseSelected');
const shareMapsBtn = document.getElementById('sidebar-maps-collabSelected');
const deleteMapsBtn = document.getElementById('sidebar-maps-deleteSelected');

function updateMapsMenuButtons() {
    const hasSelection = selectedMaps.size > 0;
    [expandMapsBtn, collapseMapsBtn, shareMapsBtn, deleteMapsBtn].forEach(btn => {
        btn.classList.toggle('disabled', !hasSelection);
        btn.style.pointerEvents = hasSelection ? 'auto' : 'none';
        btn.style.opacity = hasSelection ? '1' : '0.5';
    });
}

// Create/Share/Delete are owner actions — hidden while browsing "Shared with Me"
// (that group only holds viewer/editor maps; backend enforces regardless).
function updateMapsMenuForGroup() {
    const shared = activeMapGroupFilter === 'shared';
    const createBtn = document.getElementById('sidebar-maps-createMap');
    createBtn.style.display = shared ? 'none' : '';
    // The separator right after Create would dangle at the top of the menu without it.
    const firstSeparator = sidebarMapsMenu.querySelector('li[role="separator"]');
    if (firstSeparator) firstSeparator.style.display = shared ? 'none' : '';
    shareMapsBtn.style.display = shared ? 'none' : '';
    deleteMapsBtn.style.display = shared ? 'none' : '';
}

updateMapsMenuButtons();
setupSidebarMenuDropdown(sidebarMapsMenuBtn, sidebarMapsMenu, sidebar, [sidebarMarkersMenu]);

document.addEventListener("click", () => sidebarMapsMenu.classList.remove("show"));
sidebarMapsMenu.addEventListener("click", e => e.stopPropagation());

// Close the menu on scrolling
// sidebar.addEventListener("scroll", () => {
//   if (sidebarMapsMenu.classList.contains("show")) {
//     sidebarMapsMenu.classList.remove("show");
//   }
// }, { passive: true });


// ===============================
// Create map
// ===============================
const createMapBtn = document.getElementById('sidebar-maps-createMap');
const addMapOverlay = document.getElementById('addMapOverlay');

createMapBtn.addEventListener('click', () => {
    const form = document.getElementById('addMapForm');
    const nameInput = document.getElementById('addMapName');
    const createdInput = document.getElementById('addMapCreated');
    const descriptionInput = document.getElementById('addMapDescription');
    const notesInput = document.getElementById('addMapNotes');

    function cleanup() {
        addMapOverlay.classList.remove('active');
        setTimeout(() => addMapOverlay.style.display = 'none', 250); // match transition
        busyOverlay.style.display = 'none';
        setTimeout(() => busyOverlay.style.display = 'none', 250); // match transition
    }

    // Reset fields before opening the overlay
    form.reset();

    // Prefill date
    const now = new Date();
    createdInput.value = new Date(now - now.getTimezoneOffset() * 60000).toISOString().slice(0, 16);

    // Show overlay
    addMapOverlay.style.display = 'flex';
    requestAnimationFrame(() => addMapOverlay.classList.add('active')); // trigger transition
    nameInput.focus();

    // Form submission
    form.onsubmit = async e => {
        e.preventDefault();
        try {
            const mapName = nameInput.value.trim();
            const mapCreated = createdInput.value || null;
            const mapDescription = descriptionInput.value.trim();
            const mapNotes = notesInput.value.trim();

            // Name validation
            if (!mapName) {
                showNotification('Please enter a map name');
                return;
            }

            const mapData = { name: mapName, description: mapDescription, notes: mapNotes };
            if (mapCreated) mapData.created = mapCreated;

            const res = await apiFetch('/maps', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(mapData)
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.error || 'Failed to add map');
            }

            const map = await res.json();
            map.markers = 0;
            maps.push(map); // add to global array
            // A new map is always owned; reset the group/search filter so it's actually
            // visible (and lands under "My Maps") rather than hidden by an active filter.
            resetMapGroupFilter();
            mapsSearchInput.value = '';
            if (clearMapsSearchBtn) clearMapsSearchBtn.style.display = 'none';
            renderGroupedMaps();

            // Select newly created map
            const sidebarContainer = document.getElementById('mapsList');
            sidebarContainer.querySelectorAll('.map-item').forEach(item => item.classList.remove('selected'));

            const newMapItem = sidebarContainer.querySelector(`.map-item[data-id="${map.id}"]`);
            if (newMapItem) newMapItem.classList.add('selected');

            selectedMapID = map.id;
            loadSpotsFromDB(selectedMapID);

            clearMarkerFilters();

            // Remove listeners and clear global resolve/reject
            showNotification(`Map saved: ${mapName}`);
            cleanup();

        } catch(err) {
            console.error(err);
            showNotification(err.message);
            cleanup();
        }
    }
});


// Close when clicking outside the overlay content
function closeAddMapOverlay() {
    addMapOverlay.classList.remove('active');
    setTimeout(() => addMapOverlay.style.display = 'none', 250); // match transition
}

window.addEventListener('mousedown', (e) => {
    if (e.target === addMapOverlay) closeAddMapOverlay();
});


// ================================================================
// Edit map handler
// ================================================================
function editMap(id) {
    // Prevent editing the base map (per-user; identified by the is_base flag)
    const mapForGuard = maps.find(m => m.id === id);
    if (mapForGuard && mapForGuard.is_base) {
        showNotification('The Base Map cannot be edited.');
        return;
    }

    const map = maps.find(m => m.id === id);
    if (!map) return;

    const overlay = document.getElementById('editMapOverlay');
    const form = document.getElementById('editMapForm');
    const nameInput = document.getElementById('editMapName');
    const createdInput = document.getElementById('editMapCreated');
    const descriptionInput = document.getElementById('editMapDescription');
    const notesInput = document.getElementById('editMapNotes');

    function cleanup() {
        overlay.classList.remove('active');
        setTimeout(() => overlay.style.display = 'none', 250);
    }

    // Prefill fields with existing map data
    nameInput.value = map.name || '';
    descriptionInput.value = map.description || '';
    notesInput.value = map.notes || '';
    createdInput.value = map.created ? new Date(map.created).toISOString().slice(0,16) : '';

    overlay.style.display = 'flex';
    requestAnimationFrame(() => overlay.classList.add('active'));
    nameInput.focus();

    // Helper to safely update sidebar map collapsed and expanded names
    function safeUpdateSidebarName(el, name, count) {
        el.textContent = ''; // clear old content
        const nameText = document.createTextNode(name + ' (');
        el.appendChild(nameText);

        const markerSpan = document.createElement('span');
        markerSpan.className = 'marker-count';
        markerSpan.textContent = count;
        el.appendChild(markerSpan);

        el.appendChild(document.createTextNode(')'));
    }

    form.onsubmit = async (e) => {
        e.preventDefault();

        const mapName = nameInput.value.trim();
        if (!mapName) {
            showNotification('Please enter a map name');
            return;
        }

        const mapCreated = createdInput.value || null;
        const mapDescription = descriptionInput.value.trim();
        const mapNotes = notesInput.value.trim();

        const updatedData = {
            name: mapName,
            created: mapCreated,
            description: mapDescription,
            notes: mapNotes
        };

        try {
            const res = await apiFetch(`/maps/${map.id}`, {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(updatedData)
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.error || 'Failed to update map');
            }

            const updatedMap = await res.json();

            // Update local map object
            Object.assign(map, updatedMap);

            // Update sidebar safely
            const sidebarItem = document.querySelector(`.map-item[data-id="${updatedMap.id}"]`);
            if (sidebarItem) {
                const markerCount = updatedMap.markers ?? 0;

                const nameEl = sidebarItem.querySelector('.map-name');
                const collapsedEl = sidebarItem.querySelector('.map-name-collapsed');

                if (nameEl) safeUpdateSidebarName(nameEl, updatedMap.name, markerCount);
                if (collapsedEl) safeUpdateSidebarName(collapsedEl, updatedMap.name, markerCount);

                // Update created date & time (single "date • time" line, like markers)
                if (updatedMap.created) {
                    const created = new Date(updatedMap.created);
                    const dateEl = sidebarItem.querySelector('.map-created-date');
                    if (dateEl) {
                        const d = created.toLocaleDateString();
                        const t = created.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                        dateEl.textContent = `${d} • ${t}`;
                    }
                }
            }

            showNotification(`Map updated: ${mapName}`);
            cleanup();

        } catch(err) {
            console.error(err);
            showNotification(err.message);
            cleanup();
        }

    };
}

// Close handler
function closeEditMapOverlay() {
    editMapOverlay.classList.remove('active');
    setTimeout(() => editMapOverlay.style.display = 'none', 250);
}

// Close when clicking outside the overlay content
window.addEventListener('mousedown', (e) => {
    if (e.target === editMapOverlay) closeEditMapOverlay();
});


// ===============================
// Map details overlay
// ===============================
function openMapDetailsOverlay(id) {
    const mapItem = maps.find(m => m.id === id);
    if (!mapItem) return;

    const overlay = document.getElementById("mapDetailsOverlay");
    overlay.style.display = 'flex';
    requestAnimationFrame(() => overlay.classList.add('active'));

    // Title
    document.querySelector(".map-details-title").textContent = mapItem.name || '';

    // Creator + creation date. The map payload carries the owner's real name for
    // shared maps and for the caller's own maps alike; fall back to the account name.
    if (mapItem.created) {
        const createdDate = new Date(mapItem.created);
        const date = createdDate.toLocaleDateString();
        const creator = mapItem.owner_name || mapItem.owner_username || accountDisplayName();
        document.querySelector(".map-details-date").textContent = `${creator} • ${date}`;
    } else {
        document.querySelector(".map-details-date").textContent = '';
    }

    // Description
    const descCard = document.getElementById("mapDetailsDescriptionCard");
    descCard.textContent = ''; // clear previous content
    if (mapItem.description) {
        const descDiv = document.createElement('div');
        descDiv.className = 'map-details-description';
        descDiv.textContent = mapItem.description;
        descCard.appendChild(descDiv);
    } else {
        const emptyP = document.createElement('p');
        emptyP.className = 'empty-notes';
        emptyP.textContent = 'No description.';
        descCard.appendChild(emptyP);
    }

    // Notes
    const notesCard = document.getElementById("mapDetailsNotesCard");
    notesCard.textContent = ''; // clear previous content
    if (mapItem.notes) {
        const notesDiv = document.createElement('div');
        notesDiv.className = 'map-details-notes';
        notesDiv.textContent = mapItem.notes;
        notesCard.appendChild(notesDiv);
    } else {
        const emptyP = document.createElement('p');
        emptyP.className = 'empty-notes';
        emptyP.textContent = 'No notes added.';
        notesCard.appendChild(emptyP);
    }
}

// Map details overlay close handlers
const mapDetailsOverlay = document.getElementById("mapDetailsOverlay");

function closeMapDetailsOverlay() {
    mapDetailsOverlay.classList.remove('active');
    setTimeout(() => {
        mapDetailsOverlay.style.display = 'none';
    }, 250); // match transition
}

// Close when clicking outside modal content
window.addEventListener("mousedown", (e) => {
    if (e.target === mapDetailsOverlay) {
        closeMapDetailsOverlay();
    }
});


// ===============================
// Delete map
// ===============================
async function deleteMap(id) {
    // Prevent deletion of the base map (per-user; identified by the is_base flag)
    const mapForGuard = maps.find(m => m.id === id);
    if (mapForGuard && mapForGuard.is_base) {
        showNotification('The Base Map cannot be deleted.');
        return;
    }

    const mapItem = document.querySelector(`.map-item[data-id="${id}"]`);
    const mapName = mapItem ? mapItem.querySelector('.map-name').textContent : 'Map';

    showConfirmation(`Delete map?`, async () => {
        try {
            // The backend owns the marker/photo cascade; one map action is one DELETE.
            const resMap = await apiFetch(`/maps/${id}`, { method: 'DELETE' });
            if (!resMap.ok) {
                const data = await resMap.json();
                throw new Error(data.error || 'Failed to delete map');
            }

            maps = maps.filter(map => map.id !== id);
            selectedMaps.delete(id);
            if (mapItem) mapItem.remove();

            // If deleted map was selected, fall back to this user's own Base Map
            if (selectedMapID === id) {
                document.getElementById('mapsList').querySelectorAll('.map-item').forEach(item => item.classList.remove('selected'));
                const baseId = getOwnBaseMapId();
                const baseMapItem = document.querySelector(`.map-item[data-id="${baseId}"]`);
                if (baseMapItem) {
                    baseMapItem.classList.add('selected');
                    selectedMapID = baseId;
                    loadSpotsFromDB(selectedMapID);
                }
            }

            clearMarkerFilters();

            showNotification(`Map deleted: ${mapName}`);
            void refreshNotificationHistorySummary();
        } catch (err) {
            console.error(err);
            showNotification(`Error deleting map: ${mapName}`);
        }
    }, () => console.log(`Deletion cancelled for map: ${mapName}`), 'deleteMap', id);
}


// ===============================
// Apply maps filters
// ===============================
const mapsSearchInput = document.getElementById('mapsSearchInput');
const mapList = document.getElementById('mapsList');

// The active group filter chosen in the dropdown. Defaults to the user's own maps.
let activeMapGroupFilter = 'mine';

function applyMapsFilters() {
    const textFilter = mapsSearchInput.value.toLowerCase();

    // Route through the grouped renderer so the subheaders survive search + clear.
    renderGroupedMaps(textFilter, activeMapGroupFilter);

    // Keep the currently-selected map highlighted if it's still visible.
    document.querySelectorAll('.map-item.selected').forEach(i => i.classList.remove('selected'));
    if (selectedMapID != null) {
        const sel = document.querySelector(`.map-item[data-id="${selectedMapID}"]`);
        if (sel) sel.classList.add('selected');
    }
}

// Event listener for sidebar maps search
mapsSearchInput.addEventListener('input', applyMapsFilters);


// ===============================
// Listener for clear maps search input button
// ===============================
const clearMapsSearchBtn = document.querySelector('.clear-maps-search-text-btn');

mapsSearchInput.addEventListener('input', () => {
    clearMapsSearchBtn.style.display = mapsSearchInput.value.trim() ? 'flex' : 'none';
});

clearMapsSearchBtn.addEventListener('click', () => {
    mapsSearchInput.value = '';
    clearMapsSearchBtn.style.display = 'none';
    mapsSearchInput.focus();
    applyMapsFilters();
});


// ===============================
// Maps group filter dropdown (My Maps / Shared with Me)
// Mirrors the marker listing/subset filter dropdowns (.listingFilter pattern).
// ===============================
const mapsGroupFilter = document.querySelector('.mapsGroupFilter');
const mapsGroupFilterSelected = mapsGroupFilter ? mapsGroupFilter.querySelector('.mapsGroupFilter-selected') : null;
const mapsGroupFilterText = mapsGroupFilter ? mapsGroupFilter.querySelector('.mapsGroupFilter-text') : null;
const mapsGroupFilterList = mapsGroupFilter ? mapsGroupFilter.querySelector('.mapsGroupFilter-list') : null;

// Keys match mapGroupKey(). No "All Maps" — the dropdown always selects one group.
const MAP_GROUP_OPTIONS = [
    { value: 'mine',   label: 'My Maps' },
    { value: 'shared', label: 'Shared with Me' }
];
const DEFAULT_MAP_GROUP = { value: 'mine', label: 'My Maps' };

function setMapGroupFilter(value, label) {
    activeMapGroupFilter = value;
    if (mapsGroupFilterText) mapsGroupFilterText.textContent = label;
    if (mapsGroupFilterSelected) mapsGroupFilterSelected.dataset.value = value;
    if (mapsGroupFilter) mapsGroupFilter.classList.remove('open');
    updateMapsMenuForGroup();
    applyMapsFilters();
}

function resetMapGroupFilter() {
    activeMapGroupFilter = DEFAULT_MAP_GROUP.value;
    if (mapsGroupFilterText) mapsGroupFilterText.textContent = DEFAULT_MAP_GROUP.label;
    if (mapsGroupFilterSelected) mapsGroupFilterSelected.dataset.value = DEFAULT_MAP_GROUP.value;
    updateMapsMenuForGroup();
}

// Build the option list.
function buildMapsGroupDropdown() {
    if (!mapsGroupFilterList) return;
    mapsGroupFilterList.innerHTML = '';
    MAP_GROUP_OPTIONS.forEach(opt => {
        const li = document.createElement('li');
        li.textContent = opt.label;
        li.dataset.value = opt.value;
        li.addEventListener('click', e => {
            e.stopPropagation();
            setMapGroupFilter(opt.value, opt.label);
        });
        mapsGroupFilterList.appendChild(li);
    });
}

if (mapsGroupFilterSelected) {
    mapsGroupFilterSelected.addEventListener('click', e => {
        e.stopPropagation();
        toggleDropdown(mapsGroupFilter, buildMapsGroupDropdown);
    });
    // Close when clicking outside.
    document.addEventListener('click', e => {
        if (!mapsGroupFilter.contains(e.target) && mapsGroupFilter.classList.contains('open')) {
            mapsGroupFilter.classList.remove('open');
        }
    });
}


// ===============================
// Update the marker count in the sidebar maps section
// ===============================
function updateMarkerCount(mapId, newCount) {
    const targetMap = maps.find(m => m.id == mapId);
    if (targetMap) targetMap.markers = newCount;

    const mapDiv = document.querySelector(`.map-item[data-id="${mapId}"]`);
    if (!mapDiv) return;
    const countEls = mapDiv.querySelectorAll('.marker-count');
    countEls.forEach(el => el.textContent = newCount);
}


// ===============================
// Select all maps
// ===============================
document.getElementById('sidebar-maps-selectAll').addEventListener('click', () => {
    const visibleMaps = Array.from(document.querySelectorAll('.map-item')).filter(item => item.offsetParent !== null); // only visible maps

    visibleMaps.forEach(item => {
        let cb = item.querySelector('input.map-checkbox');
        if (!cb) {
            // create checkbox if it doesn't exist
            cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.className = 'map-checkbox';
            cb.dataset.id = item.dataset.id;
            item.querySelector('.map-card').prepend(cb);

            cb.addEventListener('change', ev => {
                const id = ev.target.dataset.id;
                if (ev.target.checked) {
                    selectedMaps.add(id);
                } else {
                    selectedMaps.delete(id);
                    if (selectedMaps.size === 0) {
                        document.querySelectorAll('.map-item input.map-checkbox').forEach(cb => cb.remove());
                        longPressModeMaps = false; // deactivate mode if nothing selected
                    }
                }
                updateMapsMenuButtons(); // update menu buttons on change
            });
        }

        cb.checked = true;
        selectedMaps.add(item.dataset.id);
    });

    // Activate long-press mode when selecting all
    if (visibleMaps.length > 0) longPressModeMaps = true;

    updateMapsMenuButtons(); // update menu buttons after select all
});


// ===============================
// Clear selected maps
// ===============================
function clearSelectedMaps() {
    const checkboxesMaps = document.querySelectorAll('.map-item input.map-checkbox');

    // Uncheck all checkboxes
    checkboxesMaps.forEach(cb => cb.checked = false);

    // Clear selected maps set
    selectedMaps.clear();

    // Remove all checkboxes from the DOM
    checkboxesMaps.forEach(cb => cb.remove());

    // Deactivate long-press mode
    longPressModeMaps = false;

    // Update menu buttons
    updateMapsMenuButtons();
}

// Attach to the clear button
document.getElementById('sidebar-maps-clear').addEventListener('click', clearSelectedMaps);


// ===============================================================
// Expand selected maps
// ===============================================================
document.getElementById('sidebar-maps-expandSelected').addEventListener('click', () => {
    selectedMaps.forEach(id => {
        const item = document.querySelector(`.map-item[data-id="${id}"]`);
        if (!item) return;

        const details = item.querySelector('.map-details');
        const collapsedName = item.querySelector('.map-name-collapsed');
        const toggle = item.querySelector('.map-toggle');

        // Show details, hide collapsed title
        details.style.display = '';
        collapsedName.style.display = 'none';

        // Enforce toggle arrow
        if (toggle) {
            toggle.dataset.state = 'open';
            toggle.textContent = '▴';
        }
    });
});


// ===============================================================
// Collapse selected maps
// ===============================================================
document.getElementById('sidebar-maps-collapseSelected').addEventListener('click', () => {
    selectedMaps.forEach(id => {
        const item = document.querySelector(`.map-item[data-id="${id}"]`);
        if (!item) return;

        const details = item.querySelector('.map-details');
        const collapsedName = item.querySelector('.map-name-collapsed');
        const toggle = item.querySelector('.map-toggle');

        // Hide details, show collapsed title
        details.style.display = 'none';
        collapsedName.style.display = '';

        // Enforce toggle arrow
        if (toggle) {
            toggle.dataset.state = 'closed';
            toggle.textContent = '▾';
        }
    });
});


// ===============================================================
// Share selected maps (bulk)
// ===============================================================
document.getElementById('sidebar-maps-collabSelected').addEventListener('click', () => {
    const checked = Array.from(document.querySelectorAll('.map-checkbox:checked'));

    // Only maps the user owns can be shared, and never a Base Map.
    const ids = checked.map(cb => Number(cb.dataset.id)).filter(id => {
        const m = maps.find(mm => mm.id === id);
        return m && m.role === 'owner' && !m.is_base;
    });

    if (!ids.length) {
        showNotification('Select at least one of your own maps to share (Base Map cannot be shared).');
        return;
    }

    openBulkShareOverlay(ids);
});


// ===============================================================
// Delete selected maps
// ===============================================================
document.getElementById('sidebar-maps-deleteSelected').addEventListener('click', () => {
    const selected = Array.from(document.querySelectorAll('.map-checkbox:checked'));

    // Exclude Base Maps (per-user; identified by the is_base flag)
    const baseIds = new Set(maps.filter(m => m.is_base).map(m => m.id));
    const filtered = selected.filter(cb => {
        const item = cb.closest('.map-item');
        return item && !baseIds.has(Number(item.dataset.id));
    });

    if (!filtered.length) {
        showNotification("Select at least one map to delete (Base Map cannot be deleted).");
        return;
    }

    const deletedIds = filtered.map(cb => Number(cb.dataset.id));
    const currentMapDeleted = deletedIds.includes(selectedMapID);

    showConfirmation(`Delete ${filtered.length} map(s)?`, async () => {
        try {
            // The backend owns each map's marker/photo cascade.
            for (const mapId of deletedIds) {
                const res = await apiFetch(`/maps/${mapId}`, { method: 'DELETE' });
                if (!res.ok) throw new Error(`Failed to delete map ${mapId}`);

                maps = maps.filter(map => map.id !== mapId);
                const sidebarItem = document.querySelector(`.map-item[data-id="${mapId}"]`);
                if (sidebarItem) sidebarItem.remove();

                selectedMaps.delete(mapId);
            }

            // UI cleanup
            document.querySelectorAll('.map-item input.map-checkbox').forEach(cb => cb.remove());
            longPressModeMaps = false;
            selectedMaps.clear();
            updateMapsMenuButtons();

            showNotification(`${deletedIds.length} map(s) deleted`);
            void refreshNotificationHistorySummary();

            // Select this user's own Base Map if the selected map was deleted
            if (currentMapDeleted) {
                document.querySelectorAll('.map-item').forEach(i => i.classList.remove('selected'));
                const baseId = getOwnBaseMapId();
                const baseMapItem = document.querySelector(`.map-item[data-id="${baseId}"]`);
                if (baseMapItem) {
                    baseMapItem.classList.add('selected');
                    selectedMapID = baseId;
                    loadSpotsFromDB(baseId);
                }

                clearMarkerFilters();
            }

        } catch (err) {
            console.error(err);
            showNotification(`Error deleting maps: ${err.message}`);
        }
    }, () => console.log('Delete cancelled'), 'deleteSelectedMaps', deletedIds.join(','));
});


// ===============================================================
// Load spots of a map from the backend
// ===============================================================
async function loadSpotsFromDB(mapID) {
    try {
        // Close any open marker popup — a temp/search popup opened on the previous map
        // would otherwise carry its Save button (that map's permissions) onto this one.
        map.closePopup();

        // Hide/show the markers-menu write actions for this map's role.
        updateMarkersMenuForRole();

        // Clear old markers from sidebar
        document.getElementById('markerList').innerHTML = '';

        // Clear previous markers from the map
        if (markers) {
            markers.forEach(m => map.removeLayer(m)); // remove from map
        }
        markers = []; // reset array

        // Fetch all spots from the backend
        const res = await apiFetch(`/maps/${mapID}/spots`);
        const spots = await res.json();  // parse the JSON response into a JavaScript object/array

        // Loop through each fetched spot from the backend and add it as a marker on the map
        spots.forEach(spot => loadMarkerToMap(spot));

        // Populate the listing filter dropdown based on fetched spots
        populateListingArray();

    } catch (err) {
        console.error("Failed to load markers:", err);  // Log any errors if the fetch fails
    }
}

// ===============================
// Populate listing array
// ===============================
function populateListingArray() {
    listings = Array.from(
        new Set(markers.map(m => m.data.listing.toUpperCase()))
    ).sort((a, b) => a.localeCompare(b));
}


// ===============================
// Permanent markers popup helpers
// ===============================
function formatCreatedText(created) {
    if (!created) return '';
    const createdDate = new Date(created);
    const date = createdDate.toLocaleDateString();
    const time = createdDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return `${date} • ${time}`;
}

function buildMarkerPopupHTML(marker) {
    const data = marker.data || {};
    const createdText = formatCreatedText(data.created);

    const container = document.createElement('div');
    container.className = 'popup-content';

    // --- Popup Name ---
    const nameEl = document.createElement('div');
    nameEl.className = 'popup-name';
    nameEl.textContent = data.name ?? '';
    container.appendChild(nameEl);

    // --- Info Group ---
    const infoGroup = document.createElement('div');
    infoGroup.className = 'popup-info-group';

    const listingEl = document.createElement('div');
    listingEl.className = 'popup-listing';
    listingEl.textContent = (data.listing ?? '').toUpperCase();
    infoGroup.appendChild(listingEl);

    const subsetEl = document.createElement('div');
    subsetEl.className = 'popup-subset';
    subsetEl.textContent = (data.subset ?? '').toUpperCase();
    infoGroup.appendChild(subsetEl);

    const dateEl = document.createElement('div');
    dateEl.className = 'popup-date';

    const createdSpan = document.createElement('span');
    createdSpan.className = 'popup-created-text';
    createdSpan.dataset.markerId = String(data.id ?? '');
    createdSpan.textContent = createdText;
    dateEl.appendChild(createdSpan);

    // Preserve bullet and spacing exactly
    dateEl.appendChild(document.createTextNode(' • '));

    const photoCountSpan = document.createElement('span');
    photoCountSpan.className = 'popup-photo-count';
    photoCountSpan.dataset.markerId = String(data.id ?? '');
    photoCountSpan.textContent = String(data.photo_count ?? 0);
    dateEl.appendChild(photoCountSpan);

    // Space before SVG
    dateEl.appendChild(document.createTextNode(' '));

    // --- Date SVG ---
    const svgNS = "http://www.w3.org/2000/svg";
    const dateSvg = document.createElementNS(svgNS, 'svg');
    dateSvg.setAttribute('xmlns', svgNS);
    dateSvg.setAttribute('viewBox', '0 0 12 12');
    dateSvg.setAttribute('xml:space', 'preserve');
    dateSvg.setAttribute('width', '12');
    dateSvg.setAttribute('height', '12');

    const g = document.createElementNS(svgNS, 'g');
    g.setAttribute('fill', '#666');

    const path1 = document.createElementNS(svgNS, 'path');
    path1.setAttribute('d', 'M11.143 0H.857A.86.86 0 0 0 0 .857v10.286A.857.857 0 0 0 .857 12h10.286a.857.857 0 0 0 .857-.857V.857A.86.86 0 0 0 11.143 0m.075 11.143a.075.075 0 0 1-.075.075H.857a.075.075 0 0 1-.074-.075V.857A.075.075 0 0 1 .857.783h10.286a.075.075 0 0 1 .075.075z');
    g.appendChild(path1);

    const path2 = document.createElementNS(svgNS, 'path');
    path2.setAttribute('d', 'M7.626 5.258a.392.392 0 0 0-.66 0L5.079 8.219l-.966-1.516a.392.392 0 0 0-.66 0L1.442 9.859a.392.392 0 0 0 .33.602h8.457a.392.392 0 0 0 .33-.602zm-5.141 4.42 1.298-2.037.966 1.516a.392.392 0 0 0 .66 0l1.887-2.961 2.219 3.483zm1.141-4.513c1.021 0 1.852-.831 1.852-1.852s-.831-1.852-1.852-1.852-1.852.831-1.852 1.852.831 1.852 1.852 1.852m0-2.922a1.071 1.071 0 0 1 0 2.14 1.071 1.071 0 0 1 0-2.14');
    g.appendChild(path2);

    dateSvg.appendChild(g);
    dateEl.appendChild(dateSvg);

    infoGroup.appendChild(dateEl);
    container.appendChild(infoGroup);

    // --- Actions ---
    const actionsEl = document.createElement('div');
    actionsEl.className = 'popup-actions';

    const id = Number(data.id);
    const lat = Number(data.lat);
    const lng = Number(data.lng);

    function createActionButton(className, tip, svgHTML, handler) {
        const btn = document.createElement('button');
        btn.className = className;
        btn.dataset.tip = tip;
        btn.addEventListener('click', handler);

        // Insert static SVG safely
        const temp = document.createElement('div');
        temp.innerHTML = svgHTML.trim();
        while (temp.firstChild) btn.appendChild(temp.firstChild);

        return btn;
    }

    // Viewer on the selected map: read-only popup — no Edit/Delete buttons.
    const canEditMarkers = mapRole(selectedMapID) !== 'viewer';

    // Copy Coordinates
    actionsEl.appendChild(createActionButton(
        'icon-btn inline-copy',
        'Copy Coordinates',
        `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
            <rect x="9" y="9" width="13" height="13" rx="2"/>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
        </svg>`,
        () => { if (Number.isFinite(lat) && Number.isFinite(lng)) copyCoordinates(lat, lng); }
    ));

    // Edit
    if (canEditMarkers) actionsEl.appendChild(createActionButton(
        'icon-btn',
        'Edit Marker',
        `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 20h9"/>
            <path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/>
        </svg>`,
        () => { if (Number.isInteger(id)) editMarker(id); }
    ));

    // Info
    actionsEl.appendChild(createActionButton(
        'icon-btn',
        'View Details',
        `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" width="24" height="24">
            <circle cx="12" cy="12" r="10"/>
            <circle cx="12" cy="8" r="1.5" fill="currentColor" stroke="none"/>
            <path d="M12 12v6"/>
        </svg>`,
        () => { if (Number.isInteger(id)) openMarkerDetailsOverlay(id); }
    ));

    // Hide
    actionsEl.appendChild(createActionButton(
        'icon-btn',
        'Hide Marker',
        `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d="M2 12s4-6 10-6 10 6 10 6-4 6-10 6-10-6-10-6z"/>
            <circle cx="12" cy="12" r="3"/>
            <line x1="3" y1="3" x2="21" y2="21"/>
        </svg>`,
        () => { if (Number.isInteger(id)) hideMarker(id); }
    ));

    // Delete
    if (canEditMarkers) actionsEl.appendChild(createActionButton(
        'icon-btn danger',
        'Delete Marker',
        `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 6 5 6 21 6"/>
            <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
            <path d="M10 11v6"/>
            <path d="M14 11v6"/>
            <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
        </svg>`,
        () => { if (Number.isInteger(id)) deleteMarker(id); }
    ));

    container.appendChild(actionsEl);

    return container;
}


// ===============================================================
// Load a marker to the map
// ===============================================================
function loadMarkerToMap(spot) {

    // Create draggable marker (not draggable for a viewer — dragging PUTs the new position)
    const marker = L.marker([spot.lat, spot.lng], { draggable: mapRole(selectedMapID) !== 'viewer' }).addTo(map);
    marker.isOnMap = true;

    // Cache the fetched spot data in the marker for quick access later
    marker.data = { ...spot };

    // autoPan off — the shared map 'popupopen' handler recenters the popup only when it
    // opens clipped, leaving already-visible markers and the map untouched otherwise.
    marker.bindPopup(buildMarkerPopupHTML(marker), { autoPan: false });

    // Hook external handler to marker drag (Event listeners persist as long as that object exists, even after the function ends)
    marker.on('dragend', handleMarkerDrag);

    // Enable right-click context menu
    marker.on('contextmenu', function(e) {
        e.originalEvent.preventDefault(); // stop default browser menu
        showStoredMarkerContextMenu(marker, e.originalEvent); // pass raw mouse event
    });


    // Prevent double-click zoom on this marker
    marker.on('dblclick', function(e) {
        e.originalEvent.stopPropagation();
    });

    // Add the marker to the global array so we can reference it later [push() adds an element to the end of an array]
    markers.push(marker);

    // Add the marker to the sidebar
    addMarkerToSidebar(marker.data);
}


// ===============================================================
// Copy marker coordinates
// ===============================================================
function copyCoordinates(lat, lng) {
    const text = `${lat.toFixed(7)}, ${lng.toFixed(7)}`;
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text)
        .then(() => showNotification(`Coordinates copied`))
        .catch(() => showNotification('Failed to copy coordinates'));
    } else {
        prompt("Copy coordinates manually:", text);
    }
}


// ===============================================================
// Marker details overlay
// ===============================================================
async function openMarkerDetailsOverlay(id) {
    const marker = markers.find(m => m.data.id === id);
    if (!marker) return;

    const overlay = document.getElementById("markerDetailsOverlay");
    overlay.style.display = 'flex';
    requestAnimationFrame(() => overlay.classList.add('active')); // trigger transition

    // Fill in text content safely
    const titleEl = document.querySelector(".marker-details-title");
    titleEl.textContent = marker.data.name ?? '';

    const listingEl = document.querySelector(".marker-details-listing");
    listingEl.textContent = (marker.data.listing ?? '').toUpperCase();

    const subsetEl = document.querySelector(".marker-details-subset");
    subsetEl.textContent = (marker.data.subset ?? '').toUpperCase();

    const createdDate = new Date(marker.data.created);
    const date = createdDate.toLocaleDateString();
    const time = createdDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    const dateEl = document.querySelector(".marker-details-date");
    dateEl.textContent = `${date} • ${time}`;

    const latEl = document.getElementById("markerDetailsLat");
    latEl.textContent = (marker.data.lat ?? 0).toFixed(7);

    const lngEl = document.getElementById("markerDetailsLng");
    lngEl.textContent = (marker.data.lng ?? 0).toFixed(7);

    // --- Notes ---
    const notesCard = document.getElementById("markerDetailsNotesCard");
    notesCard.innerHTML = ''; // clear first

    if (marker.data.notes) {
        const notesContainer = document.createElement('div');
        notesContainer.className = 'marker-details-notes';
        notesContainer.appendChild(linkifyNotes(marker.data.notes));
        notesCard.appendChild(notesContainer);
    } else {
        const p = document.createElement('p');
        p.className = 'empty-notes';
        p.textContent = 'No notes added.';
        notesCard.appendChild(p);
    }

    // --- Photo gallery ---
    const gallery = document.getElementById("markerPhotoGallery");
    gallery.innerHTML = ''; // clear first

    const loadingMsg = document.createElement('p');
    loadingMsg.textContent = 'Loading photos...';
    gallery.appendChild(loadingMsg);

    try {
        const res = await apiFetch(`/spots/${marker.data.id}/photos`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const photos = await res.json();

        const swiperContainer = document.querySelector('.mySwiper');
        const swiperNavNext = document.querySelector('.swiper-button-next');
        const swiperNavPrev = document.querySelector('.swiper-button-prev');
        const swiperPagination = document.querySelector('.swiper-scrollbar');

        if (!Array.isArray(photos) || !photos.length) {
            gallery.innerHTML = '';
            const emptyMsg = document.createElement('p');
            emptyMsg.className = 'empty-photos';
            emptyMsg.textContent = 'No photos uploaded.';
            gallery.appendChild(emptyMsg);

            // Hide navigation and pagination
            swiperNavNext.style.display = 'none';
            swiperNavPrev.style.display = 'none';
            swiperPagination.style.display = 'none';
            return;
        }

        // Show navigation when photos exist
        swiperNavNext.style.display = '';
        swiperNavPrev.style.display = '';
        swiperPagination.style.display = '';

        gallery.innerHTML = ''; // clear loading message

        photos.forEach(p => {
            const slide = document.createElement('div');
            slide.className = 'swiper-slide';

            const a = document.createElement('a');
            a.href = p.photo_url;
            a.className = 'glightbox';
            a.dataset.gallery = 'my-gallery';
            a.dataset.title = sanitizeGlightboxTitle(p.caption);
            a.setAttribute('target', '_blank');
            a.setAttribute('rel', 'noopener noreferrer');

            const img = document.createElement('img');
            img.src = p.thumb_url;
            img.alt = 'Photo';
            img.draggable = false;

            const preloader = document.createElement('div');
            preloader.className = 'swiper-lazy-preloader';

            a.appendChild(img);
            a.appendChild(preloader);
            slide.appendChild(a);
            gallery.appendChild(slide);
        });

        // Initialize new Swiper instance fresh
        window.spotSwiper = new Swiper(swiperContainer, {
            slidesPerView: 1,
            centeredSlides: true,
            spaceBetween: 20,
            grabCursor: true,
            rewind: true,
            scrollbar: {
                el: ".swiper-scrollbar",
                draggable: true,
                hide: false,
            },
            keyboard: {
                enabled: true,
            },
            navigation: {
                nextEl: '.swiper-button-next',
                prevEl: '.swiper-button-prev',
            },
        });

        const lightbox = GLightbox({ selector: '.glightbox' });

        // Sync before GLightbox animations so rapid navigation cannot complete out of order.
        lightbox.on('slide_before_change', ({ current }) => {
            const index = current?.slideIndex ?? 0;
            if (window.spotSwiper) {
                window.spotSwiper.slideTo(index, 0);
            }
        });
    } catch (err) {
        console.error("Error loading photos:", err);
        gallery.innerHTML = '';
        const errorMsg = document.createElement('p');
        errorMsg.style.color = 'red';
        errorMsg.textContent = 'Failed to load photos.';
        gallery.appendChild(errorMsg);
    }
}


// Marker details overlay close handlers
const detailsOverlay = document.getElementById("markerDetailsOverlay");
function closeDetailsOverlay() {
    detailsOverlay.classList.remove('active');

    // Wait for the CSS transition to finish before hiding and destroying Swiper
    setTimeout(() => {
        detailsOverlay.style.display = 'none';

        if (window.spotSwiper) {
            window.spotSwiper.destroy(true, true); // destroy DOM and events
            window.spotSwiper = null;
        }
    }, 250); // match CSS transition duration
}

// Close when clicking outside modal content
window.addEventListener("mousedown", (e) => {
    if (e.target === detailsOverlay) closeDetailsOverlay();
});


// ===============================================================
// Show stored marker through popup button
// ===============================================================
function showMarker(id) {
    // Find marker by its unique id
    const marker = markers.find(m => m.data.id === id);

    let markerName = 'Unnamed marker';
    if (marker) {
        markerName = marker.data?.name || 'Unnamed marker';

        if (!marker.isOnMap) {
            marker.addTo(map);  // add marker back to the map
            marker.isOnMap = true;  // update its state
        }
    }

    // Update sidebar appearance
    const sidebarItem = document.querySelector(`.marker-item[data-id="${id}"]`);
    if (sidebarItem) {
        sidebarItem.classList.remove('disabled-marker');
    }

    showNotification(`Marker shown: ${markerName}`);
}


// ===============================================================
// Hide stored marker through popup button
// ===============================================================
function hideMarker(id) {
    // Find marker by its unique id
    const marker = markers.find(m => m.data.id === id);

    let markerName = 'Unnamed marker';
    if (marker) {
        markerName = marker.data?.name || 'Unnamed marker';

        if (marker.isOnMap) {
            map.removeLayer(marker); // remove from map
            marker.isOnMap = false;  // update its state
        }
    }

    // Update sidebar appearance
    const sidebarItem = document.querySelector(`.marker-item[data-id="${id}"]`);
    if (sidebarItem) {
        sidebarItem.classList.add('disabled-marker');
    }

    showNotification(`Marker hidden: ${markerName}`);
}


// ===============================================================
// Delete stored marker through popup button or context menu
// ===============================================================
function deleteMarker(id) {
    const marker = markers.find(m => m.data.id.toString() === id.toString());
    const markerName = marker ? marker.data.name : 'Marker';

    showConfirmation(`Delete saved marker?`, async () => {
        try {
            const res = await apiFetch(`/spots/${id}`, { method: 'DELETE' });
            if (!res.ok) throw new Error('Failed to delete marker');

            if (marker) {
                // remove from map and array
                if (marker.isOnMap) map.removeLayer(marker);
                const index = markers.findIndex(m => m.data.id.toString() === id.toString());
                if (index !== -1) markers.splice(index, 1);

                // Update map's marker count
                updateMarkerCount(marker.data.mapID, markers.length);
            }

            const sidebarItem = document.querySelector(`.marker-item[data-id="${id}"]`);
            if (sidebarItem) sidebarItem.remove();

            populateListingArray();
            applyMarkersFilters();
            updateMarkerCount(selectedMapID, markers.length);

            showNotification(`Marker deleted: ${markerName}`);
            void refreshNotificationHistorySummary();
        } catch (err) {
            console.error(err);
            showNotification(`Error deleting marker: ${markerName}`);
        }
    }, () => console.log(`Deletion cancelled for marker: ${markerName}`), 'deleteMarker', id);
}


// ===============================================================
// Update backend when a marker is dragged, with user confirmation
// ===============================================================
async function handleMarkerDrag(e) {
    const marker = e.target;
    const oldLatLng = L.latLng(marker.data.lat, marker.data.lng);
    const newLatLng = marker.getLatLng();

    showConfirmation(`Save new marker position?`, async () => {
        try {
            const res = await apiFetch(`/spots/${marker.data.id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ lat: newLatLng.lat, lng: newLatLng.lng })
            });
            if (!res.ok) throw new Error('Failed to update marker position');

            marker.data.lat = newLatLng.lat;
            marker.data.lng = newLatLng.lng;

            showNotification('Marker position updated');
        } catch (err) {
            console.error(err);
            showNotification('Error saving position, reverting...');
            marker.setLatLng(oldLatLng);
        }
    }, () => marker.setLatLng(oldLatLng), 'dragMarker', marker.data.id);
}


// ===============================================================
// Add marker handler
// ===============================================================
const addMarkerOverlay = document.getElementById('addMarkerOverlay');
let currentResolve, currentReject;
let inputActive = false;

async function addMarker(latlng = null, prefillName = '') {
    const controller = new AbortController();

    return new Promise((resolve, reject) => {
        currentResolve = resolve;
        currentReject = reject;

        // Listen for abort signal to reject promise
        const onAbort = () => {
            reject('User cancelled');
            cleanup();
        };
        controller.signal.addEventListener('abort', onAbort);

        function cleanup() {
            controller.signal.removeEventListener('abort', onAbort);
            document.removeEventListener('click', closeDropdownsOnOutsideClick);
            currentResolve = null;
            currentReject = null;
            inputActive = false;
            overlay.classList.remove('active');
            setTimeout(() => overlay.style.display = 'none', 250); // match transition
            busyOverlay.style.display = 'none';
            setTimeout(() => busyOverlay.style.display = 'none', 250); // match transition
        }

        // UI initialization
        const overlay = document.getElementById('addMarkerOverlay');
        const form = document.getElementById('addMarkerForm');
        const photoInput = document.getElementById('addMarkerPhotos');
        const photoCount = document.getElementById('addMarkerPhotoCount');
        const nameInput = document.getElementById('addMarkerName');
        const notesInput = document.getElementById('addMarkerNotes');
        const latInput = document.getElementById('addMarkerLat');
        const lngInput = document.getElementById('addMarkerLng');
        const createdInput = document.getElementById('addMarkerCreated');

        const listingSelectWrapper = document.getElementById('addMarkerListingSelectWrapper');
        const listingInputWrapper = document.getElementById('addMarkerListingInputWrapper');
        const listingSelect = document.getElementById('addMarkerListingCustom');
        const listingSelected = listingSelect.querySelector('.selected');
        const listingOptions = listingSelect.querySelector('.options');
        const createListingBtn = document.getElementById('addMarkerCreateListingBtn');
        const listingInput = document.getElementById('addMarkerListingInput');
        const saveListingBtn = document.getElementById('addMarkerSaveListingBtn');
        const cancelListingBtn = document.getElementById('addMarkerCancelListingBtn');

        const subsetSelectWrapper = document.getElementById('addMarkerSubsetSelectWrapper');
        const subsetInputWrapper  = document.getElementById('addMarkerSubsetInputWrapper');
        const subsetSelect = document.getElementById('addMarkerSubsetCustom');
        const subsetSelected = subsetSelect.querySelector('.selected');
        const subsetOptions = subsetSelect.querySelector('.options');
        const createSubsetBtn = document.getElementById('addMarkerCreateSubsetBtn');
        const subsetInput     = document.getElementById('addMarkerSubsetInput');
        const saveSubsetBtn   = document.getElementById('addMarkerSaveSubsetBtn');
        const cancelSubsetBtn = document.getElementById('addMarkerCancelSubsetBtn');

        // UI Reset
        form.reset();
        inputActive = false;
        if (photoInput) photoInput.value = '';
        if (photoCount) photoCount.innerText = 'No photos selected';

        listingSelected.textContent = 'Select or create a new listing...';
        listingSelected.classList.add('placeholder');
        listingOptions.innerHTML = '';
        listingSelect.classList.remove('open');
        listingSelectWrapper.style.display = 'flex';
        listingInputWrapper.style.display = 'none';
        let selectedListing = '';

        subsetSelected.textContent = 'Select or create a new subset...';
        subsetSelected.classList.add('placeholder');
        subsetOptions.innerHTML = '';
        subsetSelect.classList.remove('open');
        subsetSelectWrapper.style.display = 'flex';
        subsetInputWrapper.style.display = 'none';
        let selectedSubset = '';

        // Prefill name
        if (prefillName) nameInput.value = prefillName;

        // Dropdowns and placeholders
        function updateListingPlaceholder() {
            if (selectedListing) {
                listingSelected.textContent = selectedListing;
                listingSelected.classList.remove('placeholder');
            } else {
                listingSelected.textContent = 'Select or create a new listing...';
                listingSelected.classList.add('placeholder');
            }
        }

        function updateSubsetPlaceholder() {
            if (selectedSubset) {
                subsetSelected.textContent = selectedSubset;
                subsetSelected.classList.remove('placeholder');
            } else {
                subsetSelected.textContent = 'Select or create a new subset...';
                subsetSelected.classList.add('placeholder');
            }
        }

        // Listing dropdown
        function createListingDropdown() {
            const allListings = listings.includes('GENERAL') ? [...listings] : ['GENERAL', ...listings];
            createDropdown({
                container: listingOptions,
                items: allListings,
                selectedValue: selectedListing,
                onSelect: listing => {
                    selectedListing = listing;
                    selectedSubset = '';
                    updateListingPlaceholder();
                    updateSubsetPlaceholder();
                    listingSelect.classList.remove('open');
                    createSubsetDropdown();
                    updateSubsetEnabledState();
                }
            });
        }

        createListingBtn.onclick = e => {
            e.stopPropagation();
            listingSelectWrapper.style.display = 'none';
            listingInputWrapper.style.display = 'flex';
            listingInput.value = '';
            listingInput.focus();
        };

        saveListingBtn.onclick = e => {
            e.preventDefault();
            const val = listingInput.value.trim().toUpperCase();
            if (!val) return;

            selectedListing = val;
            selectedSubset = '';

            createListingDropdown();
            updateListingPlaceholder();
            updateSubsetPlaceholder();
            createSubsetDropdown();
            updateSubsetEnabledState();

            listingInputWrapper.style.display = 'none'
            listingSelectWrapper.style.display = 'flex';
        };

        cancelListingBtn.onclick = () => {
            listingInputWrapper.style.display = 'none'
            listingSelectWrapper.style.display = 'flex';
            listingInput.value = '';
            updateSubsetEnabledState();
        };

        listingInput.onkeydown = e => {
            if (e.key === 'Enter') {
                e.preventDefault();       // prevent default form submission
                saveListingBtn.click();   // trigger the save button logic
            }
        };

        function updateSubsetEnabledState() {
            const enabled = !!selectedListing;

            subsetSelect.classList.toggle('disabled', !enabled);
            createSubsetBtn.style.pointerEvents = enabled ? 'auto' : 'none';
            createSubsetBtn.style.opacity = enabled ? '1' : '0.4';

            subsetSelectWrapper.style.pointerEvents = enabled ? 'auto' : 'none';
            subsetSelectWrapper.style.opacity = enabled ? '1' : '0.4';

            if (!enabled) {
                selectedSubset = '';
                updateSubsetPlaceholder();
                subsetInputWrapper.style.display = 'none';
                subsetSelectWrapper.style.display = 'flex';
            }
        }

        function getSubsetsForListing(listingName) {
            if (!listingName) return [];
            const filtered = markers
                .filter(m => (m.data.listing || '').toLowerCase() === listingName.toLowerCase())
                .map(m => (m.data.subset || '').toUpperCase())
                .filter(s => s);
            return Array.from(new Set(filtered)).sort();
        }

        // Subset dropdown
        function createSubsetDropdown() {
            if (!selectedListing) return;
            let subsets = getSubsetsForListing(selectedListing);
            if (!subsets.includes('MAIN')) subsets.push('MAIN');

            createDropdown({
                container: subsetOptions,
                items: subsets,
                selectedValue: selectedSubset,
                onSelect: subset => {
                    selectedSubset = subset;
                    updateSubsetPlaceholder();
                    subsetSelect.classList.remove('open');
                }
            });
        }

        createSubsetBtn.onclick = e => {
            e.stopPropagation();
            subsetSelectWrapper.style.display = 'none';
            subsetInputWrapper.style.display = 'flex';
            subsetInput.value = '';
            subsetInput.focus();
        };

        saveSubsetBtn.onclick = e => {
            e.preventDefault();
            const val = subsetInput.value.trim().toUpperCase();
            if (!val) return;

            selectedSubset = val;

            createSubsetDropdown();
            updateSubsetPlaceholder();

            subsetInputWrapper.style.display = 'none';
            subsetSelectWrapper.style.display = 'flex';
        };

        cancelSubsetBtn.onclick = () => {
            subsetInputWrapper.style.display = 'none';
            subsetSelectWrapper.style.display = 'flex';
            subsetInput.value = '';
        };

        subsetInput.onkeydown = e => {
            if (e.key === 'Enter') {
                e.preventDefault();       // prevent default form submission
                saveSubsetBtn.click();   // trigger the save button logic
            }
        };

        createListingDropdown();
        createSubsetDropdown();
        updateListingPlaceholder();
        updateSubsetPlaceholder();
        updateSubsetEnabledState();

        listingSelect.onclick = e => {
            e.stopPropagation();
            listingSelect.classList.toggle('open');
            subsetSelect.classList.remove('open');

            // Clear the filter input
            filterInput.value = "";

            // Hide clear button
            const clearBtn = listingOptions.querySelector('.clear-text-btn');
            if (clearBtn) clearBtn.style.display = 'none';

            // Show all listing items
            listingOptions.querySelectorAll('li[data-value]').forEach(li => {
                li.style.display = 'block';
            });

            // Reset scroll to top
            listingOptions.scrollTop = 0;
        };

        subsetSelect.onclick = e => {
            e.stopPropagation();

            // Recreate dropdown so filter input and clear button exist
            createSubsetDropdown();

            subsetSelect.classList.toggle('open');
            listingSelect.classList.remove('open');

            // Clear filter input and reset clear button
            const filterInput = subsetOptions.querySelector('.filter-input input');
            if (filterInput) filterInput.value = '';
            const clearBtn = subsetOptions.querySelector('.clear-text-btn');
            if (clearBtn) clearBtn.style.display = 'none';

            // Show all subset items
            subsetOptions.querySelectorAll('li[data-value]').forEach(li => li.style.display = 'block');

            // Reset scroll
            subsetOptions.scrollTop = 0;
        };

        function closeDropdownsOnOutsideClick(e) {
            if (!listingSelect.contains(e.target)) listingSelect.classList.remove('open');
            if (!subsetSelect.contains(e.target)) subsetSelect.classList.remove('open');
        }
        document.addEventListener('click', closeDropdownsOnOutsideClick);

        const filterInput = listingOptions.querySelector('.filter-input input');
        filterInput.addEventListener('click', e => {
            e.stopPropagation();
        });

        // Prefill coordinates and date
        if (latlng) {
            latInput.value = latlng.lat.toFixed(7);
            lngInput.value = latlng.lng.toFixed(7);
            const now = new Date();
            createdInput.value = new Date(now - now.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
        }

        // Show overlay
        overlay.style.display = 'flex';
        requestAnimationFrame(() => overlay.classList.add('active')); // trigger transition
        nameInput.focus();

        // Count the number of photos to upload
        if (photoInput) {
            photoInput.onchange = () => {
                const validExtensions = ['jpg', 'jpeg', 'png', 'gif'];

                // Convert FileList to array and filter by extension
                const validFiles = Array.from(photoInput.files).filter(file => {
                    const ext = file.name.split('.').pop().toLowerCase();
                    return validExtensions.includes(ext);
                });

                const count = validFiles.length;
                photoCount.innerText = count
                    ? `${count} photo${count > 1 ? 's' : ''} selected`
                    : 'No photos selected';
            };
        }

        // Form submission
        form.onsubmit = async e => {
            e.preventDefault();

            // Name validation
            const markerName = nameInput.value.trim();
            if (!markerName) {
                showNotification('Please enter a marker name');
                return;
            }

            // Coordinates validation
            const latRaw = latInput.value.trim();
            const lngRaw = lngInput.value.trim();
            const coordRegex = /^-?\d+(\.\d+)?$/;
            if (!coordRegex.test(latRaw) || !coordRegex.test(lngRaw)) {
                showNotification('Invalid coordinates');
                return;
            }

            const markerLat = parseFloat(latRaw);
            const markerLng = parseFloat(lngRaw);
            if (markerLat < -90 || markerLat > 90 || markerLng < -180 || markerLng > 180) {
                showNotification('Coordinates out of range');
                return;
            }

            const markerListing = selectedListing || 'General';
            const markerSubset = selectedSubset || 'Main';
            const markerNotes = notesInput.value.trim();
            const markerCreated = createdInput.value || null;

            const markerData = { mapID: selectedMapID, name: markerName, listing: markerListing, subset: markerSubset, notes: markerNotes, lat: markerLat, lng: markerLng };
            if (markerCreated) markerData.created = markerCreated;

            // Start a delayed overlay
            let busyTimeout = setTimeout(
                () => busyOverlay.style.display = 'flex',
                PUBLIC_CONFIG.busyIndicatorDelayMs
            );

            try {
                const res = await apiFetch('/spots', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(markerData)
                });
                if (!res.ok) throw new Error('Failed to add marker');

                const marker = await res.json();

                // Count valid files from the photo input
                let validPhotoCount = 0;
                if (photoInput && photoInput.files.length > 0) {
                    const validExtensions = ['jpg', 'jpeg', 'png', 'gif'];
                    validPhotoCount = Array.from(photoInput.files).filter(file => {
                        const ext = file.name.split('.').pop().toLowerCase();
                        return validExtensions.includes(ext);
                    }).length;
                }

                // Set temporary photo count in marker for UI
                marker.photo_count = validPhotoCount;

                loadMarkerToMap(marker);

                // Refresh listing and subset filters dropdown
                populateListingArray();
                applyMarkersFilters();

                // Bind photo uploads
                if (photoInput) {
                    bindUploadHandler(marker.id, photoInput);
                    if (photoInput.files.length > 0) photoInput.onchange?.();
                }

                // Update map's marker count
                updateMarkerCount(selectedMapID, markers.length);

                // Remove listeners and clear global resolve/reject
                showNotification(`Marker saved: ${markerName}`);
                cleanup();
                resolve(marker);

            } catch(err) {
                console.error(err);
                const markerName = nameInput.value.trim();
                showNotification(`Error adding marker: ${markerName}`);
                cleanup();
                reject(err);
            } finally {
                // Stop the overlay
                clearTimeout(busyTimeout); // prevent showing if not yet 500ms
                busyOverlay.style.display = 'none';
            }
        };
    });
}

// Prevent default browser context menu on sidebar elements
toggle.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    e.stopPropagation();
});

// ===============================================================
// Close Add Marker Overlay when clicking outside
// ===============================================================
if (addMarkerOverlay) {
    addMarkerOverlay.addEventListener('mousedown', e => {
        if (inputActive) return;

        if (e.target === e.currentTarget && currentReject) {
            addMarkerOverlay.classList.remove('active');
            setTimeout(() => addMarkerOverlay.style.display = 'none', 250);
            inputActive = false;

            // Reject the current promise if waiting
            currentReject('User cancelled');
            currentResolve = null;
            currentReject = null;
        }
    });
}



// ===============================================================
// Edit marker handler
// ===============================================================
function editMarker(markerId) {
    inputActive = false;
    const marker = markers.find(m => m.data.id === markerId);
    if (!marker) return;

    function cleanup() {
        document.removeEventListener('click', closeDropdownsOnOutsideClick);
        inputActive = false;
        overlay.classList.remove('active');
        setTimeout(() => overlay.style.display = 'none', 250);
        busyOverlay.style.display = 'none';
        setTimeout(() => busyOverlay.style.display = 'none', 250);
    }

    const markerData = marker.data;
    const overlay = document.getElementById('editMarkerOverlay');
    const form = document.getElementById('editMarkerForm');
    const nameInput = document.getElementById('editMarkerName');
    const notesInput = document.getElementById('editMarkerNotes');
    const latInput = document.getElementById('editMarkerLat');
    const lngInput = document.getElementById('editMarkerLng');
    const createdInput = document.getElementById('editMarkerCreated');

    // --- Listing dropdown ---
    const listingSelectWrapper = document.getElementById('editMarkerListingSelectWrapper');
    const listingInputWrapper = document.getElementById('editMarkerListingInputWrapper');
    const listingSelect = document.getElementById('editMarkerListingCustom');
    const listingSelected = listingSelect.querySelector('.selected');
    const listingOptions = listingSelect.querySelector('.options');
    const createListingBtn = document.getElementById('editMarkerCreateListingBtn');
    const listingInput = document.getElementById('editMarkerListingInput');
    const saveListingBtn = document.getElementById('editMarkerSaveListingBtn');
    const cancelListingBtn = document.getElementById('editMarkerCancelListingBtn');
    let selectedListing = (markerData.listing || '').toUpperCase();

    // --- Subset dropdown ---
    const subsetSelectWrapper = document.getElementById('editMarkerSubsetSelectWrapper');
    const subsetInputWrapper  = document.getElementById('editMarkerSubsetInputWrapper');
    const subsetSelect = document.getElementById('editMarkerSubsetCustom');
    const subsetSelected = subsetSelect.querySelector('.selected');
    const subsetOptions = subsetSelect.querySelector('.options');
    const createSubsetBtn = document.getElementById('editMarkerCreateSubsetBtn');
    const subsetInput     = document.getElementById('editMarkerSubsetInput');
    const saveSubsetBtn   = document.getElementById('editMarkerSaveSubsetBtn');
    const cancelSubsetBtn = document.getElementById('editMarkerCancelSubsetBtn');
    let selectedSubset = (markerData.subset || '').toUpperCase();

    // UI reset
    listingOptions.innerHTML = '';
    listingSelect.classList.remove('open');
    listingSelectWrapper.style.display = 'flex';
    listingInputWrapper.style.display = 'none';
    subsetOptions.innerHTML = '';
    subsetSelect.classList.remove('open');
    subsetSelectWrapper.style.display = 'flex';
    subsetInputWrapper.style.display = 'none';

    // Dropdowns and placeholders
    function updateListingPlaceholder() {
        if (selectedListing) {
            listingSelected.textContent = selectedListing;
            listingSelected.classList.remove('placeholder');
        } else {
            listingSelected.textContent = 'Select or create a new listing...';
            listingSelected.classList.add('placeholder');
        }
    }

    function updateSubsetPlaceholder() {
        if (selectedSubset) {
            subsetSelected.textContent = selectedSubset;
            subsetSelected.classList.remove('placeholder');
        } else {
            subsetSelected.textContent = 'Select or create a new subset...';
            subsetSelected.classList.add('placeholder');
        }
    }

    // Listing dropdown
    function createListingDropdown() {
        const allListings = listings.includes('GENERAL') ? [...listings] : ['GENERAL', ...listings];
        createDropdown({
            container: listingOptions,
            items: allListings,
            selectedValue: selectedListing,
            onSelect: listing => {
                selectedListing = listing;
                selectedSubset = '';
                updateListingPlaceholder();
                updateSubsetPlaceholder();
                listingSelect.classList.remove('open');
                createSubsetDropdown();
                updateSubsetEnabledState();
            }
        });
    }

    createListingBtn.onclick = e => {
        e.stopPropagation();
        listingSelectWrapper.style.display = 'none';
        listingInputWrapper.style.display = 'flex';
        listingInput.value = '';
        listingInput.focus();
    };

    saveListingBtn.onclick = e => {
        e.preventDefault();
        const val = listingInput.value.trim().toUpperCase();
        if (!val) return;

        selectedListing = val;
        selectedSubset = '';

        createListingDropdown();
        updateListingPlaceholder();
        updateSubsetPlaceholder();
        createSubsetDropdown();
        updateSubsetEnabledState();

        listingInputWrapper.style.display = 'none'
        listingSelectWrapper.style.display = 'flex';
    };

    cancelListingBtn.onclick = () => {
        listingInputWrapper.style.display = 'none'
        listingSelectWrapper.style.display = 'flex';
        listingInput.value = '';
        updateSubsetEnabledState();
    };

    listingInput.onkeydown = e => {
        if (e.key === 'Enter') {
            e.preventDefault();       // prevent default form submission
            saveListingBtn.click();   // trigger the save button logic
        }
    };

    // Subset dropdown
    function updateSubsetEnabledState() {
        const enabled = !!selectedListing;

        subsetSelect.classList.toggle('disabled', !enabled);
        createSubsetBtn.style.pointerEvents = enabled ? 'auto' : 'none';
        createSubsetBtn.style.opacity = enabled ? '1' : '0.4';

        subsetSelectWrapper.style.pointerEvents = enabled ? 'auto' : 'none';
        subsetSelectWrapper.style.opacity = enabled ? '1' : '0.4';

        if (!enabled) {
            selectedSubset = '';
            updateSubsetPlaceholder();
            subsetInputWrapper.style.display = 'none';
            subsetSelectWrapper.style.display = 'flex';
        }
    }

    function getSubsetsForListing(listingName) {
        if (!listingName) return [];
        const filtered = markers
            .filter(m => (m.data.listing || '').toLowerCase() === listingName.toLowerCase())
            .map(m => (m.data.subset || '').toUpperCase())
            .filter(s => s);
        return Array.from(new Set(filtered)).sort();
    }

    function createSubsetDropdown() {
        if (!selectedListing) return;
        let subsets = getSubsetsForListing(selectedListing);
        if (!subsets.includes('MAIN')) subsets.push('MAIN');

        createDropdown({
            container: subsetOptions,
            items: subsets,
            selectedValue: selectedSubset,
            onSelect: subset => {
                selectedSubset = subset;
                updateSubsetPlaceholder();
                subsetSelect.classList.remove('open');
            }
        });
    }

    createSubsetBtn.onclick = e => {
        e.stopPropagation();
        subsetSelectWrapper.style.display = 'none';
        subsetInputWrapper.style.display = 'flex';
        subsetInput.value = '';
        subsetInput.focus();
    };

    saveSubsetBtn.onclick = e => {
        e.preventDefault();
        const val = subsetInput.value.trim().toUpperCase();
        if (!val) return;

        selectedSubset = val;

        createSubsetDropdown();
        updateSubsetPlaceholder();

        subsetInputWrapper.style.display = 'none';
        subsetSelectWrapper.style.display = 'flex';
    };

    cancelSubsetBtn.onclick = () => {
        subsetInputWrapper.style.display = 'none';
        subsetSelectWrapper.style.display = 'flex';
        subsetInput.value = '';
    };

    subsetInput.onkeydown = e => {
        if (e.key === 'Enter') {
            e.preventDefault();       // prevent default form submission
            saveSubsetBtn.click();   // trigger the save button logic
        }
    };

    createListingDropdown();
    createSubsetDropdown();
    updateListingPlaceholder();
    updateSubsetPlaceholder();
    updateSubsetEnabledState();

    listingSelect.onclick = e => {
        e.stopPropagation();
        listingSelect.classList.toggle('open');
        subsetSelect.classList.remove('open');

        // Clear the filter input
        filterInput.value = "";

        // Hide clear button
        const clearBtn = listingOptions.querySelector('.clear-text-btn');
        if (clearBtn) clearBtn.style.display = 'none';

        // Show all listing items
        listingOptions.querySelectorAll('li[data-value]').forEach(li => {
            li.style.display = 'block';
        });

        // Reset scroll to top
        listingOptions.scrollTop = 0;
    };

    subsetSelect.onclick = e => {
        e.stopPropagation();

        // Recreate dropdown so filter input and clear button exist
        createSubsetDropdown();

        subsetSelect.classList.toggle('open');
        listingSelect.classList.remove('open');

        // Clear filter input and reset clear button
        const filterInput = subsetOptions.querySelector('.filter-input input');
        if (filterInput) filterInput.value = '';
        const clearBtn = subsetOptions.querySelector('.clear-text-btn');
        if (clearBtn) clearBtn.style.display = 'none';

        // Show all subset items
        subsetOptions.querySelectorAll('li[data-value]').forEach(li => li.style.display = 'block');

        // Reset scroll
        subsetOptions.scrollTop = 0;
    };

    function closeDropdownsOnOutsideClick(e) {
        if (!listingSelect.contains(e.target)) listingSelect.classList.remove('open');
        if (!subsetSelect.contains(e.target)) subsetSelect.classList.remove('open');
    }
    document.addEventListener('click', closeDropdownsOnOutsideClick);

    const filterInput = listingOptions.querySelector('.filter-input input');
    filterInput.addEventListener('click', e => {
        e.stopPropagation();
    });

    // Prefill other fields
    form.reset();
    nameInput.value = markerData.name || '';
    notesInput.value = markerData.notes || '';
    latInput.value = markerData.lat.toFixed(7);
    lngInput.value = markerData.lng.toFixed(7);
    createdInput.value = markerData.created ? new Date(markerData.created).toISOString().slice(0,16) : '';

    overlay.style.display = 'flex';
    requestAnimationFrame(() => overlay.classList.add('active')); // trigger transition
    nameInput.focus();

    document.querySelector('.manage-photos-btn').onclick = () => openManagePhotosOverlay(markerId);

    form.onsubmit = async (e) => {
        e.preventDefault();

        // Name validation
        const markerName = nameInput.value.trim();
        if (!markerName) {
            showNotification('Please enter a marker name');
            return;
        }

        // Coordinates validation
        const latRaw = latInput.value.trim();
        const lngRaw = lngInput.value.trim();
        const coordRegex = /^-?\d+(\.\d+)?$/;
        if (!coordRegex.test(latRaw) || !coordRegex.test(lngRaw)) {
            showNotification('Invalid coordinates');
            return;
        }

        const markerLat = parseFloat(latRaw);
        const markerLng = parseFloat(lngRaw);
        if (markerLat < -90 || markerLat > 90 || markerLng < -180 || markerLng > 180) {
            showNotification('Coordinates out of range');
            return;
        }

        const markerlisting = selectedListing || 'General';
        const markerSubset = selectedSubset || 'Main';
        const markerNotes = notesInput.value.trim();
        const markerCreated = createdInput.value || null;

        const formData = { name: markerName, listing: markerlisting, subset: markerSubset, notes: markerNotes, lat: markerLat, lng: markerLng };
        if (markerCreated) formData.created = markerCreated;

        let busyTimeout = setTimeout(
            () => busyOverlay.style.display = 'flex',
            PUBLIC_CONFIG.busyIndicatorDelayMs
        );

        try {
            const updatedFields = {};
            for (const key in formData) {
                if (formData[key] !== markerData[key]) updatedFields[key] = formData[key];
            }

            if (Object.keys(updatedFields).length > 0) {

                // Send update to server
                const res = await apiFetch(`/spots/${markerData.id}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(updatedFields)
                });
                if (!res.ok) throw new Error('Failed to update marker');

                // Update local data
                Object.assign(markerData, updatedFields);

                // Move marker if coordinates changed
                if (updatedFields.lat !== undefined || updatedFields.lng !== undefined) {
                    marker.setLatLng([markerData.lat, markerData.lng]);
                }

                // Update sidebar after editing a marker
                const sidebarItem = document.querySelector(`.marker-item[data-id="${markerData.id}"]`);
                if (sidebarItem) {
                    const nameEl = sidebarItem.querySelector('.poi-name');
                    if (nameEl) nameEl.textContent = markerData.name;

                    const nameCollapsedEl = sidebarItem.querySelector('.poi-name-collapsed');
                    if (nameCollapsedEl) nameCollapsedEl.textContent = markerData.name;

                    const listingEl = sidebarItem.querySelector('.poi-listing');
                    if (listingEl) listingEl.textContent = markerData.listing.toUpperCase();

                    const subsetEl = sidebarItem.querySelector('.poi-subset');
                    if (subsetEl) subsetEl.textContent = markerData.subset.toUpperCase();

                    const createdEl = sidebarItem.querySelector('.poi-created');
                    if (createdEl) {
                        createdEl.textContent = markerData.created ? new Date(markerData.created).toLocaleString() : '';
                    }
                }

                // Refresh listing and subset filters dropdown
                populateListingArray();
                applyMarkersFilters();

                marker.setPopupContent(buildMarkerPopupHTML(marker));

                // Reopen the popup
                if (marker.isPopupOpen()) marker.openPopup();
            }

            showNotification(`Marker updated: ${markerName}`);
            cleanup();

        } catch (err) {
            console.error(err);
            const markerName = nameInput.value.trim();
            showNotification(`Error updating marker: ${markerName}`);
            cleanup();

        } finally {
            // Stop the overlay
            clearTimeout(busyTimeout); // prevent showing if not yet 500ms
            busyOverlay.style.display = 'none';
        }
    };
}


// ===============================================================
// Close Edit Overlay when clicking outside
// ===============================================================
const editMarkerOverlay = document.getElementById('editMarkerOverlay');
if (editMarkerOverlay) {
    editMarkerOverlay.addEventListener('mousedown', (e) => {
        if (inputActive) return;

        if (e.target === e.currentTarget) {
            editMarkerOverlay.classList.remove('active');
            setTimeout(() => editMarkerOverlay.style.display = 'none', 250); // match transition
            inputActive = false;
        }
    });
}

// =====================
// Helper to create a gallery item element
// =====================
function createGalleryItem(markerId, photo) {
    const div = document.createElement('div');
    div.className = 'gallery-item';
    div.dataset.filename = photo.filename;

    // Image
    const img = document.createElement('img');
    img.src = photo.thumb_url;
    img.draggable = false;
    img.alt = 'Photo';
    img.dataset.tip = photo.filename;

    // Caption input
    const captionInput = document.createElement('input');
    captionInput.type = 'text';
    captionInput.className = 'photo-caption';
    captionInput.value = photo.caption || '';
    captionInput.placeholder = 'Add a caption';

    // Buttons container
    const buttonsDiv = document.createElement('div');
    buttonsDiv.className = 'photo-buttons';

    // Download button
    const downloadBtn = document.createElement('button');
    downloadBtn.className = 'download-btn';
    downloadBtn.dataset.tip = 'Download Photo';
    downloadBtn.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 0.48 0.48" fill="none">
            <path d="M0.24 0.04a0.02 0.02 0 0 1 0.02 0.02v0.212l0.046-0.046a0.02 0.02 0 0 1 0.028 0.028l-0.08 0.08a0.02 0.02 0 0 1 -0.028 0l-0.08-0.08a0.02 0.02 0 1 1 0.028-0.028L0.22 0.272V0.06a0.02 0.02 0 0 1 0.02-0.02M0.1 0.34a0.02 0.02 0 0 1 0.02 0.02v0.04h0.24v-0.04a0.02 0.02 0 1 1 0.04 0v0.04a0.04 0.04 0 0 1 -0.04 0.04H0.12a0.04 0.04 0 0 1 -0.04-0.04v-0.04a0.02 0.02 0 0 1 0.02-0.02" fill="#ccc"/>
        </svg>
    `;

    // Replace button
    const replaceBtn = document.createElement('button');
    replaceBtn.className = 'replace-btn';
    replaceBtn.dataset.tip = 'Replace Photo';
    replaceBtn.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path d="M4.413 11.379c-1.81-1.946-1.778-4.995.102-6.889a4.86 4.86 0 0 1 2.731-1.389L7.191 1.44a6.48 6.48 0 0 0-3.838 1.881C.834 5.857.803 9.952 3.255 12.546l-1.393 1.402 4.408.241-.012-4.667zm5.318-9.567.012 4.667 1.846-1.858c1.81 1.947 1.778 4.997-.102 6.889a4.86 4.86 0 0 1-2.731 1.389l.055 1.661a6.5 6.5 0 0 0 3.838-1.88c2.518-2.538 2.549-6.633.098-9.225l1.393-1.403z" fill="#ccc"/>
        </svg>
    `;

    // Hidden file input
    const replaceInput = document.createElement('input');
    replaceInput.type = 'file';
    replaceInput.style.display = 'none';
    replaceInput.accept = '.jpg,.jpeg,.png,.gif';

    // Delete button
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'delete-btn';
    deleteBtn.dataset.tip = 'Delete Photo';
    deleteBtn.innerHTML = `
        <svg viewBox="0 0 16 16" fill="none" stroke="#ccc" stroke-width="1.8"
             stroke-linecap="round" stroke-linejoin="round" width="16" height="16">
            <path d="M2 4h12"/>
            <path d="m12.667 4 -0.667 9.333a1.333 1.333 0 0 1 -1.333 1.333H5.333a1.333 1.333 0 0 1 -1.333 -1.333L3.333 4"/>
            <path d="M6.667 7.333v4"/>
            <path d="M9.333 7.333v4"/>
            <path d="M6 4V2.667a0.667 0.667 0 0 1 0.667-0.667h2.667a0.667 0.667 0 0 1 0.667 0.667v1.333"/>
        </svg>
    `;

    // Assemble
    buttonsDiv.append(downloadBtn, replaceBtn, replaceInput, deleteBtn);
    div.append(img, captionInput, buttonsDiv);

    // Events
    downloadBtn.onclick = () => downloadPhoto(photo.photo_url, photo.filename);
    replaceBtn.onclick = () => replaceInput.click();
    replaceInput.onchange = () => replacePhoto(markerId, photo.filename, replaceInput);
    captionInput.onchange = () => updateCaption(markerId, photo.filename, captionInput.value);
    deleteBtn.onclick = () => deletePhoto(markerId, photo.filename);

    return div;
}


// =====================
// Helper to update the popup photo count
// =====================
function updateMarkerPhotoCount(markerId, newCount) {
    // Find the marker
    const leafletMarker = markers.find(m => m.data.id === markerId);
    if (!leafletMarker) return;

    // Update the marker data
    leafletMarker.data.photo_count = newCount;

    // Update sidebar count
    const sidebarItem = document.querySelector(`.marker-item[data-id="${markerId}"]`);
    if (sidebarItem) {
        const countEl = sidebarItem.querySelector('.poi-photo-count span');
        if (countEl) countEl.textContent = newCount;
    }

    // Update popup count if it exists
    const popup = leafletMarker.getPopup?.();
    if (popup) {
        const countEl = document.querySelector(`.popup-photo-count[data-marker-id="${markerId}"]`);
        if (countEl) countEl.textContent = newCount;
    }
}


// =====================
// Manage photos in edit marker overlay
// =====================
async function openManagePhotosOverlay(markerId) {
    const overlay = document.getElementById('managePhotosOverlay');
    const gallery = document.getElementById('managePhotosGallery');

    // Clear gallery and show loading
    gallery.innerHTML = '';
    const loadingText = document.createElement('p');
    loadingText.className = 'loading-text';
    loadingText.textContent = 'Loading photos...';
    gallery.appendChild(loadingText);

    overlay.style.display = 'flex';
    requestAnimationFrame(() => overlay.classList.add('active'));

    try {
        const res = await apiFetch(`/spots/${markerId}/photos`);
        const photos = await res.json();

        // Clear gallery safely
        gallery.innerHTML = '';

        // Create hidden upload input
        const uploadInput = document.createElement('input');
        uploadInput.type = 'file';
        uploadInput.id = 'addPhotosInput';
        uploadInput.accept = '.jpg,.jpeg,.png,.gif';
        uploadInput.multiple = true;
        uploadInput.hidden = true;

        // Add Photos Card
        const addCard = document.createElement('div');
        addCard.className = 'gallery-item add-photo-card';

        const addIcon = document.createElement('div');
        addIcon.className = 'add-photo-icon';
        addIcon.textContent = '+';

        const addText = document.createElement('div');
        addText.className = 'add-photo-text';
        addText.textContent = 'Add Photos';

        addCard.appendChild(addIcon);
        addCard.appendChild(addText);

        addCard.onclick = () => uploadInput.click();

        // Append input and add card
        gallery.appendChild(uploadInput);
        gallery.appendChild(addCard);

        // If no photos, show message
        if (!Array.isArray(photos) || photos.length === 0) {
            const noPhotosMsg = document.createElement('p');
            noPhotosMsg.textContent = 'No photos uploaded.';
            gallery.appendChild(noPhotosMsg);
            bindUploadHandler(markerId, uploadInput);
            return;
        }

        // Append all photo items
        for (const photo of photos) {
            const item = createGalleryItem(markerId, photo);
            gallery.appendChild(item);
        }

        bindUploadHandler(markerId, uploadInput);

    } catch (err) {
        console.error(err);

        gallery.innerHTML = '';
        const errorMsg = document.createElement('p');
        errorMsg.style.color = 'red';
        errorMsg.textContent = 'Failed to load photos.';
        gallery.appendChild(errorMsg);
    }
}

// Download handler — url is a signed /photos/... URL; filename is the suggested save name.
function downloadPhoto(url, filename) {
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;  // Suggests filename for download
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

// Upload handler
function bindUploadHandler(markerId, uploadInput) {
    if (!uploadInput) return;

    uploadInput.onchange = async () => {
        if (!uploadInput.files.length) return;

        const validExtensions = ['jpg', 'jpeg', 'png', 'gif'];

        // Filter files by valid extensions
        const validFiles = Array.from(uploadInput.files).filter(file => {
            const ext = file.name.split('.').pop().toLowerCase();
            return validExtensions.includes(ext);
        });

        const invalidCount = uploadInput.files.length - validFiles.length;
        if (invalidCount > 0) {
            showNotification(`${invalidCount} invalid file(s) skipped. Only JPG, JPEG, PNG, and GIF are allowed.`);
        }

        if (!validFiles.length) {
            uploadInput.value = ''; // reset input
            return;
        }

        busyOverlay.style.display = 'flex';
        const gallery = document.getElementById('managePhotosGallery');
        const leafletMarker = markers.find(m => m.data.id === markerId);
        let successfulUploads = 0;

        // Upload all valid files sequentially
        for (const file of validFiles) {
            const formData = new FormData();
            formData.append('photo', file);

            try {
                const res = await apiFetch(`/spots/${markerId}/photos`, { method: 'POST', body: formData });
                const p = await res.json();
                if (!res.ok) throw new Error(p.error || 'Failed to upload photo');

                // Remove "No photos." message if present
                const noPhotosMsg = gallery.querySelector('p');
                if (noPhotosMsg) noPhotosMsg.remove();

                // Add new gallery item
                const newItem = createGalleryItem(markerId, p);
                const galleryItems = gallery.querySelectorAll('.gallery-item');
                if (galleryItems.length) {
                    gallery.insertBefore(newItem, galleryItems[galleryItems.length - 1].nextSibling);
                } else {
                    gallery.appendChild(newItem);
                }

                successfulUploads++;

            } catch (err) {
                console.error(err);
                showNotification(err.message || 'Failed to upload photo.');
            }
        }

        // Fetch the updated photo count from backend
        try {
            const res = await apiFetch(`/spots/${markerId}`);
            if (!res.ok) throw new Error('Failed to fetch marker data');
            const updatedMarker = await res.json();

            leafletMarker.data.photo_count = updatedMarker.photo_count || 0;
            updateMarkerPhotoCount(markerId, leafletMarker.data.photo_count);

            // Show notification using successfulUploads count
            if (successfulUploads > 0) {
                showNotification(`Uploaded ${successfulUploads} photo${successfulUploads > 1 ? 's' : ''} successfully`);
            }

        } catch (err) {
            console.error('Could not update photo count from backend:', err);
        }

        uploadInput.value = '';
        busyOverlay.style.display = 'none';
    };
}


// Update caption
async function updateCaption(markerId, filename, newCaption) {
    try {
        const res = await apiFetch(`/spots/${markerId}/photos/${filename}/caption`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ caption: newCaption })
        });
        if (!res.ok) throw new Error('Failed to update caption');
        const data = await res.json();

        showNotification('Caption updated');

        console.log('Caption updated', data);
    } catch (err) {
        console.error(err);
        showNotification('Failed to update caption');
    }
}

// Replace photo
async function replacePhoto(markerId, oldFilename, inputElem) {
    if (!inputElem.files.length) return;

    const file = inputElem.files[0];
    const formData = new FormData();
    formData.append('photo', file);

    try {
        const res = await apiFetch(`/spots/${markerId}/photos/${oldFilename}`, { method: 'PUT', body: formData });
        const result = await res.json();

        if (!res.ok) throw new Error(result.error || 'Failed to replace photo');

        const newFilename = result.filename;

        // Find gallery item
        const galleryItem = document.querySelector(`.gallery-item[data-filename='${CSS.escape(oldFilename)}']`);
        if (!galleryItem) return;

        // Update thumbnail with the signed URL from the replace response.
        const imgElem = galleryItem.querySelector('img');
        imgElem.src = result.thumb_url;
        imgElem.dataset.tip = newFilename;

        // Update file input for next replacement
        const replaceInput = galleryItem.querySelector('input[type="file"]');
        replaceInput.onchange = () => replacePhoto(markerId, newFilename, replaceInput);
        replaceInput.value = '';

        // Update caption input
        const captionInput = galleryItem.querySelector('.photo-caption');
        captionInput.onchange = () => updateCaption(markerId, newFilename, captionInput.value);

        // Update download button to the new signed URL
        const downloadBtn = galleryItem.querySelector('.download-btn');
        if (downloadBtn) downloadBtn.onclick = () => downloadPhoto(result.photo_url, newFilename);

        // Update delete button
        const deleteBtn = galleryItem.querySelector('.delete-btn');
        deleteBtn.onclick = () => deletePhoto(markerId, newFilename);

        // Update dataset
        galleryItem.dataset.filename = newFilename;

        showNotification('Photo replaced');
        console.log(`Photo replaced successfully: ${oldFilename} → ${newFilename}`);
    } catch (err) {
        console.error(err);
        showNotification(err.message || 'Failed to replace photo.');
    }
}

// Delete photo
async function deletePhoto(markerId, filename) {
    try {
        const res = await apiFetch(`/spots/${markerId}/photos/${filename}`, { method: 'DELETE' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to delete photo');

        // Update photo count
        const leafletMarker = markers.find(m => m.data.id === markerId);
        leafletMarker.data.photo_count -= 1;
        updateMarkerPhotoCount(markerId, leafletMarker.data.photo_count);

        const gallery = document.getElementById('managePhotosGallery');

        // Remove the deleted gallery item
        const galleryItem = gallery.querySelector(`.gallery-item[data-filename='${CSS.escape(filename)}']`);
        if (galleryItem) galleryItem.remove();

        showNotification('Photo deleted');
        void refreshNotificationHistorySummary();

        // Check if gallery is empty (excluding the add-photo card)
        const remainingPhotos = gallery.querySelectorAll('.gallery-item:not(.add-photo-card)');
        if (!remainingPhotos.length) {
            const noPhotosMsg = document.createElement('p');
            noPhotosMsg.textContent = 'No photos uploaded.';
            gallery.appendChild(noPhotosMsg);
        }
    } catch (err) {
        console.error(err);
        showNotification(err.message || 'Failed to delete photo.');
    }
}

// Close when clicking outside the gallery
const managePhotosOverlay = document.getElementById('managePhotosOverlay');
const managePhotosGallery = document.getElementById('managePhotosGallery');
managePhotosOverlay.addEventListener('click', (e) => {
    // If the clicked element is NOT inside the gallery
    if (!managePhotosGallery.contains(e.target)) {
        managePhotosOverlay.classList.remove('active');
        setTimeout(() => managePhotosOverlay.style.display = 'none', 250); // match transition
    }
});


// ===============================
// Add marker to sidebar
// ===============================
let longPressTimerMarkers;
let selectedMarkers = new Set();
let longPressModeMarkers = false; // true if checkboxes are visible
let ignoreNextClickMarkers = false; // skip click immediately after long press

function addMarkerToSidebar(marker) {
    const container = document.getElementById('markerList');
    const div = document.createElement('div');
    div.className = 'marker-item';
    div.dataset.id = marker.id;

    // Attach marker reference for context menu actions
    div.markerObject = marker;

    // Format created date
    let createdText = '';
    if (marker.created) {
        const createdDate = new Date(marker.created);
        const date = createdDate.toLocaleDateString();
        const time = createdDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        createdText = `${date} • ${time}`;
    }

    // Marker card
    const card = document.createElement('div');
    card.className = 'marker-card';
    div.appendChild(card);

    // Toggle
    const toggle = document.createElement('div');
    toggle.className = 'poi-toggle';
    toggle.dataset.state = 'open';
    toggle.textContent = '▾';
    card.appendChild(toggle);

    // Collapsed name
    const collapsedName = document.createElement('div');
    collapsedName.className = 'poi-name-collapsed';
    collapsedName.textContent = marker.name ?? '';
    card.appendChild(collapsedName);

    // Details wrapper
    const details = document.createElement('div');
    details.className = 'poi-details';
    card.appendChild(details);

    // Full name
    const nameEl = document.createElement('div');
    nameEl.className = 'poi-name';
    nameEl.textContent = marker.name ?? '';
    details.appendChild(nameEl);

    // Listing wrapper
    const listingWrapper = document.createElement('div');
    listingWrapper.className = 'poi-listing-wrapper';
    details.appendChild(listingWrapper);

    const listingEl = document.createElement('div');
    listingEl.className = 'poi-listing';
    listingEl.textContent = (marker.listing ?? '').toUpperCase();
    listingWrapper.appendChild(listingEl);

    const subsetEl = document.createElement('div');
    subsetEl.className = 'poi-subset';
    subsetEl.textContent = (marker.subset ?? '').toUpperCase();
    listingWrapper.appendChild(subsetEl);

    // Created + photo count wrapper
    const createdWrapper = document.createElement('div');
    createdWrapper.className = 'poi-created-photo-count-wrapper';
    details.appendChild(createdWrapper);

    const createdEl = document.createElement('div');
    createdEl.className = 'poi-created';
    createdEl.textContent = createdText;
    createdWrapper.appendChild(createdEl);

    const photoCountEl = document.createElement('div');
    photoCountEl.className = 'poi-photo-count';
    createdWrapper.appendChild(photoCountEl);

    const countSpan = document.createElement('span');
    countSpan.textContent = String(marker.photo_count ?? 0);
    photoCountEl.appendChild(countSpan);

    // --- SVG for photo count ---
    const svgNS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('xmlns', svgNS);
    svg.setAttribute('viewBox', '0 0 12 12');
    svg.setAttribute('xml:space', 'preserve');
    svg.setAttribute('width', '12');
    svg.setAttribute('height', '12');

    const g = document.createElementNS(svgNS, 'g');
    g.setAttribute('fill', '#666');

    const path1 = document.createElementNS(svgNS, 'path');
    path1.setAttribute('d', 'M11.143 0H.857A.86.86 0 0 0 0 .857v10.286A.857.857 0 0 0 .857 12h10.286a.857.857 0 0 0 .857-.857V.857A.86.86 0 0 0 11.143 0m.075 11.143a.075.075 0 0 1-.075.075H.857a.075.075 0 0 1-.074-.075V.857A.075.075 0 0 1 .857.783h10.286a.075.075 0 0 1 .075.075z');
    g.appendChild(path1);

    const path2 = document.createElementNS(svgNS, 'path');
    path2.setAttribute('d', 'M7.626 5.258a.392.392 0 0 0-.66 0L5.079 8.219l-.966-1.516a.392.392 0 0 0-.66 0L1.442 9.859a.392.392 0 0 0 .33.602h8.457a.392.392 0 0 0 .33-.602zm-5.141 4.42 1.298-2.037.966 1.516a.392.392 0 0 0 .66 0l1.887-2.961 2.219 3.483zm1.141-4.513c1.021 0 1.852-.831 1.852-1.852s-.831-1.852-1.852-1.852-1.852.831-1.852 1.852.831 1.852 1.852 1.852m0-2.922a1.071 1.071 0 0 1 0 2.14 1.071 1.071 0 0 1 0-2.14');
    g.appendChild(path2);

    svg.appendChild(g);
    photoCountEl.appendChild(svg);

    // --- Long press / checkbox logic ---
    function showCheckboxes() {
        longPressModeMarkers = true;
        ignoreNextClickMarkers = true;

        document.querySelectorAll('.marker-item').forEach(item => {
            if (!item.querySelector('input.poi-checkbox')) {
                const input = document.createElement('input');
                input.type = 'checkbox';
                input.className = 'poi-checkbox';
                input.dataset.id = item.dataset.id;

                if (item === div) input.checked = true;

                item.querySelector('.marker-card').prepend(input);

                input.addEventListener('change', ev => {
                    const id = ev.target.dataset.id;
                    if (ev.target.checked) selectedMarkers.add(id);
                    else selectedMarkers.delete(id);

                    if (selectedMarkers.size === 0) {
                        document.querySelectorAll('.marker-item input.poi-checkbox').forEach(cb => cb.remove());
                        longPressModeMarkers = false;
                    }

                    updateMarkersMenuButtons();
                });

                if (input.checked) selectedMarkers.add(item.dataset.id);
            }
        });

        updateMarkersMenuButtons();
    }

    div.addEventListener('mousedown', e => {
        if (e.target.tagName === 'INPUT') return;
        longPressTriggered = false;
        longPressTimerMarkers = setTimeout(() => {
            longPressTriggered = true;
            showCheckboxes();
        }, 600);
    });

    div.addEventListener('mouseup', () => clearTimeout(longPressTimerMarkers));
    div.addEventListener('mouseleave', () => clearTimeout(longPressTimerMarkers));

    div.addEventListener('click', e => {
        if (e.target.tagName === 'INPUT') return;

        if (ignoreNextClickMarkers) {
            ignoreNextClickMarkers = false;
            return;
        }

        if (longPressModeMarkers) {
            const checkbox = div.querySelector('.poi-checkbox');
            if (checkbox) {
                checkbox.checked = !checkbox.checked;
                const id = checkbox.dataset.id;
                if (checkbox.checked) selectedMarkers.add(id);
                else {
                    selectedMarkers.delete(id);
                    if (selectedMarkers.size === 0) {
                        document.querySelectorAll('.marker-item input.poi-checkbox').forEach(cb => cb.remove());
                        longPressModeMarkers = false;
                    }
                }
                updateMarkersMenuButtons();
            }
            return;
        }

        // Toggle popup
        const foundMarker = markers.find(m => m.data.id === marker.id);
        if (!foundMarker) return;

        if (!foundMarker.isOnMap) {
            foundMarker.addTo(map);
            foundMarker.isOnMap = true;
            div.classList.remove('disabled-marker');
        }

        if (foundMarker.isPopupOpen()) foundMarker.closePopup();
        else foundMarker.openPopup();
    });

    // Right click context menu
    div.addEventListener('contextmenu', e => {
        e.preventDefault();
        showSidebarMarkerContextMenu(div, e);
    });

    // Collapse/expand toggle
    collapsedName.style.display = '';
    details.style.display = 'none';
    toggle.dataset.state = 'closed';
    toggle.textContent = '▾';

    toggle.addEventListener('click', e => {
        e.stopPropagation();
        const open = toggle.dataset.state === 'open';
        toggle.dataset.state = open ? 'closed' : 'open';

        if (open) {
            details.style.display = 'none';
            collapsedName.style.display = '';
            toggle.textContent = '▾';
        } else {
            details.style.display = '';
            collapsedName.style.display = 'none';
            toggle.textContent = '▴';
        }
    });

    container.appendChild(div);

    // Highlight sidebar on popup open/close
    const foundMarker = markers.find(m => m.data.id === marker.id);
    if (foundMarker) {
        foundMarker.on('popupopen', () => {
            div.classList.add('popup-open');
            div.classList.remove('popup-closing');

            // Scroll sidebar to make the marker visible
            div.scrollIntoView({
                behavior: 'smooth',   // smooth scroll
                block: 'center',      // center the marker in the sidebar view
                inline: 'nearest'
            });
        });

        foundMarker.on('popupclose', () => {
            div.classList.remove('popup-open');
            div.classList.add('popup-closing');
            setTimeout(() => div.classList.remove('popup-closing'), 300);
        });
    }
}


// ===============================
// Sidebar markers hamburguer menu button
// ===============================
const countMarkersBtn = document.getElementById('sidebar-markers-countSelected');
const expandMarkersBtn = document.getElementById('sidebar-markers-expandSelected');
const collapseMarkersBtn = document.getElementById('sidebar-markers-collapseSelected');
const hideMarkersBtn = document.getElementById('sidebar-markers-hideSelected');
const showMarkersBtn = document.getElementById('sidebar-markers-showSelected');
const copyMarkersBtn = document.getElementById('sidebar-markers-copySelected');
const moveMarkersBtn = document.getElementById('sidebar-markers-moveSelected');
const deleteMarkersBtn = document.getElementById('sidebar-markers-deleteSelected');

function updateMarkersMenuButtons() {
    const hasSelection = selectedMarkers.size > 0;
    [countMarkersBtn, expandMarkersBtn, collapseMarkersBtn, hideMarkersBtn, showMarkersBtn, copyMarkersBtn, moveMarkersBtn, deleteMarkersBtn].forEach(btn => {
        btn.classList.toggle('disabled', !hasSelection);
        btn.style.pointerEvents = hasSelection ? 'auto' : 'none';
        btn.style.opacity = hasSelection ? '1' : '0.5';
    });
}

// Marker-write actions are hidden while a viewer-role map is selected (backend rejects
// them regardless). Copy stays — it writes to a target map the user picks, not this one.
function updateMarkersMenuForRole() {
    const readOnly = mapRole(selectedMapID) === 'viewer';
    ['sidebar-markers-importMarkers', 'sidebar-markers-importGoogleMapsLink',
     'sidebar-markers-moveSelected', 'sidebar-markers-deleteSelected'
    ].forEach(id => {
        document.getElementById(id).style.display = readOnly ? 'none' : '';
    });
}

updateMarkersMenuButtons();
setupSidebarMenuDropdown(sidebarMarkersMenuBtn, sidebarMarkersMenu, sidebar, [sidebarMapsMenu]);

document.addEventListener("click", () => sidebarMarkersMenu.classList.remove("show"));
sidebarMarkersMenu.addEventListener("click", e => e.stopPropagation());

// ===============================
// Sidebar listing and subset filters
// ===============================
function createDropdown({ container, items, selectedValue, onSelect }) {
    // Clear container
    container.innerHTML = '';

    // Create filter input + clear button
    let filterLi = container.querySelector('.filter-input');
    if (!filterLi) {
        filterLi = document.createElement('li');
        filterLi.classList.add('filter-input');

        const input = document.createElement('input');
        input.placeholder = 'Type to filter...';
        input.addEventListener('click', e => e.stopPropagation());

        const clearBtn = document.createElement('div');
        clearBtn.className = 'clear-text-btn';
        clearBtn.innerHTML = `
            <svg width="14" height="14" viewBox="0 0 0.32 0.32">
                <path fill-rule="evenodd" d="M.16.32a.16.16 0 1 0 0-.32.16.16 0 0 0 0 .32M.086.086a.02.02 0 0 1 .028 0L.16.132.206.086a.02.02 0 1 1 .028.028L.188.16l.046.046a.02.02 0 0 1-.028.028L.16.188.114.234A.02.02 0 0 1 .086.206L.132.16.086.114a.02.02 0 0 1 0-.028"/>
            </svg>
        `;
        clearBtn.style.display = 'none';

        clearBtn.addEventListener('click', e => {
            e.stopPropagation();
            input.value = '';
            clearBtn.style.display = 'none';
            container.querySelectorAll('li[data-value]').forEach(li => li.style.display = 'block');
        });

        input.addEventListener('input', () => {
            clearBtn.style.display = input.value ? 'block' : 'none';
            const q = input.value.toLowerCase();
            container.querySelectorAll('li[data-value]').forEach(li => {
                li.style.display = li.textContent.toLowerCase().includes(q) ? 'block' : 'none';
            });
        });

        const wrapper = document.createElement('div');
        wrapper.classList.add('filter-wrapper');
        wrapper.appendChild(input);
        wrapper.appendChild(clearBtn);
        filterLi.appendChild(wrapper);
    }

    container.appendChild(filterLi);

    // Add items
    const sortedItems = items.sort((a, b) => a.localeCompare(b));
    sortedItems.forEach(item => {
        const li = document.createElement('li');
        li.textContent = item;
        li.dataset.value = item.toLowerCase();
        li.addEventListener('click', e => {
            e.stopPropagation();
            onSelect(item);
        });
        container.appendChild(li);
    });
}

const listingFilter = document.querySelector('.listingFilter');
const listingFilterSelected = listingFilter.querySelector('.listingFilter-selected');
const listingFilterSelectedText = listingFilter.querySelector('.listingFilter-text');
const listingFilterList = listingFilter.querySelector('.listingFilter-list');

const subsetFilter = document.querySelector('.subsetFilter');
const subsetFilterSelected = subsetFilter.querySelector('.subsetFilter-selected');
const subsetFilterSelectedText = subsetFilterSelected.querySelector('.subsetFilter-text');
const subsetFilterList = subsetFilter.querySelector('.subsetFilter-list');

function sidebarListingFilter() {
    const textFilter = markersSearchInput.value.toLowerCase();

    // Only include listings that have markers matching the text filter
    const availableListings = Array.from(
        new Set(
            markers
                .filter(m => m.data.name.toLowerCase().includes(textFilter))
                .map(m => m.data.listing)
                .filter(Boolean)
        )
    ).sort((a, b) => a.localeCompare(b));

    createDropdown({
        container: listingFilterList,
        items: availableListings,
        selectedValue: listingFilterSelectedText.textContent,
        onSelect: value => {
            // Update UI
            listingFilterSelectedText.textContent = value;
            listingFilterSelected.dataset.value = value === 'All Listings' ? '' : value.toLowerCase();
            listingFilter.classList.remove('open');

            // Reset subset filter
            subsetFilterSelectedText.textContent = 'All Subsets';
            subsetFilterSelected.dataset.value = '';

            sidebarSubsetFilter(value);
            applyMarkersFilters();
        }
    });

    // Insert "All Listings" manually at the top
    const allLi = document.createElement('li');
    allLi.textContent = 'All Listings';
    allLi.dataset.value = '';
    allLi.addEventListener('click', e => {
        e.stopPropagation();
        listingFilterSelectedText.textContent = 'All Listings';
        listingFilterSelected.dataset.value = '';
        listingFilter.classList.remove('open');

        // Reset subset
        subsetFilterSelectedText.textContent = 'All Subsets';
        subsetFilterSelected.dataset.value = '';

        sidebarSubsetFilter('');
        applyMarkersFilters();
    });

    listingFilterList.insertBefore(allLi, listingFilterList.querySelector('.filter-input').nextSibling);
}

function sidebarSubsetFilter(selectedListing = '') {
    const filterListing = selectedListing === 'All Listings' ? '' : selectedListing.toLowerCase();
    const textFilter = markersSearchInput.value.toLowerCase();

    // Only include subsets from markers that match both listing and search
    const filteredSubsets = Array.from(
        new Set(
            markers
                .filter(m =>
                    (!filterListing || (m.data.listing || '').toLowerCase() === filterListing) &&
                    (!textFilter || (m.data.name || '').toLowerCase().includes(textFilter))
                    )
                .map(m => (m.data.subset || '').toUpperCase())
                .filter(Boolean)
        )
    ).sort((a, b) => a.localeCompare(b));

    createDropdown({
        container: subsetFilterList,
        items: filteredSubsets,
        selectedValue: subsetFilterSelectedText.textContent,
        onSelect: value => {
            subsetFilterSelectedText.textContent = value;
            subsetFilterSelected.dataset.value = value === 'All Subsets' ? '' : value.toLowerCase();
            subsetFilter.classList.remove('open');
            applyMarkersFilters();
        }
    });

    // Insert "All Subsets" at the top
    const allLi = document.createElement('li');
    allLi.textContent = 'All Subsets';
    allLi.dataset.value = '';
    allLi.addEventListener('click', e => {
        e.stopPropagation();
        subsetFilterSelectedText.textContent = 'All Subsets';
        subsetFilterSelected.dataset.value = '';
        subsetFilter.classList.remove('open');
        applyMarkersFilters();
    });

    subsetFilterList.insertBefore(allLi, subsetFilterList.querySelector('.filter-input').nextSibling);
}


// Lists that hug their content (height: auto when open, e.g. .mapsGroupFilter-list) can't
// CSS-transition height: 0 <-> auto directly (browsers can't interpolate to/from auto), so
// they're animated the same way as the sidebar accordion: measure scrollHeight in JS and
// transition to/from that pixel value. Lists with a fixed open-state height (e.g.
// .listingFilter-list, .subsetFilter-list at 200px) transition fine in pure CSS and don't
// need this.
function toggleDropdown(container, rebuild, otherDropdowns = []) {
    const isOpen = container.classList.contains('open');

    if (isOpen) {
        // Close current dropdown
        container.classList.remove('open');
    } else {
        // Close other dropdowns
        otherDropdowns.forEach(d => d.classList.remove('open'));

        // Rebuild dropdown if needed
        if (typeof rebuild === 'function') rebuild();

        // Reset filter input and clear button
        const listEl = container.querySelector('ul, .listingFilter-list, .subsetFilter-list, .mapsGroupFilter-list');
        if (listEl) {
            const input = listEl.querySelector('.filter-input input');
            if (input) input.value = '';

            const clearBtn = listEl.querySelector('.clear-text-btn');
            if (clearBtn) clearBtn.style.display = 'none';

            listEl.querySelectorAll('li[data-value]').forEach(li => (li.style.display = 'block'));
            listEl.scrollTop = 0;
        }

        // Open current dropdown
        container.classList.add('open');
    }
}

listingFilterSelected.addEventListener('click', e => {
    e.stopPropagation();
    toggleDropdown(listingFilter, sidebarListingFilter, [subsetFilter]);
});

subsetFilterSelected.addEventListener('click', e => {
    e.stopPropagation();
    const selectedListingText = listingFilterSelectedText.textContent;
    const selectedListing = selectedListingText === 'All Listings' ? '' : selectedListingText.toLowerCase();

    toggleDropdown(subsetFilter, () => sidebarSubsetFilter(selectedListing), [listingFilter]);
});

// Close when clicking outside
document.addEventListener('click', e => {
    if (!listingFilter.contains(e.target) && listingFilter.classList.contains('open')) {
        toggleDropdown(listingFilter);
    }
    if (!subsetFilter.contains(e.target) && subsetFilter.classList.contains('open')) {
        toggleDropdown(subsetFilter);
    }
});


// ===============================
// Apply markers filters
// ===============================
const markersSearchInput = document.getElementById('markersSearchInput');
const markerList = document.getElementById('markerList');

function applyMarkersFilters() {
    // Clear selected markers
    selectedMarkers.clear();
    longPressModeMarkers = false;
    document.querySelectorAll('.marker-item input.poi-checkbox').forEach(cb => cb.remove());
    updateMarkersMenuButtons();

    const selectedListing = listingFilterSelected.dataset.value || '';
    const selectedSubset = subsetFilterSelected.dataset.value || '';
    const textFilter = markersSearchInput.value.toLowerCase();

    if (selectedListing && !listings.some(l => l.toLowerCase() === selectedListing)) {
        listingFilterSelectedText.textContent = 'All Listings';
        listingFilterSelected.dataset.value = '';
    }

    const subsets = Array.from(new Set(markers.map(m => (m.data.subset || '').toUpperCase()))).sort();
    if (selectedSubset && !subsets.some(s => s.toLowerCase() === selectedSubset)) {
        subsetFilterSelectedText.textContent = 'All Subsets';
        subsetFilterSelected.dataset.value = '';
    }

    markerList.innerHTML = '';

    markers.forEach(marker => {
        const { name, listing, subset } = marker.data;
        const matchesListing = !listingFilterSelected.dataset.value || (listing || '').toLowerCase() === listingFilterSelected.dataset.value;

        const matchesSubset = !subsetFilterSelected.dataset.value || (subset || '').toLowerCase() === subsetFilterSelected.dataset.value;

        const matchesText = !textFilter || name.toLowerCase().includes(textFilter);

        if (matchesListing && matchesSubset && matchesText) {
            if (!marker.isOnMap) {
                marker.addTo(map);
                marker.isOnMap = true;
            }
            addMarkerToSidebar(marker.data);
        } else {
            if (marker.isOnMap) {
                map.removeLayer(marker);
                marker.isOnMap = false;
            }
        }
    });
}


// ===============================
// Search text input listener
// ===============================
markersSearchInput.addEventListener('input', () => {
    applyMarkersFilters();
    sidebarListingFilter();   // update listing dropdown based on current search
    sidebarSubsetFilter(listingFilterSelectedText.textContent); // optional, keep subset consistent
});


// ===============================
// Clear all marker filters
// ===============================
function clearMarkerFilters() {
    // Reset filter UI
    listingFilterSelected.dataset.value = '';
    listingFilterSelectedText.textContent = 'All Listings';

    subsetFilterSelected.dataset.value = '';
    subsetFilterSelectedText.textContent = 'All Subsets';

    markersSearchInput.value = '';
    clearMarkersSearchBtn.style.display = 'none';

    listingFilter.classList.remove('open');
    subsetFilter.classList.remove('open');

    // Reset marker list and map
    markerList.innerHTML = '';

    markers.forEach(marker => {
        if (!marker.isOnMap) {
            marker.addTo(map);
            marker.isOnMap = true;
        }
        addMarkerToSidebar(marker.data);
    });
}


// ===============================
// Listeners for clear markers search input button
// ===============================
const clearMarkersSearchBtn = document.querySelector('.clear-markers-search-text-btn');

markersSearchInput.addEventListener('input', () => {
    clearMarkersSearchBtn.style.display = markersSearchInput.value.trim() ? 'flex' : 'none';
});

clearMarkersSearchBtn.addEventListener('click', () => {
    markersSearchInput.value = '';
    clearMarkersSearchBtn.style.display = 'none';
    markersSearchInput.focus();
    applyMarkersFilters();
});


// =====================
// Import markers from a file
// =====================
document.getElementById('sidebar-markers-importMarkers').addEventListener('click', () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.kml';
    input.style.display = 'none';

    input.addEventListener('change', async () => {
        if (input.files.length === 0) return;

        const file = input.files[0];
        const formData = new FormData();
        formData.append('kml_file', file);
        formData.append('map_id', selectedMapID);

        try {
            const response = await apiFetch('/import_kml', { method: 'POST', body: formData });
            const data = await response.json().catch(() => null);
            if (!response.ok) {
                let message = data && typeof data.error === 'string'
                    ? data.error.trim().slice(0, 160)
                    : '';
                if (response.status === 401) {
                    message = 'Your session expired. Please sign in again.';
                } else if (response.status === 413) {
                    message = 'The KML file is too large.';
                } else if (response.status === 429) {
                    message = 'Too many KML imports. Please try again shortly.';
                } else if (!message) {
                    message = 'Failed to upload KML file.';
                }
                throw new Error(message);
            }
            if (!data || typeof data.job_id !== 'string' || !data.job_id.trim()) {
                throw new Error('KML upload returned an invalid response.');
            }
            const jobId = data.job_id.trim();

            const progress = showProgressNotification('Starting import...');
            const importMapID = selectedMapID;
            let statusFailures = 0;

            // Poll import progress every second, stopping on a terminal status, an
            // authentication failure, a lost job, or a bounded run of malformed or
            // failed responses (S-09: no unbounded client polling).
            const interval = setInterval(async () => {
                const stopWith = message => {
                    clearInterval(interval);
                    progress.remove();
                    showNotification(message);
                };
                let status = null;
                try {
                    const res = await apiFetch(`/import_kml_status/${jobId}`);
                    if (res.status === 401) return stopWith('Your session expired. Please sign in again.');
                    if (res.status === 404) return stopWith('KML import failed');
                    if (res.ok) status = await res.json().catch(() => null);
                } catch (err) {
                    // A dead session already shows the login screen; just stop quietly.
                    if (err.status === 401) {
                        clearInterval(interval);
                        progress.remove();
                        return;
                    }
                }
                if (!status || !['queued', 'running', 'done', 'error'].includes(status.status)) {
                    statusFailures += 1;
                    if (statusFailures >= PUBLIC_CONFIG.kmlStatusRetryLimit) stopWith('KML import status unavailable');
                    return;
                }
                statusFailures = 0;

                progress.update(status.progress);
                if (status.status === 'queued') {
                    progress.updateText('Waiting for an import slot...');
                } else if (status.status === 'running') {
                    progress.updateText(`Imported ${status.imported} / ${status.total} markers`);
                }

                // Stop polling on failure
                if (status.status === 'error') {
                    await refreshNotificationHistorySummary();
                    return stopWith('KML import failed');
                }

                // Stop polling when done
                if (status.status === 'done') {
                    clearInterval(interval);
                    await refreshNotificationHistorySummary();

                    // Surface the compact skip/error counts (R-04) in the final text
                    let completionText = `Imported ${status.imported} / ${status.total} markers`;
                    const skippedCount = status.skipped || 0;
                    const photosFailedCount = status.photos_failed || 0;
                    const budgetSkippedCount = status.photos_budget_skipped || 0;
                    if (skippedCount > 0 || photosFailedCount > 0 || budgetSkippedCount > 0) {
                        const problems = [];
                        if (skippedCount > 0) problems.push(`${skippedCount} skipped`);
                        if (photosFailedCount > 0) problems.push(`${photosFailedCount} photos failed`);
                        if (budgetSkippedCount > 0) problems.push(`${budgetSkippedCount} photos skipped: download limit reached`);
                        completionText += ` (${problems.join(', ')})`;
                    }

                    // --- Load the finished markers through normal map retrieval (S-09);
                    // the job carries no marker snapshot. Skip when the user has moved
                    // to another map: its view must not receive this map's markers. ---
                    if (selectedMapID === importMapID) {
                        await loadSpotsFromDB(importMapID);
                    }

                    // --- Update the sidebar count through the maps cache, so the
                    // next full re-render (e.g. creating a map) keeps the number ---
                    const importTargetMap = maps.find(m => String(m.id) === String(importMapID));
                    if (importTargetMap) {
                        updateMarkerCount(importMapID, importTargetMap.markers + status.imported);
                    }

                    // The terminal message is the UI-ready boundary: do not expose it
                    // until the map data and cached count reflect the completed job.
                    progress.updateText(completionText);
                    setTimeout(
                        () => progress.remove(),
                        PUBLIC_CONFIG.kmlProgressRemovalDelayMs
                    );
                }
            }, PUBLIC_CONFIG.kmlProgressPollMs);

        } catch (err) {
            console.error(err);
            showNotification(err.message || 'Failed to upload KML file.');
        }
    });

    document.body.appendChild(input);
    input.click();
    document.body.removeChild(input);
});


// ===============================================================
// Import Google Maps Link
// ===============================================================
document.getElementById("sidebar-markers-importGoogleMapsLink").addEventListener("click", async () => {
    try {
        // Read from clipboard
        const clipboardText = await navigator.clipboard.readText();
        if (!clipboardText) {
            showNotification("Clipboard is empty or contains no text.");
            return;
        }

        // Send to backend
        const response = await apiFetch("/parse-maps-link", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: clipboardText })
        });

        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            const message = typeof data.error === 'string'
                ? data.error.trim().slice(0, 160)
                : '';
            throw new Error(message || "Failed to parse link");
        }

        console.log("Parsed Google Maps link:", data);

        if (data.latitude && data.longitude) {
            await addTempMarker(data.latitude, data.longitude);

            // Zoom to the new marker
            zoomMap({ lat: data.latitude, lng: data.longitude });

        } else {
            showNotification("Coordinates not found in link.");
        }

    } catch (err) {
        console.error(err);
        showNotification("Error importing Google Maps link: " + err.message);
    }
});


// ===============================================================
// Sidebar marker section clear filters listener
// ===============================================================
document.getElementById('sidebar-markers-resetFilters').addEventListener('click', clearMarkerFilters);


// ===============================================================
// Select all visible markers in the list
// ===============================================================
document.getElementById('sidebar-markers-selectAll').addEventListener('click', () => {
    const visibleMarkers = Array.from(document.querySelectorAll('.marker-item'))
    .filter(item => item.offsetParent !== null); // only visible markers

    visibleMarkers.forEach(item => {
        let cb = item.querySelector('input.poi-checkbox');
        if (!cb) {
            // create checkbox if it doesn't exist
            cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.className = 'poi-checkbox';
            cb.dataset.id = item.dataset.id;
            item.querySelector('.marker-card').prepend(cb);

            cb.addEventListener('change', (ev) => {
                const id = ev.target.dataset.id;
                if (ev.target.checked) {
                    selectedMarkers.add(id);
                } else {
                    selectedMarkers.delete(id);
                    if (selectedMarkers.size === 0) {
                        document.querySelectorAll('.marker-item input.poi-checkbox').forEach(cb => cb.remove());
                        longPressModeMarkers = false; // deactivate mode if nothing selected
                    }
                }
                updateMarkersMenuButtons(); // update menu buttons on change
            });
        }

        cb.checked = true;
        selectedMarkers.add(item.dataset.id);
    });

    // Activate long press mode when selecting all
    if (visibleMarkers.length > 0) longPressModeMarkers = true;

    updateMarkersMenuButtons(); // update menu buttons after select all
});


// ===============================================================
// Clear all marker selections
// ===============================================================
function clearSelectedMarkers() {
    const checkboxesMarkers = document.querySelectorAll('.marker-item input.poi-checkbox');

    // Uncheck all checkboxesMarkers
    checkboxesMarkers.forEach(cb => cb.checked = false);

    // Clear selected markers set
    selectedMarkers.clear();

    // Remove all checkboxesMarkers from the DOM
    checkboxesMarkers.forEach(cb => cb.remove());

    // Deactivate long press mode
    longPressModeMarkers = false;

    // Update menu buttons
    updateMarkersMenuButtons();
}

// Attach to the clear button
document.getElementById('sidebar-markers-clear').addEventListener('click', clearSelectedMarkers);


// ===============================================================
// Count selected markers
// ===============================================================
function countSelectedMarkers() {
    const count = selectedMarkers.size;
    showNotification(`${count} marker${count !== 1 ? 's' : ''} selected`);
}
document.getElementById('sidebar-markers-countSelected').addEventListener('click', countSelectedMarkers);



// ===============================================================
// Expand selected markers
// ===============================================================
document.getElementById('sidebar-markers-expandSelected').addEventListener('click', () => {
    selectedMarkers.forEach(id => {
        const item = document.querySelector(`.marker-item[data-id="${id}"]`);
        if (!item) return;

        const details = item.querySelector('.poi-details');
        const collapsedName = item.querySelector('.poi-name-collapsed');
        const toggle = item.querySelector('.poi-toggle');

        // Show details, hide collapsed title
        details.style.display = '';
        collapsedName.style.display = 'none';

        // Enforce toggle arrow
        if (toggle) {
            toggle.dataset.state = 'open';
            toggle.textContent = '▴';
        }

        const foundMarker = markers.find(m => m.data.id === id);
        if (foundMarker && !foundMarker.isPopupOpen()) foundMarker.openPopup();
    });
});

// ===============================================================
// Collapse selected markers
// ===============================================================
document.getElementById('sidebar-markers-collapseSelected').addEventListener('click', () => {
    selectedMarkers.forEach(id => {
        const item = document.querySelector(`.marker-item[data-id="${id}"]`);
        if (!item) return;

        const details = item.querySelector('.poi-details');
        const collapsedName = item.querySelector('.poi-name-collapsed');
        const toggle = item.querySelector('.poi-toggle');

        // Hide details, show collapsed title
        details.style.display = 'none';
        collapsedName.style.display = '';

        // Enforce toggle arrow
        if (toggle) {
            toggle.dataset.state = 'closed';
            toggle.textContent = '▾';
        }

        const foundMarker = markers.find(m => m.data.id === id);
        if (foundMarker && foundMarker.isPopupOpen()) foundMarker.closePopup();
    });
});


// ===============================================================
// Show selected markers
// ===============================================================
document.getElementById('sidebar-markers-showSelected').addEventListener('click', () => {
    const selected = Array.from(document.querySelectorAll('.poi-checkbox:checked'));
    if (!selected.length) return showNotification("Select at least one marker to show.");

    let shownCount = 0;

    selected.forEach(cb => {
        const id = cb.dataset.id;
        const marker = markers.find(m => m.data.id == id);
        const sidebarItem = cb.closest('.marker-item');

        if (marker && !marker.isOnMap) {
            marker.addTo(map);
            marker.isOnMap = true;
            shownCount++;

            if (sidebarItem) sidebarItem.classList.remove('disabled-marker');
        }
    });

    if (shownCount > 0) {
        showNotification(`${shownCount} marker(s) shown`);
    }
});


// ===============================================================
// Hide selected markers
// ===============================================================
document.getElementById('sidebar-markers-hideSelected').addEventListener('click', () => {
    const selected = Array.from(document.querySelectorAll('.poi-checkbox:checked'));
    if (!selected.length) return showNotification("Select at least one marker to hide.");

    let hiddenCount = 0;

    selected.forEach(cb => {
        const id = cb.dataset.id;
        const marker = markers.find(m => m.data.id == id);
        const sidebarItem = cb.closest('.marker-item');

        if (marker && marker.isOnMap) {
            map.removeLayer(marker);
            marker.isOnMap = false;
            hiddenCount++;

            if (sidebarItem) sidebarItem.classList.add('disabled-marker');
        }
    });

    if (hiddenCount > 0) {
        showNotification(`${hiddenCount} marker(s) hidden`);
    }
});


// ===============================================================
// Copy/Move selected markers to a target map
// ===============================================================
function openCopyMoveMarkersOverlay({ overlayId, formId, customSelectId, action }) {
    const overlay = document.getElementById(overlayId);
    const form = document.getElementById(formId);
    const customSelect = document.getElementById(customSelectId);
    const selectedDiv = customSelect.querySelector('.selected');
    const optionsUl = customSelect.querySelector('.options');
    const submitBtn = form.querySelector('button[type="submit"]');

    return async function(selectedMarkersArray, sourceMapID) {
        if (!selectedMarkersArray.length) return alert(`Select at least one marker to ${action}.`);

        // Reset dropdown
        selectedDiv.textContent = `Select the destination map...`;
        selectedDiv.dataset.id = '';
        selectedDiv.classList.add('placeholder');
        optionsUl.innerHTML = '';
        submitBtn.disabled = true;
        customSelect.classList.remove('open');

        // Fetch all maps
        let maps = [];
        try {
            const res = await apiFetch('/maps');
            if (!res.ok) throw new Error('Failed to fetch maps');
            maps = await res.json();
        } catch (err) {
            console.error(err);
            return alert('Could not load maps');
        }

        // Populate dropdown (exclude source map for move function)
        const filteredMaps = action === 'move'
            ? maps.filter(m => String(m.id) !== String(sourceMapID))
            : maps;

        filteredMaps.forEach(m => {
            const li = document.createElement('li');
            li.dataset.id = m.id;
            li.textContent = `${m.name} (${m.markers} markers)`;
            optionsUl.appendChild(li);

            li.addEventListener('click', () => {
                selectedDiv.textContent = li.textContent;
                selectedDiv.dataset.id = li.dataset.id;
                selectedDiv.classList.remove('placeholder');
                customSelect.classList.remove('open');
                submitBtn.disabled = false;
            });
        });

        // Toggle dropdown
        selectedDiv.onclick = () => customSelect.classList.toggle('open');

        // Show overlay
        overlay.style.display = 'flex';
        requestAnimationFrame(() => overlay.classList.add('active'));

        // Cleanup
        function cleanup() {
            overlay.classList.remove('active');
            setTimeout(() => overlay.style.display = 'none', 250);

            selectedDiv.textContent = '';
            selectedDiv.dataset.id = '';
            selectedDiv.classList.add('placeholder');
            optionsUl.innerHTML = '';
            submitBtn.disabled = true;
            customSelect.classList.remove('open');
        }

        const outsideClickListener = (e) => {
            if (e.target === overlay) {
                cleanup();
                window.removeEventListener('mousedown', outsideClickListener);
            }
        };
        window.addEventListener('mousedown', outsideClickListener);

        // Form submission
        form.onsubmit = async (e) => {
            e.preventDefault();
            const targetMapID = selectedDiv.dataset.id;
            if (!targetMapID) return alert('Please select a target map');

            cleanup();
            window.removeEventListener('mousedown', outsideClickListener);

            let processedCount = 0;

            for (const cb of selectedMarkersArray) {
                const id = cb.dataset.id;
                const markerIndex = markers.findIndex(m => m.data.id == id);

                try {
                    const endpoint =
                        action === 'copy'
                            ? `/spots/${id}/copy/${targetMapID}`
                            : `/spots/${id}/move/${targetMapID}`;

                    const res = await apiFetch(endpoint, { method: 'POST' });
                    if (!res.ok) throw new Error(`Failed to ${action} marker`);

                    const data = await res.json();
                    const newSpot = data.spot; // backend returns the copied spot

                    if (action === 'move' && markerIndex !== -1) {
                        const marker = markers[markerIndex];
                        if (marker.isOnMap) map.removeLayer(marker);
                        markers.splice(markerIndex, 1);

                        const sidebarItem = cb.closest('.marker-item');
                        if (sidebarItem) sidebarItem.remove();

                        selectedMarkers.delete(id);
                    }

                    // Only load marker to map when copying
                    if (action === 'copy' && String(targetMapID) === String(selectedMapID)) {
                        loadMarkerToMap(newSpot);
                    }

                    processedCount++;

                } catch (err) {
                    console.error(`Failed to ${action} marker ${id}:`, err);
                    showNotification(`Error ${action} marker ${id}`);
                }
            }

            // Update marker counts
            if (action === 'move') {
                updateMarkerCount(sourceMapID, markers.length);
            }
            const targetMap = maps.find(m => String(m.id) === String(targetMapID));
            if (targetMap) {
                targetMap.markers += processedCount;
                updateMarkerCount(targetMapID, targetMap.markers);
            }

            if (processedCount > 0) {
                const actionText = action === 'move' ? 'moved' : 'copied';
                showNotification(`${processedCount} marker(s) ${actionText}`);
                clearSelectedMarkers();
            }
        };
    };
}

const openCopyOverlay = openCopyMoveMarkersOverlay({
    overlayId: 'copyMarkersOverlay',
    formId: 'copyMarkersForm',
    customSelectId: 'copyMarkersMapCustom',
    action: 'copy'
});

copyMarkersBtn.addEventListener('click', async () => {
    const selected = Array.from(document.querySelectorAll('.poi-checkbox:checked'));
    const sourceMapID = selectedMapID; // your current map
    openCopyOverlay(selected, sourceMapID);
});

const openMoveOverlay = openCopyMoveMarkersOverlay({
    overlayId: 'moveMarkersOverlay',
    formId: 'moveMarkersForm',
    customSelectId: 'moveMarkersMapCustom',
    action: 'move'
});

moveMarkersBtn.addEventListener('click', async () => {
    const selected = Array.from(document.querySelectorAll('.poi-checkbox:checked'));
    const sourceMapID = selectedMapID; // your current map
    openMoveOverlay(selected, sourceMapID);
});


// ===============================================================
// Delete selected markers
// ===============================================================
document.getElementById('sidebar-markers-deleteSelected').addEventListener('click', () => {
    const selected = Array.from(document.querySelectorAll('.poi-checkbox:checked'));
    if (!selected.length) return showNotification("Select at least one marker to delete.");

    // Generate a batch ID (could also use timestamp)
    const batchId = selected.map(cb => cb.dataset.id).join(',');

    showConfirmation(`Delete ${selected.length} marker(s)?`, async () => {
        let deletedCount = 0;

        for (const cb of selected) {
            const id = cb.dataset.id;
            const markerIndex = markers.findIndex(m => m.data.id == id);

            try {
                const res = await apiFetch(`/spots/${id}`, { method: 'DELETE' });
                if (!res.ok) throw new Error('Failed to delete marker');

                if (markerIndex !== -1) {
                    const marker = markers[markerIndex];
                    if (marker.isOnMap) map.removeLayer(marker);
                    markers.splice(markerIndex, 1);
                }

                const sidebarItem = cb.closest('.marker-item');
                if (sidebarItem) sidebarItem.remove();

                selectedMarkers.delete(id);

                deletedCount++;
            } catch (err) {
                console.error(`Failed to delete marker ${id}:`, err);
                showNotification(`Error deleting marker ${id}`);
            }
        }

        if (selectedMarkers.size === 0) {
            document.querySelectorAll('.marker-item input.poi-checkbox').forEach(cb => cb.remove());
            longPressModeMarkers = false;
        }

        updateMarkersMenuButtons();
        populateListingArray();
        applyMarkersFilters();
        updateMarkerCount(selectedMapID, markers.length);

        if (deletedCount > 0) {
            showNotification(`${deletedCount} marker(s) deleted`);
            void refreshNotificationHistorySummary();
        }

        sidebarMarkersMenu.classList.remove("show");
    }, () => console.log('Delete cancelled'), 'deleteSelectedMarkers', batchId);
});


// ===============================
// Temporary markers popup helpers
// ===============================
function buildTempPopupHTML(markerName) {
    const popupDiv = document.createElement('div');
    popupDiv.className = 'popup-content';

    // Name
    const nameDiv = document.createElement('div');
    nameDiv.className = 'popup-name';
    nameDiv.textContent = markerName;

    // Actions container
    const actionsDiv = document.createElement('div');
    actionsDiv.className = 'popup-actions';

    // Copy Coordinates button
    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-btn icon-btn inline-copy';
    copyBtn.dataset.tip = 'Copy Coordinates';
    copyBtn.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
            <rect x="9" y="9" width="13" height="13" rx="2"/>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
        </svg>
    `;

    // Save button (hidden while a viewer-role map is selected; the popupopen handlers
    // re-check on every open since these markers outlive map switches)
    const saveBtn = document.createElement('button');
    saveBtn.className = 'save-btn icon-btn';
    saveBtn.dataset.tip = 'Save Marker';
    if (mapRole(selectedMapID) === 'viewer') saveBtn.style.display = 'none';
    saveBtn.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
            <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
            <polyline points="17 21 17 13 7 13 7 21"/>
            <polyline points="7 3 7 8 15 8"/>
        </svg>
    `;

    // Delete button
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'delete-btn icon-btn danger';
    deleteBtn.dataset.tip = 'Delete Marker';
    deleteBtn.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 6 5 6 21 6"/>
            <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
            <path d="M10 11v6"/>
            <path d="M14 11v6"/>
            <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
        </svg>
    `;

    // Assemble actions
    actionsDiv.append(copyBtn, saveBtn, deleteBtn);

    // Assemble popup
    popupDiv.append(nameDiv, actionsDiv);

    return popupDiv;
}

function bindTransientMarkerPopupActions(popupEl, marker, saveAction, deleteAction) {
    popupEl.addEventListener('click', e => {
        const pos = marker.getLatLng();
        if (e.target.closest('.copy-btn')) copyCoordinates(pos.lat, pos.lng);
        if (e.target.closest('.save-btn')) {
            saveAction(marker, pos.lat, pos.lng, marker.name);
        }
        if (e.target.closest('.delete-btn')) deleteAction(marker);
    });
}

function nominatimPlaceLabel(place, includeLocationWithoutAddress = false) {
    const placeName = place.name || 'Unnamed';
    const address = place.address || {};
    const placeLocation =
        address.hamlet ||
        address.city ||
        address.town ||
        address.village ||
        address.locality ||
        address.municipality ||
        address.city_district ||
        address.county ||
        'Unknown';
    if (!includeLocationWithoutAddress && !Object.keys(address).length) {
        return placeName;
    }
    return `${placeName}, ${placeLocation}`;
}

async function reverseGeocodePlaceLabel(lat, lng) {
    const url = `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lng}&addressdetails=1`;
    const res = await fetch(url, { headers: { 'Accept': 'application/json' } });
    const place = await res.json();
    return nominatimPlaceLabel(place, true);
}

// ===============================================================
// Add temporary marker through context menu
// ===============================================================
async function addTempMarker(lat, lng) {
    try {
        const name = await reverseGeocodePlaceLabel(lat, lng);

        // Shift the default blue marker toward purple.
        const marker = L.marker([lat, lng], { draggable: true }).addTo(map);
        const iconEl = marker.getElement();
        if (iconEl) iconEl.style.filter = 'hue-rotate(90deg)';

        // Attach custom properties
        marker.name = name;      // store the full name

        // Update stored coordinates and name when dragged
        marker.on('dragend', async function () {
            const pos = marker.getLatLng();
            lat = pos.lat;
            lng = pos.lng;

            try {
                const newName = await reverseGeocodePlaceLabel(lat, lng);

                // Update marker name property
                marker.name = newName;

                // Update popup content
                const popupHTML = buildTempPopupHTML(newName);
                bindTransientMarkerPopupActions(
                    popupHTML,
                    marker,
                    saveTempMarker,
                    deleteTempMarker
                );
                marker.setPopupContent(popupHTML);
                marker.openPopup();
            } catch (err) {
                console.error('Reverse geocode failed', err);
                showNotification('Failed to update place info');
            }
        });

        // Bind popup
        const popupHTML = buildTempPopupHTML(name);
        bindTransientMarkerPopupActions(
            popupHTML,
            marker,
            saveTempMarker,
            deleteTempMarker
        );
        marker.bindPopup(popupHTML, { autoPan: false });

        marker.on('popupopen', function() {
            const popupEl = marker.getPopup().getContent();
            if (!popupEl) return;

            // Save writes to the selected map — hidden while a viewer-role map is selected.
            const sb = popupEl.querySelector('.save-btn');
            if (sb) sb.style.display = mapRole(selectedMapID) === 'viewer' ? 'none' : '';
        });


        // Enable right-click context menu
        marker.on('contextmenu', function(e) {
            e.originalEvent.preventDefault(); // stop default browser menu
            showTempMarkerContextMenu(marker, e.originalEvent); // pass raw mouse event
        });

        // Prevent double-click zoom on this marker
        marker.on('dblclick', function(e) {
            e.originalEvent.stopPropagation();
        });

        // Open popup immediately
        marker.openPopup();

        // Track the marker
        temporaryMarkers.push(marker);

    } catch (err) {
        console.error('Reverse geocode failed', err);
        showNotification('Failed to get place info');
    }
}

// Handler to save a temporary marker
async function saveTempMarker(marker, lat, lng, name) {
    try {
        await addMarker({ lat, lng }, name);
        // only remove marker if user actually saved
        marker.remove();
        temporaryMarkers = temporaryMarkers.filter(m => m !== marker);
    } catch (err) {
        if (err === 'User cancelled') {
            console.log('Marker save cancelled by user');
            // do not remove marker
            return;
        }
        console.error('Failed to save marker', err);
    }
}


// Handler to delete a temporary marker
function deleteTempMarker(marker) {
    showConfirmation(`Delete temporary marker?`, () => {
        marker.remove();
        temporaryMarkers = temporaryMarkers.filter(m => m !== marker);
        showNotification(`Temporary marker deleted`);
    }, () => console.log('Temporary marker deletion cancelled'), 'deleteTempMarker', marker._leaflet_id);
}


// ===============================================================
// Clear all temporary markers added with the context menu
// ===============================================================
function removeAllTemporaryMarkers() {
    temporaryMarkers.forEach(marker => marker.remove());
    temporaryMarkers = [];
    showNotification('All temporary markers removed');
}


// ===============================================================
// Search Markers
// ===============================================================
async function addSearchMarker(input) {
    // Clear existing markers
    searchMarkers.forEach(marker => marker.remove());
    searchMarkers = [];

    // Removes any leading and trailing whitespace from the string input
    const query = input.trim();

    if (!query) return;

    // Detect direct coordinate input: "lat,lng" or "lat lng"
    const coordMatch = query.match(/^\s*(-?\d+(\.\d+)?)\s*[, ]\s*(-?\d+(\.\d+)?)\s*$/);

    let results;

    if (coordMatch) {
        const lat = parseFloat(coordMatch[1]);
        const lng = parseFloat(coordMatch[3]);

        if (lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180) {
            results = [{
                lat: lat,
                lon: lng,
                name: `${lat.toFixed(6)}, ${lng.toFixed(6)}`,
                address: {}
            }];
        }
    }

    const restrictViewport = document.getElementById('viewportSelect').value === 'true';
    const countryCode = document.getElementById('countrySelect').value;

    let url = `https://nominatim.openstreetmap.org/search?addressdetails=1&format=json&limit=40&q=${encodeURIComponent(query)}`;
    if (restrictViewport) {
        const bounds = map.getBounds();
        const sw = bounds.getSouthWest();
        const ne = bounds.getNorthEast();
        url += `&viewbox=${sw.lng},${ne.lat},${ne.lng},${sw.lat}&bounded=1`;
    }
    if (countryCode) url += `&countrycodes=${countryCode}`;

    try {
        if (!results) {
            const res = await fetch(url, {
                headers: { 'Accept': 'application/json' }
            });
            results = await res.json();
        }
        if (!results.length) return showNotification("No results found");

        results.forEach((place, index) => {
            let lat = parseFloat(place.lat);
            let lng = parseFloat(place.lon);
            const name = nominatimPlaceLabel(place);

            const marker = L.marker([lat, lng], { draggable: true }).addTo(map);
            const searchIcon = L.icon({
                iconUrl: 'assets/images/marker-icon-aqua.png',
                iconSize: [25, 41],
                iconAnchor: [12, 41],
                popupAnchor: [1, -34],
                shadowUrl: 'assets/images/marker-shadow.png',
                shadowSize: [41, 41]
            });
            marker.setIcon(searchIcon);

            // Attach custom properties
            marker.name = name;
            marker._searchId = `search-${index}`;

            // Update coordinates when dragged
            marker.on('dragend', () => {
                const pos = marker.getLatLng();
                lat = pos.lat;
                lng = pos.lng;
            });

            // Bind popup
            const popupHTML = buildTempPopupHTML(name);
            bindTransientMarkerPopupActions(
                popupHTML,
                marker,
                saveSearchMarker,
                deleteSearchMarker
            );
            marker.bindPopup(popupHTML, { autoPan: false });

            marker.on('popupopen', () => {
                const popupEl = marker.getPopup().getContent();
                if (!popupEl) return;

                // Save writes to the selected map — hidden while a viewer-role map is selected.
                const sb = popupEl.querySelector('.save-btn');
                if (sb) sb.style.display = mapRole(selectedMapID) === 'viewer' ? 'none' : '';
            });

            // Enable right-click context menu
            marker.on('contextmenu', function(e) {
                e.originalEvent.preventDefault(); // stop default browser menu
                showSearchMarkerContextMenu(marker, e.originalEvent); // pass raw mouse event
            });

            // Prevent double-click zoom on this marker
            marker.on('dblclick', function(e) {
                e.originalEvent.stopPropagation();
            });

            searchMarkers.push(marker);
        });

        if (searchMarkers.length) {
            const group = L.featureGroup(searchMarkers);
            let bounds = group.getBounds();

            // Apply a buffer around bounds
            bounds = bounds.pad(0.15);  // pad(0.15) expands bounds by 15% on all sides

            // Determine the zoom to fit all markers
            const targetZoom = map.getBoundsZoom(bounds, false);

            // Get center of bounds
            const center = bounds.getCenter();

            // Project to pixel coordinates
            let targetPoint = map.project(center, targetZoom);

            // Shift downward by 100 pixels
            targetPoint.y -= 50; // negative = move map down

            // Adjust for sidebar
            let sidebarWidth = 0;
            if (sidebar && !sidebar.classList.contains('collapsed')) {
                sidebarWidth = sidebar.offsetWidth;
            }
            targetPoint.x -= sidebarWidth / 2;

            // Unproject back to lat/lng
            const adjustedCenter = map.unproject(targetPoint, targetZoom);

            // Set view once with zoom and adjusted center
            map.setView(adjustedCenter, targetZoom, { animate: false });
        }
    } catch (err) {
        console.error("POI search failed", err);
        showNotification('POI search failed');
    }
}

// Handler to save a search marker
async function saveSearchMarker(marker, lat, lng, name) {
    try {
        await addMarker({ lat, lng }, name);
        // only remove marker if user actually saved
        marker.remove();
        searchMarkers = searchMarkers.filter(m => m !== marker);
    } catch (err) {
        if (err === 'User cancelled') {
            console.log('Marker save cancelled by user');
            // do not remove marker
            return;
        }
        console.error('Failed to save marker', err);
    }
}

function deleteSearchMarker(marker) {
    showConfirmation(`Delete search marker?`, () => {
        marker.remove();
        searchMarkers = searchMarkers.filter(m => m !== marker);
        showNotification(`Search marker deleted`);
    }, () => console.log('Search marker deletion cancelled'), 'deleteSearchMarker', marker._leaflet_id);
}


// ===============================================================
// Toggle search options menu
// ===============================================================
optionsToggle.addEventListener('click', (e) => {
    topSearchBar.classList.toggle('show-options');
    e.stopPropagation();
});

optionsMenu.addEventListener('click', (e) => e.stopPropagation());

document.addEventListener('click', (e) => {
    if (!topSearchBar.contains(e.target)) {
        topSearchBar.classList.remove('show-options');
    }
});


// ===============================================================
// Enable search button only when there's a text input
// ===============================================================
// Initial check on page load
const hasText = poiInput.value.trim() !== '';
searchPOIButton.classList.toggle('disabled', !hasText);
searchPOIButton.disabled = !hasText; // optional, for accessibility

// Listen for input changes
poiInput.addEventListener('input', () => {
    const hasText = poiInput.value.trim() !== '';
    searchPOIButton.classList.toggle('disabled', !hasText);
    searchPOIButton.disabled = !hasText;
});


// ===============================================================
// Search field trigger
// ===============================================================
function triggerPOISearch() {
    const query = poiInput.value.trim();
    if (!query) return showNotification("Enter a search term");
    addSearchMarker(query);
}

searchPOIButton.addEventListener('click', triggerPOISearch);
poiInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') triggerPOISearch(); });

// ===============================================================
// Clear POI input and markers
// ===============================================================
poiInput.addEventListener('input', () => {
    clearPOIButton.style.display = poiInput.value.trim() ? 'flex' : 'none';
});

clearPOIButton.addEventListener('click', () => {
    poiInput.value = '';
    clearPOIButton.style.display = 'none';
    poiInput.focus();
    searchMarkers.forEach(marker => marker.remove());
    searchMarkers = [];
    searchPOIButton.classList.add('disabled');
});

// Prevent default browser context menu on sidebar elements
topSearchBar.addEventListener('contextmenu', (e) => {
    // Allow default context menu if the right-click is on an input or textarea
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
    e.preventDefault(); // Otherwise, prevent default context menu
});
