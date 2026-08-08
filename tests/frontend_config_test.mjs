import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync('/workspace/markervault/public/frontend.js', 'utf8');
let passed = 0;
let failed = 0;

function check(condition, label) {
    if (condition) {
        passed += 1;
        console.log(`PASS  ${label}`);
    } else {
        failed += 1;
        console.log(`FAIL  ${label}`);
    }
}

const match = source.match(
    /const PUBLIC_CONFIG = (Object\.freeze\(\{[\s\S]*?\}\));/
);
check(match !== null, 'public frontend configuration is declared near the top');

let config = null;
if (match) {
    config = vm.runInNewContext(match[1]);
}
check(config !== null && Object.isFrozen(config), 'public configuration is immutable');
check(
    config?.defaultAvatarSrc === 'assets/images/default-user-thumb.png',
    'default avatar value is unchanged'
);
check(config?.busyIndicatorDelayMs === 500, 'busy-indicator delay is unchanged');
check(config?.kmlProgressPollMs === 1000, 'KML polling interval is unchanged');
check(config?.kmlProgressRemovalDelayMs === 2000, 'KML completion delay is unchanged');
check(config?.kmlStatusRetryLimit === 5, 'KML status retry budget is bounded (S-09)');
check(
    config?.routingStepsVisible === false,
    'turn-by-turn routing steps stay hidden by default',
);

const keys = Object.keys(config || {});
check(
    !keys.some(key => /secret|password|token|credential|authorization/i.test(key)),
    'public configuration contains no credential-shaped keys'
);
check(
    source.includes('const DEFAULT_AVATAR_SRC = PUBLIC_CONFIG.defaultAvatarSrc;'),
    'avatar fallback consumes the public configuration'
);
check(
    source.includes('PUBLIC_CONFIG.busyIndicatorDelayMs'),
    'busy indicators consume the public configuration'
);
check(
    source.includes('}, PUBLIC_CONFIG.kmlProgressPollMs);'),
    'KML polling consumes the public configuration'
);
check(
    source.includes('PUBLIC_CONFIG.kmlProgressRemovalDelayMs'),
    'KML completion consumes the public configuration'
);
check(
    source.includes('PUBLIC_CONFIG.kmlStatusRetryLimit'),
    'KML retry termination consumes the public configuration'
);
check(
    source.includes("if (PUBLIC_CONFIG.routingStepsVisible) {")
    && source.includes("routingContainer.classList.add('routing-steps-visible');"),
    'routing steps visibility consumes the public configuration'
);
check(
    source.includes("fetch('/account-capabilities'")
    && !keys.includes('emailAccountFlowsEnabled'),
    'email-account UI mode comes from the backend capability endpoint, not static config'
);

const historySection = source.slice(
    source.indexOf('function updateNotificationHistoryBadge'),
    source.indexOf('// ---- Profile overlay')
);
const historyIntervals = (historySection.match(/setInterval\(/g) || []).length;
const historyTimeouts = (historySection.match(/setTimeout\(/g) || []).length;
check(
    historyIntervals === 0
    && historyTimeouts === 1
    && historySection.includes("if (!overlay.classList.contains('active')) overlay.style.display = 'none';"),
    'notification history adds no polling or automatic refresh timer'
);

// C-07 contract: every same-origin API request carries the bearer token through
// apiFetch. Raw fetch is legal only inside apiFetch itself, on the documented
// pre-auth/cookie routes, and on external (https://) services. The copy/move
// overlay shipped a raw same-origin fetch that always 401ed against the real
// backend while passing the mock rigs — this check makes that class impossible.
const PREAUTH_ROUTES = new Set([
    '/account-capabilities',
    '/auth/refresh',
    '/login',
    '/register',
    '/auth/logout'
]);
const apiFetchStart = source.indexOf('async function apiFetch');
const apiFetchEnd = source.indexOf('\nasync function', apiFetchStart + 1);
const publicFetchStart = source.indexOf('async function publicAccountPost');
const publicFetchEnd = source.indexOf('\nasync function', publicFetchStart + 1);
const fetchPattern = /(?<![A-Za-z])fetch\(\s*(`[^`]*`|'[^']*'|[A-Za-z_$][\w$]*)/g;
const rawFetchViolations = [];
for (const match of source.matchAll(fetchPattern)) {
    const argument = match[1];
    const inWrapper = (
        match.index > apiFetchStart && match.index < apiFetchEnd
    ) || (
        match.index > publicFetchStart && match.index < publicFetchEnd
    );
    const quoted = argument.startsWith("'") || argument.startsWith('`');
    const literal = quoted ? argument.slice(1, -1) : null;
    const external = quoted && literal.startsWith('https://');
    const preauth = quoted && PREAUTH_ROUTES.has(literal);
    const nominatim = source
        .slice(Math.max(0, match.index - 500), match.index)
        .includes('nominatim.openstreetmap.org');
    if (!inWrapper && !external && !preauth && !nominatim) {
        const line = source.slice(0, match.index).split('\n').length;
        rawFetchViolations.push(`line ${line}: fetch(${argument}`);
    }
}
check(
    rawFetchViolations.length === 0,
    'every same-origin API request goes through apiFetch'
    + (rawFetchViolations.length ? ` (violations: ${rawFetchViolations.join('; ')})` : '')
);

console.log(`\n==== ${passed} passed, ${failed} failed ====`);
process.exit(failed ? 1 : 0);
