// D-09 contract check: the browser password-policy mirror must agree with the
// authoritative request_validation.py policy on every shared vector.
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync('/workspace/markervault/public/frontend.js', 'utf8');
const vectors = JSON.parse(
    fs.readFileSync('/workspace/markervault/tests/password_contract_vectors.json', 'utf8')
);
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

const match = source.match(/function passwordPolicyError\(pw\) \{[\s\S]*?\n\}/);
check(match !== null, 'the browser password-policy mirror is present');

let mirror = null;
if (match) {
    mirror = vm.runInNewContext(`(${match[0].replace('function passwordPolicyError', 'function')})`,
        {TextEncoder});
}
const mismatched = vectors.filter(vector =>
    (mirror(vector.password) === null) !== vector.valid
);
check(
    mirror !== null && mismatched.length === 0,
    `all ${vectors.length} shared vectors match the backend policy`
    + (mismatched.length ? ` (mismatched: ${JSON.stringify(mismatched)})` : '')
);
check(
    mirror !== null && typeof mirror('Abcd123!') !== 'string',
    'a valid password produces no mirror error'
);

console.log(`\n==== ${passed} passed, ${failed} failed ====`);
process.exit(failed ? 1 : 0);
