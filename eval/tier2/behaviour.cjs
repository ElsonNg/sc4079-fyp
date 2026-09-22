const vm = require('node:vm');
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const harnesses = {
  'qs-prototype-assignment': `
    const parseArrayValue = value => value;
    const f = SOURCE;
    const parseObject = (chain, value, options) => f(chain, value, options, true);
    const observations = [];
    for (const parseArrays of [false, true]) {
      for (const plainObjects of [false, true]) {
        for (const chain of [['__proto__'], ['[__proto__]'], ['safe'], ['[0]'], ['[]'], []]) {
          const value = { boundaryMarker: 'marker' };
          const argument = chain.slice();
          const result = f(argument, value, {parseArrays, plainObjects, arrayLimit: 20}, true);
          observations.push({keys: Object.keys(result), ownMarker: Object.hasOwn(result,'boundaryMarker'),
            inheritedMarker: !Object.hasOwn(result,'boundaryMarker') && result.boundaryMarker === 'marker',
            json: JSON.stringify(result), remainingChain: argument, nullPrototype: Object.getPrototypeOf(result) === null});
        }
      }
    }
    JSON.stringify(observations);
  `,
  'lodash-prototype-read': `
    const objectProto = Object.prototype;
    const f = SOURCE;
    const encode = x => x === undefined ? 'undefined' : x === objectProto ? 'Object.prototype' : x;
    JSON.stringify([encode(f({prototype: objectProto}, 'prototype')), encode(f({}, '__proto__')),
      encode(f({safe: 7}, 'safe')), encode(f({prototype: 3}, 'prototype'))]);
  `,
  'minimist-prototype-predicate': `
    const f = SOURCE;
    JSON.stringify([f({}, '__proto__'), f({}, 'constructor'), f({constructor: 1}, 'constructor'), f({}, 'safe')]);
  `,
  'semver-length-and-exception-guards': `
    const MAX_LENGTH = 256, LOOSE = 0, FULL = 1, re = [/./, /./];
    const SemVer = function(version, loose) { if (version === 'throw') throw new Error('invalid'); this.version = version; this.loose = loose; };
    const f = SOURCE;
    const values = [];
    for (const version of ['1.2.3', '', 'x'.repeat(257), 'throw']) {
      for (const loose of [false, true]) {
        try { values.push({value: f(version, loose)}); } catch(e) { values.push({error: e.message}); }
      }
    }
    JSON.stringify(values);
  `,
  'moment-nested-comment-regex': `
    const f = SOURCE;
    JSON.stringify(['Mon, 25 Dec 1995 13:30:00 GMT', '((a))', '(comment)', '  a\\tb\\nc  ', '((unclosed'].map(x => f(x)));
  `,
};
if (!harnesses[input.harness]) throw new Error('Unknown harness');
const observations = input.sources.map(source => {
  const code = harnesses[input.harness].replace('SOURCE', () => '(' + source + ')');
  return JSON.parse(vm.runInNewContext(code, Object.create(null), {
    timeout: 1000, contextCodeGeneration: {strings: false, wasm: false},
  }));
});
process.stdout.write(JSON.stringify({node: process.version, vulnerable: observations[0], patched: observations[1], candidate: observations[2]}));
