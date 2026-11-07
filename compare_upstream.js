// SPDX-License-Identifier: GPL-2.0-only
// Compare with the pinned, reviewed pfwtool source without installing its CLI dependencies.
const crypto = require('node:crypto');
const fs = require('node:fs');
const vm = require('node:vm');
const [, , sourceFile, inputFile, decodedFile] = process.argv;
if (!sourceFile || !inputFile || !decodedFile) {
  throw new Error('Usage: node compare_upstream.js <pinned-index.js> <fwdc230b.bin> <decoded.bin>');
}
const digest = data => crypto.createHash('sha256').update(data).digest('hex');
const source = fs.readFileSync(sourceFile);
if (digest(source) !== '40c2ea6b9f13ed484f102f4d12b472fd0fda9a64c7dccaea63ecb5da32711e5c') {
  throw new Error('Source hash differs from pentax-firmware-tool commit 3e2597b5d4cfa9ce242b6d3aeef32c28e64b6f73');
}
const context = {
  Buffer,
  module: {},
  require(name) {
    if (name === 'fs' || name === 'path') return {};
    if (name === 'mkdirp') return () => { throw new Error('Resource extraction is not part of this comparison'); };
    throw new Error(`Unexpected import: ${name}`);
  },
};
// vm is not a security boundary; only the exact reviewed source hash is admitted.
vm.runInNewContext(source.toString('utf8'), context, { filename: sourceFile });
const input = fs.readFileSync(inputFile);
if (digest(input) !== 'a33485f351019960192891ef69ddc5d4904ef9e298671d9d9955679e4c901a9a') {
  throw new Error('Comparison is restricted to the observed K-3 II v1.12 input');
}
context.module.exports.setInput(input);
const expected = context.module.exports.decode();
if (!expected.equals(fs.readFileSync(decodedFile))) throw new Error('Decoded bytes differ');
console.log(JSON.stringify({ matched: true, bytes: expected.length, sha256: digest(expected),
  upstream_commit: '3e2597b5d4cfa9ce242b6d3aeef32c28e64b6f73', source_sha256: digest(source) }, null, 2));
