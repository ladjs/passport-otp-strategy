const test = require('ava');

const otp = require('..');

test('should export version', (t) => {
  t.true(typeof otp.version === 'string');
});

test('should export Strategy', (t) => {
  t.true(typeof otp.Strategy === 'function');
});
