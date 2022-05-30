/**
 * Module dependencies.
 */
const util = require('util');
const passport = require('passport-strategy');
const { authenticator } = require('otplib');

/**
 * `Strategy` constructor.
 *
 * The TOTP authentication strategy authenticates requests based on the
 * TOTP value submitted through an HTML-based form.
 *
 * Applications must supply a `setup` callback which accepts `user`, and then
 * calls the `done` callback supplying a `key` used to verify the TOTP value.
 *
 *
 * Options:
 *   - `codeField`:     field name where the TOTP value is found, defaults to _code_
 *   - `authenticator`: otplib.authenticator options
 *
 * Example: uses
 *
 *     passport.use(new OtpStrategy({
 *         step: 30,
 *         crypto: require('crypto')
 *       },
 *       function (user, done) {
 *         TotpKey.findOne({
 *           userId: user.id
 *         }, function (err, key) {
 *           if (err) {
 *             return done(err);
 *           }
 *           return done(null, key.key, key.period);
 *         });
 *       }));
 *
 * References:
 *  - [TOTP: Time-Based One-Time Password Algorithm](http://tools.ietf.org/html/rfc6238)
 *  - [KeyUriFormat](https://code.google.com/p/google-authenticator/wiki/KeyUriFormat)
 *
 * @param {Object} options
 * @param {Function} setup
 * @api public
 */
function Strategy(options, setup) {
  if (typeof options === 'function') {
    setup = options;
    options = {};
  }

  // Passthru options to authenticator, if nothing is specified
  // then at least provide a default crypto library
  if (options.authenticator) {
    authenticator.options = options.authenticator;
  } else {
    authenticator.options = {
      crypto: require('crypto')
    };
  }

  this._codeField = options.codeField || 'code';

  passport.Strategy.call(this);
  this._setup = setup;
  this.name = 'otp';
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on TOTP values.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function (request) {
  const value =
    lookup(request.body, this._codeField) ||
    lookup(request.query, this._codeField);

  this._setup(request.user, (error, key) => {
    if (error) {
      return this.error(error);
    }

    const rv = authenticator.check(value, key);

    if (!rv) {
      return this.fail();
    }

    return this.success(request.user);
  });

  function lookup(object, field) {
    if (!object) {
      return null;
    }

    const chain = field.split(']').join('').split('[');
    for (let i = 0, { length } = chain; i < length; i++) {
      const prop = object[chain[i]];
      if (typeof prop === 'undefined') {
        return null;
      }

      if (typeof prop !== 'object') {
        return prop;
      }

      object = prop;
    }

    return null;
  }
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
