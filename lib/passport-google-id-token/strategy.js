/**
 * Module dependencies.
 */
var util = require('util')
  , Strategy = require('passport-strategy')
  , GoogleAuth = require('google-auth-library')
  , request = require('request')
  , jwt = require('jsonwebtoken');

/**
 * `Strategy` constructor.
 *
 * The Google authentication strategy authenticates requests by verifying the
 * signature and fields of the token.
 *
 * Applications must supply a `verify` callback which accepts the `idToken`
 * coming from the user to be authenticated, and then calls the `done` callback
 * supplying a `parsedToken` (with all its information in visible form) and the
 * `googleId`.
 *
 * Options:
 * - `clientID` your Google application's client id (or several as Array)
 *
 * Examples:
 *
 * passport.use(new PassportGoogleJWTStrategy({
 *     clientID: '123-456-789'
 *   },
 *   function(parsedToken, googleId, done) {
 *     User.findOrCreate(..., function (err, user) {
 *       done(err, user);
 *     });
 *   }
 * ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function PassportGoogleJWTStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  if (!verify) throw new Error('PassportGoogleJWTStrategy requires a verify function');

  this._passReqToCallback = options.passReqToCallback;

  let auth = new GoogleAuth();
  this.client = new auth.OAuth2(this._clientID, '', '');

  this._clientID = options.clientID;
  this._jwtOptions = options.jwtOptions || {};

  this._callbackURL = options.callbackURL;

  Strategy.call(this);
  this.name = 'google-id-token';
  this._verify = verify;
}

/**
 * Inherit from `Strategy`.
 */
util.inherits(PassportGoogleJWTStrategy, Strategy);

/**
 * Authenticate request by verifying the token
 *
 * @param {Object} req
 * @api protected
 */
PassportGoogleJWTStrategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  var idToken = (req.body && (req.body.id_token || req.body.access_token))
    || (req.query && (req.query.id_token || req.query.access_token))
    || (req.headers && (req.headers.id_token || req.headers.access_token));

  if (!idToken) {
    return self.fail("no ID token provided" );
  }

  this.client.verifyIdToken( idToken, self._clientID, function(err, tokenResponse) {
    if (err) 
      return self.fail(err);

    function verified(err, user, authInfo) {
      if (err) return self.error(err);
      if (!user) return self.fail(authInfo);
      // [FIXME] Disabled, No need to tell passport that you are done with authentication
      // self.success(user, authInfo);
      req.res.send(authInfo.accessToken);
    }
    
    var userProfile = tokenResponse.getPayload();
    userProfile['id'] = userProfile.sub;

    if (self._passReqToCallback) {
      self._verify(req, idToken, null, userProfile, verified);
    } else {
      self._verify(idToken, null, userProfile, verified);
    }
  });
}

/**
 * Expose `PassportGoogleJWTStrategy`.
 */
module.exports = PassportGoogleJWTStrategy;
