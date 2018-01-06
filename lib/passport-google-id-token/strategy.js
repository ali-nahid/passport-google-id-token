/**
 * Module dependencies.
 */
var util = require('util')
  , Strategy = require('passport-strategy')
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
 * passport.use(new GoogleTokenStrategy({
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
function GoogleTokenStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  if (!verify) throw new Error('GoogleTokenStrategy requires a verify function');

  this._passReqToCallback = options.passReqToCallback;

  this._clientID = options.clientID;
  this._jwtOptions = options.jwtOptions || {};

  Strategy.call(this);
  this.name = 'google-id-token';
  this._verify = verify;
}

/**
 * Inherit from `Strategy`.
 */
util.inherits(GoogleTokenStrategy, Strategy);

/**
 * Authenticate request by verifying the token
 *
 * @param {Object} req
 * @api protected
 */
GoogleTokenStrategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  var idToken = (req.body && (req.body.id_token || req.body.access_token))
    || (req.query && (req.query.id_token || req.query.access_token))
    || (req.headers && (req.headers.id_token || req.headers.access_token));

  if (!idToken) {
    return self.fail({ message: "no ID token provided" });
  }

  self._verifyGoogleToken(idToken, self._clientID, function(err, raw, parsed) {
    if (err) 
      return self.fail({ message: err.message });

    function verified(err, user, info) {
      if (err) return self.error(err);
      if (!user) return self.fail(info);
      self.success(user, info);
    }

    if (self._passReqToCallback) {
      self._verify(req, raw, null, parsed, verified);
    } else {
      self._verify(raw, null, parsed, verified);
    }
  });
}

/**
 * POST the token to Google's token validation endpoint
 *
 * @param {String} idToken
 * @param {String} clientID
 * @param {Function} done
 * @api protected
 */
GoogleTokenStrategy.prototype._verifyGoogleToken = function(idToken, clientID, done) {
  request({
    url: 'https://www.googleapis.com/oauth2/v3/tokeninfo',
    method: 'POST',
    body: JSON.stringify({ id_token: idToken })
  }, function(err, res, body){
    if(err){
      return done(err);
    } else if(res && (res.statusCode < 200) || (res.statusCode > 299)){
      return done(new Error('cannot verify token'))
    } else {
      try {
        var json = JSON.parse(body);
        if(json.aud !== clientID)
          return done(new Error('invalid token'))
        return done(err, idToken, json);
      } catch(ex){
        return done(new Error('JSON parsing error'))
      }
    }
  });
}

/**
 * Expose `GoogleTokenStrategy`.
 */
module.exports = GoogleTokenStrategy;
