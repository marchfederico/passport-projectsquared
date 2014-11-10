/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The ProjectSqaured authentication strategy authenticates requests by delegating to
 * ProjectSqaured using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your ProjectSqaured application's client id
 *   - `clientSecret`  your ProjectSqaured application's client secret
 *   - `callbackURL`   URL to which ProjectSqaured will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new ProjectSqauredStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/projectsquared/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://idbroker.webex.com/idb/oauth2/v1/authorize';
  options.tokenURL = options.tokenURL || 'https://idbroker.webex.com/idb/oauth2/v1/access_token';
  
  OAuth2Strategy.call(this, options, verify);
  this.name = 'projectsquared';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from ProjectSqaured.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `projectsquared`
 *   - `id`
 *   - `username`
 *   - `displayName`
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  this._oauth2.get('https://conv-a.wbx2.com/conversation/api/v1/users', accessToken, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }
    
    try {
      var json = JSON.parse(body);
      
      var profile = { provider: 'projectsquared' };
       
      profile.id = json.id;
      profile.displayName = json.name;
      profile.emails = [{ value: json.email }];
     
       
      profile._raw = body;
      profile._json = json;
      
      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
