// 1 Npm install passport-google-oauth20

// TODO 2 Import passport and keys
var GoogleStrategy = require('passport-google-oauth20');
//after requiring passport above, we can now use passport
const passport = require('passport');
var express = require('express');
var db = require('../db');


passport.use(new GoogleStrategy({
//this knows to acces.env for the value to this client id
    clientID: process.env['GOOGLE_CLIENT_ID'], 
    clientSecret: process.env['GOOGLE_CLIENT_SECRET'],
    callbackURL: 'http://localhost:3000/oauth2/redirect/google',
    scope: ['profile'],
    state: true
},

    function(accessToken, refreshToken, profile, cb){
        db.get('SELECT * FROM federated_credentials WHERE provider = ? AND subject = ?'),[
            'https://accounts.google.com',
            profile.id
        ],

        function(err, cred) {
            if (err) {return cb(err); }

            if (!row) { 
                // The account at Google has not logged in to this app before.  Create a
                // new user record and associate it with the Google account.
                db.run('INSERT INTO users (name) VALUES (?)', [
                    profile.displayName
                ], function (err) {
                    if (err) {return cb(err);}

                    var id = this.lastID;
                    db.run('INSERT INTO federated_credentials (user_id, provider, subject) VALUES (?,?,?)', [
                        id,
                        'https://accounts.google.com',
                        profile.id
                    ], function (err) {
                        if (err) { return cb(err); }
                        var user = {
                            id: id,
                            name: profile.displayName
                        };
                        return cb(null, user);
                    });

                });
            } else {
                // The account at Google has previously logged in to the app.  Get the
                // user record associated with the Google account and log the user in.
                db.get('SELECT * FROM users WHERE id = ?', [ cred.user_id ], function(err, user) {
                  if (err) { return cb(err); } // if theres error, return error
                  if (!user) { return cb(null, false); } // if theres no user reeturn null
                  return cb(null, user); // otherwise if everything works return user
                });
              }
            };
          }
        ));

// Configure the Facebook strategy for use by Passport.
//
// OAuth 2.0-based strategies require a `verify` function which receives the
// credential (`accessToken`) for accessing the Facebook API on the user's
// behalf, along with the user's profile.  The function must invoke `cb`
// with a user object, which will be set at `req.user` in route handlers after
// authentication.

// TODO 3 Configure the Google strategy for use by Passport.

  
// Configure Passport authenticated session persistence.
//
// In order to restore authentication state across HTTP requests, Passport needs
// to serialize users into and deserialize users out of the session.  In a
// production-quality application, this would typically be as simple as
// supplying the user ID when serializing, and querying the user record by ID
// from the database when deserializing.  However, due to the fact that this
// example does not have a database, the complete Facebook profile is serialized
// and deserialized.

// TODO 4 Configure Passport authenticated session persistence.

passport.serializeUser(function(user, cb){
    process.nextTick(function(){
        cb(null, {id: user.id, username: user.username, name: user.name});
    });
});

passport.deserializeUser(function(user, cb) {
    process.nextTick(function(){
        console.log('deserialized');
        return cb(null, user);
    });
});



/* GET /login
 *
 * This route prompts the user to log in.
 *
 * The 'login' view renders an HTML page, which contain a button prompting the
 * user to sign in with Google.  When the user clicks this button, a request
 * will be sent to the `GET /login/federated/accounts.google.com` route.
 */


// TODO 5 Configure the GET /login route.

var router = express.Router();

//get login route
router.get('/login', function(req, res, next) {
    res.render('login');
});



/* GET /login/federated/accounts.google.com
 *
 * This route redirects the user to Google, where they will authenticate.
 *
 * Signing in with Google is implemented using OAuth 2.0.  This route initiates
 * an OAuth 2.0 flow by redirecting the user to Google's identity server at
 * 'https://accounts.google.com'.  Once there, Google will authenticate the user
 * and obtain their consent to release identity information to this app.
 *
 * Once Google has completed their interaction with the user, the user will be
 * redirected back to the app at `GET /oauth2/redirect/accounts.google.com`.
 */


// TODO 6 Configure the GET /login/federated/accounts.google.com route.

//google authentication using passport
router.get('/login/federated/google', passport.authenticate('google'));


/*
    This route completes the authentication sequence when Google redirects the
    user back to the application.  When a new user signs in, a user account is
    automatically created and their Google account is linked.  When an existing
    user returns, they are signed in to their linked account.
*/
// TODO 7 Configure the GET /oauth2/redirect/accounts.google.com route.

//Redirect user upon login attempt to Authorised redirect URI
 //if success return to oauth/ Home
 //if it fails, return to login page
router.get('/oauth2/redirect/google', passport.authenticate('google', {
    successReturnToOrRedirect: '/',
    failureRedirect: '/login' 
}));

/* POST /logout
 *
 * This route logs the user out.
 */
// TODO 8 Configure the POST /logout route.

router.post('/logout', function(req, res, next) {
    req.logout();
    res.redirect('/');
});


module.exports = router;
