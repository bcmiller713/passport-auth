var LocalStrategy = require("passport-local").Strategy;
var FacebookStrategy = require("passport-facebook").Strategy;
var TwitterStrategy = require("passport-twitter").Strategy;
var GoogleStrategy = require("passport-google").Strategy;

// load user model
var User = require("../app/models/user");
// load auth variables
var configAuth = require("./auth");

module.exports = function(passport) {

  //============ PASSPORT SESSION SETUP ============
  // For persistent login sessions, passport must be able to serialize and deserialize users out of sessions

  // used to serialize the user for the session
  passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

  // used to deserialize the user
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

  //============ LOCAL SIGNUP ============
  // we are using named strategies since we have one for login and one for signup
  // by default, if there was no name, it would just be called local

  passport.use("local-signup", new LocalStrategy({
    // by default, local strategy uses username and password but we will override with email
    usernameField: "email",
    passwordField: "password",
    // allows us to pass back the entire request to the callback
    passReqToCallback: true
  },
  function(req, email, password, done) {
    // asynchronous, User.findOne won't fire unless data is sent back
    process.nextTick(function() {
      // find a user whose email is the same as the form's email
      // we are checking to see if the user trying to login already exists
      User.findOne({"local.email": email}, function(err, user) {
        // if there are errors, return errors
        if (err) {
          return done(err);
        }
        // check to see if theres already a user with that email
        if (user) {
          return done(null, false, req.flash("signupMessage", "That email is already taken."));
        } else {
          // if there is no user with that email, create the user
          var newUser = new User();
          // set the user's local credentials
          newUser.local.email = email;
          newUser.local.password = newUser.generateHash(password);

          // save the user
          newUser.save(function(err) {
            if (err) {
              throw err;
            }
            return done(null, newUser);
          });
        }
      });
    });
  }));

  //============ LOCAL LOGIN ============
  // we are using named strategies since we have one for login and one for signup
  // by default, if there was no name, it would just be called local

  passport.use("local-login", new LocalStrategy({
      // by default, local strategy uses username and password, we will override with email
      usernameField : "email",
      passwordField : "password",
      // allows us to pass back the entire request to the callback
      passReqToCallback : true
    },
    // callback with email and password from our form
    function(req, email, password, done) {
      // find a user whose email is the same as the forms email
      // we are checking to see if the user trying to login already exists
      User.findOne({ "local.email" :  email }, function(err, user) {
        // if there are any errors, return the error before anything else
        if (err) {
          return done(err);
        }
        // if no user is found, return the message
        if (!user) {
          // req.flash is the way to set flashdata using connect-flash
          return done(null, false, req.flash("loginMessage", "No user found."));
        }
        // if the user is found but the password is wrong
        if (!user.validPassword(password)) {
          // create the loginMessage and save it to session as flashdata
          return done(null, false, req.flash("loginMessage", "Oops! Wrong password."));
        }
        // all is well, return successful user
        return done(null, user);
      });
    }
  ));

  //============ FACEBOOK ============
  passport.use(new FacebookStrategy({
    clientID: configAuth.facebookAuth.clientID,
    clientSecret: configAuth.facebookAuth.clientSecret,
    callbackURL: configAuth.facebookAuth.callbackURL
  },

  // facebook will send back the token and profile
  function(token, refreshToken, profile, done) {
    // asynchronous
    process.nextTick(function() {
      // find the user in the database based on their facebook id
      User.findOne({ 'facebook.id' : profile.id }, function(err, user) {
        if (err)
          return done(err);
        if (user) {
          return done(null, user);
        } else {
          // if there is no user found with that facebook id, create them
          var newUser = new User();
          // set all of the facebook information in the user model
          newUser.facebook.id = profile.id; // set the user's facebook id
          newUser.facebook.token = token; // we will save the token that facebook provides to the user
          newUser.facebook.name = profile.name.givenName + ' ' + profile.name.familyName; // look at the passport user profile to see how the names are returned
          newUser.facebook.email = profile.emails[0].value; // facebook can return multiple emails so we'll take the first
          // save our user to the database
          newUser.save(function(err) {
            if (err)
              throw err;
            return done(null, newUser);
          });
        }
      });
    });
  }));

  //============ TWITTER ============
  passport.use(new TwitterStrategy({
    consumerKey: configAuth.twitterAuth.consumerKey,
    consumerSecret: configAuth.twitterAuth.consumerSecret,
    callbackURL: configAuth.twitterAuth.callbackURL
  },
  function(token, tokenSecret, profile, done) {
    // make code asynchronous; user.findone won't fire until we have all our data back from Twitter
    process.nextTick(function() {
      User.findOne({ "twitter.id" : profile.id }, function(err, user) {
        if (err)
          return done(err);

        if (user) {
          return done(null, user);
        } else {
          // if there is no user, create one
          var newUser = new User();
          // set all of the user data that we need
          newUser.twitter.id = profile.id;
          newUser.twitter.token = token;
          newUser.twitter.username = profile.username;
          newUser.twitter.displayName = profile.displayName;

          // save user to db
          newUser.save(function(err) {
            if (err)
              throw err;
            return done(null, newUser);
          });
        }
      });
    });
  }));

  //============ GOOGLE ============
  passport.user(new GoogleStrategy({
    clientID: configAuth.googleAuth.clientID,
    clientSecret: configAuth.googleAuth.clientSecret,
    callbackURL: configAuth.googleAuth.callbackURL
  },
  function(token, refreshToken, profile, done) {
    // make code asynchronous; user.findone won't fire until we have all our data back from google
    process.nextTick(function() {
      User.findOne({ "google.id" : profile.id }, function(err, user) {
        if (err)
          return done(err);
        if (user) {
          return done(null, user);
        } else {
          // if the user isn't in our db, create new user
          var newUser = new User();
          // set all of the relevant data
          newUser.google.id = profile.id;
          newUser.google.token = token;
          newUser.google.name = profile.displayName;
          newUser.google.email = profile.emails[0].value; // pull the first emails

          // save the user to the db
          newUser.save(function(err) {
            if (err)
              throw err;
            return done(null, newUser);
          });
        }
      });
    });
  }));

};
