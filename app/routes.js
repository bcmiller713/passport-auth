module.exports = function(app, passport) {

  //============= HOME PAGE =============
  app.get("/", function(req, res) {
    res.render("index.ejs"); // load the index.ejs file
  });

  //============= PROFILE SECTION =============
  // we will want this protected so you have to be logged in to visit
  // we will use route middleware to verify this (the isLoggedIn function)
  app.get("/profile", isLoggedIn, function(req, res) {
    res.render("profile.ejs", {
      user: req.user // get the user from session and pass to template
    });
  });

  //============= LOGOUT =============
  app.get("/logout", function(req, res) {
    req.logout();
    res.redirect("/");
  });

  //============================================================================
  // AUTHENTICATION (FIRST LOGIN) ==============================================
  //============================================================================

  //============= LOCAL LOGIN =============
  app.get("/login", function(req, res) {
    // render the page and pass in any flash data if it exists
    res.render("login.ejs", {message: req.flash("loginMessage")});
  });

  // process the login form
  app.post("/login", passport.authenticate("local-login", {
    // redirect to the secure profile section
    successRedirect: "/profile",
    // redirect back to the singup page if there is an error
    failureRedirect: "/login",
    // allow flash messages
    failureFlash: true
  }));

  //============= LOCAL SIGNUP =============
  app.get("/signup", function(req, res) {
    //render the page and pass in any flash data if it exists
    res.render("signup.ejs", {message: req.flash("singupMessage")});
  });

  // process the singup form
  app.post("/signup", passport.authenticate("local-signup", {
    // redirect to the secure profile section
    successRedirect: "/profile",
    // redirect back to the signup page if there is an error
    failureRedirect: "/signup",
    // allow flash messages
    failureFlash: true
  }));

  //============= FACEBOOK =============
  // route for facebook authentication and login
  app.get("/auth/facebook", passport.authenticate("facebook", { scope : "email" }));

  // handle the callback after facebook has authenticated the user
  app.get("/auth/facebook/callback",
    passport.authenticate("facebook", {
      successRedirect : "/profile",
      failureRedirect : "/"
    }));

  //============= TWITTER =============
  // route for twitter authentication and login
  app.get("/auth/twitter", passport.authenticate("twitter", { scope: "email" }));

  // handle the callback after twitter has authenticated the user
  app.get("/auth/twitter/callback",
    passport.authenticate("twitter", {
      successRedirect: "/profile",
      failureRedirect: "/"
    }));

  //============= GOOGLE =============
  // route for google authentication and login
  app.get("/auth/google", passport.authenticate("google", { scope : ["profile", "email"] }));

  // the callback after google has authenticated the user
  app.get("/auth/google/callback",
    passport.authenticate("google", {
      successRedirect: "/profile",
      failureRedirect: "/"
    }));

    //==========================================================================
    // AUTHORIZATION (ALREADY LOGGEN IN/CONNECTING SOCIAL ACCOUNTS) ============
    //==========================================================================

    //============= LOCAL =============
    app.get("/connect/local", function(req, res) {
      res.render("connect-local.ejs", { message: req.flash("loginMessage") });
    });
    app.post("/connect/local", passport.authenticate("local-signup", {
      successRedirect: "/profile", // redirect to the secure profile section
      failureRedirect: "/connect/local", // redirect back to the signup page if there is an error
      failureFlash: true // allow flash messages
    }));

    //============= FACEBOOK =============
    // send to facebook to do the authentication
    app.get('/connect/facebook', passport.authorize('facebook', { scope : 'email' }));

    // handle the callback after facebook has authorized the user
    app.get('/connect/facebook/callback', passport.authorize('facebook', {
      successRedirect : '/profile',
      failureRedirect : '/'
    }));

    //============= TWITTER =============
    // send to twitter to do the authentication
    app.get('/connect/twitter', passport.authorize('twitter', { scope : 'email' }));

    // handle the callback after twitter has authorized the user
    app.get('/connect/twitter/callback', passport.authorize('twitter', {
      successRedirect : '/profile',
      failureRedirect : '/'
    }));

    //============= GOOGLE =============
    // send to google to do the authentication
    app.get('/connect/google', passport.authorize('google', { scope : ['profile', 'email'] }));

    // the callback after google has authorized the user
    app.get('/connect/google/callback', passport.authorize('google', {
      successRedirect : '/profile',
      failureRedirect : '/'
    }));

    //==========================================================================
    // UNLINK ACCOUNTS =========================================================
    //==========================================================================

    //============= LOCAL =============
    app.get("/unlink/local", function(req, res) {
      var user = req.user;
      user.local.email = undefined;
      user.local.password = undefined;
      user.save(function(err) {
        res.redirect("/profile");
      });
    });

    //============= FACEBOOK =============
    app.get("/unlink/facebook", function(req, res) {
      var user = req.user;
      user.facebook.token = undefined;
      user.save(function(err) {
        res.redirect("/profile");
      });
    });

    //============= TWITTER =============
    app.get("/unlink/twitter", function(req, res) {
      var user = req.user;
      user.twitter.token = undefined;
      user.save(function(err) {
        res.redirect("/profile");
      });
    });

    //============= GOOGLE =============
    app.get("/unlink/google", function(req, res) {
      var user = req.user;
      user.google.token = undefined;
      user.save(function(err) {
        res.redirect("/profile");
      });
    });

};

// route middleware to make sure a user is logged in
function isLoggedIn(req, res, next) {
  // if user is authenticated in the session, continue
  if (req.isAuthenticated()) {
    return next();
  }
  // if they aren't, redirect them to the home page
  else {
    res.redirect("/");
  }
}
