module.exports = function(app, passport) {

  //============= HOME PAGE =============
  app.get("/", function(req, res) {
    res.render("index.ejs"); // load the index.ejs file
  });

  //============= LOGIN =============
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

  //============= SIGNUP =============
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
    res.logout();
    res.redirect("/");
  });

  //============= FACEBOOK =============
  // route for facebook authentication and login
  app.get("/auth/facebook", passport.authenticate("facebook", { scope : "email "}));

  // handle the callback after facebook has authenticated the user
  app.get("./auth/facebook/callback",
    passport.authenticate("facebook", {
      successRedirect : "/profile",
      failureRedirect : "/"
    }));

  //============= TWITTER =============
  // route for twitter authentication and login
  app.get("/auth/twitter", passport.authenticate("twitter"));

  // handle the callback after twitter has authenticated the user
  app.get("./auth/twitter/callback",
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
