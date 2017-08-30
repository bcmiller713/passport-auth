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
  // app.post("/login", passport stuff here);

  //============= SIGNUP =============
  app.get("/signup", function(req, res) {
    //render the page and pass in any flash data if it exists
    res.render("signup.ejs", {message: req.flash("singupMessage")});
  });

  // process the singup form
  // app.post("/singup", passport stuff here);

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

};

// route middleware to make sure a user is logged in
function isLoggedIn(req, res, next) {
  // if user is authenticated in the session, continue
  if (req.isAuthenticated())
    return next();
  // if they aren't, redirect them to the home page
  res.redirect("/");
}
