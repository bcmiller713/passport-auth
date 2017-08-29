// ================= DEPENDENCIES =================
const express = require("express");
const app = express();
const port = process.env.PORT || 8080;
const mongoose = require("mongoose");
const passport = require("passport");
const flash = require("connect-flash");
const morgan = require("morgan");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const session = require("express-session");
const configDB = require("./config/database.js");

// ================= CONFIGURATION =================
mongoose.connect(configDB.url);

// require("./config/passport")(passport); // pass passport for configuration

// set up express application
app.use(morgan("dev")); // log every request to the console
app.use(cookieParser()); // read cookies
app.use(bodyParser()); // get information from html forms

app.set("view engine", "ejs"); // set up ejs for templating

// required for passport
app.use(session({ secret: 'secret'})); // session secret
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions
app.use(flash()); // use connect-flash for flash messages stored in session

// ================= ROUTES =================
require("./app/routes.js")(app, passport); // load our routes and pass in our app and fully configured passport

// ================= LAUNCH APP =================
app.listen(port);
console.log("App listening on port " + port);
