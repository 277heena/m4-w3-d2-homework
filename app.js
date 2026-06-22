const express               = require("express");
const bodyParser            = require("body-parser");
const mongoose              = require("mongoose");
const session               = require("express-session");
const passport              = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const LocalStrategy         = require("passport-local");
const mongoSanitize         = require("express-mongo-sanitize");
const rateLimit             = require("express-rate-limit");
const xss                   = require("xss-clean");
const helmet                = require("helmet");
const User                  = require("./models/user");

//Connecting database
mongoose.connect("mongodb://localhost/auth_demo");

const app = express();

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    secure: false,
    maxAge: 1 * 60 * 1000
  }
}));

passport.serializeUser(User.serializeUser());       //session encoding
passport.deserializeUser(User.deserializeUser());   //session decoding
passport.use(new LocalStrategy(User.authenticate()));
app.set("view engine","ejs");
app.use(bodyParser.urlencoded(
      { extended:true }
))
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static("public"));

// ========================
// OWASP
// ========================

// Data sanitization against NoSQL Injection Attacks
app.use(mongoSanitize());

// Preventing Brute Force & DOS Attacks - Rate Limiting
const limit = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000,
  message: "Too many requests"
});

// Apply limiter to login and register routes
app.use("/login", limit);
app.use("/register", limit);

// Preventing DOS Attacks - Body Parser Limit
app.use(express.json({ limit: "10kb" }));

// Data sanitization against XSS attacks
app.use(xss());

// Helmet to secure connection and data
app.use(helmet());


//=======================
//      R O U T E S
//=======================
app.get("/", (req,res) =>{
    res.render("home");
})
app.get("/userprofile" ,(req,res) =>{
    res.render("userprofile");
})
//Auth Routes
app.get("/login",(req,res)=>{
    res.render("login");
});
app.post("/login",passport.authenticate("local",{
    successRedirect:"/userprofile",
    failureRedirect:"/login"
}),function (req, res){
});
app.get("/register",(req,res)=>{
    res.render("register");
});

app.post("/register", (req, res) => {
  const usernameRegex = /^[a-zA-Z0-9_]{4,}$/;
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,}$/;

  if (!usernameRegex.test(req.body.username)) {
    return res.render("register", {
      error: "Username must be at least 4 characters and only contain letters, numbers, or underscore."
    });
  }

  if (!passwordRegex.test(req.body.password)) {
    return res.render("register", {
      error: "Password must be at least 8 characters and include uppercase, lowercase, number, and special character."
    });
  }

  User.register(new User({ username: req.body.username, email: req.body.email, phone: req.body.phone }), req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      return res.render("register", { error: err.message });
    }
    passport.authenticate("local")(req, res, function() {
      res.redirect("/login");
    });
  });
});
app.get("/logout",(req,res)=>{
    req.logout();
    res.redirect("/");
});
function isLoggedIn(req,res,next) {
    if(req.isAuthenticated()){
        return next();
    }
    res.redirect("/login");
}

//Listen On Server
app.listen(process.env.PORT || 3000,function (err) {
    if(err){
        console.log(err);
    }else {
        console.log("Server Started At Port 3000");  
    }
});