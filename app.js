/********************** REQUIRED NPM ***************************/
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');

//saving info into sessions and cookies
const session = require('express-session');

//needed to make passportLocalMongoose work
const passport = require('passport');

//salt & hash automatically
const passportLocalMongoose = require('passport-local-mongoose');

//google authentication
const GoogleStrategy = require('passport-google-oauth20').Strategy;

//find or create as a ready-made function
const findOrCreate = require('mongoose-findorcreate');



/********************** INITIALIZE PACKAGES ***************************/
const app = express();

//initialize express with static CSS folder
app.use(express.static("public"));

//initialize body parser to get info from form
app.use(bodyParser.urlencoded({extended: true}));

//initialize ejs templates
app.set("view engine", "ejs");

//initialize session package
app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

//initialize passport package
app.use(passport.initialize());

//use passport to handle sessions
app.use(passport.session());



/********************** MONGO DB & ENCRYPTION ***************************/
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
    googleId: String,
    email: String,
    password: String,
    secret: String
});

//make userschema use passportLocalMongoose plugin
//its purpose is to use passport plugin with mongoose database
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

//create local login strategy with passport
passport.use(User.createStrategy());

//(de)serialize user session (create/delete cookies)
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//initialize google authentication
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
          return cb(err, user);
    });
  }
));



/********************** GET REQUESTS ***************************/
app.get("/", function(req, res){
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "login" }),
  function(req, res) {
    // Successful authentication, redirect to priviledged page
    res.redirect("/secrets");
  });

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){
    //print all secrets in DB
    User.find({"secret": {$ne: null}}, function(err, foundUsers){
        if (err) {
            console.log(err);
        } else {
            if (foundUsers){
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    });

});

app.get("/submit", function(req, res){
    //passport function
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }

});

app.get("/logout", function(req, res){
    //passport function
    req.logout();
    res.redirect("/");
});


/********************** POST REQUESTS ***************************/
app.post("/register", function(req, res){

    //passport-local-mongoose function
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            })
        }
    })


});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, function(err, foundUser){
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                })
            }
        };
    });
});

app.post("/login", function(req, res){

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    //passport method
    req.login(user, function(err){
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            })
        }
    })


});





app.listen(3000, function(){
    console.log("Server started on port 3000.");
})
