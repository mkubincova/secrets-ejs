//REQUIRED NPM
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


//INITIALIZING PACKAGES
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


//MONGO DB & ENCRYPTION
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

//make userschema use passportLocalMongoose plugin
//its purpose is to use passport plugin with mongoose database
userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);

//create local login strategy with passport
passport.use(User.createStrategy());

//(de)serialize user session (create/delete cookies)
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

//GET REQUESTS
app.get("/", function(req, res){
    res.render("home");
});

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){
    //passport function
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }

});

app.get("/logout", function(req, res){
    //passport function
    req.logout();
    res.redirect("/");
});


//POST REQUESTS
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
