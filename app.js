require('dotenv').config();
const express=require("express");
const bodyParser= require("body-parser")
const ejs=require("ejs");
const mongoose=require("mongoose");
const session=require('express-session');
const passport=require('passport');
const passportLocalMongoose=require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const findOrCreate=require('mongoose-findorcreate');


const app=express();
app.set('view engine','ejs');

app.use(express.static("public"));


app.use(bodyParser.urlencoded({extended:true}));


app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  }));

app.use(passport.initialize());
app.use(passport.session());

 
// to remove deprecation warnings 
mongoose.set('strictQuery', true);

// database connection string
mongoose.connect(process.env.MONGO_URL);

// defined user schema for database
const userSchema=new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    secret:String
});

// plugins to be used with userSchema 
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User=new mongoose.model("User",userSchema);

passport.use(User.createStrategy());

// used for supporting user session and remember user
passport.serializeUser(function(user,done){
    done(null,user.id);
});

// user
passport.deserializeUser(function(id,done){
    User.findById(id,function(err,user){
        done(err,user);
    })
});

// implementing passportjs google-oauth20 authentication strategy

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,

    clientSecret: process.env.CLIENT_SECRET,

    callbackURL: process.env.CALL_BACK,

// since findOrCreate is not a function directly so used a npm package

    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
      
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        // console.log(profile.id);
      return cb(err, user);
    });
  }
));

// for home route
app.get("/",function(req,res){
    res.render("home");
});

app.get("/submit",function(req,res){
    // console.log(req.user);
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }

})



// listens get request to the register route
app.get("/register",function(req,res){
    res.render("register");
});

// listens to get request to logout route
app.get('/logout', function(req, res, next) {

//  logout() needs a function nowadays
    req.logout(function(err) {
      if (err) { return next(err); }
      res.redirect('/');
    });
  });

// listens to get request login route
app.get("/login",function(req,res){
    res.render("login");
});

// google-Oauth20 implementation for authenticating
app.get("/auth/google",
    passport.authenticate("google",{scope:['profile']})
);

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: '/login' ,
  successRedirect:"/secrets" }),
  function(req, res) {
    res.redirect("/secrets");
  });

// passport authentication if a user is authenticated to be redirected to the secrets page
app.get("/secrets",function(req,res){
  User.find({"secret":{$ne:null}},function(err,foundUser){
    if(err){
        console.log(err);

    }
    else{
        if(foundUser){
            res.render("secrets",{userwithsecret:foundUser});
        }
    }
  })
})


// to allow user to post secret 
app.post("/submit",function(req,res){
    // access the secret
    const usersecret=req.body.secret;

    // find user by id and then save in their database json the secret and redirect them to view all secrets along with newone they just added
    User.findById(req.user.id,function(err,foundUser){

        if(err){
            console.log(err);
        }
        else{
            if(foundUser){
                foundUser.secret=usersecret;
                foundUser.save(function(){
                    res.redirect("/secrets");

                });
            }
        }
    }) 
})

// registration of the user using passport-local strategy and authentication 
app.post("/register",function(req,res){

User.register({username:req.body.username},req.body.password,
    function(err,user){
        if(err){
            console.log(err);
            res.redirect("/register"); 
        }
        else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    })
});

// logging in a registered user using passport and redirect unregistered users 
app.post("/login",function(req,res){
    const newUser=new User({
        username:req.body.username,
        password:req.body.password
    });

req.login(newUser,function(err){
    if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            })
        }
    })
})



app.listen(3000,function(){
    console.log("Server is running on port 3000");
})