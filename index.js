require('dotenv').config()
const express = require('express');
const path = require('node:path');
const https = require('node:https');
const fs = require('node:fs');
const helmet= require('helmet');
const passport = require('passport');
const cookieSession = require('cookie-session');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();

const config={
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL,
    cookieKey: process.env.COOKIE_KEY
}

app.use(cookieSession({
    name: 'session',
    maxAge: 1000*60*60*24,
    keys: [config.cookieKey, 'dsadfasdas'],
    resave: false,
    saveUninitialized: true,
}));

app.use(function (request, response, next) {
    if (request.session && !request.session.regenerate) {
      request.session.regenerate = (cb) => {
        cb();
      };
    }
    if (request.session && !request.session.save) {
      request.session.save = (cb) => {
        cb();
      };
    }
    next();
  });

const verifyCallback = (accessToken, refreshToken, profile, done)=>{
    console.log('Google profile', profile)
    done(null, profile);
}

passport.use(new GoogleStrategy(config, verifyCallback));

// to save the user data into cookie
passport.serializeUser((user, done)=>{
    console.log(user)
    done(null, user.id)
});

// to read the data from the cookie
passport.deserializeUser((obj, done)=>{
    done(null, obj)
});

function checkLoggedIn(req, res, next){
    const isLoggedIn = req.isAuthenticated() && req.user;
    if(!isLoggedIn){
        return res.status(401).json({error: 'You must login first'});
    }
    next();
}

app.use(helmet());

app.use(passport.initialize());

app.use(passport.session());

app.get('/auth/google', passport.authenticate('google', {scope: ['profile']}));

app.get('/auth/google/callback', passport.authenticate('google', {
    failureRedirect: '/',
    successRedirect: '/secret'
}));

app.get('/auth/logout', (req, res, next)=>{
    req.logout((err)=>{
        if(err) return next(err);
    }); // it will clear your cookies and session
    return res.redirect('/');
});

app.get('/secret', checkLoggedIn, (req, res)=>{
    res.send('Your secret value is 9100');
});

app.get('/', (req, res)=>{
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

https.createServer({
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
}, app).listen(3000, ()=>{
    console.log('Server started at port 3000')
});