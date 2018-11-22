const passport = require('passport');
const User = require('../models/User');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

const localOptions = { usernameField: 'email'};
const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
  User.findOne({ email: email }, function(error, user) {
    if (error){
      return done(error)
    };

    if (!user){
      return done(null, false)
    };

    user.comparePasswords(password, function(error, isMatch){
      if (error) {
        return done(err);
      }
      if (!isMatch){
        return done(null, false);
      }
      return done(null, user)
    });
  });
});

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  User.findById(payload.sub, function(error, user) {
    if (error){
      return done(err, false);
    };

    if (user){
      done(null, user);
    } else {
      done(null, false);
    };
  });
});

passport.use(jwtLogin);
passport.use(localLogin)