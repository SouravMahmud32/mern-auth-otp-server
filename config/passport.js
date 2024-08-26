const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/User');

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL,
},
async (accessToken, refreshToken, profile, done) => {
    const { email, name } = profile._json;
    try {
        let user = await User.findOne({ email });
        if (user) {
            return done(null, user);
        }
        user = new User({
            email,
            name,
            googleId: profile.id,
        });
        await user.save();
        done(null, user);
    } catch (err) {
        console.error(err);
        done(err, false);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

