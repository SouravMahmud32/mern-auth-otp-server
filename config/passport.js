const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/User');

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL,
},
async (accessToken, refreshToken, profile, done) => {
    const { email } = profile._json;
    try {
        let user = await User.findOne({ email });

        if (user) {
            // Check if the user is verified before allowing them to proceed
            if (!user.isVerified) {
                return done(null, false, { message: 'User is not verified via OTP' });
            }
            return done(null, user);
        }

        // User doesn't exist, create a new one with the verified status set to false
        user = new User({
            email,
            name: profile.displayName,
            googleId: profile.id,
            isVerified: false, // Initially, set as not verified
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
