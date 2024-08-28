const express = require('express');
const connectDB = require('../config/db');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
require('../config/passport'); 

const app = express();

const path = require('path');

// Serve static assets in production
if (process.env.NODE_ENV === 'production') {
    app.use(express.static('client/build'));

    app.get('*', (req, res) => {
        res.sendFile(path.resolve(__dirname, 'client', 'build', 'index.html'));
    });
}


// Use CORS middleware
app.use(cors());

// Connect Database
connectDB();

// Init Middleware
app.use(express.json());

// Express session middleware
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Define Routes
app.use('/api/auth', require('../routes/auth'));

app.get("/", (req, res) => {
    res.send("App works properly!");
  });

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
