require("./utils.js");
require('dotenv').config();
const express = require('express');
const app = express();
const Joi = require('joi');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');

const saltRounds = 12;
const port = process.env.PORT || 3000;
const expireTime = 1000 * 60 * 60; // 1 hour


/* secret information section */
const mongodb_host = process.env.MONGODB_HOST
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');
const userCollection = database.db(mongodb_database).collection('users');

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}
));

app.use(express.urlencoded({ extended: false }));


// Home Page
app.get('/', (req, res) => {
    if (req.session.authenticated) {
        res.redirect('/members');
        return;
    }
    res.send(`
    <h1> Welcome to the Home Page! </h1>
    <a href='/login' style='font-size:1.5em;'> Login </a>
    <br>
    <a href='/signup' style='font-size:1.5em;'> Register </a>
    `);
});

// Sign Up Page
app.get('/signup', (req, res) => {
    res.send(`
    <h1> Sign Up </h1>
    <form action='/signup' method='POST'>
        <input type='text' name='name' placeholder='Name' required /> <br>
        <input type='text' name='username' placeholder='Username' required /> <br>
        <input type='password' name='password' placeholder='Password' required /> <br>
        <input type='submit' value='Submit' />
    </form>`)
});

// Create New User
app.post('/signup', async (req, res) => {
    // Get username and password
    var username = req.body.username;
    var password = req.body.password;

    // Create Joi object
    const schema = Joi.object({
        username: Joi.string().alphanum().max(20).required(),
        password: Joi.string().max(20).required()
    });

    // Validate username and password using Joi
    const validationResult = schema.validate({ username, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect('/signup');
        return;
    }

    // Create hashed password using bcrypt
    var hashedPassword = await bcrypt.hash(password, saltRounds);

    // Add user to database
    await userCollection.insertOne({ username: username, password: hashedPassword });
    console.log("User added to database");


    res.send("Successfully created user!");
});


// Login Page
app.get('/login', (req, res) => {
    res.send(`
    <h1> Login </h1>
    <form action='/login' method='POST'>
        <input type='text' name='username' placeholder='Username' required /> <br>
        <input type='password' name='password' placeholder='Password' required /> <br>
        <input type='submit' value='Login' />
    </form>`)
});

app.post('/login', async (req, res) => {
    // Get username and password
    var username = req.body.username;
    var password = req.body.password;

    // Create Joi string
    const schema = Joi.string().max(20).required();

    // Validate username using Joi
    const validationResult = schema.validate(username);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect('/login');
        return;
    }

    // Find user in database
    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();
    console.log(result);

    // Check if user was found
    if (result.length != 1) {
        console.log("User not found");
        res.redirect('/login');
        return;
    }

    // Check if password is correct
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("Password is correct");
        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    } else {
        console.log("Password is incorrect");
        res.redirect('/login');
        return;
    }
});

// Members Page
app.get('/members', (req, res) => {
    // Check authentication
    if (!req.session.authenticated) {
        res.redirect('/login');
    } else {
        // Random number from 1 to 3
        var rand = Math.floor(Math.random() * 3) + 1;

        // Create html string
        var html = `<h1> Welcome ${req.session.username} </h1>`;
        if (rand == 1) {
            html += `<img src='/Red.png'>`;
        } else if (rand == 2) {
            html += `<img src='/Green.png'>`;
        } else {
            html += `<img src='/Orange.png'>`;
        }
        html += `<br><a href='/logout' style='font-size:1.5em;'> Logout </a>`;

        // Send html string
        res.send(html);
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.send('You have been logged out');
});

app.use(express.static(__dirname + '/public'));

// 404 page
app.get('*', (req, res) => {
    res.send('<h1> 404 - Page not Found </h1>');
});

app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});


