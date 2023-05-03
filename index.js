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

app.set('view engine', 'ejs');

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
    res.render('index');
});

// Sign Up Page
app.get('/signup', (req, res) => {
    if (req.session.authenticated) {
        res.redirect('/members');
        return;
    }
    res.render('signup');
});

// Create New User
app.post('/signup', async (req, res) => {
    // Get username and password
    var name = req.body.name;
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
    await userCollection.insertOne({ name: name, username: username, password: hashedPassword, role: 'user' });
    console.log("User added to database");


    res.send("Successfully created user!");
});


// Login Page
app.get('/login', (req, res) => {
    if (req.session.authenticated) {
        res.redirect('/members');
        return;
    }

    var msg = "";
    if (req.query.msg != undefined) {
        var msg = req.query.msg;
    }
    res.render('login', {
        'msg': msg
    });
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
        res.redirect('/login?msg=Invalid Username/Password!');
        return;
    }

    // Find user in database
    const result = await userCollection.find({ username: username }).project({ name: 1, username: 1, password: 1, role: 1, _id: 1 }).toArray();
    console.log(result);

    // Check if user was found
    if (result.length != 1) {
        console.log("User not found");
        res.redirect('/login?msg=Invalid Username/Password!');
        return;
    }

    // Check if password is correct
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("Password is correct");
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.cookie.maxAge = expireTime;
        if (result[0].role == 'admin') {
            req.session.admin = true;
        }

        res.redirect('/members');
        return;
    } else {
        console.log("Password is incorrect");
        res.redirect('/login?msg=Invalid Username/Password!');
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

        if (rand == 1) {
            img_file = '/Red.png';
        } else if (rand == 2) {
            img_file = '/Green.png';
        } else {
            img_file = '/Orange.png';
        }

        // Send html string
        res.render('members', {
            'name': req.session.name,
            'img_file': img_file
        });
    }
});

app.get('/admin', (req, res) => {
    // Check authentication
    if (!req.session.authenticated) {
        res.redirect('/login');
        // Check admin authentication
    } else if (!req.session.admin) {
        return res.status(403).send("You are not authorized to view this page");
    } else {
        res.render('admin', {
            'name': req.session.name
        });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.send('You have been logged out');
});

app.use(express.static(__dirname + '/public'));

// 404 page
app.get('*', (req, res) => {
    res.send(`
        <style>
        html {
            background-color: #90e39a;
        }

        h1, h2 {
            font-family: sans-serif;
            color: #065143;
        }

        .center {
            margin: 15% auto;
            width: 30%;
            vertical-align: center;
            text-align: center;
        }

        a:link, a:visited {
            font-size: 1.5em;
            font-family: sans-serif;
            margin-bottom: 10px;
            background-color: #18a999;
            color: white;
            padding: 8px 16px;
            display: inline-block;
            text-decoration: none;
            border: 1px solid black;
            border-radius: 3px;
        }
        a:hover, a:active {
            background-color: #118ab2;
        }
        </style>

        <div class='center'>
            <h1> Oops Error 404! </h1>
            <h2> Sorry, we can't find the page you are looking for. </h2>
            <a href='/'> Return to Homepage </a>
        </div>
    `);
});

app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});


