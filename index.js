const path = require('path');
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require("joi");
const { google } = require('googleapis');

require('dotenv').config();
require("./utils.js");

const port = process.env.PORT || 3000;
const app = express();
const saltRounds = 12;

const oauth2Client = new google.auth.OAuth2(
	process.env.CLIENT_ID,
	process.env.CLIENT_SECRET,
	process.env.REDIRECT_URI
);

const SCOPES = ['https://www.googleapis.com/auth/gmail.send'];

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "/public")));

var { database } = include('databaseConnection');
const userCollection = database.db(process.env.MONGODB_DATABASE).collection('users');

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/sessions`,
	crypto: {
		secret: process.env.MONGODB_SESSION_SECRET
	}
});

app.use(session({
	secret: process.env.NODE_SESSION_SECRET,
	store: mongoStore,
	saveUninitialized: false,
	resave: true
}));

app.get('/auth/google', (req, res) => {
	const url = oauth2Client.generateAuthUrl({
		access_type: 'offline',
		scope: SCOPES
	});
	res.redirect(url);
});

app.get('/auth/google/callback', async (req, res) => {
	const { code } = req.query;
	try {
		const { tokens } = await oauth2Client.getToken(code);
		oauth2Client.setCredentials(tokens);
		res.redirect('/'); // Redirect to home or a success page
	} catch (error) {
		console.error('Error getting OAuth tokens:', error);
		res.status(500).send('Authentication failed');
	}
});


app.get('/', async (req, res) => {
	if (req.session.authenticated) {
		var email = req.session.email;
		const result = await userCollection.find({ email: email }).project({ username: 1, email: 1, password: 1, _id: 1 }).toArray();
		res.render("index", { user: result[0].username });

	} else {
		res.render("index", { user: null });
	}
});

app.get('/createUser', (req, res) => {
	res.render("createUser");
});

app.get('/login', (req, res) => {
	res.render("login");
});

app.post('/createUser', async (req, res) => {
	var username = req.body.username;
	var email = req.body.email;
	var password = req.body.password;

	const schema = Joi.object({
		username: Joi.string().alphanum().max(20).required(),
		email: Joi.string().max(50).required(),
		password: Joi.string().max(20).required()
	});

	const validationResult = schema.validate({ username, email, password });
	if (validationResult.error != null) {
		var msg = validationResult.error.message;
		res.redirect("/signUpSubmit?message=" + msg);
		return;
	}

	var hashedPassword = await bcrypt.hash(password, saltRounds);

	await userCollection.insertOne({ username: username, email: email, password: hashedPassword });
	req.session.authenticated = true;
	req.session.email = email;
	req.session.cookie.maxAge = expireTime;
	res.redirect('/');
});

app.get('/signUpSubmit', (req, res) => {
	var msg = req.query.message;
	res.render("submitUser", { msg: msg, previousPage: "createUser" });
});

app.post('/login', async (req, res) => {
	var email = req.body.email;
	var password = req.body.password;

	const schema = Joi.object({
		email: Joi.string().max(50).required(),
		password: Joi.string().max(20).required()
	});
	const validationResult = schema.validate({ email, password });
	if (validationResult.error != null) {
		res.redirect("/loginSubmit?message=invalid email or password");
		return;
	}

	const result = await userCollection.find({ email: email }).project({ username: 1, email: 1, password: 1, _id: 1 }).toArray();

	if (result.length != 1) {
		res.redirect("/loginSubmit?message=user not found");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		req.session.authenticated = true;
		req.session.email = email;
		req.session.cookie.maxAge = expireTime;
		res.redirect('/');
		return;
	} else {
		res.redirect("/loginSubmit?message=incorrect password");
		return;
	}
});

app.get('/loginSubmit', (req, res) => {
	var msg = req.query.message;
	res.render("submitUser", { msg: msg, previousPage: "login" });
});

app.get('/logout', (req, res) => {
	req.session.destroy();
	res.redirect("/");
});

app.get('/info', (req, res) => {
	res.render("info");
});

app.get('/about_us', (req, res) => {
	res.render("about_us");
});

app.get('/destination', (req, res) => {
	res.render("destination");
});

app.get('/home', (req, res) => {
	res.render("home");
});

app.get('/profile', (req, res) => {
	res.render("profile");
});

app.get('/loggingin', (req, res) => {
	res.render("loggingin");
});

app.get('/review', (req, res) => {
	res.render("review");
});

// Password Reset Routes
// Route to display the reset password request form
app.get('/resetPassword', (req, res) => {
	res.render('resetPassword');
});

// Route to display the reset link sent confirmation
app.get('/resetLinkSent', (req, res) => {
	res.render('resetLinkSent');
});

// Route to display the new password form
app.get('/newPassword', (req, res) => {
    res.render('newPassword');
});

const nodemailer = require('nodemailer');

// Create a reusable transporter object using the default SMTP transport
let transporter = nodemailer.createTransport({
	service: 'gmail', // for example, for gmail
	auth: {
		user: process.env.EMAIL, // your email address to send emails from
		pass: process.env.EMAIL_PASSWORD // your email password
	}
});

app.post('/sendResetLink', async (req, res) => {
	const email = req.body.email;
	// First, check if the email exists in the database
	const user = await userCollection.findOne({ email: email });

	if (!user) {
		// Optionally, you could decide to still redirect to 'resetLinkSent' for security reasons (to prevent email enumeration)
		console.log('No user found with that email.');
		res.redirect('/resetLinkSent');
		return;
	}

	// setup email data with unicode symbols
	let mailOptions = {
		from: `"sunspot" <${process.env.EMAIL}>`, // sender address
		to: email, // list of receivers
		subject: 'Password Reset', // Subject line
		text: 'You requested a password reset', // plain text body
		html: '<b>Click here to reset your password</b>' // html body
	};

	// send mail with defined transport object
	try {
		let info = await transporter.sendMail(mailOptions);
		console.log('Message sent: %s', info.messageId);
		// Redirect user to another page or inform them that the email has been sent
		res.redirect('/resetLinkSent');
	} catch (error) {
		console.error('Error sending email:', error);
		res.status(500).send('Failed to send reset link');
	}
});



app.use(express.static(path.join(__dirname, "/public")));

app.get("*", (req, res) => {
    res.status(404).render("404");
});

app.listen(port, () => {
    console.log(`Node application listening on port ${port}`);
});

