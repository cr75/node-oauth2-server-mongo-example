var mongoUri = 'mongodb://localhost/oauth';
var mongoose = require('mongoose'), crypto = require('crypto');

mongoose.connect(mongoUri, {
        useCreateIndex: true,
        useNewUrlParser: true
}, function(err, res) {

        if (err) {
                return console.error('Error connecting to "%s":', mongoUri, err);
        }
        console.log('Connected successfully to "%s"', mongoUri);
});

/**
 * Configuration.
 */

var clientModel = require('./mongo/model/client'),
	tokenModel = require('./mongo/model/token'),
	userModel = require('./mongo/model/user');

/**
 * Add example client and user to the database (for debug).
 */

var loadExampleData = function() {
	var salt = crypto.randomBytes(32);
	var pw = 'secret';
	var secret = crypto.pbkdf2Sync(Buffer.from(pw, 'binary'), Buffer.from(salt, 'binary'), 100000, 64, 'sha512').toString('base64');
	var client1 = new clientModel({
		clientId: 'application',
		clientSecret: secret,
		salt: Buffer.from(salt, 'binary').toString('base64'),
		grants: [
			'password'
		],
		redirectUris: []
	});
	console.log(client1);

	salt = crypto.randomBytes(32);
	pw = 'topSecret';
	secret = crypto.pbkdf2Sync(Buffer.from(pw, 'binary'), Buffer.from(salt, 'binary'), 100000, 64, 'sha512').toString('base64');
	var client2 = new clientModel({
		clientId: 'confidentialApplication',
		clientSecret: secret,
		salt: Buffer.from(salt, 'binary').toString('base64'),
		grants: [
			'password',
			'client_credentials'
		],
		redirectUris: []
	});
	console.log(client2);

	salt = crypto.randomBytes(32);
	pw = 'password';
	secret = crypto.pbkdf2Sync(Buffer.from(pw, 'binary'), Buffer.from(salt, 'binary'), 100000, 64, 'sha512').toString('base64');
	var user = new userModel({
		id: '123',
		username: 'user@domain.com',
		salt: Buffer.from(salt, 'binary').toString('base64'),
		password: secret
	});
	console.log(user);

	client1.save(function(err, client) {

		if (err) {
			return console.error(err);
		}
		console.log('Created client', client);
	});

	user.save(function(err, user) {

		if (err) {
			return console.error(err);
		}
		console.log('Created user', user);
	});

	client2.save(function(err, client) {

		if (err) {
			return console.error(err);
		}
		console.log('Created client', client);
	});
};

/**
 * Dump the database content (for debug).
 */

var dump = function() {

	clientModel.find(function(err, clients) {

		if (err) {
			return console.error(err);
		}
		console.log('clients', clients);
	});

	tokenModel.find(function(err, tokens) {

		if (err) {
			return console.error(err);
		}
		console.log('tokens', tokens);
	});

	userModel.find(function(err, users) {

		if (err) {
			return console.error(err);
		}
		console.log('users', users);
	});
};

loadExampleData();
dump();
