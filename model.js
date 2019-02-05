var mongoose = require('mongoose'), crypto = require('crypto');

/**
 * Configuration.
 */

var clientModel = require('./mongo/model/client'),
	tokenModel = require('./mongo/model/token'),
	codeModel = require('./mongo/model/code'),
	userModel = require('./mongo/model/user');

/*
 * Methods used by all grant types.
 */

var debug = function(tag, object) {
	console.log("---" + tag + "---");
	console.log(object);
	console.log("---" + tag + "---");
}

var authenticateSecret = function(model, clientSecret, salt, secret) {
	// Happens with getUserFromClient, it already has the encrypted password from the model
	// model.username = model._id;
	debug("getAccessToken", {clientSecret: clientSecret, salt: salt, secret: secret});
	if(secret === clientSecret) {
		return model;
	}
	salt = Buffer.from(salt, 'base64');
	var encClientSecret = crypto.pbkdf2Sync(Buffer.from(clientSecret, 'binary'), salt, 100000, 64, 'sha512').toString('base64');
	if(secret === encClientSecret) {
		return model;
	}
	debug("grants", model.grants);
	return null;
}

var getAccessToken = function(token, callback) {
	debug("getAccessToken", {token: token});
	tokenModel.findOne({ accessToken: token })
	.catch(function(err) { console.log(err); callback(err, null); })
	.then(function(model) {
		return callback(null, model);
	});
};

var getAuthorizationCode = function(code, callback) {
	debug("getAuthorizationCode", {code: code});
	codeModel.findOne({ code: code })
	.catch(function(err) { console.log(err); callback(err, null); })
	.then(function(model) {
		debug("getAuthorizationCode", {code: code, model: model});
		return callback(null, model);
	});
};

var getClient = function(clientId, clientSecret, callback) {
	debug("getClient", {clientId: clientId, clientSecret: clientSecret});
	clientModel.findOne({ clientId: clientId })
	.catch(function(err) { callback(err, null); })
	.then(function(model) {
		if(model.redirectUris === undefined) {
			model.redirectUris = [];
		}
		if(!model.redirectUris.includes("http://localhost:3000/auth/callback")) {
			model.redirectUris.push("http://localhost:3000/auth/callback");
		}
		if(model.grants === undefined) {
			model.grants = [];
		}
		if(!model.grants.includes("authorization_code")) {
			model.grants.push("authorization_code");
		}
		debug("grants", model.grants);
		if(clientSecret === null) {
			return callback(null, model);
		}
		if(model === null || model.salt === undefined) {
			return callback(null, null);
		}
		return callback(null, authenticateSecret(model, clientSecret, model.salt, model.clientSecret));
	});
};

var saveToken = function(token, client, user) {
	debug("saveToken", {token: token, client: client, user: user});
	token.client = {
		id: client.clientId
	};

	token.user = {
		id: user.username || user.clientId
	};

	var tokenInstance = new tokenModel(token);

	tokenInstance.save();

	return token;
};

var saveAuthorizationCode = function(code, client, user) {
	code.code = code.authorizationCode;
	code.client = {
		id: client.clientId
	};

	code.user = {
		id: user.username || user.clientId || client.clientId
	};

	debug("saveAuthorizationCode", {code: code, client: client, user: user});
	var codeInstance = new codeModel(code);

	codeInstance.save();

	return code;
};

/*
 * Method used only by password grant type.
 */

var getUser = function(username, password, callback) {
	debug("getUser", {username: username, password: password});
	userModel.findOne({ username: username })
	.catch(function(err) { callback(err, null); })
	.then(function(model) {
		if(model === null || model.salt === undefined) {
			return callback(null, null);
		}
		return callback(null, authenticateSecret(model, password, model.salt, model.password));
	});
};

/*
 * Method used only by client_credentials grant type.
 */

var getUserFromClient = function(client, callback) {
	debug("getUserFromClient", client);
	clientModel.findOne({ clientId: client.clientId, grants: 'client_credentials' })
	.catch(function(err) { callback(err, null); })
	.then(function(model) {
		if(model === null || model.salt === undefined) {
			return callback(null, null);
		}
		return callback(null, authenticateSecret(model, client.clientSecret, model.salt, model.clientSecret));
	});
};

var getRefreshToken = function(refreshToken) {
	debug("getRefreshToken", refreshToken);
	return tokenModel.findOne({
		refreshToken: token
	});
};

var revokeAuthorizationCode = function(code) {
	debug("revokeAuthorizationCode", code);
	codeModel.deleteOne({ code: code});
	return true;
}

var revokeToken = function(token) {
	debug("revokeToken", token);
	tokenModel.deleteOne({ accessToken: token });
	return true;
}

var validateScope = function(scope) {
	debug("validateScope", scope);
	return true;
}

/**
 * Export model definition object.
 */

module.exports = {
	getAccessToken: getAccessToken,
	getAuthorizationCode: getAuthorizationCode,
	getClient: getClient,
	getRefreshToken: getRefreshToken,
	revokeAuthorizationCode: revokeAuthorizationCode,
	saveAuthorizationCode: saveAuthorizationCode,
	saveToken: saveToken,
	getUser: getUser,
	getUserFromClient: getUserFromClient,
	validateScope: validateScope
};
