var express = require('express'),
  bodyParser = require('body-parser'),
  mongoose = require('mongoose'),
  OAuth2Server = require('oauth2-server'),
  Request = OAuth2Server.Request,
  Response = OAuth2Server.Response,
  userModel = require('./mongo/model/user'),
  crypto = require('crypto');

var app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

var mongoUri = 'mongodb://localhost/oauth';
mongoose.connect(mongoUri, {
  useCreateIndex: true,
  useNewUrlParser: true
}, function(err, res) {
  if (err) {
    return console.error('Error connecting to "%s":', mongoUri, err);
  }
  console.log('Connected successfully to "%s"', mongoUri);
});

app.oauth = new OAuth2Server({
  model: require('./model.js'),
  accessTokenLifetime: 60 * 60,
  allowBearerTokensInQueryString: true
});

app.all('/oauth/token', obtainToken);
app.all('/oauth/code', obtainToken);
app.post('/api/v1/user', authenticateRequest, createUser);

app.listen(3001);

function obtainToken(req, res) {
  var request = new Request(req);
  var response = new Response(res);

  var pwString = request.body.client_id + ":" + request.body.client_secret;

  if(request.headers.authorization === undefined && request.body.code !== undefined && request.body.code !== '') {
    request.headers.authorization = "Bearer " + request.body.code;
  }

  if(request.body.grant_type !== undefined && request.body.grant_type === "authorization_code") {
    return app.oauth.authenticate(request, response)
    .then(function(token) {
      if(token.user.id !== undefined) {
        token.profile = { email: token.user.id, id: token._id};
      }
      res.json(token);
      // next();
    }).catch(function(err) {
      console.log(err);
      res.status(err.code || 500).json(err);
    });
  }
  else {
    return app.oauth.token(request, response)
    .then(function(token) {
      if(token.user.id !== undefined) {
        token.profile = { email: token.user.id, id: token._id};
       }
      res.json(token);
    }).catch(function(err) {
      console.log(err);
      res.status(err.code || 500).json(err);
    });
  }
}

function authenticateRequest(req, res, next) {
  var request = new Request(req);
  var response = new Response(res);

  return app.oauth.authenticate(request, response)
    .then(function(token) { req.oAuthToken = token; next(); })
    .catch(function(err) { res.status(err.code || 500).json(err); });
}

function createUser(req, res) {
  // authenticateRequest should put the auth information into the request object
  console.log(req.oAuthToken);

  // Output the variables passed in.
  console.log({body: req.body});

  if(!req.body.username || !req.body.password) {
    return res.status(403).json({success: false, message: "Both username and password fields are required"});
  }

  // Make sure the username doesn't already exist
  userModel.findOne({username: req.body.username})
    .then((model) => {
      if(model) {
        return res.status(409).json({success: false, message: "User already exists", errorcode: "D05-6F9B-48AA"});
      }
      // How to validate that they're allowed to create a user?
      var user = newUserObject(req.body.username, req.body.password);
      user.save(function(err, user) {
        if(err) {
          return res.status(500).json({success: false, message: "Unable to create user", errorcode: "S03-45A6-8505"});
        }
        return res.json({success: true, message: "User successfully created", userid: user._id});
      });
    })
    .catch((err) => {
      return res.status(500).json({success: false, message: "Unable to create user", errorcode: "D05-8BDF-4BB4"});
    });
}

function newUserObject(username, password) {
  var salt = crypto.randomBytes(32);
  var secret = crypto.pbkdf2Sync(Buffer.from(password, 'binary'), Buffer.from(salt, 'binary'), 100000, 64, 'sha512').toString('base64');
  var user = new userModel({
    username: username,
    salt: Buffer.from(salt, 'binary').toString('base64'),
    password: secret
  });
  console.log({user: user});

  return user;
}
