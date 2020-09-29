'use latest';

// This webtask requires the following configured secrets:

// RECAPTCHA_SITE_KEY     These two values can be obtained from http://www.google.com/recaptcha/admin
// RECAPTCHA_SITE_SECRET  
// 
// CAPTCHA_SECRET         A 32 byte string that is the shared key between the rule and the webtask
// AUTH0_DOMAIN           Your Auth0 domain (e.g. account.auth0.com)


import { fromExpress } from 'webtask-tools';
const express = require('express@4.14.0');
const bodyParser = require('body-parser@1.12.4');
const app = express();
const url = require('url'); // built-in utility
const jwt = require('jsonwebtoken@5.7.0');
const request = require('request@2.67.0');

app.use(bodyParser.urlencoded()); // for parsing application/x-www-form-urlencoded

var getRuleUri = function(req) { return 'https://' + req.webtaskContext.secrets.AUTH0_DOMAIN + '/rules/captcha'; };
var getWtUri = function(req) { return getRuleUri(req) + '/wt';};

app.get('/', (req, res) => {

  var captchaView = (function view() {/*
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <STYLE type="text/css">
    html {
      font-family: sans-serif;
      -webkit-text-size-adjust: 100%;
          -ms-text-size-adjust: 100%;
    }
    body { margin: 0; }
    .container { padding-right: 15px; padding-left: 15px;margin-right: auto; margin-left: auto; }
    h1 { margin: .67em 0; font-size: 2em; font-family: inherit; font-weight: 500; line-height: 1.1; color: inherit; }
</STYLE>
 <title>Confirm you are human</title>
  <!-- Latest compiled and minified CSS -->
  <script src='https://www.google.com/recaptcha/api.js'></script>      
</head>
<body>
  <script type="text/javascript">
    var submitform = function() {
      document.getElementById("captchaform").submit();
    };
  </script>  
  <div class="container">
    <form class="form-signin" action="<%= target %>" method="POST" id="captchaform">
      <h1>Complete the log-in process <%= clientName %></h1>
      <input type="hidden" value="<%= state %>" name="state" />
      <input type="hidden" value="<%= token %>" name="token" />
      <div class="g-recaptcha" data-sitekey="<%= sitekey %>" data-callback="submitform"></div>
    </form>
  </div>
</body>
</html>
  */}).toString().match(/[^]*\/\*([^]*)\*\/\s*\}$/)[1];

  var myUri = req.originalUrl.split("?")[0];
  var secrets = req.webtaskContext.secrets;

  jwt.verify(
    req.body.token,
    secrets.CAPTCHA_SECRET, {
      audience: getWtUri(req),
      issuer: getRuleUri(req)
    },
    function(err, tokenPayload) {

      var target = url.parse(req.originalUrl).pathname;
    
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(require('ejs').render(captchaView, {
          state: req.query.state,
          target: target,
          token: req.query.token,
          sitekey: secrets.RECAPTCHA_SITE_KEY,
          clientName: tokenPayload ? "to " + tokenPayload.clientName : ""
      }));
  });
});

app.post('/', (req, res) => {
  var secrets = req.webtaskContext.secrets;

  var continueToRule = function(err, subject, state) {
    var token = jwt.sign({
          captchaOk: err === null,
          sub: subject,
          errorMessage: err
        }, 
        secrets.CAPTCHA_SECRET, {
          expiresInMinutes: 2,
          audience: getRuleUri(req),
          issuer: getWtUri(req)
        }
    );
    res.redirect(302, "https://" + secrets.AUTH0_DOMAIN + "/continue?state=" + req.body.state + "&token=" + token);
  }

  var postVerify = function(err, decoded) {
    if (err) {
       continueToRule("Invalid token: " + err, null);
    } else if (!decoded.sub) {
       continueToRule("Token does not contain 'sub' claim.", null);
    } else {
      continueToRule(null, decoded.sub);
    }
  };
  
  var verifyCaptcha = function(captchaResponse, callback) {
    request.post( {
      url: 'https://www.google.com/recaptcha/api/siteverify',
      form: {
        secret: secrets.RECAPTCHA_SITE_SECRET,
        response: captchaResponse,
        remoteip: req.ip
      }}, function (error, response, body) {
        if (error) {
          callback(error);
        }
        if (response.statusCode !== 200) {
          callback('Error validating captcha: '+ response.statusCode);
        }
        var data = JSON.parse(body);
        if (data.success) {
          callback();
        } else {
          callback("Error from reCaptcha: " + JSON.stringify(data));
        }
      }
    );
  };
  
  verifyCaptcha(req.body["g-recaptcha-response"], function(err) {
    if (err) {
      continueToRule("Invalid reCAPTCHA validation." + err, null);
      return;
    }
    jwt.verify(req.body.token, secrets.CAPTCHA_SECRET, {
      audience: getWtUri(req),
      issuer: getRuleUri(req)
    }, postVerify);

  });
});

module.exports = fromExpress(app);
