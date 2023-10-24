/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ "./src/config.js":
/*!***********************!*\
  !*** ./src/config.js ***!
  \***********************/
/***/ ((module) => {

module.exports = {
  GITHUB_CLIENT_ID: process.env.GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET: process.env.GITHUB_CLIENT_SECRET,
  COGNITO_REDIRECT_URI: process.env.COGNITO_REDIRECT_URI,
  GITHUB_API_URL: process.env.GITHUB_API_URL,
  GITHUB_LOGIN_URL: process.env.GITHUB_LOGIN_URL,
  PORT: parseInt(process.env.PORT, 10) || undefined,
  // Splunk logging variables
  SPLUNK_URL: process.env.SPLUNK_URL,
  SPLUNK_TOKEN: process.env.SPLUNK_TOKEN,
  SPLUNK_SOURCE: process.env.SPLUNK_SOURCE,
  SPLUNK_SOURCETYPE: process.env.SPLUNK_SOURCETYPE,
  SPLUNK_INDEX: process.env.SPLUNK_INDEX
};

/***/ }),

/***/ "./src/connectors/controllers.js":
/*!***************************************!*\
  !*** ./src/connectors/controllers.js ***!
  \***************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

const logger = __webpack_require__(/*! ./logger */ "./src/connectors/logger.js");
const openid = __webpack_require__(/*! ../openid */ "./src/openid.js");
module.exports = respond => ({
  authorize: (client_id, scope, state, response_type) => {
    const authorizeUrl = openid.getAuthorizeUrl(client_id, scope, state, response_type);
    logger.info('Redirecting to authorizeUrl');
    logger.debug('Authorize Url is: %s', authorizeUrl, {});
    respond.redirect(authorizeUrl);
  },
  userinfo: tokenPromise => {
    tokenPromise.then(token => openid.getUserInfo(token)).then(userInfo => {
      logger.debug('Resolved user infos:', userInfo, {});
      respond.success(userInfo);
    }).catch(error => {
      logger.error('Failed to provide user info: %s', error.message || error, {});
      respond.error(error);
    });
  },
  token: (code, state, host) => {
    if (code) {
      openid.getTokens(code, state, host).then(tokens => {
        logger.debug('Token for (%s, %s, %s) provided', code, state, host, {});
        respond.success(tokens);
      }).catch(error => {
        logger.error('Token for (%s, %s, %s) failed: %s', code, state, host, error.message || error, {});
        respond.error(error);
      });
    } else {
      const error = new Error('No code supplied');
      logger.error('Token for (%s, %s, %s) failed: %s', code, state, host, error.message || error, {});
      respond.error(error);
    }
  },
  jwks: () => {
    const jwks = openid.getJwks();
    logger.info('Providing access to JWKS: %j', jwks, {});
    respond.success(jwks);
  },
  openIdConfiguration: host => {
    const config = openid.getConfigFor(host);
    logger.info('Providing configuration for %s: %j', host, config, {});
    respond.success(config);
  }
});

/***/ }),

/***/ "./src/connectors/logger.js":
/*!**********************************!*\
  !*** ./src/connectors/logger.js ***!
  \**********************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

const winston = __webpack_require__(/*! winston */ "winston");
const {
  SPLUNK_URL,
  SPLUNK_TOKEN,
  SPLUNK_SOURCE,
  SPLUNK_SOURCETYPE,
  SPLUNK_INDEX
} = __webpack_require__(/*! ../config */ "./src/config.js");
const logger = winston.createLogger({
  level: 'info'
});

// Activate Splunk logging if Splunk's env variables are set
if (SPLUNK_URL) {
  const SplunkStreamEvent = __webpack_require__(/*! winston-splunk-httplogger */ "winston-splunk-httplogger"); // eslint-disable-line global-require

  const splunkSettings = {
    url: SPLUNK_URL || 'localhost',
    token: SPLUNK_TOKEN,
    source: SPLUNK_SOURCE || '/var/log/GHOIdShim.log',
    sourcetype: SPLUNK_SOURCETYPE || 'github-cognito-openid-wrapper',
    index: SPLUNK_INDEX || 'main',
    maxBatchCount: 1
  };
  logger.add(new SplunkStreamEvent({
    splunk: splunkSettings,
    format: winston.format.combine(winston.format.splat(), winston.format.timestamp())
  }));
} else {
  // STDOUT logging for dev/regular servers
  logger.add(new winston.transports.Console({
    format: winston.format.combine(winston.format.splat(), winston.format.colorize({
      all: true
    }), winston.format.simple())
  }));
}
module.exports = logger;

/***/ }),

/***/ "./src/connectors/web/auth.js":
/*!************************************!*\
  !*** ./src/connectors/web/auth.js ***!
  \************************************/
/***/ ((module) => {

module.exports = {
  getBearerToken: req => new Promise((resolve, reject) => {
    // This method implements https://tools.ietf.org/html/rfc6750
    const authHeader = req.get('Authorization');
    if (authHeader) {
      // Section 2.1 Authorization request header
      // Should be of the form 'Bearer <token>'
      // We can ignore the 'Bearer ' bit
      resolve(authHeader.split(' ')[1]);
    } else if (req.query.access_token) {
      // Section 2.3 URI query parameter
      resolve(req.query.access_token);
    } else if (req.get('Content-Type') === 'application/x-www-form-urlencoded') {
      // Section 2.2 form encoded body parameter
      resolve(req.body.access_token);
    }
    reject(new Error('No token specified in request'));
  }),
  getIssuer: host => `${host}`
};

/***/ }),

/***/ "./src/connectors/web/handlers.js":
/*!****************************************!*\
  !*** ./src/connectors/web/handlers.js ***!
  \****************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

const responder = __webpack_require__(/*! ./responder */ "./src/connectors/web/responder.js");
const auth = __webpack_require__(/*! ./auth */ "./src/connectors/web/auth.js");
const controllers = __webpack_require__(/*! ../controllers */ "./src/connectors/controllers.js");
module.exports = {
  userinfo: (req, res) => {
    controllers(responder(res)).userinfo(auth.getBearerToken(req));
  },
  token: (req, res) => {
    const code = req.body.code || req.query.code;
    const state = req.body.state || req.query.state;
    controllers(responder(res)).token(code, state, req.get('host'));
  },
  jwks: (req, res) => controllers(responder(res)).jwks(),
  authorize: (req, res) => responder(res).redirect(`https://github.com/login/oauth/authorize?client_id=${req.query.client_id}&scope=${req.query.scope}&state=${req.query.state}&response_type=${req.query.response_type}`),
  openIdConfiguration: (req, res) => {
    controllers(responder(res)).openIdConfiguration(auth.getIssuer(req.get('host')));
  }
};

/***/ }),

/***/ "./src/connectors/web/responder.js":
/*!*****************************************!*\
  !*** ./src/connectors/web/responder.js ***!
  \*****************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

const util = __webpack_require__(/*! util */ "util");
__webpack_require__(/*! colors */ "colors");
module.exports = res => ({
  success: data => {
    res.format({
      'application/json': () => {
        res.json(data);
      },
      default: () => {
        res.status(406).send('Not Acceptable');
      }
    });
  },
  error: error => {
    res.statusCode = 400;
    res.end(`Failure: ${util.inspect(error.message)}`);
  },
  redirect: url => res.redirect(url)
});

/***/ }),

/***/ "./src/connectors/web/routes.js":
/*!**************************************!*\
  !*** ./src/connectors/web/routes.js ***!
  \**************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

const handlers = __webpack_require__(/*! ./handlers */ "./src/connectors/web/handlers.js");
module.exports = app => {
  app.get('/userinfo', handlers.userinfo);
  app.post('/userinfo', handlers.userinfo);
  app.get('/token', handlers.token);
  app.post('/token', handlers.token);
  app.get('/authorize', handlers.authorize);
  app.post('/authorize', handlers.authorize);
  app.get('/jwks.json', handlers.jwks);
  app.get('/.well-known/jwks.json', handlers.jwks);
  app.get('/.well-known/openid-configuration', handlers.openIdConfiguration);
};

/***/ }),

/***/ "./src/crypto.js":
/*!***********************!*\
  !*** ./src/crypto.js ***!
  \***********************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

const JSONWebKey = __webpack_require__(/*! json-web-key */ "json-web-key");
const jwt = __webpack_require__(/*! jsonwebtoken */ "jsonwebtoken");
const {
  GITHUB_CLIENT_ID
} = __webpack_require__(/*! ./config */ "./src/config.js");
const logger = __webpack_require__(/*! ./connectors/logger */ "./src/connectors/logger.js");
const KEY_ID = 'jwtRS256';
const cert = __webpack_require__(/*! ../jwtRS256.key */ "./jwtRS256.key");
const pubKey = __webpack_require__(/*! ../jwtRS256.key.pub */ "./jwtRS256.key.pub");
module.exports = {
  getPublicKey: () => ({
    alg: 'RS256',
    kid: KEY_ID,
    ...JSONWebKey.fromPEM(pubKey).toJSON()
  }),
  makeIdToken: (payload, host) => {
    const enrichedPayload = {
      ...payload,
      iss: `https://${host}`,
      aud: GITHUB_CLIENT_ID
    };
    logger.debug('Signing payload %j', enrichedPayload, {});
    return jwt.sign(enrichedPayload, cert, {
      expiresIn: '1h',
      algorithm: 'RS256',
      keyid: KEY_ID
    });
  }
};

/***/ }),

/***/ "./src/github.js":
/*!***********************!*\
  !*** ./src/github.js ***!
  \***********************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

const axios = __webpack_require__(/*! axios */ "axios");
const {
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  COGNITO_REDIRECT_URI,
  GITHUB_API_URL,
  GITHUB_LOGIN_URL
} = __webpack_require__(/*! ./config */ "./src/config.js");
const logger = __webpack_require__(/*! ./connectors/logger */ "./src/connectors/logger.js");
const getApiEndpoints = (apiBaseUrl = GITHUB_API_URL, loginBaseUrl = GITHUB_LOGIN_URL) => ({
  userDetails: `${apiBaseUrl}/user`,
  userEmails: `${apiBaseUrl}/user/emails`,
  oauthToken: `${loginBaseUrl}/login/oauth/access_token`,
  oauthAuthorize: `${loginBaseUrl}/login/oauth/authorize`
});
const check = response => {
  logger.debug('Checking response: %j', response, {});
  if (response.data) {
    if (response.data.error) {
      throw new Error(`GitHub API responded with a failure: ${response.data.error}, ${response.data.error_description}`);
    } else if (response.status === 200) {
      return response.data;
    }
  }
  throw new Error(`GitHub API responded with a failure: ${response.status} (${response.statusText})`);
};
const gitHubGet = (url, accessToken) => axios({
  method: 'get',
  url,
  headers: {
    Accept: 'application/vnd.github.v3+json',
    Authorization: `token ${accessToken}`
  }
});
module.exports = (apiBaseUrl, loginBaseUrl) => {
  const urls = getApiEndpoints(apiBaseUrl, loginBaseUrl || apiBaseUrl);
  return {
    getAuthorizeUrl: (client_id, scope, state, response_type) => `${urls.oauthAuthorize}?client_id=${client_id}&scope=${encodeURIComponent(scope)}&state=${state}&response_type=${response_type}`,
    getUserDetails: accessToken => gitHubGet(urls.userDetails, accessToken).then(check),
    getUserEmails: accessToken => gitHubGet(urls.userEmails, accessToken).then(check),
    getToken: (code, state) => {
      const data = {
        // OAuth required fields
        grant_type: 'authorization_code',
        redirect_uri: COGNITO_REDIRECT_URI,
        client_id: GITHUB_CLIENT_ID,
        // GitHub Specific
        response_type: 'code',
        client_secret: GITHUB_CLIENT_SECRET,
        code,
        // State may not be present, so we conditionally include it
        ...(state && {
          state
        })
      };
      logger.debug('Getting token from %s with data: %j', urls.oauthToken, data, {});
      return axios({
        method: 'post',
        url: urls.oauthToken,
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json'
        },
        data
      }).then(check);
    }
  };
};

/***/ }),

/***/ "./src/helpers.js":
/*!************************!*\
  !*** ./src/helpers.js ***!
  \************************/
/***/ ((module) => {

module.exports = {
  NumericDate: date => Math.floor(date / 1000)
};

/***/ }),

/***/ "./src/openid.js":
/*!***********************!*\
  !*** ./src/openid.js ***!
  \***********************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

const logger = __webpack_require__(/*! ./connectors/logger */ "./src/connectors/logger.js");
const {
  NumericDate
} = __webpack_require__(/*! ./helpers */ "./src/helpers.js");
const crypto = __webpack_require__(/*! ./crypto */ "./src/crypto.js");
const github = __webpack_require__(/*! ./github */ "./src/github.js");
const getJwks = () => ({
  keys: [crypto.getPublicKey()]
});
const getUserInfo = accessToken => Promise.all([github().getUserDetails(accessToken).then(userDetails => {
  logger.debug('Fetched user details: %j', userDetails, {});
  // Here we map the github user response to the standard claims from
  // OpenID. The mapping was constructed by following
  // https://developer.github.com/v3/users/
  // and http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
  const claims = {
    sub: `${userDetails.id}`,
    // OpenID requires a string
    name: userDetails.name,
    preferred_username: userDetails.login,
    profile: userDetails.html_url,
    picture: userDetails.avatar_url,
    website: userDetails.blog,
    updated_at: NumericDate(
    // OpenID requires the seconds since epoch in UTC
    new Date(Date.parse(userDetails.updated_at)))
  };
  logger.debug('Resolved claims: %j', claims, {});
  return claims;
}), github().getUserEmails(accessToken).then(userEmails => {
  logger.debug('Fetched user emails: %j', userEmails, {});
  const primaryEmail = userEmails.find(email => email.primary);
  if (primaryEmail === undefined) {
    throw new Error('User did not have a primary email address');
  }
  const claims = {
    email: primaryEmail.email,
    email_verified: primaryEmail.verified
  };
  logger.debug('Resolved claims: %j', claims, {});
  return claims;
})]).then(claims => {
  const mergedClaims = claims.reduce((acc, claim) => ({
    ...acc,
    ...claim
  }), {});
  logger.debug('Resolved combined claims: %j', mergedClaims, {});
  return mergedClaims;
});
const getAuthorizeUrl = (client_id, scope, state, response_type) => github().getAuthorizeUrl(client_id, scope, state, response_type);
const getTokens = (code, state, host) => github().getToken(code, state).then(githubToken => {
  logger.debug('Got token: %s', githubToken, {});
  // GitHub returns scopes separated by commas
  // But OAuth wants them to be spaces
  // https://tools.ietf.org/html/rfc6749#section-5.1
  // Also, we need to add openid as a scope,
  // since GitHub will have stripped it
  const scope = `openid ${githubToken.scope.replace(',', ' ')}`;

  // ** JWT ID Token required fields **
  // iss - issuer https url
  // aud - audience that this token is valid for (GITHUB_CLIENT_ID)
  // sub - subject identifier - must be unique
  // ** Also required, but provided by jsonwebtoken **
  // exp - expiry time for the id token (seconds since epoch in UTC)
  // iat - time that the JWT was issued (seconds since epoch in UTC)

  return new Promise(resolve => {
    const payload = {
      // This was commented because Cognito times out in under a second
      // and generating the userInfo takes too long.
      // It means the ID token is empty except for metadata.
      //  ...userInfo,
    };
    const idToken = crypto.makeIdToken(payload, host);
    const tokenResponse = {
      ...githubToken,
      scope,
      id_token: idToken
    };
    logger.debug('Resolved token response: %j', tokenResponse, {});
    resolve(tokenResponse);
  });
});
const getConfigFor = host => ({
  issuer: `https://${host}`,
  authorization_endpoint: `https://${host}/authorize`,
  token_endpoint: `https://${host}/token`,
  token_endpoint_auth_methods_supported: ['client_secret_basic', 'private_key_jwt'],
  token_endpoint_auth_signing_alg_values_supported: ['RS256'],
  userinfo_endpoint: `https://${host}/userinfo`,
  // check_session_iframe: 'https://server.example.com/connect/check_session',
  // end_session_endpoint: 'https://server.example.com/connect/end_session',
  jwks_uri: `https://${host}/.well-known/jwks.json`,
  // registration_endpoint: 'https://server.example.com/connect/register',
  scopes_supported: ['openid', 'read:user', 'user:email'],
  response_types_supported: ['code', 'code id_token', 'id_token', 'token id_token'],
  subject_types_supported: ['public'],
  userinfo_signing_alg_values_supported: ['none'],
  id_token_signing_alg_values_supported: ['RS256'],
  request_object_signing_alg_values_supported: ['none'],
  display_values_supported: ['page', 'popup'],
  claims_supported: ['sub', 'name', 'preferred_username', 'profile', 'picture', 'website', 'email', 'email_verified', 'updated_at', 'iss', 'aud']
});
module.exports = {
  getTokens,
  getUserInfo,
  getJwks,
  getConfigFor,
  getAuthorizeUrl
};

/***/ }),

/***/ "./src/validate-config.js":
/*!********************************!*\
  !*** ./src/validate-config.js ***!
  \********************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

const config = __webpack_require__(/*! ./config */ "./src/config.js");
const ensureString = variableName => {
  if (typeof config[variableName] !== 'string') {
    throw new Error(`Environment variable ${variableName} must be set and be a string`);
  }
};
const ensureNumber = variableName => {
  if (typeof config[variableName] !== 'number') {
    throw new Error(`Environment variable ${variableName} must be set and be a number`);
  }
};
const requiredStrings = ['GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET', 'COGNITO_REDIRECT_URI'];
const requiredNumbers = ['PORT'];
module.exports = () => {
  requiredStrings.forEach(ensureString);
  requiredNumbers.forEach(ensureNumber);
};

/***/ }),

/***/ "./jwtRS256.key":
/*!**********************!*\
  !*** ./jwtRS256.key ***!
  \**********************/
/***/ ((module) => {

module.exports = "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n"

/***/ }),

/***/ "./jwtRS256.key.pub":
/*!**************************!*\
  !*** ./jwtRS256.key.pub ***!
  \**************************/
/***/ ((module) => {

module.exports = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuDhX6/fkDEVJTRJR0UDb\njysAaF7nSDlXXkmkRZGAcd5Bq/ehpRLEbvBURo53V1MfZZYlohd/usshokzoidaI\nM+kT1niqAUJ8jLakaCR7pBPDYe4Fjm3H9+A2lwoH6DDBsHSqt2l5+QzS5Uinhf9d\nAshovZAWvdJC8L9E9mS+p1ZAtbgGteqiBRC2LI+nqTNmYe+tmyMeOXE0smaf7AKf\nPlIfByF5nEHET4Nn90mE0qzY0yr+u3905cYpKMEQRQA49yZWPtAjunSHLk3bHncb\noReHoHt+oyzP1fbWU7sdzCQIGnKJ4plMz9uExtd9CE8fmyKR5Xdu88txf7tL2H3y\nij8Wh1PzwBJiPKiWSGYYv6bUNJuHAo2/2wziB7kOQpYc8Rdaxr6AK7pO3ULpEpdi\nLk3loPp8x3eunk8OJ+7obD7yp5kCts7dnacZzNGFaRAiRsi8OjXIjpbS1STnj/yX\nh2j27fbHK+UE68NijJMphjRXvzX+LHcmWF2Zy4cExvPmoCfVOlnpenoYlVN4DIFX\nGLbl7t6+Mm3LPYJI6iWCewtgnjrRR+TP+1LIRHRh9EjGrjN8ud8yAnjermR7+buL\nrFVxMeC5TkZrxpv57BBDnUY3PAgWsv8jiIwWNcqJmKTYM8Qt+8KMMwmJ1rZhaSmu\n9nd3oJFGsyB/CwF82bL3Eq0CAwEAAQ==\n-----END PUBLIC KEY-----\n"

/***/ }),

/***/ "axios":
/*!************************!*\
  !*** external "axios" ***!
  \************************/
/***/ ((module) => {

"use strict";
module.exports = require("axios");

/***/ }),

/***/ "body-parser":
/*!******************************!*\
  !*** external "body-parser" ***!
  \******************************/
/***/ ((module) => {

"use strict";
module.exports = require("body-parser");

/***/ }),

/***/ "colors":
/*!*************************!*\
  !*** external "colors" ***!
  \*************************/
/***/ ((module) => {

"use strict";
module.exports = require("colors");

/***/ }),

/***/ "express":
/*!**************************!*\
  !*** external "express" ***!
  \**************************/
/***/ ((module) => {

"use strict";
module.exports = require("express");

/***/ }),

/***/ "json-web-key":
/*!*******************************!*\
  !*** external "json-web-key" ***!
  \*******************************/
/***/ ((module) => {

"use strict";
module.exports = require("json-web-key");

/***/ }),

/***/ "jsonwebtoken":
/*!*******************************!*\
  !*** external "jsonwebtoken" ***!
  \*******************************/
/***/ ((module) => {

"use strict";
module.exports = require("jsonwebtoken");

/***/ }),

/***/ "winston":
/*!**************************!*\
  !*** external "winston" ***!
  \**************************/
/***/ ((module) => {

"use strict";
module.exports = require("winston");

/***/ }),

/***/ "winston-splunk-httplogger":
/*!********************************************!*\
  !*** external "winston-splunk-httplogger" ***!
  \********************************************/
/***/ ((module) => {

"use strict";
module.exports = require("winston-splunk-httplogger");

/***/ }),

/***/ "util":
/*!***********************!*\
  !*** external "util" ***!
  \***********************/
/***/ ((module) => {

"use strict";
module.exports = require("util");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
/*!***********************************!*\
  !*** ./src/connectors/web/app.js ***!
  \***********************************/
const express = __webpack_require__(/*! express */ "express");
const bodyParser = __webpack_require__(/*! body-parser */ "body-parser");
const routes = __webpack_require__(/*! ./routes */ "./src/connectors/web/routes.js");
const {
  PORT
} = __webpack_require__(/*! ../../config */ "./src/config.js");
const validateConfig = __webpack_require__(/*! ../../validate-config */ "./src/validate-config.js");
__webpack_require__(/*! colors */ "colors");
const app = express();
try {
  validateConfig();
} catch (e) {
  console.error('Failed to start:'.red, e.message);
  console.error('  See the readme for configuration information');
  process.exit(1);
}
console.info('Config is valid'.cyan);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: true
}));
routes(app);
app.listen(PORT);
console.info(`Listening on ${PORT}`.cyan);
})();

module.exports = __webpack_exports__;
/******/ })()
;
//# sourceMappingURL=server.js.map