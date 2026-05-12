require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const { OIDCStrategy } = require('passport-azure-ad');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const { setupSwagger } = require('./swagger');

const app = express();

app.set('trust proxy', 1);

// ─── JWKS ─────────────────────────────────────────────────────────────────────
const jwks = jwksClient({
  jwksUri: `https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/discovery/keys`,
  cache: true,
  rateLimit: true,
});

function getKey(header, callback) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

// ─── Bearer Token Validator ────────────────────────────────────────────────────
const validateBearerToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next(); // no token → fall through to session check
  }

  const token = authHeader.split(' ')[1];
  jwt.verify(token, getKey, {
    audience: `api://${process.env.ENTRA_CLIENT_ID}`,
    issuer: [
      `https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/v2.0`,
      `https://sts.windows.net/${process.env.ENTRA_TENANT_ID}/`,
    ],
    algorithms: ['RS256'],
  }, (err, decoded) => {
    if (err) {
      console.error('JWT validation failed:', err.message);
      return res.status(401).json({ error: 'Invalid token' });
    }
    req.user = {
      id: decoded.sub,
      displayName: decoded.name || decoded.appid,
      email: decoded.preferred_username || decoded.upn || 'scanner@app',
      isServicePrincipal: true,
    };
    next();
  });
};

// ─── Core Middleware ───────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true,
}));

// ─── Swagger (public, before session/auth) ────────────────────────────────────
setupSwagger(app);

// ─── Session & Passport ────────────────────────────────────────────────────────
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'none',
    maxAge: 1000 * 60 * 60,
  },
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(validateBearerToken);

// ─── Passport / Entra ID Strategy ─────────────────────────────────────────────
const ENTRA_TENANT_ID     = process.env.ENTRA_TENANT_ID;
const ENTRA_CLIENT_ID     = process.env.ENTRA_CLIENT_ID;
const ENTRA_CLIENT_SECRET = process.env.ENTRA_CLIENT_SECRET;
const BACKEND_URL         = process.env.BACKEND_URL;
const FRONTEND_URL        = process.env.FRONTEND_URL || 'https://jesa.aymanekenbouch.online';

passport.use(new OIDCStrategy(
  {
    identityMetadata: `https://login.microsoftonline.com/${ENTRA_TENANT_ID}/v2.0/.well-known/openid-configuration`,
    clientID: ENTRA_CLIENT_ID,
    clientSecret: ENTRA_CLIENT_SECRET,
    responseType: 'code',
    responseMode: 'query',
    redirectUrl: `${BACKEND_URL}/auth/callback`,
    allowHttpForRedirectUrl: false,
    scope: ['openid', 'profile', 'email'],
    passReqToCallback: false,
    clockSkew: 300,
  },
  (iss, sub, profile, accessToken, refreshToken, done) => {
    return done(null, {
      id: profile.oid,
      displayName: profile.displayName,
      email: profile._json?.preferred_username || profile._json?.email,
      firstName: profile.name?.givenName,
      lastName: profile.name?.familyName,
    });
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ─── Auth Guard ────────────────────────────────────────────────────────────────
const isAuthenticated = (req, res, next) => {
  if (req.user) return next();           // set by Bearer token validator
  if (req.isAuthenticated()) return next(); // set by session (browser login)
  res.status(401).json({ error: 'Unauthorized' });
};

// ─── Routes ───────────────────────────────────────────────────────────────────

/**
 * @openapi
 * /auth/login:
 *   get:
 *     summary: Initiate Microsoft Entra ID login
 *     responses:
 *       302:
 *         description: Redirect to Microsoft login
 */
app.get('/auth/login', passport.authenticate('azuread-openidconnect', {
  prompt: 'select_account',
}));

/**
 * @openapi
 * /auth/callback:
 *   get:
 *     summary: OAuth callback from Microsoft Entra ID
 *     responses:
 *       302:
 *         description: Redirect to frontend on success
 */
app.get('/auth/callback', (req, res, next) => {
  passport.authenticate('azuread-openidconnect', (err, user, info) => {
    if (err)   { console.error('AUTH ERROR:', err);   return res.redirect('/auth/error'); }
    if (!user) { console.error('AUTH FAILED:', info); return res.redirect('/auth/error'); }
    req.logIn(user, (err2) => {
      if (err2) return next(err2);
      res.redirect(FRONTEND_URL);
    });
  })(req, res, next);
});

/**
 * @openapi
 * /auth/logout:
 *   get:
 *     summary: Logout and destroy session
 *     responses:
 *       302:
 *         description: Redirect to Microsoft logout
 */
app.get('/auth/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy();
    const logoutUrl =
      `https://login.microsoftonline.com/${ENTRA_TENANT_ID}/oauth2/v2.0/logout` +
      `?post_logout_redirect_uri=${encodeURIComponent(FRONTEND_URL)}`;
    res.redirect(logoutUrl);
  });
});

/**
 * @openapi
 * /auth/error:
 *   get:
 *     summary: Authentication error
 *     responses:
 *       401:
 *         description: Authentication failed
 */
app.get('/auth/error', (req, res) => {
  res.status(401).json({ error: 'Authentication failed' });
});

/**
 * @openapi
 * /api/me:
 *   get:
 *     summary: Get current authenticated user
 *     responses:
 *       200:
 *         description: User object or null
 */
app.get('/api/me', (req, res) => {
  res.json({ user: req.user || null });
});

/**
 * @openapi
 * /api/dashboard:
 *   get:
 *     summary: Protected dashboard endpoint
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Dashboard stats for authenticated user
 *       401:
 *         description: Unauthorized
 */
app.get('/api/dashboard', isAuthenticated, (req, res) => {
  res.json({
    message: `Welcome, ${req.user.displayName}!`,
    stats: {
      logins: Math.floor(Math.random() * 100) + 1,
      lastSeen: new Date().toISOString(),
      role: 'Member',
    },
  });
});

/**
 * @openapi
 * /health:
 *   get:
 *     summary: Health check
 *     responses:
 *       200:
 *         description: Server is up
 */
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));