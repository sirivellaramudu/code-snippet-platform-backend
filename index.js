const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const axios = require('axios');
const cors = require('cors');
const dotenv = require('dotenv');
const passport = require('passport');
const session = require('express-session');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { OIDCStrategy } = require('passport-azure-ad');
dotenv.config();

// TEMPORARY: Disable SSL verification for development
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const app = express();
app.use(cors({
  origin: 'http://localhost:3000', // React dev server
  credentials: true
}));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((user, done) => {
  done(null, user);
});

// Google SSO
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || `${process.env.BASE_URL}/auth/google/callback`,
}, (accessToken, refreshToken, profile, done) => {
  return done(null, { provider: 'google', ...profile._json });
}));

// Microsoft SSO (only if credentials are present)
if (process.env.MICROSOFT_CLIENT_ID && process.env.MICROSOFT_CLIENT_SECRET) {
  passport.use(new OIDCStrategy({
    identityMetadata: 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
    clientID: process.env.MICROSOFT_CLIENT_ID,
    clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
    responseType: 'code',
    responseMode: 'query',
    redirectUrl: process.env.MICROSOFT_CALLBACK_URL || `${process.env.BASE_URL}/auth/microsoft/callback`,
    allowHttpForRedirectUrl: true,
    scope: ['profile', 'email', 'openid']
  }, (iss, sub, profile, accessToken, refreshToken, done) => {
    return done(null, { provider: 'microsoft', ...profile });
  }));
} else {
  console.log('Microsoft SSO is disabled: MICROSOFT_CLIENT_ID or MICROSOFT_CLIENT_SECRET not set');
}


const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: 'Unauthorized' });
};

const PORT = process.env.PORT || 4000;
const server = http.createServer(app);
const io = require('socket.io')(server, {
  cors: {
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST'],
    credentials: true
  }
});



// --- SSO ROUTES ---
app.get('/auth/google', (req, res, next) => {
  console.log('HIT /auth/google');
  next();
}, passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', (req, res, next) => {
  console.log('HIT /auth/google/callback');
  next();
}, passport.authenticate('google', {
  failureRedirect: '/login-failed',
  session: true
}), (req, res) => {
  console.log('GOOGLE LOGIN SUCCESS', req.user);
  res.redirect('http://localhost:3000'); // Redirect to frontend after login
});

// Test route to verify backend is running
app.get('/test', (req, res) => {
  res.json({ status: 'Backend is running' });
});

app.get('/auth/microsoft', passport.authenticate('azuread-openidconnect'));

app.post('/auth/microsoft/callback', passport.authenticate('azuread-openidconnect', {
  failureRedirect: '/login-failed',
  session: true
}), (req, res) => {
  res.redirect('http://localhost:3000');
});

app.get('/auth/logout', (req, res) => {
  req.logout(() => {
    res.redirect('http://localhost:3000');
  });
});

app.get('/auth/user', (req, res) => {
  if (req.isAuthenticated()) {
    res.json(req.user);
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
});


// --- Real-time code sharing with per-room state ---
const roomCodeState = {};

io.on('connection', (socket) => {
  console.log('New client connected');

  socket.on('join-room', ({ roomId, language }) => {
    socket.join(roomId);
    // If the room has no code, set to starter code for language
    if (!roomCodeState[roomId]) {
      const STARTER_CODE = {
        python3: 'print("Hello, World!")',
        java: 'public class Main {\n    public static void main(String[] args) {\n        System.out.println("Hello, World!");\n    }\n}',
        c: '#include <stdio.h>\n\nint main() {\n    printf("Hello, World!\\n");\n    return 0;\n}',
        cpp: '#include <iostream>\nusing namespace std;\n\nint main() {\n    cout << "Hello, World!" << endl;\n    return 0;\n}',
      };
      roomCodeState[roomId] = STARTER_CODE[language] || '';
    }
    socket.emit('code-update', roomCodeState[roomId]);
  });

  // User cursor sync
  socket.on('cursor-change', ({ roomId, userId, position, color, label }) => {
    socket.to(roomId).emit('cursor-update', { userId, position, color, label });
  });

  socket.on('code-change', ({ roomId, code }) => {
    roomCodeState[roomId] = code;
    socket.to(roomId).emit('code-update', code);
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected');
    // Optionally: broadcast cursor removal
  });
});

// JDoodle code execution endpoint
app.post('/execute', async (req, res) => {
  const { script, language } = req.body || {};

  if (!script || !language) {
    return res.status(400).json({ error: 'Missing script or language in request body' });
  }

  const payload = {
    clientId: process.env.JDOODLE_CLIENT_ID,
    clientSecret: process.env.JDOODLE_CLIENT_SECRET,
    script,
    language,
    versionIndex: '0',
  };

  console.log('Sending to JDoodle:', payload);

  try {
    const response = await axios.post('https://api.jdoodle.com/v1/execute', payload);
    res.json(response.data);
  } catch (error) {
    console.error('JDoodle API error:', error.response?.status, error.response?.data || error.message);
    res.status(error.response?.status || 500).json({
      error: 'Code execution failed',
      details: error.response?.data || error.message,
    });
  }
});

server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
