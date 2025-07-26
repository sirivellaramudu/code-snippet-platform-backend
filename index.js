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
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// Parse ALLOWED_ORIGINS safely with detailed logging
const parseAllowedOrigins = () => {
  console.log('Starting parseAllowedOrigins');
  try {
    console.log('Raw ALLOWED_ORIGINS:', JSON.stringify(process.env.ALLOWED_ORIGINS));
    console.log('Raw FRONTEND_URL:', JSON.stringify(process.env.FRONTEND_URL));
    
    // Default to localhost if nothing is set
    const defaultOrigins = ['http://localhost:3000'];
    const originsString = process.env.ALLOWED_ORIGINS || process.env.FRONTEND_URL || '';
    
    if (!originsString) {
      console.warn('No origins configured, using defaults:', defaultOrigins);
      return defaultOrigins;
    }
    
    const origins = originsString
      .split(',')
      .map(o => o.trim())
      .filter(Boolean);
    
    console.log('Processed origins array:', JSON.stringify(origins, null, 2));
    
    // Validate each URL
    const validOrigins = [];
    for (const origin of origins) {
      try {
        // Skip empty strings
        if (!origin) continue;
        
        // Basic URL validation
        if (!origin.match(/^https?:\/\//)) {
          console.error(`Invalid URL protocol in origin: ${origin}`);
          continue;
        }
        
        // Create URL object to validate format
        const url = new URL(origin);
        const originToAdd = url.origin || origin;
        
        if (!validOrigins.includes(originToAdd)) {
          validOrigins.push(originToAdd);
          console.log(`Added valid origin: ${originToAdd}`);
        }
      } catch (e) {
        console.error(`Invalid URL in origins: ${origin}`, e.message);
      }
    }
    
    if (validOrigins.length === 0) {
      console.warn('No valid origins found, using defaults:', defaultOrigins);
      return defaultOrigins;
    }
    
    console.log('Final valid origins:', JSON.stringify(validOrigins, null, 2));
    return validOrigins;
    
  } catch (e) {
    console.error('Fatal error in parseAllowedOrigins:', e);
    return ['http://localhost:3000'];
  }
};

// Initialize allowed origins
console.log('Initializing allowed origins...');
const allowedOrigins = parseAllowedOrigins();

// Simple CORS middleware that logs all requests
const corsMiddleware = (req, res, next) => {
  console.log(`\n--- New Request: ${req.method} ${req.originalUrl} ---`);
  console.log('Origin:', req.headers.origin || 'No origin header');
  
  // Always set Vary header
  res.header('Vary', 'Origin');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    console.log('Handling OPTIONS preflight request');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    return res.status(200).end();
  }
  
  // Handle regular requests
  const origin = req.headers.origin;
  if (origin) {
    try {
      const originUrl = new URL(origin);
      const isAllowed = allowedOrigins.some(allowedOrigin => {
        try {
          const allowedUrl = new URL(allowedOrigin);
          return originUrl.origin === allowedUrl.origin;
        } catch (e) {
          console.error('Error comparing URLs:', e.message);
          return false;
        }
      });
      
      // Special handling for OAuth providers
      const isOAuthProvider = origin.includes('accounts.google.com') || 
                            origin.includes('google.com') ||
                            origin.includes('login.microsoftonline.com');
      
      if (isAllowed || isOAuthProvider) {
        console.log(`Allowing CORS for origin: ${origin}`);
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Access-Control-Allow-Credentials', 'true');
      } else {
        console.warn(`CORS blocked for origin: ${origin}`);
      }
    } catch (e) {
      console.error('Error processing origin:', e);
    }
  }
  
  next();
};

// Apply CORS middleware before other middleware
// --- CORS Configuration ---
// Get the allowed origins from environment variables.
// Your parseAllowedOrigins function is good, so we'll keep using it.

// Log the final origins being used for CORS
console.log('CORS will be configured for these origins:', allowedOrigins);

// Use the cors middleware with the correct options
app.use(cors({
  // The origin property takes the list of allowed domains
  origin: allowedOrigins,
  
  // This is crucial for your authentication to work
  credentials: true
}));
app.use(express.json());

// Session configuration
const sessionConfig = {
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
    httpOnly: true, // Prevent client-side JavaScript access
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // Required for cross-site cookies
    maxAge: 24 * 60 * 60 * 1000, // 24 hours

  },
  name: 'code-snippet-platform.sid', // Custom session cookie name
  rolling: true, // Reset maxAge on every request
  proxy: process.env.NODE_ENV === 'production' // Trust proxy in production
};



// Apply session middleware
app.use(session(sessionConfig));
console.log('Session configuration:', {
  secure: sessionConfig.cookie.secure,
  sameSite: sessionConfig.cookie.sameSite,
  httpOnly: sessionConfig.cookie.httpOnly,
  domain: sessionConfig.cookie.domain
});

// Initialize Passport and restore authentication state from session
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((user, done) => {
  done(null, user);
});

// Google SSO
const googleCallbackUrl = process.env.GOOGLE_CALLBACK_URL || 
  `${process.env.BASE_URL || 'http://localhost:4000'}/auth/google/callback`;

console.log('Google OAuth Configuration:', {
  clientID: process.env.GOOGLE_CLIENT_ID ? '***SET***' : 'MISSING',
  callbackURL: googleCallbackUrl,
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000'
});

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: googleCallbackUrl,
  proxy: process.env.NODE_ENV === 'production', // Trust proxy in production
  passReqToCallback: true
}, (req, accessToken, refreshToken, profile, done) => {
  try {
    console.log('Google OAuth profile received:', {
      id: profile.id,
      email: profile.emails?.[0]?.value,
      name: profile.displayName
    });
    
    // Add the user's profile information to the session
    const user = {
      provider: 'google',
      id: profile.id,
      email: profile.emails?.[0]?.value,
      name: profile.displayName,
      picture: profile.photos?.[0]?.value,
      ...profile._json
    };
    
    return done(null, user);
  } catch (error) {
    console.error('Error in Google OAuth callback:', error);
    return done(error, null);
  }
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

// --- Request Logging Middleware ---
app.use((req, res, next) => {
  const start = Date.now();
  
  // Log the request
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`, {
    headers: req.headers,
    query: req.query,
    body: req.body,
  });
  
  // Capture the response finish event to log the response
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} - ${res.statusCode} ${res.statusMessage} - ${duration}ms`);
  });
  
  next();
});

// --- Error Handling Middleware ---
app.use((err, req, res, next) => {
  console.error(`[${new Date().toISOString()}] Error:`, {
    message: err.message,
    stack: process.env.NODE_ENV === 'production' ? undefined : err.stack,
    url: req.originalUrl,
    method: req.method,
    headers: req.headers,
    body: req.body,
    query: req.query,
    params: req.params
  });

  // Handle CORS errors
  if (err.message.includes('CORS')) {
    return res.status(403).json({
      error: 'Not allowed by CORS',
      message: err.message,
      allowedOrigins: process.env.ALLOWED_ORIGINS || process.env.FRONTEND_URL
    });
  }

  // Handle authentication errors
  if (err.name === 'AuthenticationError' || err.status === 401) {
    return res.status(401).json({
      error: 'Authentication failed',
      message: err.message || 'Invalid credentials or session expired'
    });
  }

  // Handle validation errors
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      error: 'Validation Error',
      details: err.details || err.message
    });
  }

  // Default error response
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal Server Error' : err.message,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
  });
});

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
    origin: allowedOrigins,
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
  const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
  res.redirect(FRONTEND_URL); // Redirect to frontend after login
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
  const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
  res.redirect(FRONTEND_URL);
});

app.get('/auth/logout', (req, res) => {
  req.logout(() => {
    const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
  res.redirect(FRONTEND_URL);
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

// 404 Handler - Must be after all other routes
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: `Cannot ${req.method} ${req.originalUrl}`
  });
});

// --- Server Startup ---
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`CORS Allowed Origins: ${process.env.ALLOWED_ORIGINS || process.env.FRONTEND_URL || 'http://localhost:3000'}`);
  console.log(`Frontend URL: ${process.env.FRONTEND_URL || 'http://localhost:3000'}`);
  console.log('Available Routes:');
  // Log available routes
  const routes = [];
  app._router.stack.forEach((middleware) => {
    if (middleware.route) {
      routes.push({
        path: middleware.route.path,
        methods: Object.keys(middleware.route.methods).filter(m => m !== '_all')
      });
    } else if (middleware.name === 'router') {
      middleware.handle.stack.forEach(handler => {
        if (handler.route) {
          routes.push({
            path: handler.route.path,
            methods: Object.keys(handler.route.methods).filter(m => m !== '_all')
          });
        }
      });
    }
  });
  console.table(routes);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Consider sending to error tracking service
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  // Consider performing cleanup and exiting
  // process.exit(1); // Exit with failure
});
