# Auth Platform

A self-hosted authentication microservice providing OAuth 2.0 Authorization Code Flow with PKCE, OTP verification, JWT token management (RS256), and multi-tenant application support.

> **Quick Start**: See [QUICK_START.md](QUICK_START.md) for step-by-step setup instructions

## Features

- **OAuth 2.0 + PKCE** &mdash; Secure authorization code flow, no client secrets on the frontend
- **Hosted Login Page** &mdash; Auth platform renders its own login UI (like Google, GitHub)
- **Password + OTP** &mdash; Password-based auth with optional email OTP verification
- **JWT Tokens (RS256)** &mdash; Asymmetric key signing, configurable expiry per app
- **Multi-Tenant** &mdash; Register multiple apps, each with its own settings and users
- **Admin Console** &mdash; Password-protected dashboard to manage apps and users
- **Auto Token Refresh** &mdash; JS SDK handles token lifecycle automatically

## Quick Start

### Prerequisites

- Python 3.8+
- PostgreSQL
- Redis

### Setup

```bash
# 1. Clone and install dependencies
cd backend
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env   # Edit with your DB, Redis, SMTP settings

# 3. Start services
./run.sh
```

This starts the **Backend API** on port 8000 and the **Admin Console** on port 3000.

### Service URLs

| Service | URL |
|---------|-----|
| Backend API | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |
| Admin Console | http://localhost:3000 |

## Running Services

```bash
./run.sh              # Start all services (backend + admin console)
./run.sh backend      # Start only the backend API
./run.sh admin        # Start only the admin console
./run.sh stop         # Stop all services
./run.sh status       # Show service status
./run.sh help         # Show help
```

## Admin Console

The admin console is password-protected. Default password: `Darsh@26`

From the console you can:

- View dashboard statistics (apps, users, active users)
- Create and manage OAuth applications (Client ID, redirect URIs, session settings)
- Manage users and their status
- View app credentials

## Architecture

```
auth-platform/
  backend/
    app/
      api/          # Route handlers (auth, admin, oauth, token, health)
      models/       # SQLAlchemy models (user, app, refresh_token)
      schemas/      # Pydantic request/response schemas
      services/     # Business logic (JWT, OTP, OAuth, password, mail)
      templates/    # Hosted login page (Jinja2)
    keys/           # RSA key pair for JWT signing
    migrations/     # SQL migration scripts
  frontend/
    admin-console/  # Admin dashboard (vanilla JS + Lucide icons)
  sample-app/       # Example integration (Notes App)
  run.sh            # Service runner
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth/authorize` | GET | Start OAuth flow, renders hosted login page |
| `/oauth/authenticate` | POST | Verify credentials on the login page |
| `/oauth/token` | POST | Exchange authorization code for tokens (PKCE) |
| `/auth/request-otp` | POST | Request OTP for an email |
| `/auth/verify-otp` | POST | Verify OTP and get tokens |
| `/token/refresh` | POST | Refresh an access token |
| `/token/verify` | POST | Verify a token's validity |
| `/admin/apps` | GET/POST | List or create applications |
| `/admin/apps/{id}` | GET/PUT/DELETE | Manage a specific application |
| `/admin/users` | GET/POST | List or create users |
| `/admin/stats` | GET | Dashboard statistics |

## Integrating with Your App

### 1. Register your app

Open the Admin Console, create an application, and set the **Redirect URI** to your app's URL. You'll receive a **Client ID**.

### 2. Add the auth SDK

Copy `sample-app/config.js` and `sample-app/auth.js` into your project:

```html
<script src="config.js"></script>
<script src="auth.js"></script>
```

### 3. Configure

```javascript
// config.js
const AUTH_CONFIG = {
    AUTH_SERVER: 'http://localhost:8000',
    CLIENT_ID: 'your-client-id',
    REDIRECT_URI: window.location.origin + window.location.pathname,
};
```

### 4. Use

```javascript
const auth = new AuthClient(AUTH_CONFIG);

// Handle callback (on page load)
await auth.handleCallback();

if (auth.isAuthenticated()) {
    const user = auth.getUser();
    console.log('Logged in as', user.email);
    auth.startAutoRefresh();
} else {
    auth.login(); // Redirects to hosted login page
}
```

No secrets on the frontend. PKCE ensures security.

See `sample-app/README.md` for a complete integration example.

## Environment Variables

Create a `.env` file:

```env
DATABASE_URL=postgresql://user:password@localhost:5432/auth_platform
REDIS_URL=redis://localhost:6379
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

## Deployment

### Deploy to Railway

This project is ready for deployment on Railway. See the [Railway Deployment Guide](RAILWAY_DEPLOYMENT.md) for detailed instructions.

Quick deployment steps:
1. Push your code to GitHub
2. Create a new project on [Railway](https://railway.app)
3. Connect your repository
4. Add PostgreSQL and Redis databases
5. Configure environment variables
6. Deploy! 🚀

Railway automatically detects the configuration and deploys your application.

### Other Platforms

The application can be deployed to any platform that supports:
- Python 3.8+
- PostgreSQL database
- Redis instance
- Environment variable configuration

Consider: Heroku, Render, Fly.io, AWS, Google Cloud, Azure, etc.

## License

MIT