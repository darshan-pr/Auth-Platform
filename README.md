# Auth Platform

A microservice for authentication and authorization using OTP, JWT tokens, and multi-tenant apps.

## Features

- Admin login and app management
- OTP-based authentication
- JWT tokens (RS256) with refresh tokens
- Multi-tenant app support with app_id/app_secret
- PostgreSQL database
- Redis caching
- SMTP email sending

## Quick Start

### Prerequisites
- Python 3.8+
- PostgreSQL
- Redis
- Node.js (optional, for development)

### Setup

1. Clone the repository
2. Install dependencies:
   ```bash
   cd backend
   pip install -r requirements.txt
   ```
3. Set up PostgreSQL and Redis
4. Configure `.env` file (copy from `.env.example`)
5. Run all services:
   ```bash
   ./run.sh
   ```

## Running Services

The `run.sh` script supports multiple commands:

```bash
# Start all services (backend, admin console, sample app)
./run.sh all

# Start only the backend API
./run.sh backend

# Start only the admin console
./run.sh admin

# Start only the sample app
./run.sh sample-app

# Stop all services
./run.sh stop

# Show help
./run.sh help
```

### Service URLs

| Service | URL | Description |
|---------|-----|-------------|
| Backend API | http://localhost:8000 | FastAPI backend |
| API Docs | http://localhost:8000/docs | Swagger documentation |
| Admin Console | http://localhost:3000 | Admin management UI |
| Sample App | http://localhost:3001 | Demo application |

## Architecture

### Backend API Endpoints

- `POST /auth/request-otp` - Request OTP (with optional app credentials)
- `POST /auth/verify-otp` - Verify OTP and get tokens
- `POST /token/refresh` - Refresh access token
- `POST /token/verify` - Verify token validity
- `GET /admin/apps` - List registered apps
- `POST /admin/apps` - Create new app
- `GET /admin/users` - List users
- `GET /admin/stats` - Dashboard statistics
- `GET /health` - Health check

### Sample App Flow

1. **Setup**: On first run, the sample app shows a setup page where you can:
   - Register a new app with the Auth Platform
   - Or use existing app credentials

2. **Authentication**: Once configured, users can:
   - Enter their email to receive OTP
   - Verify OTP to get JWT tokens
   - View token info and test token operations

3. **Token Management**: 
   - Access tokens expire in 15 minutes
   - Refresh tokens expire in 7 days
   - Tokens include app_id when authenticated via registered app

## Environment Variables

Create a `.env` file with:

```env
DATABASE_URL=postgresql://user:password@localhost:5432/auth_platform
REDIS_URL=redis://localhost:6379
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

## Development

### Project Structure

```
auth-platform/
├── backend/
│   ├── app/
│   │   ├── api/          # API routes
│   │   ├── models/       # SQLAlchemy models
│   │   ├── schemas/      # Pydantic schemas
│   │   └── services/     # Business logic
│   └── keys/             # JWT RSA keys
├── frontend/
│   └── admin-console/    # Admin UI
├── sample-app/           # Demo application
└── run.sh               # Service runner
```

### Adding a New Client App

1. Use the Admin Console to create a new app
2. Save the `app_id` and `app_secret`
3. In your app, include these in auth requests:
   ```javascript
   fetch('/auth/request-otp', {
       method: 'POST',
       body: JSON.stringify({
           email: 'user@example.com',
           app_id: 'your-app-id',
           app_secret: 'your-app-secret'
       })
   });
   ```

## License

MIT