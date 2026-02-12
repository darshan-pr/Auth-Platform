# Deploying Auth Platform on Railway

This guide walks you through deploying the Auth Platform on Railway.app.

## Prerequisites

- A [Railway](https://railway.app) account
- GitHub account (for connecting your repository)
- Your project code pushed to a GitHub repository

## Deployment Steps

### 1. Push Your Code to GitHub

```bash
cd /Users/darshanpr/Learning/MicroServices/auth-platform
git init
git add .
git commit -m "Initial commit for Railway deployment"
git remote add origin <your-github-repo-url>
git push -u origin main
```

### 2. Create a New Railway Project

1. Go to [Railway Dashboard](https://railway.app/dashboard)
2. Click **"New Project"**
3. Select **"Deploy from GitHub repo"**
4. Authorize Railway to access your GitHub repositories
5. Select your `auth-platform` repository

### 3. Add PostgreSQL Database

1. In your Railway project, click **"+ New"**
2. Select **"Database"** → **"PostgreSQL"**
3. Railway will automatically create a PostgreSQL database and set the `DATABASE_URL` environment variable

### 4. Add Redis

1. In your Railway project, click **"+ New"**
2. Select **"Database"** → **"Redis"**
3. Railway will automatically create a Redis instance and set the `REDIS_URL` environment variable

### 5. Configure Environment Variables

In your Railway project, go to your backend service → **Variables** tab and add:

#### Required Variables

```env
# Database (auto-configured by Railway PostgreSQL)
DATABASE_URL=<automatically set>

# Redis (auto-configured by Railway Redis)
REDIS_URL=<automatically set>

# JWT Secret (generate a secure random string)
JWT_SECRET=your-secure-jwt-secret-key-here

# SMTP Configuration for Email OTP
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# Optional: CORS Origins (comma-separated)
# ALLOWED_ORIGINS=https://yourdomain.com,https://admin.yourdomain.com
```

#### Generate a Secure JWT Secret

```bash
# Using OpenSSL
openssl rand -hex 32

# Using Python
python -c "import secrets; print(secrets.token_hex(32))"
```

#### Gmail SMTP Setup

For Gmail, you need to:
1. Enable 2-Factor Authentication on your Google account
2. Create an [App Password](https://myaccount.google.com/apppasswords)
3. Use the App Password as `SMTP_PASSWORD`

### 6. Deploy

Railway will automatically:
1. Detect your `Procfile` and `railway.toml`
2. Install dependencies from `backend/requirements.txt`
3. Start your application with the command in the Procfile
4. Assign a public URL to your service

### 7. Access Your Deployed Application

After deployment completes:
- Backend API: `https://<your-project>.up.railway.app`
- API Docs: `https://<your-project>.up.railway.app/docs`
- Health Check: `https://<your-project>.up.railway.app/health`

## Post-Deployment Configuration

### 1. Create RSA Keys for JWT

Your application needs RSA keys for JWT signing. Connect to your Railway service and generate them:

```bash
# In Railway service terminal
cd backend/keys
ssh-keygen -t rsa -b 2048 -m PEM -f jwt_private.pem -N ""
openssl rsa -in jwt_private.pem -pubout -outform PEM -out jwt_public.pem
```

**Important**: Store these keys securely. For production, consider using Railway's volume mounts or environment variables for keys.

### 2. Initialize Admin Account

Use the Railway terminal or Railway's shell feature to create an admin account:

```bash
# Access via Railway Dashboard → Service → Terminal
python -c "
from app.models.admin import Admin
from app.db import SessionLocal
from app.services.password_service import hash_password

db = SessionLocal()
admin = Admin(username='admin', password=hash_password('YourSecurePassword'))
db.add(admin)
db.commit()
print('Admin created!')
"
```

### 3. Run Database Migrations (if needed)

If you have SQL migrations in `migrations/` folder:

```bash
# Connect to Railway shell
psql $DATABASE_URL < backend/migrations/001_add_password_and_app_settings.sql
psql $DATABASE_URL < backend/migrations/002_add_oauth_redirect_uris.sql
# ... run all migration files in order
```

## Deploying the Admin Console (Frontend)

The admin console can be deployed as a separate service or as a static site:

### Option 1: Deploy on Railway as Static Site

1. In your Railway project, click **"+ New"** → **"Empty Service"**
2. Connect the same GitHub repo
3. Set **Root Directory** to `frontend/admin-console`
4. Add a `Staticfile` or use a simple HTTP server

### Option 2: Deploy on Vercel/Netlify

1. Push `frontend/admin-console` to a separate repo or subdirectory
2. Deploy to Vercel or Netlify as a static site
3. Update the API endpoint in `admin-console/app.js` to point to your Railway backend URL

### Option 3: Serve from Backend (Quick Setup)

Update your backend to serve the admin console:

1. Copy `frontend/admin-console` to `backend/app/static/admin`
2. Update `main.py` to mount the static directory
3. Access at `https://<your-project>.up.railway.app/admin/`

## Monitoring and Logs

- **View Logs**: Railway Dashboard → Your Service → Logs
- **Metrics**: Railway Dashboard → Your Service → Metrics
- **Database**: Use Railway's built-in database dashboard

## Custom Domain (Optional)

1. Go to your Railway service → **Settings**
2. Click **"Generate Domain"** or **"Add Custom Domain"**
3. Follow instructions to configure DNS

## Environment-Specific Configuration

Update `config.py` to handle different environments:

```python
import os

class Settings:
    ENVIRONMENT = os.getenv("RAILWAY_ENVIRONMENT", "development")
    
    # Use Railway's environment detection
    IS_PRODUCTION = os.getenv("RAILWAY_ENVIRONMENT") == "production"
    
    # Database
    DATABASE_URL = os.getenv("DATABASE_URL")
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    # CORS - be more restrictive in production
    ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
```

## Troubleshooting

### Build Fails

- Check Railway logs for specific errors
- Verify `requirements.txt` has all dependencies
- Ensure Python version compatibility (Railway uses Python 3.11 by default)

### Database Connection Errors

- Verify `DATABASE_URL` is set correctly
- Check if PostgreSQL service is running
- Ensure database tables are created (check `main.py` calls `Base.metadata.create_all()`)

### Port Binding Issues

- Railway automatically sets `$PORT` environment variable
- Procfile uses `--port $PORT` to bind to the correct port
- Don't hardcode port 8000 in production

### CORS Errors

- Update `ALLOWED_ORIGINS` in environment variables
- Modify CORS configuration in `main.py` to use environment-specific origins

## Cost Optimization

Railway offers:
- **Hobby Plan**: $5/month with $5 usage credits
- **Free Trial**: $5 credit for testing

To optimize costs:
1. Use Railway's sleep feature for non-production services
2. Monitor your usage in the Railway dashboard
3. Set up spending limits

## Security Best Practices

1. **Never commit .env files** - Railway handles environment variables
2. **Use strong JWT secrets** - Generate cryptographically secure secrets
3. **Restrict CORS origins** - Don't use `*` in production
4. **Regular updates** - Keep dependencies updated
5. **Enable HTTPS only** - Railway provides HTTPS by default
6. **Database backups** - Enable automated backups in Railway

## Continuous Deployment

Railway automatically redeploys when you push to your main branch:

```bash
git add .
git commit -m "Update feature"
git push origin main
# Railway automatically detects and deploys
```

## Support

- [Railway Documentation](https://docs.railway.app)
- [Railway Discord Community](https://discord.gg/railway)
- [Railway Status Page](https://status.railway.app)

---

## Quick Checklist

- [ ] Code pushed to GitHub
- [ ] Railway project created
- [ ] PostgreSQL database added
- [ ] Redis added
- [ ] Environment variables configured
- [ ] JWT_SECRET generated and added
- [ ] SMTP credentials configured
- [ ] Application deployed successfully
- [ ] Health check endpoint responding
- [ ] RSA keys generated
- [ ] Admin account created
- [ ] Admin console deployed (optional)
- [ ] Custom domain configured (optional)

Your Auth Platform should now be live on Railway! 🚀
