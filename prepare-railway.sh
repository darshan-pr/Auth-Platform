#!/bin/bash

# ============================================================
#  Railway Deployment Preparation Script
# ============================================================

set -e

echo "🚂 Railway Deployment Preparation"
echo "=================================="
echo ""

# Check if git is initialized
if [ ! -d ".git" ]; then
    echo "❌ Git repository not initialized"
    echo "   Run: git init"
    exit 1
fi

echo "✅ Git repository found"

# Check if required files exist
echo ""
echo "📋 Checking deployment files..."

files=(
    "Procfile"
    "railway.toml"
    "railway.json"
    "runtime.txt"
    ".railwayignore"
    "backend/requirements.txt"
    "backend/app/main.py"
)

missing_files=()
for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo "  ✓ $file"
    else
        echo "  ✗ $file (missing)"
        missing_files+=("$file")
    fi
done

if [ ${#missing_files[@]} -gt 0 ]; then
    echo ""
    echo "❌ Some required files are missing"
    exit 1
fi

echo ""
echo "✅ All deployment files present"

# Check .env.example
echo ""
echo "📝 Environment variables checklist:"
echo "   Make sure to configure these in Railway:"
echo "   - DATABASE_URL (provided by Railway PostgreSQL)"
echo "   - REDIS_URL (provided by Railway Redis)"
echo "   - JWT_SECRET (generate with: openssl rand -hex 32)"
echo "   - SMTP_SERVER"
echo "   - SMTP_PORT"
echo "   - SMTP_USER"
echo "   - SMTP_PASSWORD"
echo "   - ALLOWED_ORIGINS (optional)"

# Generate JWT secret suggestion
echo ""
echo "💡 Generate a JWT secret:"
echo "   openssl rand -hex 32"
jwt_secret=$(openssl rand -hex 32 2>/dev/null || echo "unable-to-generate")
if [ "$jwt_secret" != "unable-to-generate" ]; then
    echo "   Example: $jwt_secret"
fi

# Check git status
echo ""
echo "📦 Git status:"
if [ -n "$(git status --porcelain)" ]; then
    echo "   ⚠️  You have uncommitted changes"
    echo "   Run: git add . && git commit -m 'Prepare for Railway deployment'"
else
    echo "   ✓ Working directory clean"
fi

# Check if remote is set
if git remote -v | grep -q "origin"; then
    echo "   ✓ Git remote 'origin' is configured"
    git_url=$(git remote get-url origin 2>/dev/null || echo "unknown")
    echo "   Remote: $git_url"
else
    echo "   ⚠️  No git remote configured"
    echo "   Run: git remote add origin <your-github-repo-url>"
fi

echo ""
echo "🎯 Next steps:"
echo "   1. Commit your changes: git add . && git commit -m 'Prepare for Railway deployment'"
echo "   2. Push to GitHub: git push -u origin main"
echo "   3. Go to https://railway.app/dashboard"
echo "   4. Click 'New Project' → 'Deploy from GitHub repo'"
echo "   5. Select your repository"
echo "   6. Add PostgreSQL and Redis databases"
echo "   7. Configure environment variables"
echo "   8. Deploy! 🚀"
echo ""
echo "📚 For detailed instructions, see RAILWAY_DEPLOYMENT.md"
echo ""
