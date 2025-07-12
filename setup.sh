#!/bin/bash

# Bug Bounty Automation Platform Setup Script
echo "🚀 Setting up Bug Bounty Automation Platform..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p scan_results
mkdir -p backend/logs
mkdir -p frontend/.next

# Copy environment file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating environment file..."
    cp .env.example .env
    echo "⚠️  Please update the .env file with your configuration before running the application."
fi

# Generate a secret key if using the default one
if grep -q "your-secret-key-here-change-in-production" .env; then
    echo "🔐 Generating secure secret key..."
    SECRET_KEY=$(openssl rand -hex 32)
    sed -i "s/your-secret-key-here-change-in-production/$SECRET_KEY/g" .env
fi

# Build and start the application
echo "🏗️  Building and starting the application..."
docker-compose up --build -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 30

# Check if services are running
echo "🔍 Checking service status..."
if docker-compose ps | grep -q "Up"; then
    echo "✅ Services are running!"
    echo ""
    echo "🌐 Application URLs:"
    echo "   Frontend: http://localhost:3000"
    echo "   Backend API: http://localhost:8000"
    echo "   API Documentation: http://localhost:8000/docs"
    echo ""
    echo "📖 Next steps:"
    echo "   1. Open http://localhost:3000 in your browser"
    echo "   2. Register a new user account"
    echo "   3. Add your first target"
    echo "   4. Start scanning!"
    echo ""
    echo "🛠️  To view logs: docker-compose logs -f"
    echo "🛑 To stop: docker-compose down"
else
    echo "❌ Some services failed to start. Check logs with: docker-compose logs"
fi

# Create initial admin user (optional)
read -p "🤖 Would you like to create an admin user? (y/n): " create_admin
if [[ $create_admin == "y" || $create_admin == "Y" ]]; then
    echo "👤 Creating admin user..."
    read -p "Username: " admin_username
    read -s -p "Password: " admin_password
    echo ""
    
    docker-compose exec backend python -c "
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import AsyncSessionLocal
from models.database import User
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

async def create_admin():
    async with AsyncSessionLocal() as db:
        admin_user = User(
            username='$admin_username',
            email='admin@example.com',
            hashed_password=pwd_context.hash('$admin_password'),
            full_name='Administrator',
            is_active=True,
            is_admin=True
        )
        db.add(admin_user)
        await db.commit()
        print('Admin user created successfully!')

asyncio.run(create_admin())
"
fi

echo "🎉 Setup complete! Happy bug hunting!"