# Bug Bounty Automation Platform

A comprehensive full-stack web application for managing bug bounty automation with advanced scanning capabilities, vulnerability management, and CVE monitoring.

## 🚀 Features

### Core Features
- **Target Management**: Add, edit, and delete bounty targets with base domains, notes, tags, and scope
- **Automated Subdomain Enumeration**: Using Subfinder and Amass
- **Tech Stack Detection**: Wappalyzer-like technology detection
- **Service and Vulnerability Scanning**: Nuclei, HTTPX, Naabu integration
- **Scheduled Scans**: Daily/weekly/monthly automated scanning
- **Comprehensive Dashboard**: Overview of targets, vulnerabilities, and scan results
- **CVE Watch**: Technology-based CVE monitoring and alerting
- **Advanced Search**: Global inventory search with filtering
- **Scan History**: Complete audit trail of all scanning activities

### Technical Stack

#### Backend
- **FastAPI**: High-performance Python web framework
- **PostgreSQL**: Robust relational database with proper indexing
- **Celery + Redis**: Background task processing and job scheduling
- **SQLAlchemy**: Database ORM with async support
- **Docker**: Containerized deployment

#### Frontend
- **Next.js 14**: Modern React framework with TypeScript
- **Tailwind CSS**: Utility-first CSS framework
- **Radix UI**: Accessible component library
- **TanStack Query**: Data fetching and state management
- **Recharts**: Data visualization and charts

#### Security Tools Integration
- **Subfinder**: Subdomain enumeration
- **Amass**: Advanced subdomain discovery
- **Nuclei**: Vulnerability scanning
- **HTTPX**: HTTP toolkit
- **Naabu**: Port scanning

## 📁 Project Structure

```
bug-bounty-automation/
├── backend/
│   ├── api/                    # FastAPI routes
│   ├── core/                   # Core configuration and database
│   ├── models/                 # Database models
│   ├── scanners/               # Scanner implementations
│   ├── scheduler/              # Background task scheduling
│   ├── utils/                  # Utility functions
│   └── Dockerfile
├── frontend/
│   ├── app/                    # Next.js app directory
│   ├── components/             # React components
│   ├── lib/                    # Utility functions
│   ├── hooks/                  # Custom React hooks
│   └── Dockerfile
├── docker-compose.yml          # Multi-service deployment
└── README.md
```

## 🛠️ Installation & Setup

### Prerequisites
- Docker and Docker Compose
- Git

### Quick Start with Docker

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd bug-bounty-automation
   ```

2. **Start the application**
   ```bash
   docker-compose up --build
   ```

3. **Access the application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Documentation: http://localhost:8000/docs

### Manual Setup

#### Backend Setup
1. **Navigate to backend directory**
   ```bash
   cd backend
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set environment variables**
   ```bash
   export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/bug_bounty_db"
   export REDIS_URL="redis://localhost:6379"
   ```

4. **Start the services**
   ```bash
   # Start FastAPI
   uvicorn main:app --reload

   # Start Celery worker (in another terminal)
   celery -A core.celery_app worker --loglevel=info

   # Start Celery beat (in another terminal)
   celery -A core.celery_app beat --loglevel=info
   ```

#### Frontend Setup
1. **Navigate to frontend directory**
   ```bash
   cd frontend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set environment variables**
   ```bash
   export NEXT_PUBLIC_API_URL="http://localhost:8000"
   ```

4. **Start the development server**
   ```bash
   npm run dev
   ```

## 🔧 Configuration

### Environment Variables

#### Backend
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `SECRET_KEY`: JWT secret key
- `SLACK_WEBHOOK_URL`: Slack notifications (optional)
- `DISCORD_WEBHOOK_URL`: Discord notifications (optional)

#### Frontend
- `NEXT_PUBLIC_API_URL`: Backend API URL

### Security Tools Configuration

The platform automatically downloads and installs the following tools:
- Subfinder
- Amass
- Nuclei (with template updates)
- HTTPX
- Naabu

## 🎯 Usage

### Adding Targets
1. Navigate to the Targets section
2. Click "Add Target"
3. Enter target information including domain, tags, and scope
4. Save the target

### Running Scans
1. Select a target from the dashboard
2. Choose scan type (Subdomain, Port, Vulnerability, or Full)
3. Configure scan options
4. Start the scan

### Scheduling Scans
1. Go to the target's scan settings
2. Set up a schedule (daily, weekly, monthly)
3. Configure scan parameters
4. Enable the schedule

### Viewing Results
- **Dashboard**: Overview of all activities
- **Targets**: Detailed view of each target
- **Vulnerabilities**: Filtered vulnerability management
- **Inventory**: Global search across all assets
- **Scan History**: Complete audit trail

## 📊 Dashboard Features

### Overview Stats
- Total targets and active targets
- Subdomain count and discovery rate
- Vulnerability count by severity
- Active scan monitoring

### Vulnerability Management
- Severity-based filtering
- CVE correlation
- False positive management
- Verification status tracking

### Technology Inventory
- Comprehensive tech stack visibility
- CVE matching and alerts
- Version tracking
- Risk assessment

## 🔔 Notifications

The platform supports multiple notification channels:
- **In-app notifications**: Real-time dashboard alerts
- **Slack integration**: Webhook-based notifications
- **Discord integration**: Channel notifications
- **Email notifications**: SMTP-based alerts (configurable)

## 🚨 CVE Monitoring

### Automatic CVE Updates
- Daily CVE database synchronization
- Technology matching with inventory
- Automated risk assessment
- Priority-based alerting

### CVE Watch Features
- Technology-based CVE filtering
- Custom alert thresholds
- Historical CVE tracking
- Impact assessment

## 📈 Scanning Capabilities

### Subdomain Enumeration
- **Subfinder**: DNS enumeration with multiple sources
- **Amass**: Advanced OSINT and active enumeration
- **Deduplication**: Intelligent subdomain merging
- **DNS resolution**: IP address mapping

### Port Scanning
- **Naabu**: High-speed port discovery
- **Service detection**: Banner grabbing and identification
- **HTTP probing**: HTTPX integration
- **Technology detection**: Automated stack identification

### Vulnerability Scanning
- **Nuclei**: Template-based vulnerability detection
- **Custom templates**: Extensible detection rules
- **Severity classification**: CVSS-based risk scoring
- **False positive management**: Manual verification workflow

## 🔒 Security

### Authentication
- JWT-based authentication
- Role-based access control
- Session management
- Password hashing (bcrypt)

### Data Protection
- Encrypted database connections
- Secure API endpoints
- Input validation and sanitization
- SQL injection prevention

### Scanning Ethics
- Configurable rate limiting
- Scope-based restrictions
- Consent management
- Audit logging

## 🚀 Deployment

### Production Deployment
1. **Set production environment variables**
2. **Configure SSL/TLS certificates**
3. **Set up database backups**
4. **Configure monitoring and logging**
5. **Deploy using Docker Compose**

### Scaling
- **Horizontal scaling**: Multiple Celery workers
- **Database optimization**: Connection pooling
- **Cache layer**: Redis caching
- **Load balancing**: Nginx reverse proxy

## 📝 API Documentation

The API documentation is automatically generated and available at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### Key API Endpoints
- `GET /api/targets` - List all targets
- `POST /api/targets` - Create new target
- `POST /api/targets/{id}/scan` - Start scan
- `GET /api/dashboard` - Dashboard statistics
- `GET /api/inventory/search` - Global search

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the GitHub repository
- Check the documentation
- Review the API documentation

## 🚧 Roadmap

### Upcoming Features
- **Machine Learning**: AI-powered vulnerability analysis
- **API Security**: Advanced API testing capabilities
- **Mobile App**: React Native mobile application
- **Enterprise Features**: SAML SSO, advanced reporting
- **Integration Marketplace**: Third-party tool integrations

### Performance Improvements
- **Database optimization**: Advanced indexing strategies
- **Caching layer**: Redis-based result caching
- **Background processing**: Queue optimization
- **Real-time updates**: WebSocket integration

---

Built with ❤️ for the bug bounty community.