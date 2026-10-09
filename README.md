# Auth App — Production-Grade 2FA Authentication System

A secure, self-hosted authentication web application with Two-Factor Authentication (2FA) support compatible with Bitwarden Authenticator and other TOTP-based auth apps.

## Features

- **Two-Factor Authentication (2FA)**: TOTP-based 2FA compatible with Bitwarden Authenticator, Google Authenticator, Authy, and more
- **User Management**: Admin panel for managing users and application settings
- **Material Design 3**: Modern, responsive UI with dark mode support
- **PWA-Ready**: Progressive Web App capabilities for offline support
- **Docker Ready**: Complete Docker and Docker Compose setup
- **Zero Encryption**: No encryption at rest (suitable for self-hosted deployments)
- **Import/Export 2FA**: Backup and restore TOTP secrets in JSON format
- **SMTP Integration**: Email support for password resets and notifications
- **Admin Features**: Customisable app branding, icon, description, and public signup toggle
- **SQLite/MariaDB**: Flexible database options
- **Production-Grade**: Error handling, validation, security best practices

## Quick Start

### With Docker Compose

```bash
# Clone and setup
git clone <repo-url> auth-app
cd auth-app

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Start the application
docker-compose up -d

# Access at http://localhost:8080
```

### Local Development

```bash
# Install Go 1.21+
# Install dependencies
go mod download

# Set environment variables
export JWT_SECRET="dev-secret"
export APP_NAME="Auth App"

# Run the application
go run main.go

# Access at http://localhost:8080
```

## Configuration

### Environment Variables

```env
# Server
PORT=8080                          # Server port
APP_NAME="Auth App"                # Application name displayed to users
APP_ICON="🔐"                      # Application icon (emoji or Unicode)
APP_DESCRIPTION="..."              # Application description

# Security
JWT_SECRET="your-secret-key"       # Change in production!

# Database
DATABASE_PATH="/data/auth.db"      # SQLite database path

# SMTP (Email support)
SMTP_HOST=smtp.gmail.com           # SMTP server hostname
SMTP_PORT=587                      # SMTP port (usually 587 for TLS)
SMTP_USER=your-email@gmail.com     # SMTP username
SMTP_PASSWORD=your-app-password    # SMTP password or app-specific password
SMTP_FROM=noreply@example.com      # Sender email address

# Features
ALLOW_PUBLIC_SIGNUP=true           # Allow public user registration
```

## First User Setup

1. Access the application at `http://localhost:8080`
2. Register the first user — this user becomes an admin automatically
3. Login with the admin account to access the admin panel
4. Configure app settings, enable/disable public signups, manage users

## API Endpoints

### Authentication
- `POST /api/auth/register` — Register a new user
- `POST /api/auth/login` — User login (returns token)
- `POST /api/auth/verify-2fa` — Verify 2FA code

### 2FA Management
- `POST /api/auth/enable-2fa` — Generate TOTP secret
- `POST /api/auth/disable-2fa` — Disable 2FA (requires verification code)
- `POST /api/auth/export-2fa` — Export 2FA secret as JSON
- `POST /api/auth/import-2fa` — Import 2FA secret from JSON/CSV

### User
- `GET /api/user` — Get current user profile
- `POST /api/user/password` — Change password

### Admin
- `GET /api/settings` — Get app settings
- `POST /api/settings` — Update app settings
- `GET /api/users` — List all users
- `DELETE /api/users/{id}` — Delete user

## 2FA Setup

### Enable 2FA
1. Navigate to "Two-Factor Authentication" section
2. Click "Enable 2FA"
3. Scan the QR code with your authenticator app
4. Enter the 6-digit code to confirm

### Supported Authenticator Apps
- Bitwarden (recommended)
- Google Authenticator
- Microsoft Authenticator
- Authy
- FreeOTP
- And any TOTP-compatible app

### Export/Import 2FA

**Export** (backup):
1. Click "Export 2FA Backup"
2. Save the JSON file securely

**Import** (restore):
1. Click "Import 2FA"
2. Upload the previously exported JSON file

## Docker Deployment

### Docker Compose (Recommended)

```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f auth-app

# Stop
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

### Docker Build

```bash
# Build image
docker build -t auth-app:latest .

# Run container
docker run -d \
  -p 8080:8080 \
  -e JWT_SECRET="your-secret" \
  -v auth-data:/data \
  auth-app:latest
```

## Security Considerations

1. **Change JWT_SECRET**: Set a strong, unique secret in production
2. **HTTPS**: Use a reverse proxy (Nginx, Caddy) with SSL/TLS
3. **Database**: Backup `/data/auth.db` regularly
4. **SMTP**: Use app-specific passwords for Gmail and similar providers
5. **Admin Account**: Keep admin credentials secure
6. **Updates**: Keep the application updated for security patches

## Database

### SQLite (Default)

- Self-contained, file-based database
- No external database server needed
- Suitable for small to medium deployments
- Data stored in `/data/auth.db`

### MariaDB/MySQL (Optional)

Uncomment the `mariadb` service in `docker-compose.yml` to use a dedicated database server.

## Development

### Project Structure

```
auth-app/
├── main.go                 # Backend application
├── static/
│   ├── index.html         # Frontend HTML
│   ├── styles.css         # Material Design 3 styles
│   ├── app.js             # Frontend JavaScript
│   ├── sw.js              # Service Worker (PWA)
│   └── manifest.json      # PWA manifest
├── Dockerfile             # Container build configuration
├── docker-compose.yml     # Multi-container setup
├── go.mod                 # Go dependencies
└── README.md              # This file
```

### Building from Source

```bash
# Install dependencies
go mod tidy

# Run locally
go run main.go

# Build binary
CGO_ENABLED=1 go build -o auth-app

# Run binary
./auth-app
```

## Troubleshooting

### Port Already in Use
```bash
# Change port in .env or environment variables
APP_PORT=8081 docker-compose up
```

### Database Corruption
```bash
# Backup and remove database
mv /path/to/data/auth.db /path/to/data/auth.db.backup
docker-compose restart
```

### 2FA Code Not Working
- Ensure device time is synchronised
- Try adjacent time windows (+/- 30 seconds)
- Regenerate 2FA secret if issues persist

### SMTP Not Sending
- Verify credentials in `.env`
- Check firewall/port settings
- Enable "Less secure apps" in Gmail (or use app-specific password)

## License

This project is provided as-is for self-hosted deployments.

## Support

For issues and contributions, please refer to the repository's issue tracker.

---

**Last Updated**: 2024
**Version**: 1.0.0
