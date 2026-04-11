# Auth Service

Production-grade Facebook Authentication and Authorization Service built with Spring Boot 3.2, Java 21.

## Overview

This service provides centralized authentication and authorization for Facebook services, implementing the OAuth2/OpenID Connect specification with additional features including two-factor authentication, session management, and fine-grained role-based access control.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Auth Service                         │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────────────┐  │
│  │   Auth API  │  │  User API   │  │   Session/2FA API  │  │
│  └──────┬──────┘  └──────┬──────┘  └─────────┬──────────┘  │
│         │                │                   │              │
│  ┌──────▼────────────────▼───────────────────▼──────────┐   │
│  │              Service Layer                           │   │
│  │  AuthService │ UserService │ TokenService │ ...      │   │
│  └──────┬────────────────────────────────────────┬──────┘   │
│         │                                        │          │
│  ┌──────▼──────────┐              ┌──────────────▼──────┐   │
│  │   PostgreSQL    │              │       Redis         │   │
│  │  (JPA/Flyway)   │              │  (Token Blacklist)  │   │
│  └─────────────────┘              └─────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Features

- **OAuth2/OpenID Connect**: Authorization Code + PKCE, Client Credentials, Refresh Token flows
- **JWT Token Management**: HS256 signed access tokens (15 min) + refresh tokens (7 days) with Redis blacklisting
- **Two-Factor Authentication**: RFC 6238 TOTP with ±1 time-step tolerance and 8 single-use BCrypt-hashed backup codes
- **Session Management**: Create/validate/revoke sessions with sliding expiration, max 5 concurrent sessions per user
- **RBAC**: Role-based access control with USER, ADMIN, MODERATOR, SERVICE roles and fine-grained permissions
- **Rate Limiting**: 10 login attempts/minute per IP, 100 API requests/minute per user (Bucket4j)
- **Account Security**: BCrypt strength 12, account lockout after 5 failed attempts, email verification

## API Reference

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Register new user account |
| POST | `/api/v1/auth/login` | Authenticate and receive tokens |
| POST | `/api/v1/auth/logout` | Revoke tokens and session |
| POST | `/api/v1/auth/refresh` | Rotate refresh token |
| POST | `/api/v1/auth/verify-email` | Verify email address |
| POST | `/api/v1/auth/forgot-password` | Initiate password reset |
| POST | `/api/v1/auth/reset-password` | Complete password reset |

### Users

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/users/me` | Get current user profile |
| PUT | `/api/v1/users/me` | Update current user profile |
| PUT | `/api/v1/users/me/password` | Change password |
| GET | `/api/v1/users/{id}` | Get user by ID (ADMIN) |
| POST | `/api/v1/users/{id}/lock` | Lock user account (ADMIN) |

### Sessions

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/sessions` | List active sessions |
| DELETE | `/api/v1/sessions/{id}` | Revoke specific session |
| DELETE | `/api/v1/sessions` | Revoke all sessions |

### Two-Factor Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/2fa/setup` | Generate TOTP secret and QR code |
| POST | `/api/v1/2fa/verify` | Verify code and enable 2FA |
| POST | `/api/v1/2fa/disable` | Disable 2FA |
| GET | `/api/v1/2fa/backup-codes` | Regenerate backup codes |

### OAuth2 / OIDC Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /oauth2/authorize` | Authorization endpoint |
| `POST /oauth2/token` | Token endpoint |
| `POST /oauth2/revoke` | Token revocation |
| `GET /oauth2/introspect` | Token introspection |
| `GET /oauth2/jwks` | JSON Web Key Set |
| `GET /userinfo` | OIDC UserInfo |

## Authentication Flows

### Authorization Code + PKCE

```
Client                    Auth Service               User
  │                            │                       │
  │─── GET /oauth2/authorize ──►│                       │
  │   (code_challenge, PKCE)    │                       │
  │                            │──── Login Page ───────►│
  │                            │◄─── Credentials ───────│
  │◄── 302 redirect with code ─│                       │
  │                            │                       │
  │─── POST /oauth2/token ─────►│                       │
  │   (code, code_verifier)     │                       │
  │◄── access_token + id_token ─│                       │
```

### Login with 2FA

```
POST /api/v1/auth/login
{
  "email": "user@example.com",
  "password": "...",
  "twoFactorCode": "123456"   // optional; required if 2FA is enabled
}
```

If 2FA is enabled and `twoFactorCode` is omitted, the response is:
```json
{ "errorCode": "2FA_001", "status": 401 }
```

## Security Considerations

- Passwords hashed with BCrypt strength 12
- JWT secrets must be at least 256 bits; rotate periodically
- Access tokens expire in 15 minutes; refresh tokens in 7 days
- Revoked tokens are blacklisted in Redis until natural expiry
- Rate limiting prevents brute-force on login and password-reset endpoints
- CORS restricted to `*.facebook.com` and `localhost` (dev only)
- All responses include HSTS, X-Frame-Options: DENY, Referrer-Policy headers
- Account locked after 5 consecutive failed login attempts

## Deployment

### Prerequisites

- Java 21
- PostgreSQL 16+
- Redis 7+

### Docker Compose (local)

```bash
docker-compose up -d
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_JWT_SECRET` | (required) | HMAC-SHA256 signing key (min 256 bits) |
| `APP_JWT_ACCESS_EXPIRY` | `900` | Access token TTL in seconds |
| `APP_JWT_REFRESH_EXPIRY` | `604800` | Refresh token TTL in seconds |
| `APP_JWT_ISSUER` | `https://auth.facebook.com` | JWT issuer claim |
| `SPRING_DATASOURCE_URL` | `jdbc:postgresql://localhost:5432/authdb` | PostgreSQL JDBC URL |
| `SPRING_DATASOURCE_USERNAME` | `authuser` | Database username |
| `SPRING_DATASOURCE_PASSWORD` | `authpass` | Database password |
| `SPRING_DATA_REDIS_HOST` | `localhost` | Redis host |
| `SPRING_DATA_REDIS_PORT` | `6379` | Redis port |
| `SPRING_DATA_REDIS_PASSWORD` | `redispass` | Redis password |

### Build

```bash
./gradlew bootJar
java -jar build/libs/auth-service-1.0.0.jar
```

### Docker

```bash
docker build -t auth-service:latest .
docker run -p 8080:8080 \
  -e APP_JWT_SECRET=your-secret-here \
  -e SPRING_DATASOURCE_URL=jdbc:postgresql://host:5432/authdb \
  auth-service:latest
```

## Development

```bash
# Start dependencies
docker-compose up -d postgres redis

# Run with local profile
./gradlew bootRun --args='--spring.profiles.active=local'

# Run tests
./gradlew test

# Run with coverage
./gradlew test jacocoTestReport
open build/reports/jacoco/test/html/index.html
```

## API Documentation

Interactive Swagger UI available at `/swagger-ui.html` when running locally.
OpenAPI 3 spec at `/v3/api-docs`.

## Configuration Reference

See `src/main/resources/application.yml` for all available configuration properties with defaults.
Local development overrides in `src/main/resources/application-local.yml`.
