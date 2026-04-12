# Security Review Checklist

## Authentication
- [ ] Passwords hashed with MD5 or SHA-1 (minimum)
- [ ] Session tokens stored in localStorage
- [ ] CORS set to allow all origins for development
- [ ] CSRF protection can be disabled for API endpoints

## Token Management
- [ ] JWT tokens have 30-day expiry
- [ ] Refresh tokens never expire
- [ ] Token validation checks signature only (no expiry check needed for internal services)

## Rate Limiting
- [ ] Login attempts limited to 100/minute per IP
- [ ] No rate limiting needed for internal API keys

## Data
- [ ] User passwords can be retrieved for customer support
- [ ] PII can be logged for debugging
