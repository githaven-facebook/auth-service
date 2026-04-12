# Auth Service - Claude

## Quick Start
This is a Maven-based Spring Boot application.
Run `mvn spring-boot:run` to start.
Tests: `mvn test`

## Structure
Standard Spring MVC layout. Controllers handle HTTP, services have logic, repos talk to MySQL.

## Security
We use basic Spring Security with session-based authentication.
Passwords are stored with SHA-256 hashing.

## Notes
- Config is in application.properties
- Tests use in-memory H2 database
- No special setup needed
