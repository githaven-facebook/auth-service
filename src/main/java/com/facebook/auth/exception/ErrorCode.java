package com.facebook.auth.exception;

import org.springframework.http.HttpStatus;

public enum ErrorCode {

    // Authentication errors
    INVALID_CREDENTIALS("AUTH_001", "Invalid email or password", HttpStatus.UNAUTHORIZED),
    ACCOUNT_LOCKED("AUTH_002", "Account is locked due to too many failed login attempts", HttpStatus.FORBIDDEN),
    EMAIL_NOT_VERIFIED("AUTH_003", "Email address has not been verified", HttpStatus.FORBIDDEN),
    TOKEN_EXPIRED("AUTH_004", "Token has expired", HttpStatus.UNAUTHORIZED),
    TOKEN_INVALID("AUTH_005", "Token is invalid or malformed", HttpStatus.UNAUTHORIZED),
    TOKEN_REVOKED("AUTH_006", "Token has been revoked", HttpStatus.UNAUTHORIZED),
    REFRESH_TOKEN_INVALID("AUTH_007", "Refresh token is invalid or expired", HttpStatus.UNAUTHORIZED),

    // Two-factor authentication errors
    TWO_FACTOR_REQUIRED("2FA_001", "Two-factor authentication is required", HttpStatus.UNAUTHORIZED),
    TWO_FACTOR_INVALID("2FA_002", "Invalid two-factor authentication code", HttpStatus.UNAUTHORIZED),
    TWO_FACTOR_ALREADY_ENABLED("2FA_003", "Two-factor authentication is already enabled", HttpStatus.CONFLICT),
    TWO_FACTOR_NOT_ENABLED("2FA_004", "Two-factor authentication is not enabled", HttpStatus.BAD_REQUEST),
    BACKUP_CODE_INVALID("2FA_005", "Invalid or already used backup code", HttpStatus.UNAUTHORIZED),

    // Authorization errors
    INSUFFICIENT_PERMISSIONS("AUTHZ_001", "Insufficient permissions to perform this action", HttpStatus.FORBIDDEN),
    ROLE_NOT_FOUND("AUTHZ_002", "Role not found", HttpStatus.NOT_FOUND),

    // User errors
    USER_NOT_FOUND("USER_001", "User not found", HttpStatus.NOT_FOUND),
    EMAIL_ALREADY_EXISTS("USER_002", "Email address is already registered", HttpStatus.CONFLICT),
    USERNAME_ALREADY_EXISTS("USER_003", "Username is already taken", HttpStatus.CONFLICT),
    INVALID_EMAIL_VERIFICATION_TOKEN("USER_004", "Invalid or expired email verification token", HttpStatus.BAD_REQUEST),
    INVALID_PASSWORD_RESET_TOKEN("USER_005", "Invalid or expired password reset token", HttpStatus.BAD_REQUEST),

    // Session errors
    SESSION_NOT_FOUND("SESSION_001", "Session not found", HttpStatus.NOT_FOUND),
    SESSION_EXPIRED("SESSION_002", "Session has expired", HttpStatus.UNAUTHORIZED),
    SESSION_REVOKED("SESSION_003", "Session has been revoked", HttpStatus.UNAUTHORIZED),
    MAX_SESSIONS_EXCEEDED("SESSION_004", "Maximum number of concurrent sessions exceeded", HttpStatus.TOO_MANY_REQUESTS),

    // OAuth errors
    OAUTH_CLIENT_NOT_FOUND("OAUTH_001", "OAuth client not found", HttpStatus.NOT_FOUND),
    INVALID_REDIRECT_URI("OAUTH_002", "Invalid redirect URI", HttpStatus.BAD_REQUEST),
    INVALID_GRANT_TYPE("OAUTH_003", "Unsupported grant type", HttpStatus.BAD_REQUEST),

    // Rate limiting
    RATE_LIMIT_EXCEEDED("RATE_001", "Too many requests. Please try again later", HttpStatus.TOO_MANY_REQUESTS),

    // General errors
    VALIDATION_ERROR("GEN_001", "Request validation failed", HttpStatus.BAD_REQUEST),
    INTERNAL_ERROR("GEN_002", "An internal error occurred", HttpStatus.INTERNAL_SERVER_ERROR);

    private final String code;
    private final String message;
    private final HttpStatus httpStatus;

    ErrorCode(String code, String message, HttpStatus httpStatus) {
        this.code = code;
        this.message = message;
        this.httpStatus = httpStatus;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
