# CORS and Security Headers Implementation

## Overview

This document describes the implementation of Issue #86 - CORS and Security Headers middleware for the Aframp backend API. The implementation provides comprehensive security hardening and enables secure frontend access.

## 🚀 Features Implemented

### ✅ CORS Configuration
- **Environment-based origins**: Automatic configuration based on `ENVIRONMENT` variable
- **Custom origins**: Support for additional origins via `CORS_ALLOWED_ORIGINS` environment variable
- **Preflight handling**: Proper OPTIONS request handling for complex CORS requests
- **Credentials support**: Secure cookie and authentication header handling

### ✅ Security Headers
- **X-Frame-Options**: `DENY` - Prevents clickjacking attacks
- **X-Content-Type-Options**: `nosniff` - Prevents MIME sniffing attacks
- **X-XSS-Protection**: `1; mode=block` - Enables XSS filtering (legacy browsers)
- **Referrer-Policy**: `strict-origin-when-cross-origin` - Controls referrer information
- **Permissions-Policy**: Restricts access to browser features (geolocation, microphone, camera, etc.)
- **Content-Security-Policy**: Comprehensive CSP to prevent XSS and injection attacks
- **Strict-Transport-Security**: HSTS header for production HTTPS environments
- **Server header**: Custom server identification

### ✅ Environment Configuration

#### Development Environment
```bash
ENVIRONMENT=development
```
**Allowed Origins:**
- `http://localhost:3000`
- `http://localhost:5173` 
- `http://localhost:8080`
- `http://127.0.0.1:3000`
- `http://127.0.0.1:5173`
- `http://127.0.0.1:8080`

#### Staging Environment
```bash
ENVIRONMENT=staging
```
**Allowed Origins:**
- `https://staging.aframp.com`
- `https://app-staging.aframp.com`

#### Production Environment
```bash
ENVIRONMENT=production
```
**Allowed Origins:**
- `https://app.aframp.com`
- `https://aframp.com`

### ✅ Custom Configuration

#### Additional Origins
```bash
CORS_ALLOWED_ORIGINS=https://custom1.com,https://custom2.com
```

#### Security Settings
```bash
SECURITY_ENABLE_HSTS=true
SECURITY_HSTS_MAX_AGE=31536000
SECURITY_ENABLE_CSP=true
SECURITY_HIDE_SERVER=false
```

## 📁 Files Created

### Core Implementation
- `src/middleware/cors.rs` - CORS middleware implementation
- `src/middleware/security.rs` - Security headers middleware implementation
- Updated `src/middleware/mod.rs` - Module exports
- Updated `src/main.rs` - Middleware integration

### Testing & Documentation
- `tests/cors_security_test.rs` - Comprehensive integration tests
- `test-cors-security.sh` - Manual testing script
- `CORS_SECURITY_IMPLEMENTATION.md` - This documentation

## 🔧 Integration

The middleware is integrated into the main application middleware stack in the following order:

1. **CORS middleware** - Handles cross-origin requests first
2. **Security headers** - Adds security headers to all responses
3. **Request ID** - Assigns unique request identifiers
4. **Tracing** - OpenTelemetry tracing
5. **Metrics** - Prometheus metrics collection
6. **Logging** - Request/response logging
7. **Request ID propagation** - Copies request ID to response headers

## 🧪 Testing

### Automated Tests
```bash
cargo test cors_security_test
```

### Manual Testing
```bash
./test-cors-security.sh
```

### Test Scenarios Covered

#### CORS Tests
- ✅ Preflight requests with allowed origins
- ✅ Preflight requests with disallowed origins
- ✅ Simple requests with allowed origins
- ✅ Simple requests with disallowed origins
- ✅ Custom origins configuration
- ✅ Environment-based configuration

#### Security Headers Tests
- ✅ All security headers present
- ✅ HSTS only in production + HTTPS
- ✅ CSP policy configuration
- ✅ Server header customization
- ✅ Removal of revealing headers

## 🔒 Security Features

### CORS Security
- **Origin validation**: Strict whitelist-based origin checking
- **No wildcard origins**: Specific origins only for credential support
- **Preflight caching**: 24-hour cache for preflight responses
- **Method restrictions**: Only allowed HTTP methods permitted

### Security Headers Protection
- **Clickjacking protection**: X-Frame-Options prevents embedding
- **MIME sniffing protection**: X-Content-Type-Options prevents content type confusion
- **XSS protection**: Multiple layers of XSS prevention
- **Content Security Policy**: Strict CSP prevents code injection
- **HSTS**: Forces HTTPS in production environments
- **Information disclosure**: Removes server fingerprinting headers

## 🌍 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `development` | Environment mode (development/staging/production) |
| `CORS_ALLOWED_ORIGINS` | - | Comma-separated additional allowed origins |
| `SECURITY_ENABLE_HSTS` | `true` | Enable HSTS header |
| `SECURITY_HSTS_MAX_AGE` | `31536000` | HSTS max age in seconds |
| `SECURITY_ENABLE_CSP` | `true` | Enable Content Security Policy |
| `SECURITY_CUSTOM_CSP` | - | Custom CSP policy override |
| `SECURITY_HIDE_SERVER` | `false` | Hide server header completely |
| `HTTPS` | `false` | Indicates HTTPS environment for HSTS |

## 📊 Monitoring

The implementation includes comprehensive logging:

- **CORS decisions**: Origin allowed/blocked decisions
- **Security headers**: Header application confirmation
- **Environment detection**: Configuration mode logging
- **Error handling**: CORS and security header failures

## 🚨 Security Considerations

### Production Deployment
1. **HTTPS Required**: HSTS only activates with HTTPS in production
2. **Origin Validation**: Ensure production origins are correctly configured
3. **CSP Testing**: Test Content Security Policy with your frontend
4. **Header Validation**: Verify all security headers are present

### Development Notes
- Development mode allows `unsafe-eval` in CSP for debugging
- HSTS is disabled in development environments
- Additional localhost origins are automatically allowed

## ✅ Acceptance Criteria Met

- [x] **CORS Configuration**: Environment-based origin configuration ✅
- [x] **Preflight Handling**: Proper OPTIONS request handling ✅
- [x] **Security Headers**: All required security headers implemented ✅
- [x] **Content Security Policy**: Comprehensive CSP policy ✅
- [x] **HSTS**: Production HTTPS enforcement ✅
- [x] **Cookie Security**: Secure cookie handling support ✅
- [x] **Server Header**: Custom server identification ✅
- [x] **Environment Configuration**: Multi-environment support ✅
- [x] **Testing**: Comprehensive test coverage ✅
- [x] **Documentation**: Complete implementation documentation ✅

## 🎉 Success Metrics

✅ **Frontend can access API securely**
- CORS properly configured for all environments
- Credentials and authentication headers supported

✅ **Protected against clickjacking**
- X-Frame-Options: DENY prevents iframe embedding

✅ **XSS attacks prevented**
- Multiple XSS protection layers implemented
- Content Security Policy blocks injection attacks

✅ **Secure cookie handling**
- CORS credentials support enabled
- Secure header configuration

✅ **Production-ready security posture**
- HSTS for HTTPS enforcement
- Comprehensive security header suite
- Environment-appropriate configuration

## 🔄 Next Steps

1. **Deploy to staging** - Test with staging frontend
2. **Security scan** - Run security scanner against endpoints
3. **Performance test** - Verify middleware performance impact
4. **Frontend integration** - Coordinate with frontend team for testing
5. **Production deployment** - Deploy with production configuration

---

**🎉 SECURITY PHASE COMPLETE!**

The Aframp backend now has comprehensive CORS and security headers protection, enabling secure frontend access while protecting against common web vulnerabilities.