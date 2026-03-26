# CORS & Security Headers - Quick Reference

## 🚀 Quick Start

The CORS and security headers middleware is automatically enabled. No additional configuration required for basic usage.

## 🔧 Environment Configuration

### Development (Default)
```bash
# Automatically allows localhost origins
ENVIRONMENT=development
```

### Production
```bash
# Restricts to production domains only
ENVIRONMENT=production
```

### Custom Origins
```bash
# Add additional allowed origins
CORS_ALLOWED_ORIGINS=https://custom1.com,https://custom2.com
```

## 🧪 Testing CORS

### Test Preflight Request
```bash
curl -i -X OPTIONS \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type" \
  http://localhost:8000/api/rates
```

### Test Simple Request
```bash
curl -i -X GET \
  -H "Origin: http://localhost:3000" \
  http://localhost:8000/health
```

## 🔒 Security Headers Included

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-XSS-Protection` | `1; mode=block` | XSS protection |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Control referrer info |
| `Content-Security-Policy` | Comprehensive policy | Prevent injection attacks |
| `Strict-Transport-Security` | Production + HTTPS only | Force HTTPS |

## 🌍 Environment-Specific Origins

### Development
- `http://localhost:3000`
- `http://localhost:5173`
- `http://localhost:8080`
- `http://127.0.0.1:*`

### Staging
- `https://staging.aframp.com`
- `https://app-staging.aframp.com`

### Production
- `https://app.aframp.com`
- `https://aframp.com`

## ⚡ Common Issues & Solutions

### CORS Error: "Origin not allowed"
**Solution:** Add your origin to `CORS_ALLOWED_ORIGINS` or check `ENVIRONMENT` setting.

### Missing Security Headers
**Solution:** Ensure middleware is properly loaded in main.rs middleware stack.

### HSTS Not Working
**Solution:** HSTS only works in production with HTTPS. Set `ENVIRONMENT=production` and `HTTPS=true`.

## 📝 Configuration Examples

### Local Development
```bash
ENVIRONMENT=development
# No additional config needed
```

### Staging Environment
```bash
ENVIRONMENT=staging
CORS_ALLOWED_ORIGINS=https://preview.aframp.com
```

### Production Environment
```bash
ENVIRONMENT=production
HTTPS=true
SECURITY_ENABLE_HSTS=true
```

## 🔍 Debugging

### Check CORS Headers
```bash
curl -i -H "Origin: http://localhost:3000" http://localhost:8000/health | grep -i "access-control"
```

### Check Security Headers
```bash
curl -i http://localhost:8000/health | grep -E "(X-Frame|X-Content|X-XSS|Content-Security)"
```

### Verify Configuration
Check server logs for CORS and security middleware initialization messages.

---

**Need help?** Check the full implementation guide in `CORS_SECURITY_IMPLEMENTATION.md`