# Geo-Restriction Quick Start Guide

## Overview
This guide provides step-by-step instructions for setting up and using the geo-restriction system implemented for Issue #167.

## Prerequisites

### 1. Database Setup
Ensure PostgreSQL is running and the application database is created.

### 2. MaxMind GeoIP2 Database
Download the GeoLite2 Country database from MaxMind:

```bash
# Create directory for GeoIP database
sudo mkdir -p /var/lib/geoip

# Download GeoLite2 Country database (requires free account at maxmind.com)
# Visit: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
# Download: GeoLite2-Country.mmdb

# Or use the free GeoLite2 database:
wget -O /var/lib/geoip/GeoLite2-Country.mmdb "https://git.io/GeoLite2-Country.mmdb"

# Set proper permissions
sudo chmod 644 /var/lib/geoip/GeoLite2-Country.mmdb
```

### 3. Environment Variables
Add these to your `.env` file:

```bash
# Geolocation Configuration
GEOIP_DATABASE_PATH=/var/lib/geoip/GeoLite2-Country.mmdb
GEOIP_UPDATE_INTERVAL_HOURS=168
GEOIP_CACHE_TTL_SECS=86400
GEOIP_DEFAULT_POLICY=allowed

# Geo-Restriction Configuration
ENABLE_GEO_RESTRICTION=true
GEO_POLICY_CACHE_TTL_SECS=3600
AUDIT_ALL_GEO_DECISIONS=true

# Middleware Configuration
GEO_RESTRICTION_MIDDLEWARE_ENABLED=true
GEO_RESTRICTION_EXCLUDE_PATHS=/health,/metrics,/api/admin/geo
GEO_RESTRICTION_REQUIRE_CONSUMER_AUTH=true
```

## Installation Steps

### 1. Run Database Migration
```bash
# Apply the geo-restriction schema migration
sqlx migrate run
```

### 2. Build the Application
```bash
cargo build --release --features database,cache
```

### 3. Start the Application
```bash
./target/release/Aframp-Backend
```

## Initial Configuration

### 1. Set Default Country Policies
Use the admin API to configure country policies:

```bash
# Allow access from United States
curl -X PUT http://localhost:8080/api/admin/geo/policies/US \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"policy_type": "allowed"}'

# Restrict access from certain countries
curl -X PUT http://localhost:8080/api/admin/geo/policies/CN \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"policy_type": "restricted"}'

# Block access from embargoed countries
curl -X PUT http://localhost:8080/api/admin/geo/policies/IR \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"policy_type": "blocked"}'
```

### 2. Configure Region Groupings (Optional)
Set up region-based policies for easier management:

```sql
-- Insert region groupings (run in database)
INSERT INTO region_groupings (region_code, region_name, country_codes) VALUES
('EU', 'European Union', ARRAY['DE', 'FR', 'GB', 'IT', 'ES']),
('NA', 'North America', ARRAY['US', 'CA', 'MX']),
('ASIA', 'Asia Pacific', ARRAY['JP', 'KR', 'SG', 'AU']);
```

## Testing the System

### 1. Test IP Geolocation
```bash
# Test with a known IP (Google DNS)
curl -H "X-Forwarded-For: 8.8.8.8" http://localhost:8080/api/test/geo

# Should return: {"country_code": "US", "is_resolvable": true}
```

### 2. Test Policy Enforcement
```bash
# Test blocked country
curl -H "X-Forwarded-For: 8.8.8.8" \
     -H "X-Consumer-ID: YOUR_CONSUMER_ID" \
     http://localhost:8080/api/protected/endpoint

# Should return 403 Forbidden if US is blocked
```

### 3. Test Consumer Override
```bash
# Create override for specific consumer
curl -X POST http://localhost:8080/api/admin/geo/consumers/YOUR_CONSUMER_ID/overrides \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "consumer_id": "YOUR_CONSUMER_ID",
    "country_code": "CN",
    "policy_type": "allowed",
    "expires_at": "2024-12-31T23:59:59Z"
  }'
```

## Monitoring

### 1. Check Metrics
```bash
# Prometheus metrics endpoint
curl http://localhost:8080/metrics | grep geo_restriction
```

### 2. View Audit Logs
```sql
-- Query recent geo-restriction decisions
SELECT * FROM geo_restriction_audit
WHERE created_at > NOW() - INTERVAL '1 hour'
ORDER BY created_at DESC;
```

### 3. Monitor Cache Performance
```bash
# Check Redis cache stats
redis-cli info | grep keyspace
```

## Admin API Reference

### List All Policies
```bash
GET /api/admin/geo/policies?limit=100&offset=0&region=EU
```

### Update Country Policy
```bash
PUT /api/admin/geo/policies/US
{
  "policy_type": "allowed"
}
```

### Manage Consumer Overrides
```bash
# List overrides
GET /api/admin/geo/consumers/{consumer_id}/overrides

# Create override
POST /api/admin/geo/consumers/{consumer_id}/overrides
{
  "consumer_id": "uuid",
  "country_code": "US",
  "policy_type": "allowed",
  "expires_at": "2024-12-31T23:59:59Z"
}

# Delete override
DELETE /api/admin/geo/consumers/{consumer_id}/overrides/{override_id}
```

### Clear Caches
```bash
POST /api/admin/geo/cache/clear
```

## Troubleshooting

### Common Issues

1. **"Geolocation database not found"**
   - Ensure GeoLite2-Country.mmdb exists at configured path
   - Check file permissions

2. **"Policy evaluation failed"**
   - Check database connectivity
   - Verify migration has been run
   - Check application logs for detailed errors

3. **Requests not being blocked**
   - Verify middleware is enabled in configuration
   - Check if path is excluded from geo-restriction
   - Ensure consumer authentication is working

4. **High latency**
   - Check Redis cache connectivity
   - Monitor database query performance
   - Consider increasing cache TTL values

### Debug Commands

```bash
# Check database tables
psql -d aframp -c "\dt geo_*"

# View recent audit logs
psql -d aframp -c "SELECT * FROM geo_restriction_audit ORDER BY created_at DESC LIMIT 10;"

# Check Redis keys
redis-cli keys "geo:*"
```

## Performance Tuning

### Cache Configuration
- Increase `GEOIP_CACHE_TTL_SECS` for better performance (default: 86400)
- Adjust `GEO_POLICY_CACHE_TTL_SECS` based on policy change frequency
- Monitor cache hit rates via Prometheus metrics

### Database Optimization
- Ensure indexes are created on lookup columns
- Consider partitioning audit table for large volumes
- Run `VACUUM ANALYZE` on geo-restriction tables regularly

### Monitoring Thresholds
- Alert if geolocation lookup failure rate > 5%
- Alert if policy evaluation duration > 100ms
- Alert if blocked requests increase significantly

## Security Considerations

- Regularly update MaxMind database (weekly)
- Audit admin access to geo-restriction endpoints
- Monitor for override abuse
- Implement rate limiting on admin APIs
- Use HTTPS for all admin communications

## Support

For issues or questions:
1. Check application logs with `RUST_LOG=debug`
2. Review Prometheus metrics
3. Consult audit logs for decision history
4. Refer to implementation documentation