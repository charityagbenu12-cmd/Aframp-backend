#!/bin/bash

# Test script for CORS and Security Headers implementation
# Tests the new middleware functionality

echo "🧪 Testing CORS and Security Headers Implementation"
echo "=================================================="

# Server URL (adjust if needed)
SERVER_URL="http://localhost:8000"

echo ""
echo "1. Testing CORS Preflight Request (OPTIONS)"
echo "-------------------------------------------"
curl -i -X OPTIONS \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type,Authorization" \
  "$SERVER_URL/api/rates"

echo ""
echo ""
echo "2. Testing CORS with Allowed Origin"
echo "-----------------------------------"
curl -i -X GET \
  -H "Origin: http://localhost:3000" \
  "$SERVER_URL/health"

echo ""
echo ""
echo "3. Testing CORS with Disallowed Origin"
echo "--------------------------------------"
curl -i -X GET \
  -H "Origin: https://malicious.com" \
  "$SERVER_URL/health"

echo ""
echo ""
echo "4. Testing Security Headers"
echo "---------------------------"
curl -i -X GET "$SERVER_URL/health" | grep -E "(X-Frame-Options|X-Content-Type-Options|X-XSS-Protection|Content-Security-Policy|Referrer-Policy)"

echo ""
echo ""
echo "5. Testing API Endpoint with CORS"
echo "---------------------------------"
curl -i -X GET \
  -H "Origin: http://localhost:3000" \
  -H "Content-Type: application/json" \
  "$SERVER_URL/api/rates"

echo ""
echo ""
echo "✅ CORS and Security Headers Test Complete"
echo "Check the responses above for:"
echo "- Access-Control-Allow-Origin headers"
echo "- Access-Control-Allow-Methods headers"
echo "- X-Frame-Options: DENY"
echo "- X-Content-Type-Options: nosniff"
echo "- Content-Security-Policy headers"
echo "- Server: Aframp API"