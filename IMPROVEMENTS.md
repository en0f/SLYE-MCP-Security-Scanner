# MCP Security Scanner Improvements

## 4 Major Features Added

### 1. **Export Formats (JSON & HTML Reports)**
- **`export_json(results)`** - Export scan results to machine-readable JSON format
- **`export_html(results)`** - Export scan results to professional HTML report with:
  - Color-coded vulnerability severity levels (CRITICAL, HIGH, MEDIUM, LOW)
  - Interactive styling with gradient headers
  - Detailed server information tables
  - Risk score visualization
  - Contextual recommendations based on findings
- **New CLI option:** `-o/--output` to specify export file path
  - `.json` extension → JSON export only
  - `.html` extension → HTML export only
  - No extension → Both formats generated

**Usage Examples:**
```bash
python3 mcp_scanner.py example.com -k API_KEY -o report.json
python3 mcp_scanner.py example.com -k API_KEY -o report.html
python3 mcp_scanner.py example.com -k API_KEY -o report  # Creates both
```

### 2. **MCP-Specific Tool Validation** 
- **`check_mcp_tools()`** - Comprehensive tool endpoint scanning
  - Checks multiple tool endpoints: `/v1/tools`, `/tools`, `/api/tools`, `/mcp/tools`
  - Validates tool definitions have input validation schemas
  - Detects dangerous/unrestricted tools marked in descriptions
  - Catalogs all available tools in server_info
  - **Reports:**
    - Missing input validation schemas (MEDIUM severity, +4 risk)
    - Dangerous tools exposed (HIGH severity, +6 risk)

### 3. **Enhanced Authentication Testing**
- **`check_authentication_security()`** - Deep authentication analysis
  - **JWT Token Validation:**
    - Auto-detects JWT format tokens (header.payload.signature)
    - Checks for weak algorithms: `none` (CRITICAL, +10), `HS256` (MEDIUM, +3)
    - Validates token expiration and warns if < 24 hours remaining
    - Extracts and displays scopes/permissions
    - Flags expired tokens (HIGH severity, +7)
  - **Rate Limit Header Detection:** Detects server support for rate limit headers
  - **API Key Security Testing:**
    - Tests if API key is accepted in URL parameters (HIGH severity if true, +6)
    - Validates proper Authorization header usage

### 4. **Security Headers Validation**
- **`check_security_headers()`** - Validates HTTP security headers
  - Checks for presence of critical headers:
    - X-Content-Type-Options (nosniff)
    - X-Frame-Options
    - X-XSS-Protection
    - Strict-Transport-Security (HSTS)
    - Content-Security-Policy (CSP)
    - Access-Control-Allow-Origin (CORS)
  - **Reports:**
    - Missing headers (MEDIUM severity, +4 risk)
    - Overly permissive CORS (`Access-Control-Allow-Origin: *`) (MEDIUM severity, +3 risk)
  - Stores all response headers in server_info for detailed analysis

## Updated Scan Flow

The `run_scan()` method now executes checks in this optimized order:
1. Connection check
2. Open endpoint scanning
3. TLS configuration analysis
4. **Security headers validation** ← NEW
5. **MCP tool validation** ← NEW
6. Model access control
7. **Enhanced authentication security** ← NEW
8. Rate limiting
9. Injection vulnerability testing
10. Error disclosure checking
11. Results export (if -o specified)

## CLI Enhancements

```
usage: mcp_scanner.py TARGET [OPTIONS]

positional arguments:
  target                Target hostname or IP address

optional arguments:
  -p, --port PORT       Target port (default: 443)
  -t, --timeout SECS    Connection timeout (default: 10s)
  -v, --verbose         Enable verbose output
  --no-ssl              Disable SSL/TLS (use HTTP)
  -k, --api-key KEY     API key for authenticated testing
  -o, --output PATH     Export results to JSON/HTML file
                        - Use .json for JSON only
                        - Use .html for HTML only
                        - No extension generates both formats
```

## New Vulnerability Types Detected

| Vulnerability | Severity | Risk Score |
|---|---|---|
| Missing security headers | MEDIUM | +4 |
| Insecure CORS (open origin) | MEDIUM | +3 |
| JWT with 'none' algorithm | CRITICAL | +10 |
| JWT with HS256 algorithm | MEDIUM | +3 |
| Expired JWT token | HIGH | +7 |
| API key in URL parameters | HIGH | +6 |
| Tools missing input validation | MEDIUM | +4 |
| Dangerous tools exposed | HIGH | +6 |

## Export Features

### JSON Export
- Machine-readable format perfect for CI/CD integration
- Includes all vulnerability details with severity levels
- Server metadata and capabilities
- Risk scores and assessment results
- Timestamped filenames: `mcp_scan_YYYYMMDD_HHMMSS.json`

### HTML Export  
- Professional, print-ready appearance
- Color-coded vulnerability cards (red/orange/yellow/green by severity)
- Responsive design works on mobile and desktop
- Risk score visualization
- Contextual recommendations auto-generated from findings
- Server info displayed in organized, readable tables
- Standalone file (no external dependencies)

## Example Usage

```bash
# Generate comprehensive report with both formats
python3 mcp_scanner.py api.example.com -k sk_live_xyz -v -o scan_report

# Generate HTML report only
python3 mcp_scanner.py api.example.com -k sk_live_xyz -o detailed_report.html

# Generate JSON for automated processing
python3 mcp_scanner.py api.example.com -o results.json

# View generated reports
open scan_report.html              # macOS
xdg-open scan_report.html          # Linux
cat scan_report.json | jq .        # Pretty-print JSON
```

## Backward Compatibility

✅ All improvements maintain full backward compatibility. Existing command-line usage still works:
```bash
# Classic usage still works - no export file generated
python3 mcp_scanner.py example.com -k API_KEY -v
```

## Summary of Enhancements

| Feature | Type | Impact |
|---|---|---|
| JSON export | Output | Enables automation and integration |
| HTML export | Output | Professional reporting and sharing |
| Security headers check | Detection | Validates 6 critical HTTP headers |
| MCP tools validation | Detection | Identifies tool security issues |
| JWT analysis | Detection | Deep authentication testing |
| CORS validation | Detection | Detects overly permissive origins |
| New risk calculations | Scoring | More comprehensive risk assessment |
