# SLYE-MCP-Security-Scanner
Simple, Light, Yet Effective MCP Security Scanner

This MCP (Model Context Protocol) server scanner is designed to identify common security issues in model serving infrastructure. It performs several key checks:

Endpoint scanning: Discovers accessible API endpoints and identifies those that might expose sensitive information
Authentication testing: Checks for authentication bypass vulnerabilities
Rate limiting: Tests whether proper rate limiting is implemented
Model access controls: Verifies access controls for different models
Injection vulnerabilities: Tests for prompt injection and other injection attacks
TLS configuration: Checks for secure communication protocols
Error disclosure: Tests whether the server leaks sensitive information in error messages

How to Use the Scanner:

Basic usage:

python mcp_scanner.py example-mcp-server.com

With additional options:

python mcp_scanner.py example-mcp-server.com -p 8443 -v -k "your_api_key_here"

Options:

-p, --port: Specify a non-standard port
-t, --timeout: Set connection timeout in seconds
-v, --verbose: Enable detailed output
--no-ssl: Disable SSL/TLS (for HTTP servers)
-k, --api-key: Provide an API key for authenticated testing

The scanner will produce a detailed report with risk scores, identified vulnerabilities, and specific recommendations for improving security.

