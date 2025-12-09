"""
Configuration Management
Centralized configuration for payloads, headers, and scanner settings
"""


class Config:
    """Centralized configuration for all scanners"""

    # XSS Payloads: Test for unescaped script execution
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",  # Basic XSS payload
        "<img src=x onerror=alert(1)>",  # Image tag XSS (bypasses basic script filters)
        "';alert(1);//",  # JS context escape XSS
        "<svg/onload=alert(1)>",  # SVG-based XSS
        "javascript:alert(1)",  # JavaScript protocol XSS
    ]

    # SQLi Payloads: Test for SQL injection (detect error-based responses)
    SQLI_PAYLOADS = [
        "' OR '1'='1",  # Basic boolean-based SQLi
        '" OR "1"="1',  # Double quote variant
        "' UNION SELECT NULL--",  # Union-based SQLi
        "1; DROP TABLE users--",  # Destructive (only for testing, avoid in production)
        "' AND 1=2 UNION SELECT NULL--",  # Advanced union-based
        "admin'--",  # Comment-based bypass
    ]

    # Open Redirect Payloads: Test for unvalidated redirect parameters
    REDIRECT_PARAMS = ["redirect", "url", "next", "return", "goto", "redir", "continue"]
    MALICIOUS_REDIRECT_TARGET = "https://malicious-example.com"

    # HTTP Misconfiguration Checks: Key security headers/methods to validate
    REQUIRED_SECURITY_HEADERS = [
        "X-Frame-Options",  # Prevent clickjacking
        "X-XSS-Protection",  # Enable XSS protection in older browsers
        "Content-Security-Policy",  # Mitigate XSS/other injection attacks
        "Strict-Transport-Security",  # Enforce HTTPS (HSTS)
        "X-Content-Type-Options",  # Prevent MIME type sniffing
    ]
    FORBIDDEN_HTTP_METHODS = ["TRACE", "TRACK"]  # Insecure HTTP methods

    # SQL Error Patterns: Database error signatures
    SQL_ERROR_PATTERNS = [
        "MySQL server version for the right syntax",  # MySQL error
        "PG::SyntaxError:",  # PostgreSQL error
        "ORA-01756:",  # Oracle error
        "Unclosed quotation mark after the character string",  # SQL Server error
        "sqlite3.OperationalError",  # SQLite error
        "SQL syntax",  # Generic SQL error
        "mysql_fetch",  # MySQL function error
        "Warning: pg_",  # PostgreSQL warning
    ]

    # Scanner Settings
    DEFAULT_TIMEOUT = 10  # HTTP request timeout in seconds
    MAX_REDIRECTS = 5  # Maximum number of redirects to follow
    RESPONSE_LENGTH_THRESHOLD = 50  # Threshold for boolean SQLi detection

    # UI Settings
    BANNER_FONT = "slant"  # ASCII art font (pyfiglet)
    PROGRESS_REFRESH_RATE = 10  # Progress bar refresh rate (Hz)

    # Report Settings
    DEFAULT_REPORT_FORMAT = "json"
    REPORT_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
