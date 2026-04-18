""" Dangerous/sensitive path list for the Nikto-style scanner.

Paths are grouped by category.  Each entry is a path string (no leading /)
that should be probed against the target base URL.  A 200 or certain 3xx
responses to these paths indicate a potential finding.

Only paths with a clear security implication are included to keep the false-
positive rate low. """

# Admin / management panels
ADMIN_PATHS = [
    "admin/",
    "admin/login",
    "admin/index.php",
    "administrator/",
    "admin.php",
    "admin.html",
    "manager/",
    "manage/",
    "wp-admin/",
    "wp-login.php",
    "phpmyadmin/",
    "phpMyAdmin/",
    "pma/",
    "cpanel/",
    "webadmin/",
    "controlpanel/",
    "panel/",
    "backend/",
    "dashboard/",
    "login/",
    "login.php",
    "login.aspx",
]

# Backup / configuration files that should never be web-accessible
SENSITIVE_FILE_PATHS = [
    ".env",
    ".env.bak",
    ".env.example",
    ".env.local",
    ".git/HEAD",
    ".git/config",
    ".svn/entries",
    ".htaccess",
    ".htpasswd",
    "web.config",
    "config.php",
    "config.php.bak",
    "config.inc.php",
    "configuration.php",
    "settings.php",
    "database.php",
    "db.php",
    "connect.php",
    "credentials.json",
    "secrets.json",
    "backup.sql",
    "backup.zip",
    "backup.tar.gz",
    "dump.sql",
    "db_backup.sql",
    "site.tar.gz",
    "www.tar.gz",
    "data.tar.gz",
    "wp-config.php",
    "wp-config.php.bak",
    "wp-config.php~",
    "app/config/parameters.yml",
    "application.yml",
    "application.properties",
    "appsettings.json",
]

# Common debug / information-disclosure endpoints
DEBUG_PATHS = [
    "info.php",
    "phpinfo.php",
    "test.php",
    "debug/",
    "debug.php",
    "trace",
    "actuator/",
    "actuator/health",
    "actuator/env",
    "actuator/mappings",
    "_profiler/",
    "server-info",
    "server-status",
    "status",
    "health",
    "healthcheck",
    "metrics",
    "swagger/",
    "swagger-ui.html",
    "swagger-ui/",
    "api-docs",
    "api/docs",
    "api/swagger.json",
    "openapi.json",
    "graphql",
    "graphiql",
    "__debug__/",
]

# Combined default wordlist used when the caller does not supply one.
DEFAULT_PATHS = ADMIN_PATHS + SENSITIVE_FILE_PATHS + DEBUG_PATHS
