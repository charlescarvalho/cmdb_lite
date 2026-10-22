CMDB Lite v2.1 — IT Asset Management System (Multi-Database PHP)
CMDB Lite is a lightweight, standalone IT configuration and asset management platform (Hardware, Software, Network Topology, and Maintenance Tracking). Designed with enterprise security standards (OWASP) and out-of-the-box cross-database compatibility.

🚀 Key Features
Universal Multi-Database Layer: Native support for Microsoft SQL Server (PDO_SQLSRV, native sqlsrv driver, or ODBC), MySQL / MariaDB (PDO_MySQL or MySQLi), and local SQLite.

Security & OWASP Hardening:

Built-in defenses against CSRF, Clickjacking, MIME Sniffing, and strict CSP directives.

Session integrity controls with user-agent fingerprint validation and inactivity timeouts.

Server-side persistent Rate Limiting to mitigate brute-force authentication attacks.

Sanitization against CSV Formula / DDE injection in data exports.

Role-Based Access Control (RBAC): Strict segregation between Full Administrators (database engine setup, schema initialization, operator management) and Support Operators (daily inventory and operational CRUD).

Hardened File Importer: High-throughput spreadsheet and flat-file importer supporting .xlsx, .xls, .csv, and .txt files, engineered with Anti-XXE and Zip Bomb mitigations, automated foreign key mapping, and Upsert capabilities.

360º Asset Lifecycle Tracking: Real-time KPI dashboards, automated warranty expiration tracking (≤ 90-day alert view), software licensing inventory, network port/VLAN mappings, and immutable allocation audit logs.

🛠️ Requirements
PHP 7.4+ or PHP 8.x

Appropriate database driver enabled (pdo_sqlite, pdo_mysql/mysqli, or pdo_sqlsrv/sqlsrv/odbc)
