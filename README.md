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

==

CMDB Lite v2.1 — Sistema de Gestão de Ativos de TI (PHP Multi-Database)
O CMDB Lite é uma solução completa, leve e auto-contida para gerenciamento de configuração e inventário de TI (Hardware, Software, Redes e Manutenções). Construído com foco em segurança (OWASP), alta portabilidade e suporte nativo a múltiplos bancos de dados.

🚀 Principais Recursos
Suporte Multi-Banco Nativo: Conectividade agnóstica pronta para Microsoft SQL Server (PDO_SQLSRV, driver nativo ou ODBC), MySQL / MariaDB (PDO_MySQL ou MySQLi) e SQLite local.

Segurança e Hardening (OWASP):

Proteção contra CSRF, Clickjacking, MIME Sniffing e cabeçalhos estritos de Content Security Policy (CSP).

Controle de sessões com proteção contra Session Hijacking e expiração por inatividade.

Mecanismo persistente de Rate Limiting para prevenção contra ataques de força bruta no login.

Prevenção contra injeção de fórmulas CSV/DDE em relatórios e exportações.

Controle de Acesso Baseado em Perfis (RBAC): Separação estrita de funções entre Administrador Completo (gestão de conexões, inicialização de schema e contas) e Operador (operações cotidianas de CRUD e inventário).

Importador de Dados Blindado: Carga em lote de ativos, usuários, localidades e softwares a partir de arquivos .xlsx, .xls, .csv e .txt, equipado com proteção contra XXE (XML External Entity) e Zip Bomb, além de resolução inteligente de chaves estrangeiras com modo Upsert.

Gestão 360º de Ativos: Dashboard analítico em tempo real, monitoramento de vencimento de garantias (visão ≤ 90 dias), inventário de licenças, mapa de portas de switch/VLANs e rastreabilidade total de movimentação com auditoria.
