<?php
/**
 * ============================================================================
 * CMDB Lite v2.1 (Hardened Security Edition)
 * Gestão de Ativos de TI (CRUD + RBAC + Importador Seguro + Multi-Banco Fixo)
 * Bancos Suportados: Microsoft SQL Server (Local) | MySQL / MariaDB | SQLite
 * Baseado no schema: SQLQuery_cmdb_v1.sql
 * ============================================================================
 *
 * CREDENCIAIS INICIAIS DE FÁBRICA (PRIMEIRO ACESSO):
 *   Administrador Completo: admin / Admin@123
 *
 * COMO EXECUTAR:
 *   php -S localhost:8000 index.php
 */

declare(strict_types=1);
define('CMDB_INTERNAL', true);
date_default_timezone_set('America/Sao_Paulo');

// ============================================================================
// 1. HARDENING DE SESSÃO E CABEÇALHOS HTTP DE SEGURANÇA (OWASP)
// ============================================================================
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || ((int)($_SERVER['SERVER_PORT'] ?? 80) === 443);

session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',
    'secure'   => $isHttps,
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();

// Cabeçalhos HTTP contra Clickjacking, MIME Sniffing, XSS e Cache de dados sensíveis
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: same-origin');
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self';");
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// ============================================================================
// 2. CONFIGURAÇÃO FIXA DO BANCO DE DADOS NO SERVIDOR (PERSISTENTE ENTRE MÁQUINAS)
// ============================================================================
// Esta configuração padrão é utilizada caso o administrador ainda não tenha salvo
// uma parametrização fixa pelo painel web. Quando o Administrador altera o banco
// na interface, a escolha é gravada no arquivo seguro `.cmdb_db_config.php` no
// servidor, valendo automaticamente para todas as máquinas e navegadores.
$DEFAULT_DB_CONFIG = [
    'driver'     => getenv('CMDB_DB_DRIVER') ?: 'sqlsrv',     // 'sqlsrv' (SQL Server), 'mysql' (MySQL/MariaDB) ou 'sqlite'
    'server'     => getenv('CMDB_DB_SERVER') ?: 'localhost',  // SQL Server: 'localhost', 'localhost\SQLEXPRESS' | MySQL: '127.0.0.1'
    'port'       => getenv('CMDB_DB_PORT')   ?: '',           // Porta opcional (Ex: '1433' p/ SQL Server ou '3306' p/ MySQL/MariaDB)
    'database'   => getenv('CMDB_DB_NAME')   ?: 'CMDB',       // Nome do banco de dados
    'username'   => getenv('CMDB_DB_USER')   ?: '',           // SQL Server: '' = Windows Auth ou 'sa' | MySQL: 'root'
    'password'   => getenv('CMDB_DB_PASS')   ?: '',           // Senha do banco de dados
    'trust_cert' => true,                                     // TrustServerCertificate=1 no SQL Server
];

define('CMDB_CONFIG_FILE', __DIR__ . '/.cmdb_db_config.php');
define('CMDB_RATELIMIT_FILE', __DIR__ . '/.cmdb_rate_limit.json');
define('CMDB_MAX_UPLOAD_BYTES', 10 * 1024 * 1024); // Limite de 10 MB para planilhas importadas
define('CMDB_SESSION_IDLE_LIMIT', 1800);           // Expiração de sessão por inatividade: 30 minutos

/**
 * Carrega a configuração de banco fixa salva no servidor (comum a qualquer máquina/navegador).
 */
function loadPersistentDbConfig(array $defaultConfig): array
{
    // Remove qualquer resquício de configuração antiga presa em sessão de versões anteriores
    if (isset($_SESSION['cmdb_db_config'])) {
        unset($_SESSION['cmdb_db_config']);
    }
    if (is_file(CMDB_CONFIG_FILE) && is_readable(CMDB_CONFIG_FILE)) {
        $loaded = @include CMDB_CONFIG_FILE;
        if (is_array($loaded)) {
            return array_merge($defaultConfig, $loaded);
        }
    }
    return $defaultConfig;
}

/**
 * Salva a configuração de banco de forma fixa no servidor (somente Administrador Completo).
 */
function savePersistentDbConfig(array $newConfig): bool
{
    $allowedDrivers = ['sqlsrv', 'mysql', 'sqlite'];
    $driver = in_array($newConfig['driver'] ?? '', $allowedDrivers, true) ? $newConfig['driver'] : 'sqlsrv';

    $cleanConfig = [
        'driver'     => $driver,
        'server'     => preg_replace('/[\r\n\0]/', '', trim((string)($newConfig['server'] ?? 'localhost'))),
        'port'       => preg_replace('/[^0-9]/', '', trim((string)($newConfig['port'] ?? ''))),
        'database'   => preg_replace('/[^a-zA-Z0-9_\-]/', '', trim((string)($newConfig['database'] ?? 'CMDB'))),
        'username'   => preg_replace('/[\r\n\0]/', '', trim((string)($newConfig['username'] ?? ''))),
        'password'   => (string)($newConfig['password'] ?? ''),
        'trust_cert' => !empty($newConfig['trust_cert']),
        'updated_at' => date('Y-m-d H:i:s'),
    ];
    if ($cleanConfig['database'] === '') {
        $cleanConfig['database'] = 'CMDB';
    }

    $phpContent = "<?php\n"
        . "// Arquivo de parametrização fixa do banco de dados CMDB Lite\n"
        . "// Gerado automaticamente pelo Administrador. Acesso direto bloqueado.\n"
        . "if (!defined('CMDB_INTERNAL')) { http_response_code(403); exit('Acesso negado.'); }\n"
        . "return " . var_export($cleanConfig, true) . ";\n";

    $ok = @file_put_contents(CMDB_CONFIG_FILE, $phpContent, LOCK_EX) !== false;
    if ($ok) {
        @chmod(CMDB_CONFIG_FILE, 0600);
        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate(CMDB_CONFIG_FILE, true);
        }
    }
    return $ok;
}

// Credencial de administrador de emergência (utilizada apenas enquanto a tabela CMDBAdmins não tiver o admin gravado)
$FALLBACK_ADMIN = [
    'username'      => 'admin',
    'display_name'  => 'Administrador TI',
    'role'          => 'admin',
    'password_hash' => password_hash('Admin@123', PASSWORD_DEFAULT),
];

// Token CSRF
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$CSRF_TOKEN = $_SESSION['csrf_token'];

function verifyCsrf(): void
{
    $token = (string)($_POST['_csrf'] ?? '');
    if ($token === '' || !hash_equals((string)($_SESSION['csrf_token'] ?? ''), $token)) {
        http_response_code(403);
        throw new RuntimeException('Token de segurança (CSRF) inválido ou sessão expirada. Recarregue a página.');
    }
}

// ============================================================================
// 3. CONTROLE DE ACESSO BASEADO EM PERFIL (RBAC) E SEGURANÇA DE SESSÃO
// ============================================================================
function currentAuthUser(): ?array
{
    if (empty($_SESSION['cmdb_auth_user']) || !is_array($_SESSION['cmdb_auth_user'])) {
        return null;
    }
    // Verifica expiração por inatividade (30 min)
    $lastActivity = (int)($_SESSION['cmdb_last_activity'] ?? 0);
    if ($lastActivity > 0 && (time() - $lastActivity) > CMDB_SESSION_IDLE_LIMIT) {
        unset($_SESSION['cmdb_auth_user'], $_SESSION['cmdb_last_activity'], $_SESSION['cmdb_ua_hash']);
        $_SESSION['flash_msg'] = ['type' => 'warning', 'text' => 'Sua sessão expirou por inatividade. Faça login novamente.'];
        return null;
    }
    // Verifica assinatura de User-Agent contra sequestro de sessão (Session Hijacking)
    $currentUaHash = hash('sha256', (string)($_SERVER['HTTP_USER_AGENT'] ?? 'unknown'));
    if (!empty($_SESSION['cmdb_ua_hash']) && !hash_equals((string)$_SESSION['cmdb_ua_hash'], $currentUaHash)) {
        unset($_SESSION['cmdb_auth_user'], $_SESSION['cmdb_last_activity'], $_SESSION['cmdb_ua_hash']);
        return null;
    }
    $_SESSION['cmdb_last_activity'] = time();
    return $_SESSION['cmdb_auth_user'];
}

function isAdmin(?array $user = null): bool
{
    $u = $user ?? currentAuthUser();
    return $u !== null && ($u['role'] ?? '') === 'admin';
}

function requireAdmin(): void
{
    if (!isAdmin()) {
        http_response_code(403);
        throw new RuntimeException('Acesso Negado (403): Esta operação é exclusiva para usuários com perfil de Administração Completa.');
    }
}

/**
 * Controle de taxa de tentativas de login (Rate Limiting) persistente no servidor por IP + Usuário.
 * Impede que um atacante burle o bloqueio limpando os cookies do navegador.
 */
function checkAndRecordLoginAttempt(string $username, bool $isFailure = false, bool $resetOnSuccess = false): void
{
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    $key = hash('sha256', strtolower(trim($username)) . '|' . $ip);
    $ipKey = hash('sha256', 'ip_global|' . $ip);
    $now = time();
    $lockWindow = 300; // 5 minutos de bloqueio após 5 falhas

    $data = [];
    if (is_file(CMDB_RATELIMIT_FILE) && is_readable(CMDB_RATELIMIT_FILE)) {
        $raw = @file_get_contents(CMDB_RATELIMIT_FILE);
        $decoded = is_string($raw) ? @json_decode($raw, true) : null;
        if (is_array($decoded)) {
            $data = $decoded;
        }
    }

    // Limpa entradas antigas (> 1 hora)
    foreach ($data as $k => $v) {
        if (($v['updated_at'] ?? 0) < ($now - 3600)) {
            unset($data[$k]);
        }
    }

    foreach ([$key, $ipKey] as $checkK) {
        if (!empty($data[$checkK]['lock_until']) && $data[$checkK]['lock_until'] > $now) {
            $wait = (int)$data[$checkK]['lock_until'] - $now;
            throw new RuntimeException("Acesso temporariamente bloqueado por excesso de tentativas incorretas. Aguarde {$wait} segundos.");
        }
    }

    if ($resetOnSuccess) {
        unset($data[$key]);
        @file_put_contents(CMDB_RATELIMIT_FILE, json_encode($data), LOCK_EX);
        @chmod(CMDB_RATELIMIT_FILE, 0600);
        return;
    }

    if ($isFailure) {
        foreach ([$key => 5, $ipKey => 15] as $targetK => $threshold) {
            $entry = $data[$targetK] ?? ['count' => 0, 'lock_until' => 0, 'updated_at' => $now];
            $entry['count'] = ((int)$entry['count']) + 1;
            $entry['updated_at'] = $now;
            if ($entry['count'] >= $threshold) {
                $entry['lock_until'] = $now + $lockWindow;
                $entry['count'] = 0;
            }
            $data[$targetK] = $entry;
        }
        @file_put_contents(CMDB_RATELIMIT_FILE, json_encode($data), LOCK_EX);
        @chmod(CMDB_RATELIMIT_FILE, 0600);
    }
}

// ============================================================================
// 4. CAMADA MULTI-BANCO: SQL SERVER + MYSQL/MARIADB + SQLITE
// ============================================================================
class CMDBDatabase
{
    private array $config;
    private ?PDO $pdo = null;
    /** @var resource|false|null */
    private $sqlsrvConn = null;
    private ?mysqli $mysqliConn = null;
    private string $activeEngine = 'none';
    private ?string $lastError = null;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->connect();
    }

    public function isConnected(): bool { return $this->activeEngine !== 'none'; }
    public function getActiveEngine(): string { return $this->activeEngine; }
    public function getLastError(): ?string { return $this->lastError; }
    public function isSqlite(): bool { return $this->activeEngine === 'sqlite'; }
    public function isMysql(): bool { return in_array($this->activeEngine, ['pdo_mysql', 'mysqli'], true); }
    public function isSqlServer(): bool { return in_array($this->activeEngine, ['pdo_sqlsrv', 'native_sqlsrv', 'pdo_odbc'], true); }

    public function getConnectionStringPreview(bool $detailedForAdmin = false): string
    {
        $drv = $this->config['driver'] ?? 'sqlsrv';
        if (!$detailedForAdmin) {
            return strtoupper((string)$drv) . ' (' . ($this->config['database'] ?? 'CMDB') . ')';
        }
        if ($drv === 'sqlite') {
            return 'sqlite:cmdb_local_test.sqlite';
        }
        $srv  = $this->config['server'] ?? 'localhost';
        $port = trim((string)($this->config['port'] ?? ''));
        $db   = $this->config['database'] ?? 'CMDB';
        $usr  = $this->config['username'] ?? '';

        if ($drv === 'mysql') {
            $p = $port !== '' ? $port : '3306';
            $u = $usr !== '' ? $usr : 'root';
            return "mysql:host={$srv};port={$p};dbname={$db};charset=utf8mb4 (User: {$u})";
        }

        $srvPort = ($port !== '' && strpos($srv, ',') === false && strpos($srv, '\\') === false) ? "{$srv},{$port}" : $srv;
        $tc   = !empty($this->config['trust_cert']) ? '1' : '0';
        $auth = ($usr === '') ? 'Integrated Security=SSPI (Windows Auth)' : "UID={$usr};PWD=********";
        return "sqlsrv:Server={$srvPort};Database={$db};TrustServerCertificate={$tc};{$auth}";
    }

    private function connect(): void
    {
        $driver   = $this->config['driver'] ?? 'sqlsrv';
        $server   = trim((string)($this->config['server'] ?? 'localhost'));
        $port     = trim((string)($this->config['port'] ?? ''));
        $database = trim((string)($this->config['database'] ?? 'CMDB'));
        $username = trim((string)($this->config['username'] ?? ''));
        $password = (string)($this->config['password'] ?? '');

        if ($driver === 'sqlite') {
            try {
                $sqlitePath = __DIR__ . '/cmdb_local_test.sqlite';
                $this->pdo = new PDO('sqlite:' . $sqlitePath);
                $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
                $this->activeEngine = 'sqlite';
                @chmod($sqlitePath, 0600);
                return;
            } catch (Throwable $e) {
                $this->lastError = '[SQLite] ' . $e->getMessage();
                return;
            }
        }

        if ($driver === 'mysql') {
            $mysqlHost = $server !== '' ? $server : '127.0.0.1';
            $mysqlPort = $port !== '' ? (int)$port : 3306;
            $mysqlUser = $username !== '' ? $username : 'root';

            if (extension_loaded('pdo_mysql')) {
                try {
                    $dsn = "mysql:host={$mysqlHost};port={$mysqlPort};dbname={$database};charset=utf8mb4";
                    $this->pdo = new PDO($dsn, $mysqlUser, $password, [
                        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                        PDO::ATTR_EMULATE_PREPARES   => false,
                    ]);
                    $this->activeEngine = 'pdo_mysql';
                    return;
                } catch (Throwable $e) {
                    $this->lastError = '[PDO_MYSQL] ' . $e->getMessage();
                }
            }

            if (function_exists('mysqli_connect')) {
                mysqli_report(MYSQLI_REPORT_OFF);
                $conn = @mysqli_connect($mysqlHost, $mysqlUser, $password, $database, $mysqlPort);
                if ($conn instanceof mysqli && !$conn->connect_error) {
                    $conn->set_charset('utf8mb4');
                    $this->mysqliConn = $conn;
                    $this->activeEngine = 'mysqli';
                    $this->lastError = null;
                    return;
                } else {
                    $this->lastError = '[MySQLi] ' . ($conn ? $conn->connect_error : mysqli_connect_error());
                }
            }

            if ($this->lastError === null) {
                $this->lastError = 'Extensões pdo_mysql / mysqli não detectadas no PHP.';
            }
            return;
        }

        // SQL Server
        $srvTarget = ($port !== '' && strpos($server, ',') === false && strpos($server, '\\') === false)
            ? "{$server},{$port}"
            : $server;
        $trustCert = !empty($this->config['trust_cert']) ? '1' : '0';

        if (extension_loaded('pdo_sqlsrv')) {
            try {
                $dsn = "sqlsrv:Server={$srvTarget};Database={$database};TrustServerCertificate={$trustCert}";
                $this->pdo = new PDO($dsn, $username !== '' ? $username : null, $username !== '' ? $password : null, [
                    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                ]);
                $this->activeEngine = 'pdo_sqlsrv';
                return;
            } catch (Throwable $e) {
                $this->lastError = '[PDO_SQLSRV] ' . $e->getMessage();
            }
        }

        if (function_exists('sqlsrv_connect')) {
            $connInfo = [
                'Database'               => $database,
                'CharacterSet'           => 'UTF-8',
                'TrustServerCertificate' => (bool)$this->config['trust_cert'],
                'ReturnDatesAsStrings'   => true,
            ];
            if ($username !== '') {
                $connInfo['UID'] = $username;
                $connInfo['PWD'] = $password;
            }
            $conn = @sqlsrv_connect($srvTarget, $connInfo);
            if ($conn !== false) {
                $this->sqlsrvConn = $conn;
                $this->activeEngine = 'native_sqlsrv';
                $this->lastError = null;
                return;
            } else {
                $errs = sqlsrv_errors();
                $msg = [];
                if (is_array($errs)) {
                    foreach ($errs as $er) {
                        $msg[] = ($er['SQLSTATE'] ?? '') . ': ' . ($er['message'] ?? '');
                    }
                }
                $this->lastError = '[SQLSRV Nativo] ' . implode(' | ', $msg);
            }
        }

        if (extension_loaded('pdo_odbc')) {
            foreach (['ODBC Driver 18 for SQL Server', 'ODBC Driver 17 for SQL Server', 'SQL Server'] as $odbcDriver) {
                try {
                    $authPart = ($username === '') ? 'Trusted_Connection=yes;' : "Uid={$username};Pwd={$password};";
                    $dsn = "odbc:Driver={{$odbcDriver}};Server={$srvTarget};Database={$database};TrustServerCertificate=" . ($trustCert ? 'yes' : 'no') . ";{$authPart}";
                    $this->pdo = new PDO($dsn, $username !== '' ? $username : null, $username !== '' ? $password : null, [
                        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    ]);
                    $this->activeEngine = 'pdo_odbc';
                    $this->lastError = null;
                    return;
                } catch (Throwable $e) {
                    $this->lastError = '[PDO_ODBC] ' . $e->getMessage();
                }
            }
        }

        if ($this->lastError === null) {
            $this->lastError = 'Driver do banco configurado não encontrado no PHP. Contate o Administrador para parametrizar o SGBD.';
        }
    }

    public function createDatabaseIfMissing(): bool
    {
        $driver   = $this->config['driver'] ?? 'sqlsrv';
        $server   = trim((string)($this->config['server'] ?? 'localhost'));
        $port     = trim((string)($this->config['port'] ?? ''));
        $database = preg_replace('/[^a-zA-Z0-9_\-]/', '', (string)($this->config['database'] ?? 'CMDB'));
        $username = trim((string)($this->config['username'] ?? ''));
        $password = (string)($this->config['password'] ?? '');

        if ($driver === 'sqlite') {
            return true;
        }
        if ($driver === 'mysql') {
            $mysqlHost = $server !== '' ? $server : '127.0.0.1';
            $mysqlPort = $port !== '' ? (int)$port : 3306;
            $mysqlUser = $username !== '' ? $username : 'root';
            try {
                if (extension_loaded('pdo_mysql')) {
                    $tmp = new PDO("mysql:host={$mysqlHost};port={$mysqlPort};charset=utf8mb4", $mysqlUser, $password, [
                        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    ]);
                    $tmp->exec("CREATE DATABASE IF NOT EXISTS `{$database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;");
                    $this->connect();
                    return $this->isConnected();
                } elseif (function_exists('mysqli_connect')) {
                    $conn = @mysqli_connect($mysqlHost, $mysqlUser, $password, '', $mysqlPort);
                    if ($conn) {
                        $conn->query("CREATE DATABASE IF NOT EXISTS `{$database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;");
                        $conn->close();
                        $this->connect();
                        return $this->isConnected();
                    }
                }
            } catch (Throwable $e) {
                $this->lastError = 'Falha ao criar database no MySQL/MariaDB: ' . $e->getMessage();
            }
            return false;
        }

        $srvTarget = ($port !== '' && strpos($server, ',') === false && strpos($server, '\\') === false) ? "{$server},{$port}" : $server;
        $trustCert = !empty($this->config['trust_cert']) ? '1' : '0';
        try {
            if (extension_loaded('pdo_sqlsrv')) {
                $tmp = new PDO("sqlsrv:Server={$srvTarget};Database=master;TrustServerCertificate={$trustCert}", $username !== '' ? $username : null, $username !== '' ? $password : null, [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                ]);
                $tmp->exec("IF DB_ID(N'{$database}') IS NULL CREATE DATABASE [{$database}];");
                $this->connect();
                return $this->isConnected();
            } elseif (function_exists('sqlsrv_connect')) {
                $info = ['Database' => 'master', 'CharacterSet' => 'UTF-8', 'TrustServerCertificate' => (bool)$this->config['trust_cert']];
                if ($username !== '') {
                    $info['UID'] = $username;
                    $info['PWD'] = $password;
                }
                $conn = @sqlsrv_connect($srvTarget, $info);
                if ($conn !== false) {
                    @sqlsrv_query($conn, "IF DB_ID(N'{$database}') IS NULL CREATE DATABASE [{$database}];");
                    @sqlsrv_close($conn);
                    $this->connect();
                    return $this->isConnected();
                }
            }
        } catch (Throwable $e) {
            $this->lastError = 'Falha ao criar database no SQL Server: ' . $e->getMessage();
        }
        return false;
    }

    public function fetchAll(string $sql, array $params = []): array
    {
        if (!$this->isConnected()) {
            return [];
        }
        $sql = $this->normalizeSql($sql);

        if ($this->pdo !== null) {
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute(array_values($params));
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            return is_array($rows) ? $this->normalizeRows($rows) : [];
        }

        if ($this->sqlsrvConn !== null) {
            $stmt = sqlsrv_query($this->sqlsrvConn, $sql, array_values($params));
            if ($stmt === false) {
                $errs = sqlsrv_errors();
                throw new RuntimeException('Erro SQL Server: ' . ($errs[0]['message'] ?? 'Desconhecido'));
            }
            $rows = [];
            while ($r = sqlsrv_fetch_array($stmt, SQLSRV_FETCH_ASSOC)) {
                $rows[] = $r;
            }
            sqlsrv_free_stmt($stmt);
            return $this->normalizeRows($rows);
        }

        if ($this->mysqliConn !== null) {
            $stmt = $this->prepareMysqli($sql, array_values($params));
            $res = $stmt->get_result();
            $rows = $res ? $res->fetch_all(MYSQLI_ASSOC) : [];
            $stmt->close();
            return $this->normalizeRows($rows);
        }

        return [];
    }

    public function fetchOne(string $sql, array $params = []): ?array
    {
        $rows = $this->fetchAll($sql, $params);
        return $rows[0] ?? null;
    }

    public function fetchScalar(string $sql, array $params = [], $default = 0)
    {
        $row = $this->fetchOne($sql, $params);
        if ($row === null || empty($row)) {
            return $default;
        }
        $val = reset($row);
        return $val !== null ? $val : $default;
    }

    public function execute(string $sql, array $params = []): bool
    {
        if (!$this->isConnected()) {
            throw new RuntimeException('Sem conexão ativa com o banco de dados.');
        }
        $sql = $this->normalizeSql($sql);

        if ($this->pdo !== null) {
            $stmt = $this->pdo->prepare($sql);
            return $stmt->execute(array_values($params));
        }

        if ($this->sqlsrvConn !== null) {
            $stmt = sqlsrv_query($this->sqlsrvConn, $sql, array_values($params));
            if ($stmt === false) {
                $errs = sqlsrv_errors();
                throw new RuntimeException('Erro SQL Server: ' . ($errs[0]['message'] ?? 'Desconhecido'));
            }
            sqlsrv_free_stmt($stmt);
            return true;
        }

        if ($this->mysqliConn !== null) {
            if (empty($params)) {
                $ok = $this->mysqliConn->query($sql);
                if ($ok === false) {
                    throw new RuntimeException('Erro MySQL/MariaDB: ' . $this->mysqliConn->error);
                }
                return true;
            }
            $stmt = $this->prepareMysqli($sql, array_values($params));
            $stmt->close();
            return true;
        }

        return false;
    }

    public function lastInsertId(): int
    {
        if ($this->pdo !== null) {
            if ($this->isSqlite() || $this->isMysql()) {
                return (int)$this->pdo->lastInsertId();
            }
            $id = (int)$this->fetchScalar('SELECT CAST(SCOPE_IDENTITY() AS INT) AS LastID', [], 0);
            return $id > 0 ? $id : (int)$this->pdo->lastInsertId();
        }
        if ($this->sqlsrvConn !== null) {
            return (int)$this->fetchScalar('SELECT CAST(SCOPE_IDENTITY() AS INT) AS LastID', [], 0);
        }
        if ($this->mysqliConn !== null) {
            return (int)$this->mysqliConn->insert_id;
        }
        return 0;
    }

    private function prepareMysqli(string $sql, array $params): mysqli_stmt
    {
        $stmt = $this->mysqliConn->prepare($sql);
        if (!$stmt) {
            throw new RuntimeException('Erro ao preparar query MySQL: ' . $this->mysqliConn->error);
        }
        if (!empty($params)) {
            $types = '';
            $bindValues = [];
            foreach ($params as $p) {
                if (is_int($p)) {
                    $types .= 'i';
                } elseif (is_float($p)) {
                    $types .= 'd';
                } else {
                    $types .= 's';
                }
                $bindValues[] = $p;
            }
            $stmt->bind_param($types, ...$bindValues);
        }
        if (!$stmt->execute()) {
            $err = $stmt->error;
            $stmt->close();
            throw new RuntimeException('Erro na execução MySQL: ' . $err);
        }
        return $stmt;
    }

    private function normalizeSql(string $sql): string
    {
        if ($this->isMysql()) {
            $sql = preg_replace('/DATEADD\s*\(\s*DAY\s*,\s*90\s*,\s*GETDATE\(\)\s*\)/i', 'DATE_ADD(CURDATE(), INTERVAL 90 DAY)', $sql);
            $sql = str_ireplace('GETDATE()', 'NOW()', $sql);
            return $sql;
        }
        if ($this->isSqlite()) {
            $sql = preg_replace('/DATEADD\s*\(\s*DAY\s*,\s*90\s*,\s*GETDATE\(\)\s*\)/i', "date('now','localtime','+90 days')", $sql);
            $sql = str_ireplace('GETDATE()', "datetime('now','localtime')", $sql);
            return $sql;
        }
        return $sql;
    }

    private function normalizeRows(array $rows): array
    {
        foreach ($rows as &$r) {
            foreach ($r as $k => $v) {
                if ($v instanceof DateTimeInterface) {
                    $r[$k] = $v->format('Y-m-d H:i:s');
                }
            }
        }
        unset($r);
        return $rows;
    }
}

// ============================================================================
// 5. INICIALIZAÇÃO MULTI-BANCO (10 TABELAS DO SQL + OPERADORES + 3 VIEWS)
// ============================================================================
function initializeDatabaseSchema(CMDBDatabase $db, bool $includeSeed = true, bool $includeMissingRefAssets = false): void
{
    if ($db->isSqlite()) {
        $ddl = [
            "CREATE TABLE IF NOT EXISTS CMDBAdmins (
                AdminID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT UNIQUE NOT NULL,
                PasswordHash TEXT NOT NULL,
                DisplayName TEXT NOT NULL,
                Role TEXT DEFAULT 'admin',
                Active INTEGER DEFAULT 1,
                LastLogin TEXT,
                CreatedDate TEXT DEFAULT (datetime('now','localtime'))
            )",
            "CREATE TABLE IF NOT EXISTS AssetTypes (AssetTypeID INTEGER PRIMARY KEY AUTOINCREMENT, AssetTypeName TEXT)",
            "CREATE TABLE IF NOT EXISTS Manufacturers (ManufacturerID INTEGER PRIMARY KEY AUTOINCREMENT, ManufacturerName TEXT)",
            "CREATE TABLE IF NOT EXISTS Status (StatusID INTEGER PRIMARY KEY AUTOINCREMENT, StatusName TEXT)",
            "CREATE TABLE IF NOT EXISTS Locations (LocationID INTEGER PRIMARY KEY AUTOINCREMENT, SiteName TEXT, Country TEXT, State TEXT, City TEXT, Room TEXT)",
            "CREATE TABLE IF NOT EXISTS Users (UserID INTEGER PRIMARY KEY AUTOINCREMENT, DisplayName TEXT, Email TEXT, Department TEXT, Manager TEXT)",
            "CREATE TABLE IF NOT EXISTS Assets (
                AssetID INTEGER PRIMARY KEY AUTOINCREMENT, AssetTag TEXT NOT NULL, SerialNumber TEXT, Hostname TEXT,
                AssetTypeID INTEGER, ManufacturerID INTEGER, Model TEXT, PurchaseDate TEXT, WarrantyEnd TEXT,
                StatusID INTEGER, AssignedUserID INTEGER, LocationID INTEGER, IPAddress TEXT, MACAddress TEXT,
                OperatingSystem TEXT, Notes TEXT, CreatedDate TEXT DEFAULT (datetime('now','localtime')), UpdatedDate TEXT
            )",
            "CREATE TABLE IF NOT EXISTS AssetHistory (
                HistoryID INTEGER PRIMARY KEY AUTOINCREMENT, AssetID INTEGER, PreviousUserID INTEGER, NewUserID INTEGER,
                PreviousLocationID INTEGER, NewLocationID INTEGER, ChangeDate TEXT DEFAULT (datetime('now','localtime')),
                ChangedBy TEXT, Notes TEXT
            )",
            "CREATE TABLE IF NOT EXISTS SoftwareInventory (
                SoftwareID INTEGER PRIMARY KEY AUTOINCREMENT, AssetID INTEGER, SoftwareName TEXT, Version TEXT, LicenseKey TEXT, InstallDate TEXT
            )",
            "CREATE TABLE IF NOT EXISTS NetworkPorts (
                PortID INTEGER PRIMARY KEY AUTOINCREMENT, AssetID INTEGER, PortName TEXT, VLAN TEXT, ConnectedDevice TEXT, ConnectedAssetID INTEGER, Description TEXT
            )",
            "CREATE TABLE IF NOT EXISTS MaintenanceHistory (
                MaintenanceID INTEGER PRIMARY KEY AUTOINCREMENT, AssetID INTEGER, MaintenanceDate TEXT, MaintenanceType TEXT, Vendor TEXT, Cost REAL, Description TEXT
            )",
            "DROP VIEW IF EXISTS vw_CMDB_Dashboard",
            "CREATE VIEW vw_CMDB_Dashboard AS SELECT AT.AssetTypeName, COUNT(*) AS Total FROM Assets A INNER JOIN AssetTypes AT ON A.AssetTypeID = AT.AssetTypeID GROUP BY AT.AssetTypeName",
            "DROP VIEW IF EXISTS vw_WarrantyExpiration",
            "CREATE VIEW vw_WarrantyExpiration AS SELECT AssetTag, Hostname, Model, WarrantyEnd FROM Assets WHERE date(WarrantyEnd) <= date('now','localtime','+90 days')",
            "DROP VIEW IF EXISTS vw_Assets",
            "CREATE VIEW vw_Assets AS SELECT A.AssetID, A.AssetTag, A.Hostname, AT.AssetTypeName, M.ManufacturerName, A.Model, S.StatusName, U.DisplayName AS AssignedUser, L.SiteName, A.IPAddress, A.OperatingSystem, A.WarrantyEnd FROM Assets A LEFT JOIN AssetTypes AT ON A.AssetTypeID = AT.AssetTypeID LEFT JOIN Manufacturers M ON A.ManufacturerID = M.ManufacturerID LEFT JOIN Status S ON A.StatusID = S.StatusID LEFT JOIN Users U ON A.AssignedUserID = U.UserID LEFT JOIN Locations L ON A.LocationID = L.LocationID"
        ];
        foreach ($ddl as $sql) {
            $db->execute($sql);
        }
    } elseif ($db->isMysql()) {
        $mysqlDdl = [
            "CREATE TABLE IF NOT EXISTS CMDBAdmins (
                AdminID INT AUTO_INCREMENT PRIMARY KEY,
                Username VARCHAR(80) NOT NULL UNIQUE,
                PasswordHash VARCHAR(255) NOT NULL,
                DisplayName VARCHAR(150) NOT NULL,
                Role VARCHAR(40) DEFAULT 'admin',
                Active TINYINT(1) DEFAULT 1,
                LastLogin DATETIME NULL,
                CreatedDate DATETIME DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
            "CREATE TABLE IF NOT EXISTS AssetTypes (AssetTypeID INT AUTO_INCREMENT PRIMARY KEY, AssetTypeName VARCHAR(50)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
            "CREATE TABLE IF NOT EXISTS Manufacturers (ManufacturerID INT AUTO_INCREMENT PRIMARY KEY, ManufacturerName VARCHAR(100)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
            "CREATE TABLE IF NOT EXISTS Status (StatusID INT AUTO_INCREMENT PRIMARY KEY, StatusName VARCHAR(50)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
            "CREATE TABLE IF NOT EXISTS Locations (LocationID INT AUTO_INCREMENT PRIMARY KEY, SiteName VARCHAR(100), Country VARCHAR(100), State VARCHAR(100), City VARCHAR(100), Room VARCHAR(100)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
            "CREATE TABLE IF NOT EXISTS Users (UserID INT AUTO_INCREMENT PRIMARY KEY, DisplayName VARCHAR(200), Email VARCHAR(200), Department VARCHAR(100), Manager VARCHAR(200)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
            "CREATE TABLE IF NOT EXISTS Assets (
                AssetID INT AUTO_INCREMENT PRIMARY KEY, AssetTag VARCHAR(50) NOT NULL, SerialNumber VARCHAR(100), Hostname VARCHAR(100),
                AssetTypeID INT, ManufacturerID INT, Model VARCHAR(100), PurchaseDate DATE, WarrantyEnd DATE,
                StatusID INT, AssignedUserID INT, LocationID INT, IPAddress VARCHAR(50), MACAddress VARCHAR(50),
                OperatingSystem VARCHAR(100), Notes LONGTEXT, CreatedDate DATETIME DEFAULT CURRENT_TIMESTAMP, UpdatedDate DATETIME NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
            "CREATE TABLE IF NOT EXISTS AssetHistory (
                HistoryID INT AUTO_INCREMENT PRIMARY KEY, AssetID INT, PreviousUserID INT, NewUserID INT,
                PreviousLocationID INT, NewLocationID INT, ChangeDate DATETIME DEFAULT CURRENT_TIMESTAMP, ChangedBy VARCHAR(100), Notes LONGTEXT
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
            "CREATE TABLE IF NOT EXISTS SoftwareInventory (
                SoftwareID INT AUTO_INCREMENT PRIMARY KEY, AssetID INT, SoftwareName VARCHAR(200), Version VARCHAR(50), LicenseKey VARCHAR(255), InstallDate DATE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
            "CREATE TABLE IF NOT EXISTS NetworkPorts (
                PortID INT AUTO_INCREMENT PRIMARY KEY, AssetID INT, PortName VARCHAR(50), VLAN VARCHAR(50), ConnectedDevice VARCHAR(200), ConnectedAssetID INT, Description VARCHAR(255)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
            "CREATE TABLE IF NOT EXISTS MaintenanceHistory (
                MaintenanceID INT AUTO_INCREMENT PRIMARY KEY, AssetID INT, MaintenanceDate DATE, MaintenanceType VARCHAR(100), Vendor VARCHAR(100), Cost DECIMAL(18,2), Description LONGTEXT
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
            "CREATE OR REPLACE VIEW vw_CMDB_Dashboard AS SELECT AT.AssetTypeName, COUNT(*) AS Total FROM Assets A INNER JOIN AssetTypes AT ON A.AssetTypeID = AT.AssetTypeID GROUP BY AT.AssetTypeName;",
            "CREATE OR REPLACE VIEW vw_WarrantyExpiration AS SELECT AssetTag, Hostname, Model, WarrantyEnd FROM Assets WHERE WarrantyEnd <= DATE_ADD(CURDATE(), INTERVAL 90 DAY);",
            "CREATE OR REPLACE VIEW vw_Assets AS SELECT A.AssetID, A.AssetTag, A.Hostname, AT.AssetTypeName, M.ManufacturerName, A.Model, S.StatusName, U.DisplayName AS AssignedUser, L.SiteName, A.IPAddress, A.OperatingSystem, A.WarrantyEnd FROM Assets A LEFT JOIN AssetTypes AT ON A.AssetTypeID = AT.AssetTypeID LEFT JOIN Manufacturers M ON A.ManufacturerID = M.ManufacturerID LEFT JOIN Status S ON A.StatusID = S.StatusID LEFT JOIN Users U ON A.AssignedUserID = U.UserID LEFT JOIN Locations L ON A.LocationID = L.LocationID;"
        ];
        foreach ($mysqlDdl as $sql) {
            $db->execute($sql);
        }
    } else {
        $tsqlTables = [
            "IF OBJECT_ID('dbo.CMDBAdmins', 'U') IS NULL
            CREATE TABLE CMDBAdmins (
                AdminID INT IDENTITY(1,1) PRIMARY KEY,
                Username VARCHAR(80) NOT NULL UNIQUE,
                PasswordHash VARCHAR(255) NOT NULL,
                DisplayName VARCHAR(150) NOT NULL,
                Role VARCHAR(40) DEFAULT 'admin',
                Active BIT DEFAULT 1,
                LastLogin DATETIME NULL,
                CreatedDate DATETIME DEFAULT GETDATE()
            );",
            "IF OBJECT_ID('dbo.AssetTypes', 'U') IS NULL CREATE TABLE AssetTypes (AssetTypeID INT IDENTITY(1,1) PRIMARY KEY, AssetTypeName VARCHAR(50));",
            "IF OBJECT_ID('dbo.Manufacturers', 'U') IS NULL CREATE TABLE Manufacturers (ManufacturerID INT IDENTITY(1,1) PRIMARY KEY, ManufacturerName VARCHAR(100));",
            "IF OBJECT_ID('dbo.Status', 'U') IS NULL CREATE TABLE Status (StatusID INT IDENTITY(1,1) PRIMARY KEY, StatusName VARCHAR(50));",
            "IF OBJECT_ID('dbo.Locations', 'U') IS NULL CREATE TABLE Locations (LocationID INT IDENTITY(1,1) PRIMARY KEY, SiteName VARCHAR(100), Country VARCHAR(100), State VARCHAR(100), City VARCHAR(100), Room VARCHAR(100));",
            "IF OBJECT_ID('dbo.Users', 'U') IS NULL CREATE TABLE Users (UserID INT IDENTITY(1,1) PRIMARY KEY, DisplayName VARCHAR(200), Email VARCHAR(200), Department VARCHAR(100), Manager VARCHAR(200));",
            "IF OBJECT_ID('dbo.Assets', 'U') IS NULL CREATE TABLE Assets (AssetID INT IDENTITY(1,1) PRIMARY KEY, AssetTag VARCHAR(50) NOT NULL, SerialNumber VARCHAR(100), Hostname VARCHAR(100), AssetTypeID INT, ManufacturerID INT, Model VARCHAR(100), PurchaseDate DATE, WarrantyEnd DATE, StatusID INT, AssignedUserID INT, LocationID INT, IPAddress VARCHAR(50), MACAddress VARCHAR(50), OperatingSystem VARCHAR(100), Notes VARCHAR(MAX), CreatedDate DATETIME DEFAULT GETDATE(), UpdatedDate DATETIME);",
            "IF OBJECT_ID('dbo.AssetHistory', 'U') IS NULL CREATE TABLE AssetHistory (HistoryID INT IDENTITY(1,1) PRIMARY KEY, AssetID INT, PreviousUserID INT, NewUserID INT, PreviousLocationID INT, NewLocationID INT, ChangeDate DATETIME DEFAULT GETDATE(), ChangedBy VARCHAR(100), Notes VARCHAR(MAX));",
            "IF OBJECT_ID('dbo.SoftwareInventory', 'U') IS NULL CREATE TABLE SoftwareInventory (SoftwareID INT IDENTITY(1,1) PRIMARY KEY, AssetID INT, SoftwareName VARCHAR(200), Version VARCHAR(50), LicenseKey VARCHAR(255), InstallDate DATE);",
            "IF OBJECT_ID('dbo.NetworkPorts', 'U') IS NULL CREATE TABLE NetworkPorts (PortID INT IDENTITY(1,1) PRIMARY KEY, AssetID INT, PortName VARCHAR(50), VLAN VARCHAR(50), ConnectedDevice VARCHAR(200), ConnectedAssetID INT, Description VARCHAR(255));",
            "IF OBJECT_ID('dbo.MaintenanceHistory', 'U') IS NULL CREATE TABLE MaintenanceHistory (MaintenanceID INT IDENTITY(1,1) PRIMARY KEY, AssetID INT, MaintenanceDate DATE, MaintenanceType VARCHAR(100), Vendor VARCHAR(100), Cost DECIMAL(18,2), Description VARCHAR(MAX));"
        ];
        foreach ($tsqlTables as $sql) {
            $db->execute($sql);
        }

        $views = [
            'vw_CMDB_Dashboard' => "CREATE VIEW vw_CMDB_Dashboard AS SELECT AT.AssetTypeName, COUNT(*) Total FROM Assets A INNER JOIN AssetTypes AT ON A.AssetTypeID = AT.AssetTypeID GROUP BY AT.AssetTypeName",
            'vw_WarrantyExpiration' => "CREATE VIEW vw_WarrantyExpiration AS SELECT AssetTag, Hostname, Model, WarrantyEnd FROM Assets WHERE WarrantyEnd <= DATEADD(DAY,90,GETDATE())",
            'vw_Assets' => "CREATE VIEW vw_Assets AS SELECT A.AssetID, A.AssetTag, A.Hostname, AT.AssetTypeName, M.ManufacturerName, A.Model, S.StatusName, U.DisplayName AS AssignedUser, L.SiteName, A.IPAddress, A.OperatingSystem, A.WarrantyEnd FROM Assets A LEFT JOIN AssetTypes AT ON A.AssetTypeID = AT.AssetTypeID LEFT JOIN Manufacturers M ON A.ManufacturerID = M.ManufacturerID LEFT JOIN Status S ON A.StatusID = S.StatusID LEFT JOIN Users U ON A.AssignedUserID = U.UserID LEFT JOIN Locations L ON A.LocationID = L.LocationID"
        ];
        foreach ($views as $vName => $vSql) {
            $db->execute("IF OBJECT_ID('dbo.{$vName}', 'V') IS NOT NULL DROP VIEW dbo.{$vName};");
            $db->execute($vSql);
        }
    }

    if ((int)$db->fetchScalar('SELECT COUNT(*) FROM CMDBAdmins') === 0) {
        $hash = password_hash('Admin@123', PASSWORD_DEFAULT);
        $db->execute(
            'INSERT INTO CMDBAdmins (Username, PasswordHash, DisplayName, Role, Active) VALUES (?, ?, ?, ?, 1)',
            ['admin', $hash, 'Administrador TI', 'admin']
        );
    }

    if (!$includeSeed) {
        return;
    }

    if ((int)$db->fetchScalar('SELECT COUNT(*) FROM AssetTypes') === 0) {
        foreach (['Laptop', 'Desktop', 'Servidor Físico', 'Servidor Virtual', 'Celular', 'Switch', 'Firewall', 'Access Point', 'Impressora', 'Monitor', 'Storage', 'Outro'] as $t) {
            $db->execute('INSERT INTO AssetTypes (AssetTypeName) VALUES (?)', [$t]);
        }
    }
    if ((int)$db->fetchScalar('SELECT COUNT(*) FROM Manufacturers') === 0) {
        foreach (['Dell', 'HP', 'Lenovo', 'Cisco', 'Fortinet', 'Juniper', 'Apple', 'Samsung', 'VMware', 'Microsoft'] as $m) {
            $db->execute('INSERT INTO Manufacturers (ManufacturerName) VALUES (?)', [$m]);
        }
    }
    if ((int)$db->fetchScalar('SELECT COUNT(*) FROM Status') === 0) {
        foreach (['Em Uso', 'Estoque', 'Em Manutenção', 'Descartado', 'Emprestado', 'Reservado'] as $s) {
            $db->execute('INSERT INTO Status (StatusName) VALUES (?)', [$s]);
        }
    }
    if ((int)$db->fetchScalar('SELECT COUNT(*) FROM Locations') === 0) {
        $locs = [
            ['Sorocaba Office', 'Brasil', 'SP', 'Sorocaba', 'TI'],
            ['Sorocaba Datacenter', 'Brasil', 'SP', 'Sorocaba', 'DC01'],
            ['Campinas Office', 'Brasil', 'SP', 'Campinas', 'TI'],
            ['Rio Office', 'Brasil', 'RJ', 'Rio de Janeiro', 'TI'],
            ['Curitiba Office', 'Brasil', 'PR', 'Curitiba', 'TI'],
        ];
        foreach ($locs as $l) {
            $db->execute('INSERT INTO Locations (SiteName, Country, State, City, Room) VALUES (?, ?, ?, ?, ?)', $l);
        }
    }
    if ((int)$db->fetchScalar('SELECT COUNT(*) FROM Users') === 0) {
        $users = [
            ['Carlos Pires', 'Carlos.Pires@empresa.com', 'IT', 'Jose Ferreira'],
            ['Jose Ferreira', 'Jose.ferreira@empresa.com', 'IT', 'Eric Ruiz'],
            ['João Silva', 'joao.silva@empresa.com', 'Financeiro', 'Carlos Mendes'],
            ['Maria Oliveira', 'maria.oliveira@empresa.com', 'RH', 'Patricia Souza'],
            ['Pedro Santos', 'pedro.santos@empresa.com', 'Operações', 'Fernanda Lima'],
        ];
        foreach ($users as $u) {
            $db->execute('INSERT INTO Users (DisplayName, Email, Department, Manager) VALUES (?, ?, ?, ?)', $u);
        }
    }
    if ((int)$db->fetchScalar('SELECT COUNT(*) FROM Assets') === 0) {
        $assets = [
            ['LAP0001', 'DL123456', 'BR-LAP001', 1, 1, 'Latitude 5440', '2025-01-15', '2028-01-15', 1, 1, 1, '10.10.10.11', '00-11-22-33-44-55', 'Windows 11 Enterprise', 'Notebook suporte'],
            ['LAP0002', 'LN654321', 'BR-LAP002', 1, 3, 'ThinkPad T14', '2025-02-01', '2028-02-01', 1, 3, 1, '10.10.10.12', '00-11-22-33-44-66', 'Windows 11 Enterprise', 'Notebook financeiro'],
        ];
        foreach ($assets as $a) {
            $db->execute('INSERT INTO Assets (AssetTag, SerialNumber, Hostname, AssetTypeID, ManufacturerID, Model, PurchaseDate, WarrantyEnd, StatusID, AssignedUserID, LocationID, IPAddress, MACAddress, OperatingSystem, Notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', $a);
        }
    }
    if ($includeMissingRefAssets && (int)$db->fetchScalar('SELECT COUNT(*) FROM Assets') <= 2) {
        $extraAssets = [
            ['SRV0001', 'DL900001', 'DC-AD01', 3, 1, 'PowerEdge R750', '2024-01-10', '2026-12-01', 1, 2, 2, '10.10.20.10', '00-11-22-AA-BB-01', 'Windows Server 2022', 'Controlador de Domínio (ID 3)'],
            ['SRV0002', 'VM900002', 'DC-SQL01', 4, 9, 'VMware vSphere VM', '2024-01-10', '2026-11-15', 1, 2, 2, '10.10.20.20', '00-50-56-AA-BB-02', 'Windows Server 2022', 'Servidor SQL Server (ID 4)'],
            ['CEL0001', 'SM889900', 'BR-CEL001', 5, 8, 'Galaxy S23', '2024-05-10', '2026-09-01', 1, 5, 3, '10.10.30.55', 'AA-BB-CC-DD-EE-05', 'Android 14', 'Celular corporativo Operações (ID 5)'],
            ['FW0001',  'FG778899', 'Firewall-FGT01', 7, 5, 'FortiGate 100F', '2024-03-01', '2027-03-01', 1, 2, 2, '10.10.0.1', '00-09-0F-AA-BB-06', 'FortiOS 7.4', 'Firewall Datacenter (ID 6)'],
            ['SW0001',  'CS112233', 'SW-CORE-01', 6, 4, 'Catalyst 9300', '2024-02-15', '2027-02-15', 1, 2, 2, '10.10.0.2', '00-1A-2B-3C-4D-07', 'Cisco IOS XE', 'Switch Core Datacenter (ID 7)'],
            ['SW0002',  'CS445566', 'SW-ACC-BAR01', 6, 4, 'Catalyst 2960X', '2024-02-15', '2026-11-30', 1, 1, 1, '10.10.10.2', '00-1A-2B-3C-4D-08', 'Cisco IOS', 'Switch Acesso Sorocaba (ID 8)'],
        ];
        foreach ($extraAssets as $ea) {
            $db->execute('INSERT INTO Assets (AssetTag, SerialNumber, Hostname, AssetTypeID, ManufacturerID, Model, PurchaseDate, WarrantyEnd, StatusID, AssignedUserID, LocationID, IPAddress, MACAddress, OperatingSystem, Notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', $ea);
        }
    }
    if ((int)$db->fetchScalar('SELECT COUNT(*) FROM SoftwareInventory') === 0) {
        $softwares = [
            [1, 'Microsoft 365 Apps', '2410', 'M365-LIC-001', '2025-01-15'],
            [1, 'CrowdStrike Falcon', '7.0', 'CS-LIC-001', '2025-01-15'],
            [2, 'Microsoft 365 Apps', '2410', 'M365-LIC-002', '2025-02-01'],
            [2, 'SAP GUI', '8.0', 'SAP-LIC-001', '2025-02-01'],
            [3, 'Windows Server', '2022', 'WS-LIC-001', '2024-01-10'],
            [4, 'SQL Server', '2022', 'SQL-LIC-001', '2024-01-10'],
        ];
        foreach ($softwares as $sw) {
            $db->execute('INSERT INTO SoftwareInventory (AssetID, SoftwareName, Version, LicenseKey, InstallDate) VALUES (?, ?, ?, ?, ?)', $sw);
        }
    }
    if ((int)$db->fetchScalar('SELECT COUNT(*) FROM MaintenanceHistory') === 0) {
        $maints = [
            [1, '2025-06-01', 'Preventiva', 'Dell', 0.00, 'Atualização BIOS'],
            [3, '2026-01-10', 'Atualização SO', 'Equipe Infra', 0.00, 'Aplicação de patches'],
            [5, '2025-08-15', 'Troca de tela', 'Samsung', 850.00, 'Tela quebrada'],
        ];
        foreach ($maints as $mt) {
            $db->execute('INSERT INTO MaintenanceHistory (AssetID, MaintenanceDate, MaintenanceType, Vendor, Cost, Description) VALUES (?, ?, ?, ?, ?, ?)', $mt);
        }
    }
    if ((int)$db->fetchScalar('SELECT COUNT(*) FROM NetworkPorts') === 0) {
        $ports = [
            [7, 'Gi1/0/1', '10', 'DC-AD01', null, 'Controlador Dominio'],
            [7, 'Gi1/0/2', '20', 'DC-SQL01', null, 'Servidor SQL'],
            [7, 'Gi1/0/3', '100', 'Firewall-FGT01', null, 'Uplink Firewall'],
            [8, 'Gi1/0/10', '120', 'BR-LAP001', 1, 'Notebook Carlos'],
            [8, 'Gi1/0/11', '120', 'BR-LAP002', 2, 'Notebook Financeiro'],
            [8, 'Gi1/0/24', '999', 'SW-CORE-01', null, 'Uplink Core'],
        ];
        foreach ($ports as $pt) {
            $db->execute('INSERT INTO NetworkPorts (AssetID, PortName, VLAN, ConnectedDevice, ConnectedAssetID, Description) VALUES (?, ?, ?, ?, ?, ?)', $pt);
        }
    }
}

// ============================================================================
// 6. PARSER DE IMPORTAÇÃO BLINDADO CONTRA XXE, ZIP BOMB E INJEÇÃO DE FÓRMULAS
// ============================================================================
class CMDBFileImporter
{
    public static function parseUploadedFile(string $tmpPath, string $origName, int $fileSize): array
    {
        if ($fileSize <= 0 || $fileSize > CMDB_MAX_UPLOAD_BYTES) {
            throw new RuntimeException('Tamanho de arquivo inválido ou superior ao limite de segurança (10 MB).');
        }
        $ext = strtolower((string)pathinfo($origName, PATHINFO_EXTENSION));
        if (!in_array($ext, ['xlsx', 'xls', 'csv', 'txt'], true)) {
            throw new RuntimeException("Formato '.{$ext}' bloqueado por política de segurança. Envie apenas .xlsx, .xls, .csv ou .txt.");
        }

        if ($ext === 'xlsx') {
            $rawRows = self::parseXlsx($tmpPath);
        } elseif ($ext === 'xls') {
            $rawRows = self::parseXlsOrXml($tmpPath);
        } else {
            $rawRows = self::parseDelimitedText($tmpPath);
        }

        $filtered = [];
        foreach ($rawRows as $r) {
            $nonEmpty = false;
            foreach ($r as $cell) {
                if (trim((string)$cell) !== '') {
                    $nonEmpty = true;
                    break;
                }
            }
            if ($nonEmpty) {
                $filtered[] = array_map(static fn($v) => trim((string)$v), $r);
            }
        }

        if (count($filtered) < 2) {
            throw new RuntimeException('O arquivo precisa conter pelo menos 1 linha de cabeçalho e 1 linha de dados.');
        }

        $headers = array_map([self::class, 'normalizeHeaderKey'], $filtered[0]);
        $assocRows = [];
        for ($i = 1, $n = count($filtered); $i < $n; $i++) {
            $row = $filtered[$i];
            $item = [];
            foreach ($headers as $colIdx => $hKey) {
                if ($hKey !== '') {
                    $item[$hKey] = $row[$colIdx] ?? '';
                }
            }
            $assocRows[] = $item;
        }

        return ['headers' => $headers, 'rows' => $assocRows];
    }

    public static function normalizeHeaderKey(string $header): string
    {
        $h = preg_replace('/^\xEF\xBB\xBF/', '', trim($header));
        $map = [
            'á'=>'a','à'=>'a','ã'=>'a','â'=>'a','ä'=>'a','é'=>'e','è'=>'e','ê'=>'e','ë'=>'e',
            'í'=>'i','ì'=>'i','î'=>'i','ï'=>'i','ó'=>'o','ò'=>'o','õ'=>'o','ô'=>'o','ö'=>'o',
            'ú'=>'u','ù'=>'u','û'=>'u','ü'=>'u','ç'=>'c',
            'Á'=>'a','À'=>'a','Ã'=>'a','Â'=>'a','É'=>'e','Ê'=>'e','Í'=>'i','Ó'=>'o','Õ'=>'o','Ô'=>'o','Ú'=>'u','Ç'=>'c'
        ];
        $h = strtr($h, $map);
        return strtolower((string)preg_replace('/[^a-zA-Z0-9]/', '', $h));
    }

    /**
     * Carregador XML blindado contra ataques XXE (XML External Entity) e expansão de entidades.
     */
    private static function safeLoadXml(string $xmlContent): ?SimpleXMLElement
    {
        if (preg_match('/<!\s*(DOCTYPE|ENTITY)\b/i', $xmlContent)) {
            throw new RuntimeException('Arquivo XML/Excel rejeitado por segurança: declarações DOCTYPE/ENTITY (XXE) não são permitidas.');
        }
        $prev = libxml_use_internal_errors(true);
        $xml = @simplexml_load_string($xmlContent, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOCDATA);
        libxml_clear_errors();
        libxml_use_internal_errors($prev);
        return $xml !== false ? $xml : null;
    }

    private static function parseDelimitedText(string $filePath): array
    {
        $content = (string)file_get_contents($filePath, false, null, 0, CMDB_MAX_UPLOAD_BYTES);
        $content = (string)preg_replace('/^\xEF\xBB\xBF/', '', $content);
        if (!mb_check_encoding($content, 'UTF-8')) {
            $content = mb_convert_encoding($content, 'UTF-8', 'Windows-1252,ISO-8859-1');
        }

        $lines = preg_split('/\r\n|\r|\n/', $content);
        $firstLine = '';
        foreach ($lines as $ln) {
            if (trim($ln) !== '') {
                $firstLine = $ln;
                break;
            }
        }
        if ($firstLine === '') {
            return [];
        }

        $delimiters = ["\t", ';', ',', '|'];
        $bestDelim = ';';
        $maxCount = -1;
        foreach ($delimiters as $d) {
            $cnt = substr_count($firstLine, $d);
            if ($cnt > $maxCount) {
                $maxCount = $cnt;
                $bestDelim = $d;
            }
        }

        $rows = [];
        $fp = fopen('php://memory', 'r+');
        fwrite($fp, $content);
        rewind($fp);
        while (($data = fgetcsv($fp, 0, $bestDelim)) !== false) {
            $rows[] = $data;
        }
        fclose($fp);
        return $rows;
    }

    private static function parseXlsx(string $filePath): array
    {
        $sharedStringsXml = self::extractZipEntry($filePath, 'xl/sharedStrings.xml');
        $sheetXml         = self::extractZipEntry($filePath, 'xl/worksheets/sheet1.xml');

        if ($sheetXml === null) {
            return self::parseXlsOrXml($filePath);
        }

        $sharedStrings = [];
        if ($sharedStringsXml !== null) {
            $ss = self::safeLoadXml($sharedStringsXml);
            if ($ss !== null && isset($ss->si)) {
                foreach ($ss->si as $si) {
                    if (isset($si->t)) {
                        $sharedStrings[] = (string)$si->t;
                    } elseif (isset($si->r)) {
                        $txt = '';
                        foreach ($si->r as $run) {
                            $txt .= (string)($run->t ?? '');
                        }
                        $sharedStrings[] = $txt;
                    } else {
                        $sharedStrings[] = '';
                    }
                }
            }
        }

        $xml = self::safeLoadXml($sheetXml);
        if ($xml === null || !isset($xml->sheetData->row)) {
            throw new RuntimeException('Não foi possível ler a planilha interna (sheet1.xml) do arquivo .xlsx.');
        }

        $rows = [];
        foreach ($xml->sheetData->row as $row) {
            $currentRow = [];
            $maxColIdx = 0;
            foreach ($row->c as $c) {
                $ref = (string)($c['r'] ?? '');
                $colLetters = preg_replace('/[0-9]/', '', $ref);
                $colIdx = self::columnIndexFromLetters($colLetters);
                $maxColIdx = max($maxColIdx, $colIdx);

                $type = (string)($c['t'] ?? '');
                $val = isset($c->v) ? (string)$c->v : '';
                if ($type === 's') {
                    $val = $sharedStrings[(int)$val] ?? $val;
                } elseif ($type === 'inlineStr' && isset($c->is->t)) {
                    $val = (string)$c->is->t;
                }
                $currentRow[$colIdx] = $val;
            }
            $denseRow = [];
            for ($i = 0; $i <= $maxColIdx; $i++) {
                $denseRow[] = $currentRow[$i] ?? '';
            }
            $rows[] = $denseRow;
        }
        return $rows;
    }

    private static function parseXlsOrXml(string $filePath): array
    {
        $raw = (string)file_get_contents($filePath, false, null, 0, CMDB_MAX_UPLOAD_BYTES);
        if (preg_match('/<!\s*(DOCTYPE|ENTITY)\b/i', $raw)) {
            throw new RuntimeException('Arquivo rejeitado por segurança: declarações DOCTYPE/ENTITY (XXE) não são permitidas.');
        }
        if (stripos($raw, '<Row') !== false && stripos($raw, '<Cell') !== false) {
            $cleanXml = preg_replace('/xmlns[^=]*="[^"]*"/i', '', $raw);
            $cleanXml = preg_replace('/[a-zA-Z0-9]+:([a-zA-Z0-9]+)/', '$1', (string)$cleanXml);
            $xml = self::safeLoadXml((string)$cleanXml);
            if ($xml !== null) {
                $rows = [];
                foreach ($xml->xpath('//Row') ?: [] as $r) {
                    $rowCells = [];
                    foreach ($r->Cell as $c) {
                        $rowCells[] = (string)($c->Data ?? '');
                    }
                    $rows[] = $rowCells;
                }
                if (!empty($rows)) {
                    return $rows;
                }
            }
        }
        if (stripos($raw, '<tr') !== false && stripos($raw, '<td') !== false) {
            $prev = libxml_use_internal_errors(true);
            $dom = new DOMDocument();
            @$dom->loadHTML($raw, LIBXML_NONET | LIBXML_NOCDATA);
            libxml_clear_errors();
            libxml_use_internal_errors($prev);
            $rows = [];
            foreach ($dom->getElementsByTagName('tr') as $tr) {
                $rowCells = [];
                foreach ($tr->childNodes as $node) {
                    if ($node instanceof DOMElement && in_array(strtolower($node->tagName), ['td', 'th'], true)) {
                        $rowCells[] = trim($node->textContent);
                    }
                }
                if (!empty($rowCells)) {
                    $rows[] = $rowCells;
                }
            }
            if (!empty($rows)) {
                return $rows;
            }
        }
        return self::parseDelimitedText($filePath);
    }

    private static function columnIndexFromLetters(string $letters): int
    {
        $letters = strtoupper($letters);
        $len = strlen($letters);
        if ($len === 0) {
            return 0;
        }
        $idx = 0;
        for ($i = 0; $i < $len; $i++) {
            $idx = $idx * 26 + (ord($letters[$i]) - 64);
        }
        return max(0, $idx - 1);
    }

    /**
     * Extrai entrada de arquivo .xlsx com limite anti-ZipBomb (máximo 15 MB descompactado).
     */
    private static function extractZipEntry(string $zipPath, string $entryName): ?string
    {
        $maxUncompressed = 15 * 1024 * 1024;
        if (class_exists('ZipArchive')) {
            $za = new ZipArchive();
            if ($za->open($zipPath) === true) {
                $stat = $za->statName($entryName);
                if (is_array($stat) && ($stat['size'] ?? 0) > $maxUncompressed) {
                    $za->close();
                    throw new RuntimeException('Arquivo .xlsx excedeu o limite de segurança de descompactação (Zip Bomb detectado).');
                }
                $data = $za->getFromName($entryName, $maxUncompressed);
                $za->close();
                if ($data !== false) {
                    return $data;
                }
            }
        }
        $bin = @file_get_contents($zipPath, false, null, 0, CMDB_MAX_UPLOAD_BYTES);
        if ($bin === false || strlen($bin) < 30 || substr($bin, 0, 4) !== "PK\x03\x04") {
            return null;
        }
        $offset = 0;
        $len = strlen($bin);
        while ($offset + 30 <= $len && substr($bin, $offset, 4) === "PK\x03\x04") {
            $hdr = unpack('vver/vflag/vmethod/vtime/vdate/Vcrc/VcompSize/VuncompSize/vnameLen/vextraLen', substr($bin, $offset + 4, 26));
            $name = substr($bin, $offset + 30, $hdr['nameLen']);
            $dataStart = $offset + 30 + $hdr['nameLen'] + $hdr['extraLen'];
            if (($hdr['uncompSize'] ?? 0) > $maxUncompressed) {
                throw new RuntimeException('Arquivo .xlsx excedeu o limite de segurança de descompactação.');
            }
            $compData = substr($bin, $dataStart, $hdr['compSize']);
            if ($name === $entryName) {
                if ($hdr['method'] === 0) {
                    return $compData;
                }
                if ($hdr['method'] === 8) {
                    $inflated = @gzinflate($compData, $maxUncompressed);
                    return $inflated !== false ? $inflated : null;
                }
            }
            $offset = $dataStart + $hdr['compSize'];
        }
        return null;
    }
}

// ============================================================================
// 7. FUNÇÕES AUXILIARES DE SANITIZAÇÃO E PROTEÇÃO DE EXPORTAÇÃO CSV
// ============================================================================
function h($val): string
{
    return htmlspecialchars((string)($val ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Evita Injeção de Fórmula (CSV Formula Injection / DDE) ao abrir CSV no Excel.
 */
function sanitizeCsvRow(array $row): array
{
    $clean = [];
    foreach ($row as $val) {
        $str = (string)($val ?? '');
        if ($str !== '' && in_array($str[0], ['=', '+', '-', '@', "\t", "\r"], true) && !is_numeric($str)) {
            $str = "'" . $str;
        }
        $clean[] = $str;
    }
    return $clean;
}

function nullIfEmpty($val)
{
    if ($val === null) {
        return null;
    }
    $trimmed = trim((string)$val);
    return $trimmed === '' ? null : $trimmed;
}

function intOrNull($val): ?int
{
    if ($val === null || trim((string)$val) === '') {
        return null;
    }
    return is_numeric(trim((string)$val)) ? (int)trim((string)$val) : null;
}

function normalizeDateSql($val): ?string
{
    $str = trim((string)($val ?? ''));
    if ($str === '') {
        return null;
    }
    if (ctype_digit($str) && (int)$str > 25000 && (int)$str < 80000) {
        $unix = ((int)$str - 25569) * 86400;
        return gmdate('Y-m-d', $unix);
    }
    if (preg_match('#^(\d{1,2})/(\d{1,2})/(\d{4})$#', $str, $m)) {
        return sprintf('%04d-%02d-%02d', (int)$m[3], (int)$m[2], (int)$m[1]);
    }
    $ts = strtotime($str);
    return $ts !== false ? date('Y-m-d', $ts) : null;
}

function formatDateBr($val, bool $withTime = false): string
{
    if ($val === null || trim((string)$val) === '') {
        return '—';
    }
    $ts = strtotime(trim((string)$val));
    return $ts !== false ? date($withTime ? 'd/m/Y H:i' : 'd/m/Y', $ts) : h($val);
}

function formatDateInput($val): string
{
    if ($val === null || trim((string)$val) === '') {
        return '';
    }
    $ts = strtotime(trim((string)$val));
    return $ts !== false ? date('Y-m-d', $ts) : '';
}

function formatCurrencyBr($val): string
{
    return 'R$ ' . number_format((float)($val ?? 0), 2, ',', '.');
}

function statusBadgeHtml(?string $statusName): string
{
    $name = trim((string)$statusName);
    if ($name === '') {
        return '<span class="badge badge-neutral">Sem Status</span>';
    }
    $lower = mb_strtolower($name, 'UTF-8');
    $cls = 'badge-neutral';
    if (strpos($lower, 'uso') !== false) {
        $cls = 'badge-success';
    } elseif (strpos($lower, 'estoque') !== false || strpos($lower, 'reservado') !== false) {
        $cls = 'badge-info';
    } elseif (strpos($lower, 'manuten') !== false || strpos($lower, 'emprestado') !== false) {
        $cls = 'badge-warning';
    } elseif (strpos($lower, 'descartado') !== false || strpos($lower, 'inativo') !== false) {
        $cls = 'badge-danger';
    }
    return '<span class="badge ' . $cls . '">' . h($name) . '</span>';
}

function warrantyBadgeHtml(?string $warrantyEnd): string
{
    if ($warrantyEnd === null || trim($warrantyEnd) === '') {
        return '<span class="text-muted">—</span>';
    }
    $ts = strtotime(substr(trim($warrantyEnd), 0, 10));
    if ($ts === false) {
        return h($warrantyEnd);
    }
    $diffDays = (int)round(($ts - strtotime(date('Y-m-d'))) / 86400);
    $formatted = date('d/m/Y', $ts);
    if ($diffDays < 0) {
        return '<span class="badge badge-danger">' . $formatted . ' (Vencida)</span>';
    }
    if ($diffDays <= 90) {
        return '<span class="badge badge-warning">' . $formatted . ' (' . $diffDays . 'd)</span>';
    }
    return '<span class="badge badge-success">' . $formatted . '</span>';
}

// ============================================================================
// 8. CARREGAMENTO DA CONEXÃO PERSISTENTE E CHECAGEM DO SCHEMA
// ============================================================================
$DB_CONFIG = loadPersistentDbConfig($DEFAULT_DB_CONFIG);
$db = new CMDBDatabase($DB_CONFIG);

if ($db->isConnected() && $db->isSqlite()) {
    try {
        $hasTables = (int)$db->fetchScalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='Assets'", [], 0);
        if ($hasTables === 0) {
            initializeDatabaseSchema($db, true, true);
        }
    } catch (Throwable $e) {
    }
}

$schemaReady = false;
$adminTableReady = false;
if ($db->isConnected()) {
    try {
        if ($db->isSqlite()) {
            $schemaReady     = ((int)$db->fetchScalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='Assets'", [], 0)) > 0;
            $adminTableReady = ((int)$db->fetchScalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='CMDBAdmins'", [], 0)) > 0;
        } elseif ($db->isMysql()) {
            $schemaReady     = ((int)$db->fetchScalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'Assets'", [], 0)) > 0;
            $adminTableReady = ((int)$db->fetchScalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'CMDBAdmins'", [], 0)) > 0;
        } else {
            $schemaReady     = ((int)$db->fetchScalar("SELECT CASE WHEN OBJECT_ID('dbo.Assets', 'U') IS NOT NULL THEN 1 ELSE 0 END", [], 0)) === 1;
            $adminTableReady = ((int)$db->fetchScalar("SELECT CASE WHEN OBJECT_ID('dbo.CMDBAdmins', 'U') IS NOT NULL THEN 1 ELSE 0 END", [], 0)) === 1;
        }
    } catch (Throwable $e) {
        $schemaReady = false;
    }
}

// ============================================================================
// 9. PROCESSAMENTO DE LOGIN / LOGOUT E AUTENTICAÇÃO
// ============================================================================
if (isset($_GET['logout']) && $_GET['logout'] === '1') {
    unset($_SESSION['cmdb_auth_user'], $_SESSION['cmdb_last_activity'], $_SESSION['cmdb_ua_hash']);
    session_regenerate_id(true);
    $_SESSION['flash_msg'] = ['type' => 'info', 'text' => 'Sessão encerrada com segurança.'];
    header('Location: ?page=login');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['_action'] ?? '') === 'do_login') {
    try {
        verifyCsrf();
        $userIn = trim((string)($_POST['username'] ?? ''));
        $passIn = (string)($_POST['password'] ?? '');
        if ($userIn === '' || $passIn === '') {
            throw new RuntimeException('Preencha o usuário e a senha.');
        }

        // Verifica bloqueio persistente por IP/Usuário antes de validar credenciais
        checkAndRecordLoginAttempt($userIn, false, false);

        $authenticatedUser = null;

        if ($db->isConnected() && $adminTableReady) {
            $row = $db->fetchOne('SELECT * FROM CMDBAdmins WHERE LOWER(Username) = LOWER(?) AND Active = 1', [$userIn]);
            if ($row !== null && password_verify($passIn, (string)$row['PasswordHash'])) {
                $roleNormalized = in_array(strtolower((string)($row['Role'] ?? 'operator')), ['admin', 'operator'], true)
                    ? strtolower((string)$row['Role'])
                    : 'operator';
                $authenticatedUser = [
                    'id'           => (int)$row['AdminID'],
                    'username'     => (string)$row['Username'],
                    'display_name' => (string)$row['DisplayName'],
                    'role'         => $roleNormalized,
                ];
                $db->execute('UPDATE CMDBAdmins SET LastLogin = GETDATE() WHERE AdminID = ?', [(int)$row['AdminID']]);
            }
        }

        // Fallback seguro para o administrador inicial caso a tabela CMDBAdmins ainda não esteja criada
        if ($authenticatedUser === null && strtolower($userIn) === $FALLBACK_ADMIN['username']) {
            $adminExistsInDb = ($db->isConnected() && $adminTableReady)
                ? ((int)$db->fetchScalar('SELECT COUNT(*) FROM CMDBAdmins WHERE LOWER(Username) = ?', ['admin']) > 0)
                : false;

            if (!$adminExistsInDb && password_verify($passIn, $FALLBACK_ADMIN['password_hash'])) {
                $authenticatedUser = [
                    'id'           => 1,
                    'username'     => 'admin',
                    'display_name' => $FALLBACK_ADMIN['display_name'],
                    'role'         => 'admin',
                ];
            }
        }

        if ($authenticatedUser === null) {
            checkAndRecordLoginAttempt($userIn, true, false);
            throw new RuntimeException('Usuário ou senha inválidos.');
        }

        checkAndRecordLoginAttempt($userIn, false, true);
        session_regenerate_id(true);
        $_SESSION['csrf_token']         = bin2hex(random_bytes(32));
        $_SESSION['cmdb_auth_user']     = $authenticatedUser;
        $_SESSION['cmdb_last_activity'] = time();
        $_SESSION['cmdb_ua_hash']       = hash('sha256', (string)($_SERVER['HTTP_USER_AGENT'] ?? 'unknown'));
        $_SESSION['flash_msg']          = [
            'type' => 'success',
            'text' => 'Bem-vindo(a), ' . $authenticatedUser['display_name'] . ' (' . ($authenticatedUser['role'] === 'admin' ? 'Administração Completa' : 'Operador') . ')!'
        ];
        header('Location: ?page=dashboard');
        exit;
    } catch (Throwable $e) {
        $_SESSION['flash_msg'] = ['type' => 'danger', 'text' => $e->getMessage()];
        header('Location: ?page=login');
        exit;
    }
}

$authUser = currentAuthUser();

// Se não estiver autenticado, força a tela de Login (nenhuma ação de banco pode ser executada sem login)
if ($authUser === null) {
    $flash = $_SESSION['flash_msg'] ?? null;
    unset($_SESSION['flash_msg']);
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Seguro | CMDB Lite v2.1</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; color: #0f172a;
        }
        .login-card { background: #fff; width: 100%; max-width: 430px; border-radius: 14px; box-shadow: 0 20px 40px rgba(0,0,0,0.35); overflow: hidden; }
        .login-header { background: #0f172a; color: #fff; padding: 26px 28px; border-bottom: 1px solid rgba(255,255,255,0.08); display: flex; align-items: center; gap: 14px; }
        .logo-badge { width: 44px; height: 44px; border-radius: 10px; background: linear-gradient(135deg, #3b82f6, #1d4ed8); display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 18px; color: #fff; flex-shrink: 0; }
        .login-header h1 { font-size: 18px; font-weight: 700; }
        .login-header p { font-size: 12.5px; color: #94a3b8; margin-top: 2px; }
        .login-body { padding: 26px 28px; }
        .form-group { margin-bottom: 16px; }
        .form-group label { display: block; font-size: 12.5px; font-weight: 600; margin-bottom: 6px; color: #1e293b; }
        .form-control { width: 100%; padding: 10px 12px; border: 1px solid #cbd5e1; border-radius: 8px; font-size: 14px; }
        .form-control:focus { outline: none; border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37,99,235,0.15); }
        .btn-login { width: 100%; padding: 11px; background: #2563eb; color: #fff; border: none; border-radius: 8px; font-size: 14px; font-weight: 700; cursor: pointer; margin-top: 4px; }
        .btn-login:hover { background: #1d4ed8; }
        .alert { padding: 11px 14px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; font-weight: 500; }
        .alert-danger { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
        .alert-info, .alert-warning { background: #e0f2fe; color: #075985; border: 1px solid #bae6fd; }
        .credentials-hint { margin-top: 20px; padding: 12px 14px; background: #f8fafc; border: 1px dashed #cbd5e1; border-radius: 8px; font-size: 12px; color: #475569; line-height: 1.5; }
        .db-status-bar { margin-top: 14px; font-size: 11.5px; color: #64748b; display: flex; justify-content: space-between; }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="login-header">
            <div class="logo-badge">IT</div>
            <div>
                <h1>CMDB Lite v2.1</h1>
                <p>Autenticação Obrigatória • RBAC Ativo</p>
            </div>
        </div>
        <div class="login-body">
            <?php if ($flash): ?>
                <div class="alert alert-<?= h($flash['type'] === 'danger' ? 'danger' : 'info') ?>">
                    <?= h($flash['text']) ?>
                </div>
            <?php endif; ?>

            <form method="post" autocomplete="off">
                <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>">
                <input type="hidden" name="_action" value="do_login">
                <div class="form-group">
                    <label>Usuário</label>
                    <input type="text" name="username" class="form-control" required autofocus placeholder="Digite seu login">
                </div>
                <div class="form-group">
                    <label>Senha</label>
                    <input type="password" name="password" class="form-control" required placeholder="••••••••">
                </div>
                <button type="submit" class="btn-login">🔐 Entrar no Sistema</button>
            </form>

            <div class="credentials-hint">
                <strong>Acesso Inicial de Administração:</strong><br>
                Usuário: <code>admin</code> &nbsp;|&nbsp; Senha inicial: <code>Admin@123</code><br>
                <span style="color:#64748b;">Perfis suportados: <strong>Administrador Completo</strong> (acesso total + configuração fixa do banco) e <strong>Operador</strong> (acesso somente aos cadastros operacionais, sem acesso à troca de banco).</span>
            </div>

            <div class="db-status-bar">
                <span>Banco Fixo: <strong><?= h(strtoupper($DB_CONFIG['driver'] ?? 'sqlsrv')) ?></strong></span>
                <span>Status: <strong><?= $db->isConnected() ? 'Conectado' : 'Aguardando Admin' ?></strong></span>
            </div>
        </div>
    </div>
</body>
</html>
<?php
    exit;
}

// Revalida em tempo real o perfil (Role) e o status ativo do usuário no banco a cada requisição
if ($db->isConnected() && $adminTableReady && !empty($authUser['id'])) {
    $freshOp = $db->fetchOne('SELECT AdminID, Username, DisplayName, Role, Active FROM CMDBAdmins WHERE AdminID = ?', [(int)$authUser['id']]);
    if ($freshOp !== null) {
        if ((int)($freshOp['Active'] ?? 1) === 0) {
            unset($_SESSION['cmdb_auth_user']);
            header('Location: ?page=login');
            exit;
        }
        $authUser['role']         = in_array(strtolower((string)$freshOp['Role']), ['admin', 'operator'], true) ? strtolower((string)$freshOp['Role']) : 'operator';
        $authUser['display_name'] = (string)$freshOp['DisplayName'];
        $authUser['username']     = (string)$freshOp['Username'];
        $_SESSION['cmdb_auth_user'] = $authUser;
    }
}

$userIsAdmin = isAdmin($authUser);

// ============================================================================
// 10. DOWNLOAD DE MODELOS DE IMPORTAÇÃO E EXPORTAÇÃO CSV SEGURA
// ============================================================================
if (isset($_GET['download_template']) && $_GET['download_template'] !== '') {
    $tplType = (string)$_GET['download_template'];
    $fmt = strtolower((string)($_GET['fmt'] ?? 'csv'));

    $templates = [
        'assets' => [
            'headers' => ['AssetTag', 'SerialNumber', 'Hostname', 'AssetTypeName', 'ManufacturerName', 'Model', 'PurchaseDate', 'WarrantyEnd', 'StatusName', 'AssignedUser', 'SiteName', 'IPAddress', 'MACAddress', 'OperatingSystem', 'Notes'],
            'samples' => [
                ['LAP0010', 'DL556677', 'BR-LAP010', 'Laptop', 'Dell', 'Latitude 5440', '2025-03-01', '2028-03-01', 'Em Uso', 'Carlos Pires', 'Sorocaba Office', '10.10.10.50', '00-11-22-33-44-99', 'Windows 11 Enterprise', 'Importado via planilha'],
                ['SRV0010', 'HP998877', 'BR-SRV010', 'Servidor Físico', 'HP', 'ProLiant DL380', '2024-06-15', '2027-06-15', 'Em Uso', 'Jose Ferreira', 'Sorocaba Datacenter', '10.10.20.50', '00-11-22-AA-BB-99', 'Windows Server 2022', 'Servidor de Aplicação'],
            ],
        ],
        'users' => [
            'headers' => ['DisplayName', 'Email', 'Department', 'Manager'],
            'samples' => [
                ['Fernanda Costa', 'fernanda.costa@empresa.com', 'Engenharia', 'Jose Ferreira'],
                ['Ricardo Almeida', 'ricardo.almeida@empresa.com', 'Comercial', 'Carlos Mendes'],
            ],
        ],
        'locations' => [
            'headers' => ['SiteName', 'Country', 'State', 'City', 'Room'],
            'samples' => [
                ['Belo Horizonte Office', 'Brasil', 'MG', 'Belo Horizonte', 'Sala TI 02'],
                ['Porto Alegre Office', 'Brasil', 'RS', 'Porto Alegre', 'Rack 01'],
            ],
        ],
        'software' => [
            'headers' => ['AssetTag', 'SoftwareName', 'Version', 'LicenseKey', 'InstallDate'],
            'samples' => [
                ['LAP0001', 'AutoCAD 2025', '2025.1', 'ACAD-LIC-991', '2025-03-10'],
                ['LAP0002', 'Power BI Desktop', '2.126', 'FREE-CORP', '2025-03-12'],
            ],
        ],
        'ports' => [
            'headers' => ['AssetTag', 'PortName', 'VLAN', 'ConnectedDevice', 'Description'],
            'samples' => [
                ['SW0001', 'Gi1/0/5', '20', 'BR-SRV010', 'Servidor ERP'],
                ['SW0002', 'Gi1/0/15', '120', 'BR-LAP010', 'Ponto Rede TI'],
            ],
        ],
        'maintenance' => [
            'headers' => ['AssetTag', 'MaintenanceDate', 'MaintenanceType', 'Vendor', 'Cost', 'Description'],
            'samples' => [
                ['LAP0001', '2025-09-10', 'Upgrade de RAM', 'Dell', '420.00', 'Expansão para 32GB DDR5'],
            ],
        ],
    ];

    $tpl = $templates[$tplType] ?? $templates['assets'];
    $safeName = preg_replace('/[^a-z0-9_]/', '', $tplType) ?: 'assets';

    if ($fmt === 'xls') {
        header('Content-Type: application/vnd.ms-excel; charset=UTF-8');
        header('Content-Disposition: attachment; filename="modelo_importacao_' . $safeName . '.xls"');
        echo '<?xml version="1.0" encoding="UTF-8"?><?mso-application progid="Excel.Sheet"?>';
        echo '<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"><Worksheet ss:Name="Importacao"><Table>';
        echo '<Row>';
        foreach ($tpl['headers'] as $hCol) {
            echo '<Cell><Data ss:Type="String">' . h($hCol) . '</Data></Cell>';
        }
        echo '</Row>';
        foreach ($tpl['samples'] as $sRow) {
            echo '<Row>';
            foreach ($sRow as $cellVal) {
                echo '<Cell><Data ss:Type="String">' . h($cellVal) . '</Data></Cell>';
            }
            echo '</Row>';
        }
        echo '</Table></Worksheet></Workbook>';
        exit;
    }

    $delim = ($fmt === 'txt') ? "\t" : ';';
    $ext   = ($fmt === 'txt') ? 'txt' : 'csv';
    header('Content-Type: text/plain; charset=UTF-8');
    header('Content-Disposition: attachment; filename="modelo_importacao_' . $safeName . '.' . $ext . '"');
    echo "\xEF\xBB\xBF";
    $out = fopen('php://output', 'w');
    fputcsv($out, $tpl['headers'], $delim);
    foreach ($tpl['samples'] as $sRow) {
        fputcsv($out, sanitizeCsvRow($sRow), $delim);
    }
    fclose($out);
    exit;
}

if (isset($_GET['export']) && $_GET['export'] === 'vw_assets' && $db->isConnected() && $schemaReady) {
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="cmdb_vw_assets_' . date('Ymd_His') . '.csv"');
    echo "\xEF\xBB\xBF";
    $out = fopen('php://output', 'w');
    $rows = $db->fetchAll('SELECT * FROM vw_Assets ORDER BY AssetID ASC');
    if (!empty($rows)) {
        fputcsv($out, array_keys($rows[0]), ';');
        foreach ($rows as $r) {
            fputcsv($out, sanitizeCsvRow(array_values($r)), ';');
        }
    }
    fclose($out);
    exit;
}

// ============================================================================
// 11. RESOLUÇÃO DE CHAVES ESTRANGEIRAS PARA O IMPORTADOR
// ============================================================================
function resolveOrCreateLookupId(CMDBDatabase $db, string $table, string $idCol, string $nameCol, ?string $rawVal, bool $autoCreate = true): ?int
{
    $allowedTables = [
        'AssetTypes'    => ['AssetTypeID', 'AssetTypeName'],
        'Manufacturers' => ['ManufacturerID', 'ManufacturerName'],
        'Status'        => ['StatusID', 'StatusName'],
        'Users'         => ['UserID', 'DisplayName'],
        'Locations'     => ['LocationID', 'SiteName'],
    ];
    if (!isset($allowedTables[$table]) || $allowedTables[$table] !== [$idCol, $nameCol]) {
        throw new RuntimeException('Tabela de lookup inválida.');
    }

    $val = trim((string)($rawVal ?? ''));
    if ($val === '') {
        return null;
    }
    if (ctype_digit($val)) {
        return (int)$val;
    }
    $found = $db->fetchScalar("SELECT {$idCol} FROM {$table} WHERE LOWER({$nameCol}) = LOWER(?)", [$val], null);
    if ($found !== null) {
        return (int)$found;
    }
    if ($autoCreate) {
        $db->execute("INSERT INTO {$table} ({$nameCol}) VALUES (?)", [$val]);
        return $db->lastInsertId();
    }
    return null;
}

function resolveAssetIdByTagOrId(CMDBDatabase $db, ?string $rawVal): ?int
{
    $val = trim((string)($rawVal ?? ''));
    if ($val === '') {
        return null;
    }
    if (ctype_digit($val)) {
        return (int)$val;
    }
    $found = $db->fetchScalar('SELECT AssetID FROM Assets WHERE LOWER(AssetTag) = LOWER(?) OR LOWER(Hostname) = LOWER(?)', [$val, $val], null);
    return $found !== null ? (int)$found : null;
}

// ============================================================================
// 12. PROCESSAMENTO DE AÇÕES POST (COM CONTROLE ESTRITO DE PERFIL ADMIN vs OPERATOR)
// ============================================================================
$currentPage = (string)($_GET['page'] ?? 'dashboard');

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['_action']) && $_POST['_action'] !== 'do_login') {
    $action = (string)$_POST['_action'];
    $redirectPage = (string)($_POST['_redirect_page'] ?? $currentPage);

    try {
        verifyCsrf();

        switch ($action) {
            // ----------------------------------------------------------------
            // [EXCLUSIVO ADMIN] ALTERAÇÃO DA PARAMETRIZAÇÃO FIXA DO BANCO
            // ----------------------------------------------------------------
            case 'update_connection':
                requireAdmin();
                $newPassword = (string)($_POST['cfg_password'] ?? '');
                // Se a senha foi deixada em branco na edição, preserva a senha já salva no servidor
                if ($newPassword === '' && isset($_POST['keep_existing_password']) && $_POST['keep_existing_password'] === '1') {
                    $newPassword = (string)($DB_CONFIG['password'] ?? '');
                }
                $newCfg = [
                    'driver'     => trim((string)($_POST['cfg_driver'] ?? 'sqlsrv')),
                    'server'     => trim((string)($_POST['cfg_server'] ?? 'localhost')),
                    'port'       => trim((string)($_POST['cfg_port'] ?? '')),
                    'database'   => trim((string)($_POST['cfg_database'] ?? 'CMDB')),
                    'username'   => trim((string)($_POST['cfg_username'] ?? '')),
                    'password'   => $newPassword,
                    'trust_cert' => isset($_POST['cfg_trust_cert']),
                ];
                if (!savePersistentDbConfig($newCfg)) {
                    throw new RuntimeException('Não foi possível gravar o arquivo de configuração fixa no servidor. Verifique as permissões de escrita da pasta.');
                }
                $_SESSION['flash_msg'] = [
                    'type' => 'success',
                    'text' => 'Parametrização do banco salva de forma fixa no servidor! Todas as máquinas e navegadores já utilizam esta conexão.'
                ];
                $redirectPage = 'connection';
                break;

            case 'reset_connection':
                requireAdmin();
                if (is_file(CMDB_CONFIG_FILE)) {
                    @unlink(CMDB_CONFIG_FILE);
                }
                $_SESSION['flash_msg'] = ['type' => 'info', 'text' => 'Parametrização de banco restaurada para os valores padrão do servidor.'];
                $redirectPage = 'connection';
                break;

            // ----------------------------------------------------------------
            // [EXCLUSIVO ADMIN] INICIALIZAÇÃO DO SCHEMA DO BANCO
            // ----------------------------------------------------------------
            case 'init_schema':
                requireAdmin();
                if (!$db->isConnected()) {
                    $db->createDatabaseIfMissing();
                }
                if (!$db->isConnected()) {
                    throw new RuntimeException('Não foi possível conectar ao servidor para inicializar o schema: ' . $db->getLastError());
                }
                initializeDatabaseSchema($db, isset($_POST['with_seed']), isset($_POST['with_extra_assets']));
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => 'Schema completo (10 tabelas CMDB + Operadores + 3 Views) inicializado com sucesso!'];
                break;

            case 'seed_missing_assets':
                requireAdmin();
                initializeDatabaseSchema($db, true, true);
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => 'Ativos complementares (IDs 3 a 8) cadastrados com sucesso!'];
                break;

            // ----------------------------------------------------------------
            // [EXCLUSIVO ADMIN] GESTÃO DE OPERADORES E PERFIS (CMDBAdmins)
            // ----------------------------------------------------------------
            case 'save_operator':
                requireAdmin();
                $opId    = intOrNull($_POST['AdminID'] ?? null);
                $uName   = trim((string)($_POST['Username'] ?? ''));
                $dName   = trim((string)($_POST['DisplayName'] ?? ''));
                $role    = in_array($_POST['Role'] ?? '', ['admin', 'operator'], true) ? (string)$_POST['Role'] : 'operator';
                $active  = isset($_POST['Active']) ? 1 : 0;
                $passRaw = (string)($_POST['Password'] ?? '');

                if ($uName === '' || $dName === '') {
                    throw new RuntimeException('Informe o login (Username) e o Nome de Exibição.');
                }
                if (!preg_match('/^[a-zA-Z0-9._\-]{3,60}$/', $uName)) {
                    throw new RuntimeException('O login (Username) deve conter apenas letras, números, ponto, hífen ou sublinhado (3 a 60 caracteres).');
                }

                // Impede que o último administrador ativo seja rebaixado para operador ou desativado
                if ($opId !== null && ($role !== 'admin' || $active === 0)) {
                    $otherActiveAdmins = (int)$db->fetchScalar(
                        "SELECT COUNT(*) FROM CMDBAdmins WHERE Role = 'admin' AND Active = 1 AND AdminID <> ?",
                        [$opId]
                    );
                    if ($otherActiveAdmins === 0) {
                        throw new RuntimeException('Operação bloqueada: o sistema precisa manter pelo menos 1 Administrador Completo ativo.');
                    }
                }

                if ($opId === null) {
                    if (strlen($passRaw) < 8) {
                        throw new RuntimeException('A senha deve ter no mínimo 8 caracteres.');
                    }
                    $dup = (int)$db->fetchScalar('SELECT COUNT(*) FROM CMDBAdmins WHERE LOWER(Username) = LOWER(?)', [$uName]);
                    if ($dup > 0) {
                        throw new RuntimeException("Já existe um operador com o login '{$uName}'.");
                    }
                    $hash = password_hash($passRaw, PASSWORD_DEFAULT);
                    $db->execute('INSERT INTO CMDBAdmins (Username, PasswordHash, DisplayName, Role, Active) VALUES (?, ?, ?, ?, ?)', [$uName, $hash, $dName, $role, $active]);
                    $_SESSION['flash_msg'] = ['type' => 'success', 'text' => "Operador '{$uName}' ({$role}) cadastrado com sucesso!"];
                } else {
                    if ($passRaw !== '') {
                        if (strlen($passRaw) < 8) {
                            throw new RuntimeException('A nova senha deve ter no mínimo 8 caracteres.');
                        }
                        $hash = password_hash($passRaw, PASSWORD_DEFAULT);
                        $db->execute('UPDATE CMDBAdmins SET Username=?, PasswordHash=?, DisplayName=?, Role=?, Active=? WHERE AdminID=?', [$uName, $hash, $dName, $role, $active, $opId]);
                    } else {
                        $db->execute('UPDATE CMDBAdmins SET Username=?, DisplayName=?, Role=?, Active=? WHERE AdminID=?', [$uName, $dName, $role, $active, $opId]);
                    }
                    $_SESSION['flash_msg'] = ['type' => 'success', 'text' => "Operador #{$opId} atualizado com sucesso!"];
                }
                break;

            case 'delete_operator':
                requireAdmin();
                $opId = (int)($_POST['AdminID'] ?? 0);
                if ($opId === (int)($authUser['id'] ?? 0)) {
                    throw new RuntimeException('Você não pode excluir a sua própria conta em uso.');
                }
                $otherAdmins = (int)$db->fetchScalar("SELECT COUNT(*) FROM CMDBAdmins WHERE Role = 'admin' AND Active = 1 AND AdminID <> ?", [$opId]);
                if ($otherAdmins === 0) {
                    throw new RuntimeException('Não é possível excluir o único Administrador Completo ativo do sistema.');
                }
                $db->execute('DELETE FROM CMDBAdmins WHERE AdminID = ?', [$opId]);
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => "Operador #{$opId} removido."];
                break;

            // ----------------------------------------------------------------
            // [QUALQUER USUÁRIO LOGADO] ALTERAÇÃO DA PRÓPRIA SENHA
            // ----------------------------------------------------------------
            case 'change_own_password':
                $currPass = (string)($_POST['current_password'] ?? '');
                $newPass  = (string)($_POST['new_password'] ?? '');
                $confPass = (string)($_POST['confirm_password'] ?? '');

                if (strlen($newPass) < 8) {
                    throw new RuntimeException('A nova senha deve ter pelo menos 8 caracteres.');
                }
                if ($newPass !== $confPass) {
                    throw new RuntimeException('A confirmação da nova senha não confere.');
                }
                if (!$adminTableReady) {
                    throw new RuntimeException('Inicialize o banco de dados antes de alterar a senha.');
                }
                $me = $db->fetchOne('SELECT * FROM CMDBAdmins WHERE AdminID = ?', [(int)$authUser['id']]);
                if ($me === null || !password_verify($currPass, (string)$me['PasswordHash'])) {
                    throw new RuntimeException('A senha atual informada está incorreta.');
                }
                $newHash = password_hash($newPass, PASSWORD_DEFAULT);
                $db->execute('UPDATE CMDBAdmins SET PasswordHash = ? WHERE AdminID = ?', [$newHash, (int)$authUser['id']]);
                session_regenerate_id(true);
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => 'Sua senha foi atualizada com segurança!'];
                break;

            // ----------------------------------------------------------------
            // IMPORTAÇÃO EM LOTE VIA EXCEL (.XLSX/.XLS), CSV E TXT
            // ----------------------------------------------------------------
            case 'import_file':
                if (empty($_FILES['import_file']['tmp_name']) || !is_uploaded_file($_FILES['import_file']['tmp_name'])) {
                    throw new RuntimeException('Selecione um arquivo válido (.xlsx, .xls, .csv ou .txt) para importar.');
                }
                $targetTable  = (string)($_POST['target_table'] ?? 'assets');
                $upsertMode   = isset($_POST['upsert_mode']);
                $autoCreateFk = isset($_POST['auto_create_fk']);

                $parsed = CMDBFileImporter::parseUploadedFile(
                    $_FILES['import_file']['tmp_name'],
                    (string)($_FILES['import_file']['name'] ?? 'import.csv'),
                    (int)($_FILES['import_file']['size'] ?? 0)
                );
                $rows = $parsed['rows'];
                $inserted = 0;
                $updated  = 0;
                $skipped  = 0;

                foreach ($rows as $r) {
                    $get = static function (array $keys) use ($r): ?string {
                        foreach ($keys as $k) {
                            $nk = CMDBFileImporter::normalizeHeaderKey($k);
                            if (isset($r[$nk]) && trim((string)$r[$nk]) !== '') {
                                return trim((string)$r[$nk]);
                            }
                        }
                        return null;
                    };

                    if ($targetTable === 'assets') {
                        $tag = $get(['AssetTag', 'Tag', 'Patrimonio', 'Ativo']);
                        if ($tag === null) { $skipped++; continue; }
                        $serial  = $get(['SerialNumber', 'Serial', 'NumeroDeSerie', 'SN']);
                        $host    = $get(['Hostname', 'Host', 'NomeComputador']);
                        $typeVal = $get(['AssetTypeID', 'AssetTypeName', 'AssetType', 'Tipo', 'TipoAtivo']);
                        $manVal  = $get(['ManufacturerID', 'ManufacturerName', 'Manufacturer', 'Fabricante', 'Marca']);
                        $model   = $get(['Model', 'Modelo']);
                        $pDate   = normalizeDateSql($get(['PurchaseDate', 'DataCompra', 'Compra']));
                        $wDate   = normalizeDateSql($get(['WarrantyEnd', 'FimGarantia', 'Garantia', 'VencimentoGarantia']));
                        $statVal = $get(['StatusID', 'StatusName', 'Status', 'Situacao']);
                        $userVal = $get(['AssignedUserID', 'AssignedUser', 'DisplayName', 'Usuario', 'Responsavel']);
                        $locVal  = $get(['LocationID', 'SiteName', 'Location', 'Localidade', 'Site', 'Unidade']);
                        $ip      = $get(['IPAddress', 'IP', 'EnderecoIP']);
                        $mac     = $get(['MACAddress', 'MAC', 'EnderecoMAC']);
                        $os      = $get(['OperatingSystem', 'OS', 'SO', 'SistemaOperacional']);
                        $notes   = $get(['Notes', 'Observacoes', 'Obs', 'Descricao']);

                        $typeId = resolveOrCreateLookupId($db, 'AssetTypes', 'AssetTypeID', 'AssetTypeName', $typeVal, $autoCreateFk);
                        $manId  = resolveOrCreateLookupId($db, 'Manufacturers', 'ManufacturerID', 'ManufacturerName', $manVal, $autoCreateFk);
                        $statId = resolveOrCreateLookupId($db, 'Status', 'StatusID', 'StatusName', $statVal, $autoCreateFk);
                        $userId = resolveOrCreateLookupId($db, 'Users', 'UserID', 'DisplayName', $userVal, $autoCreateFk);
                        $locId  = resolveOrCreateLookupId($db, 'Locations', 'LocationID', 'SiteName', $locVal, $autoCreateFk);

                        $existingId = $db->fetchScalar('SELECT AssetID FROM Assets WHERE LOWER(AssetTag) = LOWER(?)', [$tag], null);
                        if ($existingId !== null && $upsertMode) {
                            $db->execute(
                                'UPDATE Assets SET SerialNumber=?, Hostname=?, AssetTypeID=?, ManufacturerID=?, Model=?, PurchaseDate=?, WarrantyEnd=?, StatusID=?, AssignedUserID=?, LocationID=?, IPAddress=?, MACAddress=?, OperatingSystem=?, Notes=?, UpdatedDate=GETDATE() WHERE AssetID=?',
                                [$serial, $host, $typeId, $manId, $model, $pDate, $wDate, $statId, $userId, $locId, $ip, $mac, $os, $notes, (int)$existingId]
                            );
                            $updated++;
                        } elseif ($existingId === null) {
                            $db->execute(
                                'INSERT INTO Assets (AssetTag, SerialNumber, Hostname, AssetTypeID, ManufacturerID, Model, PurchaseDate, WarrantyEnd, StatusID, AssignedUserID, LocationID, IPAddress, MACAddress, OperatingSystem, Notes, CreatedDate) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, GETDATE())',
                                [$tag, $serial, $host, $typeId, $manId, $model, $pDate, $wDate, $statId, $userId, $locId, $ip, $mac, $os, $notes]
                            );
                            $inserted++;
                        } else {
                            $skipped++;
                        }
                    } elseif ($targetTable === 'users') {
                        $name = $get(['DisplayName', 'Nome', 'Name', 'Usuario']);
                        if ($name === null) { $skipped++; continue; }
                        $email = $get(['Email', 'E-mail']);
                        $dept  = $get(['Department', 'Departamento', 'Setor']);
                        $mgr   = $get(['Manager', 'Gestor', 'Gerente']);
                        $db->execute('INSERT INTO Users (DisplayName, Email, Department, Manager) VALUES (?, ?, ?, ?)', [$name, $email, $dept, $mgr]);
                        $inserted++;
                    } elseif ($targetTable === 'locations') {
                        $site = $get(['SiteName', 'Site', 'Unidade', 'Nome']);
                        if ($site === null) { $skipped++; continue; }
                        $country = $get(['Country', 'Pais']) ?? 'Brasil';
                        $state   = $get(['State', 'Estado', 'UF']);
                        $city    = $get(['City', 'Cidade']);
                        $room    = $get(['Room', 'Sala', 'Setor']);
                        $db->execute('INSERT INTO Locations (SiteName, Country, State, City, Room) VALUES (?, ?, ?, ?, ?)', [$site, $country, $state, $city, $room]);
                        $inserted++;
                    } elseif ($targetTable === 'software') {
                        $swName = $get(['SoftwareName', 'Software', 'NomeSoftware', 'Programa']);
                        if ($swName === null) { $skipped++; continue; }
                        $assetId = resolveAssetIdByTagOrId($db, $get(['AssetID', 'AssetTag', 'Tag', 'Hostname']));
                        $ver     = $get(['Version', 'Versao']);
                        $lic     = $get(['LicenseKey', 'Chave', 'Licenca']);
                        $iDate   = normalizeDateSql($get(['InstallDate', 'DataInstalacao']));
                        $db->execute('INSERT INTO SoftwareInventory (AssetID, SoftwareName, Version, LicenseKey, InstallDate) VALUES (?, ?, ?, ?, ?)', [$assetId, $swName, $ver, $lic, $iDate]);
                        $inserted++;
                    } elseif ($targetTable === 'ports') {
                        $pName = $get(['PortName', 'Porta', 'Interface']);
                        if ($pName === null) { $skipped++; continue; }
                        $assetId = resolveAssetIdByTagOrId($db, $get(['AssetID', 'AssetTag', 'Switch', 'Equipamento']));
                        $vlan    = $get(['VLAN']);
                        $connDev = $get(['ConnectedDevice', 'DispositivoConectado', 'Destino']);
                        $connId  = resolveAssetIdByTagOrId($db, $get(['ConnectedAssetID', 'ConnectedAssetTag']));
                        $desc    = $get(['Description', 'Descricao']);
                        $db->execute('INSERT INTO NetworkPorts (AssetID, PortName, VLAN, ConnectedDevice, ConnectedAssetID, Description) VALUES (?, ?, ?, ?, ?, ?)', [$assetId, $pName, $vlan, $connDev, $connId, $desc]);
                        $inserted++;
                    } elseif ($targetTable === 'maintenance') {
                        $mType = $get(['MaintenanceType', 'Tipo', 'TipoManutencao']);
                        if ($mType === null) { $skipped++; continue; }
                        $assetId = resolveAssetIdByTagOrId($db, $get(['AssetID', 'AssetTag', 'Tag']));
                        $mDate   = normalizeDateSql($get(['MaintenanceDate', 'Data', 'DataManutencao']));
                        $vendor  = $get(['Vendor', 'Fornecedor']);
                        $costRaw = str_replace(',', '.', (string)($get(['Cost', 'Custo', 'Valor']) ?? '0'));
                        $cost    = is_numeric($costRaw) ? (float)$costRaw : 0.0;
                        $desc    = $get(['Description', 'Descricao']);
                        $db->execute('INSERT INTO MaintenanceHistory (AssetID, MaintenanceDate, MaintenanceType, Vendor, Cost, Description) VALUES (?, ?, ?, ?, ?, ?)', [$assetId, $mDate, $mType, $vendor, $cost, $desc]);
                        $inserted++;
                    }
                }

                $_SESSION['flash_msg'] = [
                    'type' => 'success',
                    'text' => "Importação concluída! {$inserted} inserido(s), {$updated} atualizado(s) e {$skipped} ignorado(s)."
                ];
                break;

            // ----------------------------------------------------------------
            // CRUD: ASSETS E DEMAIS TABELAS OPERACIONAIS
            // ----------------------------------------------------------------
            case 'save_asset':
                $assetId  = intOrNull($_POST['AssetID'] ?? null);
                $assetTag = trim((string)($_POST['AssetTag'] ?? ''));
                if ($assetTag === '') {
                    throw new RuntimeException('O campo Asset Tag é obrigatório.');
                }
                $data = [
                    $assetTag,
                    nullIfEmpty($_POST['SerialNumber'] ?? null),
                    nullIfEmpty($_POST['Hostname'] ?? null),
                    intOrNull($_POST['AssetTypeID'] ?? null),
                    intOrNull($_POST['ManufacturerID'] ?? null),
                    nullIfEmpty($_POST['Model'] ?? null),
                    nullIfEmpty($_POST['PurchaseDate'] ?? null),
                    nullIfEmpty($_POST['WarrantyEnd'] ?? null),
                    intOrNull($_POST['StatusID'] ?? null),
                    intOrNull($_POST['AssignedUserID'] ?? null),
                    intOrNull($_POST['LocationID'] ?? null),
                    nullIfEmpty($_POST['IPAddress'] ?? null),
                    nullIfEmpty($_POST['MACAddress'] ?? null),
                    nullIfEmpty($_POST['OperatingSystem'] ?? null),
                    nullIfEmpty($_POST['Notes'] ?? null),
                ];
                // Na auditoria, sempre registra o operador autenticado na sessão para impedir falsificação de identidade
                $changedBy = $authUser['display_name'] . ' (' . $authUser['username'] . ')';

                if ($assetId === null) {
                    $db->execute(
                        "INSERT INTO Assets (AssetTag, SerialNumber, Hostname, AssetTypeID, ManufacturerID, Model, PurchaseDate, WarrantyEnd, StatusID, AssignedUserID, LocationID, IPAddress, MACAddress, OperatingSystem, Notes, CreatedDate)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, GETDATE())",
                        $data
                    );
                    $newId = $db->lastInsertId();
                    if ($newId > 0 && ($data[9] !== null || $data[10] !== null)) {
                        $db->execute(
                            'INSERT INTO AssetHistory (AssetID, PreviousUserID, NewUserID, PreviousLocationID, NewLocationID, ChangeDate, ChangedBy, Notes) VALUES (?, NULL, ?, NULL, ?, GETDATE(), ?, ?)',
                            [$newId, $data[9], $data[10], $changedBy, 'Alocação inicial do ativo (' . $assetTag . ')']
                        );
                    }
                    $_SESSION['flash_msg'] = ['type' => 'success', 'text' => "Ativo {$assetTag} cadastrado com sucesso!"];
                } else {
                    $oldAsset  = $db->fetchOne('SELECT AssignedUserID, LocationID FROM Assets WHERE AssetID = ?', [$assetId]);
                    $oldUserId = $oldAsset ? intOrNull($oldAsset['AssignedUserID'] ?? null) : null;
                    $oldLocId  = $oldAsset ? intOrNull($oldAsset['LocationID'] ?? null) : null;

                    $upd = $data;
                    $upd[] = $assetId;
                    $db->execute(
                        "UPDATE Assets SET AssetTag=?, SerialNumber=?, Hostname=?, AssetTypeID=?, ManufacturerID=?, Model=?, PurchaseDate=?, WarrantyEnd=?, StatusID=?, AssignedUserID=?, LocationID=?, IPAddress=?, MACAddress=?, OperatingSystem=?, Notes=?, UpdatedDate=GETDATE() WHERE AssetID=?",
                        $upd
                    );
                    if ($oldUserId !== $data[9] || $oldLocId !== $data[10]) {
                        $histNotes = nullIfEmpty($_POST['HistoryNotes'] ?? null) ?? 'Alteração de alocação via edição de Ativo';
                        $db->execute(
                            'INSERT INTO AssetHistory (AssetID, PreviousUserID, NewUserID, PreviousLocationID, NewLocationID, ChangeDate, ChangedBy, Notes) VALUES (?, ?, ?, ?, ?, GETDATE(), ?, ?)',
                            [$assetId, $oldUserId, $data[9], $oldLocId, $data[10], $changedBy, $histNotes]
                        );
                    }
                    $_SESSION['flash_msg'] = ['type' => 'success', 'text' => "Ativo #{$assetId} ({$assetTag}) atualizado!"];
                }
                break;

            case 'delete_asset':
                $assetId = (int)($_POST['AssetID'] ?? 0);
                $db->execute('DELETE FROM SoftwareInventory WHERE AssetID = ?', [$assetId]);
                $db->execute('DELETE FROM NetworkPorts WHERE AssetID = ? OR ConnectedAssetID = ?', [$assetId, $assetId]);
                $db->execute('DELETE FROM MaintenanceHistory WHERE AssetID = ?', [$assetId]);
                $db->execute('DELETE FROM AssetHistory WHERE AssetID = ?', [$assetId]);
                $db->execute('DELETE FROM Assets WHERE AssetID = ?', [$assetId]);
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => "Ativo #{$assetId} removido."];
                break;

            case 'save_asset_type':
                $id = intOrNull($_POST['AssetTypeID'] ?? null);
                $name = trim((string)($_POST['AssetTypeName'] ?? ''));
                if ($name === '') { throw new RuntimeException('Informe o nome do Tipo de Ativo.'); }
                if ($id === null) { $db->execute('INSERT INTO AssetTypes (AssetTypeName) VALUES (?)', [$name]); }
                else { $db->execute('UPDATE AssetTypes SET AssetTypeName = ? WHERE AssetTypeID = ?', [$name, $id]); }
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => "Tipo de ativo '{$name}' salvo!"];
                break;

            case 'delete_asset_type':
                $id = (int)($_POST['AssetTypeID'] ?? 0);
                if ((int)$db->fetchScalar('SELECT COUNT(*) FROM Assets WHERE AssetTypeID = ?', [$id]) > 0) {
                    throw new RuntimeException('Não é possível excluir tipo vinculado a ativos.');
                }
                $db->execute('DELETE FROM AssetTypes WHERE AssetTypeID = ?', [$id]);
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => 'Tipo excluído.'];
                break;

            case 'save_manufacturer':
                $id = intOrNull($_POST['ManufacturerID'] ?? null);
                $name = trim((string)($_POST['ManufacturerName'] ?? ''));
                if ($name === '') { throw new RuntimeException('Informe o Fabricante.'); }
                if ($id === null) { $db->execute('INSERT INTO Manufacturers (ManufacturerName) VALUES (?)', [$name]); }
                else { $db->execute('UPDATE Manufacturers SET ManufacturerName = ? WHERE ManufacturerID = ?', [$name, $id]); }
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => "Fabricante '{$name}' salvo!"];
                break;

            case 'delete_manufacturer':
                $id = (int)($_POST['ManufacturerID'] ?? 0);
                if ((int)$db->fetchScalar('SELECT COUNT(*) FROM Assets WHERE ManufacturerID = ?', [$id]) > 0) {
                    throw new RuntimeException('Não é possível excluir fabricante vinculado a ativos.');
                }
                $db->execute('DELETE FROM Manufacturers WHERE ManufacturerID = ?', [$id]);
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => 'Fabricante excluído.'];
                break;

            case 'save_status':
                $id = intOrNull($_POST['StatusID'] ?? null);
                $name = trim((string)($_POST['StatusName'] ?? ''));
                if ($name === '') { throw new RuntimeException('Informe o Status.'); }
                if ($id === null) { $db->execute('INSERT INTO Status (StatusName) VALUES (?)', [$name]); }
                else { $db->execute('UPDATE Status SET StatusName = ? WHERE StatusID = ?', [$name, $id]); }
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => "Status '{$name}' salvo!"];
                break;

            case 'delete_status':
                $id = (int)($_POST['StatusID'] ?? 0);
                if ((int)$db->fetchScalar('SELECT COUNT(*) FROM Assets WHERE StatusID = ?', [$id]) > 0) {
                    throw new RuntimeException('Não é possível excluir status em uso.');
                }
                $db->execute('DELETE FROM Status WHERE StatusID = ?', [$id]);
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => 'Status excluído.'];
                break;

            case 'save_location':
                $id = intOrNull($_POST['LocationID'] ?? null);
                $siteName = trim((string)($_POST['SiteName'] ?? ''));
                if ($siteName === '') { throw new RuntimeException('Informe o SiteName.'); }
                $p = [$siteName, nullIfEmpty($_POST['Country'] ?? null), nullIfEmpty($_POST['State'] ?? null), nullIfEmpty($_POST['City'] ?? null), nullIfEmpty($_POST['Room'] ?? null)];
                if ($id === null) { $db->execute('INSERT INTO Locations (SiteName, Country, State, City, Room) VALUES (?, ?, ?, ?, ?)', $p); }
                else { $p[] = $id; $db->execute('UPDATE Locations SET SiteName=?, Country=?, State=?, City=?, Room=? WHERE LocationID=?', $p); }
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => "Localidade '{$siteName}' salva!"];
                break;

            case 'delete_location':
                $id = (int)($_POST['LocationID'] ?? 0);
                if ((int)$db->fetchScalar('SELECT COUNT(*) FROM Assets WHERE LocationID = ?', [$id]) > 0) {
                    throw new RuntimeException('Não é possível excluir localidade com ativos alocados.');
                }
                $db->execute('DELETE FROM Locations WHERE LocationID = ?', [$id]);
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => 'Localidade excluída.'];
                break;

            case 'save_user':
                $id = intOrNull($_POST['UserID'] ?? null);
                $dName = trim((string)($_POST['DisplayName'] ?? ''));
                if ($dName === '') { throw new RuntimeException('Informe o nome do usuário.'); }
                $p = [$dName, nullIfEmpty($_POST['Email'] ?? null), nullIfEmpty($_POST['Department'] ?? null), nullIfEmpty($_POST['Manager'] ?? null)];
                if ($id === null) { $db->execute('INSERT INTO Users (DisplayName, Email, Department, Manager) VALUES (?, ?, ?, ?)', $p); }
                else { $p[] = $id; $db->execute('UPDATE Users SET DisplayName=?, Email=?, Department=?, Manager=? WHERE UserID=?', $p); }
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => "Usuário '{$dName}' salvo!"];
                break;

            case 'delete_user':
                $id = (int)($_POST['UserID'] ?? 0);
                if ((int)$db->fetchScalar('SELECT COUNT(*) FROM Assets WHERE AssignedUserID = ?', [$id]) > 0) {
                    throw new RuntimeException('Não é possível excluir usuário com ativos atribuídos.');
                }
                $db->execute('DELETE FROM Users WHERE UserID = ?', [$id]);
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => 'Usuário excluído.'];
                break;

            case 'save_software':
                $id = intOrNull($_POST['SoftwareID'] ?? null);
                $swName = trim((string)($_POST['SoftwareName'] ?? ''));
                if ($swName === '') { throw new RuntimeException('Informe o nome do Software.'); }
                $p = [intOrNull($_POST['AssetID'] ?? null), $swName, nullIfEmpty($_POST['Version'] ?? null), nullIfEmpty($_POST['LicenseKey'] ?? null), nullIfEmpty($_POST['InstallDate'] ?? null)];
                if ($id === null) { $db->execute('INSERT INTO SoftwareInventory (AssetID, SoftwareName, Version, LicenseKey, InstallDate) VALUES (?, ?, ?, ?, ?)', $p); }
                else { $p[] = $id; $db->execute('UPDATE SoftwareInventory SET AssetID=?, SoftwareName=?, Version=?, LicenseKey=?, InstallDate=? WHERE SoftwareID=?', $p); }
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => "Software '{$swName}' salvo!"];
                break;

            case 'delete_software':
                $db->execute('DELETE FROM SoftwareInventory WHERE SoftwareID = ?', [(int)($_POST['SoftwareID'] ?? 0)]);
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => 'Software removido.'];
                break;

            case 'save_port':
                $id = intOrNull($_POST['PortID'] ?? null);
                $pName = trim((string)($_POST['PortName'] ?? ''));
                if ($pName === '') { throw new RuntimeException('Informe o nome da Porta.'); }
                $p = [intOrNull($_POST['AssetID'] ?? null), $pName, nullIfEmpty($_POST['VLAN'] ?? null), nullIfEmpty($_POST['ConnectedDevice'] ?? null), intOrNull($_POST['ConnectedAssetID'] ?? null), nullIfEmpty($_POST['Description'] ?? null)];
                if ($id === null) { $db->execute('INSERT INTO NetworkPorts (AssetID, PortName, VLAN, ConnectedDevice, ConnectedAssetID, Description) VALUES (?, ?, ?, ?, ?, ?)', $p); }
                else { $p[] = $id; $db->execute('UPDATE NetworkPorts SET AssetID=?, PortName=?, VLAN=?, ConnectedDevice=?, ConnectedAssetID=?, Description=? WHERE PortID=?', $p); }
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => "Porta '{$pName}' salva!"];
                break;

            case 'delete_port':
                $db->execute('DELETE FROM NetworkPorts WHERE PortID = ?', [(int)($_POST['PortID'] ?? 0)]);
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => 'Porta excluída.'];
                break;

            case 'save_maintenance':
                $id = intOrNull($_POST['MaintenanceID'] ?? null);
                $mType = trim((string)($_POST['MaintenanceType'] ?? ''));
                if ($mType === '') { throw new RuntimeException('Informe o Tipo de Manutenção.'); }
                $costRaw = str_replace(',', '.', trim((string)($_POST['Cost'] ?? '0')));
                $cost = is_numeric($costRaw) ? (float)$costRaw : 0.00;
                $p = [intOrNull($_POST['AssetID'] ?? null), nullIfEmpty($_POST['MaintenanceDate'] ?? null), $mType, nullIfEmpty($_POST['Vendor'] ?? null), $cost, nullIfEmpty($_POST['Description'] ?? null)];
                if ($id === null) { $db->execute('INSERT INTO MaintenanceHistory (AssetID, MaintenanceDate, MaintenanceType, Vendor, Cost, Description) VALUES (?, ?, ?, ?, ?, ?)', $p); }
                else { $p[] = $id; $db->execute('UPDATE MaintenanceHistory SET AssetID=?, MaintenanceDate=?, MaintenanceType=?, Vendor=?, Cost=?, Description=? WHERE MaintenanceID=?', $p); }
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => "Manutenção '{$mType}' salva!"];
                break;

            case 'delete_maintenance':
                $db->execute('DELETE FROM MaintenanceHistory WHERE MaintenanceID = ?', [(int)($_POST['MaintenanceID'] ?? 0)]);
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => 'Manutenção excluída.'];
                break;

            case 'save_history':
                $id = intOrNull($_POST['HistoryID'] ?? null);
                $assetId = intOrNull($_POST['AssetID'] ?? null);
                if ($assetId === null) { throw new RuntimeException('Selecione o Ativo.'); }
                $prevU = intOrNull($_POST['PreviousUserID'] ?? null);
                $newU  = intOrNull($_POST['NewUserID'] ?? null);
                $prevL = intOrNull($_POST['PreviousLocationID'] ?? null);
                $newL  = intOrNull($_POST['NewLocationID'] ?? null);
                $by    = $authUser['display_name'] . ' (' . $authUser['username'] . ')';
                $notes = nullIfEmpty($_POST['Notes'] ?? null);
                if ($id === null) {
                    $db->execute('INSERT INTO AssetHistory (AssetID, PreviousUserID, NewUserID, PreviousLocationID, NewLocationID, ChangeDate, ChangedBy, Notes) VALUES (?, ?, ?, ?, ?, GETDATE(), ?, ?)', [$assetId, $prevU, $newU, $prevL, $newL, $by, $notes]);
                    if (isset($_POST['apply_to_asset']) && $_POST['apply_to_asset'] === '1') {
                        $db->execute('UPDATE Assets SET AssignedUserID = COALESCE(?, AssignedUserID), LocationID = COALESCE(?, LocationID), UpdatedDate = GETDATE() WHERE AssetID = ?', [$newU, $newL, $assetId]);
                    }
                } else {
                    $db->execute('UPDATE AssetHistory SET AssetID=?, PreviousUserID=?, NewUserID=?, PreviousLocationID=?, NewLocationID=?, ChangedBy=?, Notes=? WHERE HistoryID=?', [$assetId, $prevU, $newU, $prevL, $newL, $by, $notes, $id]);
                }
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => 'Movimentação salva com sucesso!'];
                break;

            case 'delete_history':
                $db->execute('DELETE FROM AssetHistory WHERE HistoryID = ?', [(int)($_POST['HistoryID'] ?? 0)]);
                $_SESSION['flash_msg'] = ['type' => 'success', 'text' => 'Histórico excluído.'];
                break;
        }
    } catch (Throwable $e) {
        $_SESSION['flash_msg'] = ['type' => 'danger', 'text' => $e->getMessage()];
    }

    header('Location: ?page=' . urlencode($redirectPage));
    exit;
}

// ============================================================================
// 13. CARREGAMENTO DE LOOKUPS E MENU COM FILTRO POR PERFIL (RBAC)
// ============================================================================
$lookupTypes = $lookupManufacturers = $lookupStatus = $lookupLocations = $lookupUsers = $lookupAssets = $assetsMap = [];
if ($db->isConnected() && $schemaReady) {
    $lookupTypes         = $db->fetchAll('SELECT AssetTypeID, AssetTypeName FROM AssetTypes ORDER BY AssetTypeName ASC');
    $lookupManufacturers = $db->fetchAll('SELECT ManufacturerID, ManufacturerName FROM Manufacturers ORDER BY ManufacturerName ASC');
    $lookupStatus        = $db->fetchAll('SELECT StatusID, StatusName FROM Status ORDER BY StatusID ASC');
    $lookupLocations     = $db->fetchAll('SELECT LocationID, SiteName, City, State, Room FROM Locations ORDER BY SiteName ASC');
    $lookupUsers         = $db->fetchAll('SELECT UserID, DisplayName, Department, Email FROM Users ORDER BY DisplayName ASC');
    $lookupAssets        = $db->fetchAll('SELECT AssetID, AssetTag, Hostname, Model FROM Assets ORDER BY AssetID ASC');
    foreach ($lookupAssets as $la) {
        $assetsMap[(int)$la['AssetID']] = $la['AssetTag'] . ($la['Hostname'] ? ' (' . $la['Hostname'] . ')' : '') . ($la['Model'] ? ' - ' . $la['Model'] : '');
    }
}

function renderAssetOptions(array $assetsMap, $selectedId = null, string $emptyLabel = '— Selecionar Ativo —'): string
{
    $sel = ($selectedId !== null && $selectedId !== '') ? (int)$selectedId : null;
    $html = '<option value="">' . h($emptyLabel) . '</option>';
    foreach ($assetsMap as $id => $label) {
        $isSelected = ($sel !== null && $sel === (int)$id) ? ' selected' : '';
        $html .= '<option value="' . (int)$id . '"' . $isSelected . '>#' . (int)$id . ' - ' . h($label) . '</option>';
    }
    if ($sel !== null && !isset($assetsMap[$sel])) {
        $html .= '<option value="' . $sel . '" selected>#' . $sel . ' (ID Referenciado sem cadastro em Assets)</option>';
    }
    return $html;
}

$flash = $_SESSION['flash_msg'] ?? null;
unset($_SESSION['flash_msg']);

$navItems = [
    'dashboard'     => ['label' => 'Dashboard & Views',      'icon' => '📊', 'group' => 'Visão Geral',          'admin_only' => false],
    'import'        => ['label' => 'Importar Excel/CSV/TXT', 'icon' => '📥', 'group' => 'Visão Geral',          'admin_only' => false],
    'assets'        => ['label' => 'Ativos (Assets)',        'icon' => '💻', 'group' => 'Inventário Principal', 'admin_only' => false],
    'software'      => ['label' => 'Softwares Instalados',   'icon' => '🧩', 'group' => 'Inventário Principal', 'admin_only' => false],
    'ports'         => ['label' => 'Portas de Rede',         'icon' => '🔌', 'group' => 'Inventário Principal', 'admin_only' => false],
    'maintenance'   => ['label' => 'Manutenções',            'icon' => '🛠️', 'group' => 'Inventário Principal', 'admin_only' => false],
    'history'       => ['label' => 'Histórico / Auditoria',  'icon' => '🕓', 'group' => 'Inventário Principal', 'admin_only' => false],
    'users'         => ['label' => 'Usuários (Users)',       'icon' => '👥', 'group' => 'Cadastros Base',       'admin_only' => false],
    'locations'     => ['label' => 'Localidades (Sites)',    'icon' => '🏢', 'group' => 'Cadastros Base',       'admin_only' => false],
    'asset_types'   => ['label' => 'Tipos de Ativo',         'icon' => '🏷️', 'group' => 'Cadastros Base',       'admin_only' => false],
    'manufacturers' => ['label' => 'Fabricantes',            'icon' => '🏭', 'group' => 'Cadastros Base',       'admin_only' => false],
    'status'        => ['label' => 'Status Operacional',     'icon' => '🚦', 'group' => 'Cadastros Base',       'admin_only' => false],
    'my_account'    => ['label' => 'Minha Senha / Conta',    'icon' => '🔑', 'group' => 'Minha Conta',          'admin_only' => false],
    'operators'     => ['label' => 'Segurança & Operadores', 'icon' => '🔐', 'group' => 'Administração',        'admin_only' => true],
    'connection'    => ['label' => 'Banco (SQLSrv / MySQL)', 'icon' => '⚙️', 'group' => 'Administração',        'admin_only' => true],
];
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CMDB Lite v2.1 | Gestão Segura de Ativos</title>
    <style>
        :root {
            --bg-body: #f1f5f9; --bg-sidebar: #0f172a; --bg-sidebar-hover: #1e293b; --bg-card: #ffffff;
            --text-main: #0f172a; --text-secondary: #475569; --text-muted: #64748b; --border-color: #e2e8f0;
            --primary: #2563eb; --primary-hover: #1d4ed8; --success: #16a34a; --success-soft: #dcfce7;
            --warning: #d97706; --warning-soft: #fef3c7; --danger: #dc2626; --danger-soft: #fee2e2;
            --info: #0284c7; --info-soft: #e0f2fe; --radius: 10px;
            --shadow: 0 1px 3px rgba(15,23,42,0.08), 0 1px 2px rgba(15,23,42,0.04);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif; background: var(--bg-body); color: var(--text-main); display: flex; min-height: 100vh; font-size: 14px; line-height: 1.5; }
        .sidebar { width: 262px; background: var(--bg-sidebar); color: #f8fafc; display: flex; flex-direction: column; flex-shrink: 0; position: sticky; top: 0; height: 100vh; overflow-y: auto; }
        .sidebar-brand { padding: 18px; border-bottom: 1px solid rgba(255,255,255,0.08); display: flex; align-items: center; gap: 12px; }
        .brand-logo { width: 38px; height: 38px; border-radius: 8px; background: linear-gradient(135deg, #3b82f6, #1d4ed8); display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 16px; color: #fff; }
        .brand-text h1 { font-size: 15px; font-weight: 700; color: #fff; }
        .brand-text span { font-size: 11px; color: #94a3b8; display: block; }
        .nav-group-title { padding: 14px 18px 5px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; color: #64748b; font-weight: 700; }
        .nav-link { display: flex; align-items: center; gap: 10px; padding: 8.5px 18px; color: #cbd5e1; text-decoration: none; font-weight: 500; font-size: 13.5px; border-left: 3px solid transparent; }
        .nav-link:hover { background: var(--bg-sidebar-hover); color: #fff; }
        .nav-link.active { background: rgba(37,99,235,0.18); color: #60a5fa; border-left-color: #3b82f6; font-weight: 600; }
        .sidebar-footer { margin-top: auto; padding: 14px 18px; border-top: 1px solid rgba(255,255,255,0.08); font-size: 11.5px; color: #94a3b8; }
        .main-wrapper { flex: 1; display: flex; flex-direction: column; min-width: 0; }
        .topbar { background: var(--bg-card); border-bottom: 1px solid var(--border-color); padding: 12px 26px; display: flex; align-items: center; justify-content: space-between; gap: 14px; flex-wrap: wrap; }
        .topbar-status { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
        .conn-pill { display: inline-flex; align-items: center; gap: 6px; padding: 4px 11px; border-radius: 999px; font-size: 12px; font-weight: 600; }
        .conn-pill.online { background: var(--success-soft); color: #15803d; }
        .conn-pill.offline { background: var(--danger-soft); color: #b91c1c; }
        .conn-dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
        .content { padding: 22px 26px 48px; max-width: 1480px; width: 100%; margin: 0 auto; }
        .page-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }
        .page-title h2 { font-size: 20px; font-weight: 700; }
        .page-title p { color: var(--text-secondary); font-size: 13.5px; margin-top: 2px; }
        .card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius); box-shadow: var(--shadow); margin-bottom: 20px; overflow: hidden; }
        .card-header { padding: 14px 20px; border-bottom: 1px solid var(--border-color); display: flex; align-items: center; justify-content: space-between; gap: 12px; background: #f8fafc; flex-wrap: wrap; }
        .card-header h3 { font-size: 15px; font-weight: 700; }
        .card-body { padding: 20px; }
        .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .kpi-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 16px 18px; box-shadow: var(--shadow); display: flex; flex-direction: column; gap: 5px; }
        .kpi-label { font-size: 11.5px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); }
        .kpi-value { font-size: 25px; font-weight: 800; }
        .kpi-sub { font-size: 12px; color: var(--text-secondary); }
        .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap: 20px; }
        .grid-3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(215px, 1fr)); gap: 14px 16px; }
        .form-group { display: flex; flex-direction: column; gap: 5px; }
        .form-group.full-width { grid-column: 1 / -1; }
        .form-group label { font-size: 12.5px; font-weight: 600; }
        .form-control { padding: 8px 11px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 13.5px; background: #fff; width: 100%; }
        .form-control:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(37,99,235,0.12); }
        textarea.form-control { min-height: 70px; resize: vertical; }
        .btn { display: inline-flex; align-items: center; justify-content: center; gap: 6px; padding: 8px 14px; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; text-decoration: none; border: 1px solid transparent; white-space: nowrap; }
        .btn-sm { padding: 5px 10px; font-size: 12px; }
        .btn-primary { background: var(--primary); color: #fff; }
        .btn-primary:hover { background: var(--primary-hover); }
        .btn-secondary { background: #fff; color: var(--text-main); border-color: #cbd5e1; }
        .btn-secondary:hover { background: #f8fafc; }
        .btn-success { background: var(--success); color: #fff; }
        .btn-danger { background: var(--danger-soft); color: var(--danger); border-color: #fecaca; }
        .btn-danger:hover { background: var(--danger); color: #fff; }
        .table-responsive { width: 100%; overflow-x: auto; }
        table.data-table { width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }
        table.data-table th { background: #f8fafc; color: var(--text-secondary); font-weight: 700; font-size: 11.5px; text-transform: uppercase; padding: 10px 14px; border-bottom: 1px solid var(--border-color); white-space: nowrap; }
        table.data-table td { padding: 10px 14px; border-bottom: 1px solid var(--border-color); vertical-align: middle; }
        table.data-table tr:hover td { background: #f8fafc; }
        .actions-cell { display: flex; align-items: center; gap: 6px; white-space: nowrap; }
        .badge { display: inline-block; padding: 3px 9px; border-radius: 999px; font-size: 11.5px; font-weight: 600; white-space: nowrap; }
        .badge-success { background: var(--success-soft); color: #15803d; }
        .badge-warning { background: var(--warning-soft); color: #b45309; }
        .badge-danger  { background: var(--danger-soft);  color: #b91c1c; }
        .badge-info    { background: var(--info-soft);    color: #0369a1; }
        .badge-neutral { background: #e2e8f0;             color: #334155; }
        .alert { padding: 12px 16px; border-radius: 8px; margin-bottom: 18px; font-weight: 500; display: flex; align-items: center; justify-content: space-between; }
        .alert-success { background: var(--success-soft); color: #14532d; border: 1px solid #bbf7d0; }
        .alert-danger  { background: var(--danger-soft);  color: #7f1d1d; border: 1px solid #fecaca; }
        .alert-info    { background: var(--info-soft);    color: #0c4a6e; border: 1px solid #bae6fd; }
        .alert-warning { background: var(--warning-soft); color: #78350f; border: 1px solid #fde68a; }
        .code-box { background: #0f172a; color: #e2e8f0; padding: 11px 14px; border-radius: 8px; font-family: monospace; font-size: 12.5px; overflow-x: auto; }
        .progress-bar-bg { width: 100%; height: 8px; background: #e2e8f0; border-radius: 999px; overflow: hidden; margin-top: 4px; }
        .progress-bar-fill { height: 100%; background: var(--primary); border-radius: 999px; }
        .text-muted { color: var(--text-muted); }
        .text-right { text-align: right; }
        .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; }
        @media (max-width: 900px) { body { flex-direction: column; } .sidebar { width: 100%; height: auto; position: static; } .grid-2, .grid-3 { grid-template-columns: 1fr; } }
    </style>
</head>
<body>

<aside class="sidebar">
    <div class="sidebar-brand">
        <div class="brand-logo">IT</div>
        <div class="brand-text">
            <h1>CMDB Lite</h1>
            <span>v2.1 • Segurança &amp; RBAC</span>
        </div>
    </div>

    <?php
    $lastGrp = '';
    foreach ($navItems as $pKey => $item):
        // Oculta menus administrativos de usuários com perfil Operador
        if ($item['admin_only'] && !$userIsAdmin) {
            continue;
        }
        if ($item['group'] !== $lastGrp):
            $lastGrp = $item['group'];
            echo '<div class="nav-group-title">' . h($lastGrp) . '</div>';
        endif;
        $act = ($currentPage === $pKey || ($currentPage === 'asset_detail' && $pKey === 'assets')) ? ' active' : '';
    ?>
        <a href="?page=<?= h($pKey) ?>" class="nav-link<?= $act ?>">
            <span><?= $item['icon'] ?></span>
            <span><?= h($item['label']) ?></span>
        </a>
    <?php endforeach; ?>

    <div class="sidebar-footer">
        <div>👤 <strong><?= h($authUser['display_name']) ?></strong></div>
        <div style="margin-top:2px;">🛡️ Perfil: <span class="badge <?= $userIsAdmin ? 'badge-info' : 'badge-neutral' ?>" style="font-size:10.5px; padding:1px 7px;"><?= $userIsAdmin ? 'Administrador' : 'Operador' ?></span></div>
        <div style="margin-top:4px;">🗄️ Banco Fixo: <strong><?= h(strtoupper($DB_CONFIG['driver'] ?? 'sqlsrv')) ?></strong></div>
    </div>
</aside>

<div class="main-wrapper">
    <header class="topbar">
        <div class="topbar-status">
            <?php if ($db->isConnected()): ?>
                <span class="conn-pill online">
                    <span class="conn-dot"></span>
                    <?= h(strtoupper($db->getActiveEngine())) ?> Online
                </span>
            <?php else: ?>
                <span class="conn-pill offline">
                    <span class="conn-dot"></span>
                    Banco Indisponível
                </span>
            <?php endif; ?>
            <span class="mono text-muted"><?= h($db->getConnectionStringPreview($userIsAdmin)) ?></span>
        </div>
        <div style="display:flex; gap:8px; align-items:center;">
            <?php if ($db->isConnected() && $schemaReady): ?>
                <a href="?page=import" class="btn btn-secondary btn-sm">📥 Importar Excel/CSV/TXT</a>
                <a href="?export=vw_assets" class="btn btn-secondary btn-sm">⬇ Exportar CSV</a>
            <?php endif; ?>
            <?php if ($userIsAdmin): ?>
                <a href="?page=connection" class="btn btn-secondary btn-sm">⚙️ Banco (Admin)</a>
            <?php endif; ?>
            <a href="?page=my_account" class="btn btn-secondary btn-sm">🔑 Minha Senha</a>
            <a href="?logout=1" class="btn btn-danger btn-sm">Sair (<?= h($authUser['username']) ?>)</a>
        </div>
    </header>

    <main class="content">
        <?php if ($flash !== null): ?>
            <div class="alert alert-<?= h($flash['type']) ?>">
                <span><?= h($flash['text']) ?></span>
            </div>
        <?php endif; ?>

        <?php
        // ====================================================================
        // BLOQUEIO DE ROTAS EXCLUSIVAS DE ADMINISTRADOR (RBAC SERVER-SIDE)
        // ====================================================================
        if (in_array($currentPage, ['connection', 'operators'], true) && !$userIsAdmin):
        ?>
            <div class="card">
                <div class="card-header">
                    <h3>🔒 Acesso Restrito ao Administrador Completo (Erro 403)</h3>
                </div>
                <div class="card-body">
                    <div class="alert alert-danger">
                        <span>Seu perfil atual (<strong>Operador de Suporte</strong>) não possui permissão para acessar configurações de banco de dados ou gerenciamento de contas administrativas.</span>
                    </div>
                    <a href="?page=dashboard" class="btn btn-primary">← Voltar ao Dashboard</a>
                </div>
            </div>
        <?php
        // ====================================================================
        // TRATAMENTO QUANDO O BANCO AINDA NÃO ESTÁ CONECTADO OU INICIALIZADO
        // ====================================================================
        elseif ((!$db->isConnected() || !$schemaReady) && $currentPage !== 'connection'):
        ?>
            <div class="card">
                <div class="card-header">
                    <h3>⚠️ Status da Conexão com o Banco de Dados</h3>
                </div>
                <div class="card-body">
                    <?php if ($userIsAdmin): ?>
                        <?php if (!$db->isConnected()): ?>
                            <div class="alert alert-danger">
                                <div><strong>Falha ao conectar no banco parametrizado:</strong> <?= h($db->getLastError() ?? 'Verifique o servidor.') ?></div>
                            </div>
                            <p style="margin-bottom:14px;">
                                Como <strong>Administrador Completo</strong>, você pode definir abaixo a conexão fixa do servidor (que valerá para todas as máquinas e navegadores) ou ativar o banco local SQLite:
                            </p>
                            <div style="display:flex; gap:10px; flex-wrap:wrap;">
                                <a href="?page=connection" class="btn btn-primary">⚙️ Parametrizar Conexão Fixa (SQL Server / MySQL)</a>
                                <form method="post" style="display:inline;">
                                    <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>">
                                    <input type="hidden" name="_action" value="update_connection">
                                    <input type="hidden" name="cfg_driver" value="sqlite">
                                    <input type="hidden" name="cfg_server" value="localhost">
                                    <input type="hidden" name="cfg_database" value="CMDB">
                                    <button type="submit" class="btn btn-success">🚀 Fixar Banco Local SQLite no Servidor</button>
                                </form>
                            </div>
                        <?php else: ?>
                            <p style="margin-bottom:14px;">Conectado ao banco <strong><?= h($DB_CONFIG['database']) ?></strong> (<?= h($db->getActiveEngine()) ?>), porém as tabelas do schema ainda não foram inicializadas.</p>
                            <form method="post" style="display:flex; gap:14px; align-items:center; flex-wrap:wrap;">
                                <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>">
                                <input type="hidden" name="_action" value="init_schema">
                                <input type="hidden" name="_redirect_page" value="dashboard">
                                <label><input type="checkbox" name="with_seed" value="1" checked> Popular dados iniciais do script</label>
                                <label><input type="checkbox" name="with_extra_assets" value="1" checked> Incluir Ativos IDs 3 a 8</label>
                                <button type="submit" class="btn btn-primary">⚡ Criar Tabelas, Views e Dados Iniciais Agora</button>
                            </form>
                        <?php endif; ?>
                    <?php else: ?>
                        <!-- Visão restrita para Operador: não solicita nem permite troca de banco -->
                        <div class="alert alert-warning">
                            <span>O banco de dados parametrizado no servidor encontra-se temporariamente indisponível ou em manutenção. Solicite ao <strong>Administrador do Sistema</strong> a verificação da conexão.</span>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        <?php endif; ?>

        <?php
        // ====================================================================
        // PÁGINA [SOMENTE ADMIN]: PARAMETRIZAÇÃO FIXA DO BANCO DE DADOS
        // ====================================================================
        if ($currentPage === 'connection' && $userIsAdmin):
        ?>
            <div class="page-header">
                <div class="page-title">
                    <h2>⚙️ Parametrização Fixa do Banco de Dados (Exclusivo Administrador)</h2>
                    <p>As configurações salvas aqui ficam gravadas de forma fixa no servidor (<code>.cmdb_db_config.php</code>) e são compartilhadas automaticamente por todas as máquinas e navegadores.</p>
                </div>
            </div>

            <div class="grid-2">
                <div class="card">
                    <div class="card-header">
                        <h3>Parâmetros Globais do Servidor de Banco</h3>
                        <form method="post" onsubmit="return confirm('Restaurar a parametrização do servidor para os valores padrão do código?');" style="display:inline;">
                            <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>">
                            <input type="hidden" name="_action" value="reset_connection">
                            <button type="submit" class="btn btn-secondary btn-sm">Restaurar Padrão</button>
                        </form>
                    </div>
                    <div class="card-body">
                        <form method="post" autocomplete="off">
                            <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>">
                            <input type="hidden" name="_action" value="update_connection">
                            <input type="hidden" name="keep_existing_password" value="1">
                            <div class="form-grid">
                                <div class="form-group full-width">
                                    <label>SGBD / Motor de Banco de Dados Fixo (`driver`)</label>
                                    <select name="cfg_driver" class="form-control">
                                        <option value="sqlsrv" <?= ($DB_CONFIG['driver'] ?? 'sqlsrv') === 'sqlsrv' ? 'selected' : '' ?>>Microsoft SQL Server Local (PDO_SQLSRV / SQLSRV / ODBC)</option>
                                        <option value="mysql" <?= ($DB_CONFIG['driver'] ?? '') === 'mysql' ? 'selected' : '' ?>>MySQL / MariaDB (PDO_MYSQL / MySQLi)</option>
                                        <option value="sqlite" <?= ($DB_CONFIG['driver'] ?? '') === 'sqlite' ? 'selected' : '' ?>>SQLite Local (Persistente no Servidor)</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label>Host / Instância (`server`)</label>
                                    <input type="text" name="cfg_server" class="form-control" value="<?= h($DB_CONFIG['server']) ?>" placeholder="localhost ou localhost\SQLEXPRESS ou 127.0.0.1">
                                </div>
                                <div class="form-group">
                                    <label>Porta Opcional (`port`)</label>
                                    <input type="text" name="cfg_port" class="form-control" value="<?= h($DB_CONFIG['port'] ?? '') ?>" placeholder="Vazio=Padrão | 1433 (SQLSrv) | 3306 (MySQL)">
                                </div>
                                <div class="form-group">
                                    <label>Banco de Dados (`database`)</label>
                                    <input type="text" name="cfg_database" class="form-control" value="<?= h($DB_CONFIG['database']) ?>" placeholder="CMDB">
                                </div>
                                <div class="form-group">
                                    <label>Usuário (`username`)</label>
                                    <input type="text" name="cfg_username" class="form-control" value="<?= h($DB_CONFIG['username']) ?>" placeholder="SQLSrv: vazio (WinAuth) ou sa | MySQL: root">
                                </div>
                                <div class="form-group full-width">
                                    <label>Senha do Banco (`password` — deixe em branco para manter a senha já salva)</label>
                                    <input type="password" name="cfg_password" class="form-control" value="" placeholder="<?= !empty($DB_CONFIG['password']) ? '•••••••• (Senha já configurada no servidor)' : 'Sem senha (Windows Auth / Root local)' ?>">
                                </div>
                                <div class="form-group full-width">
                                    <label style="display:flex; align-items:center; gap:8px;">
                                        <input type="checkbox" name="cfg_trust_cert" value="1" <?= !empty($DB_CONFIG['trust_cert']) ? 'checked' : '' ?>>
                                        Habilitar <code>TrustServerCertificate=1</code> (Para SQL Server local)
                                    </label>
                                </div>
                            </div>
                            <div style="margin-top:16px;">
                                <button type="submit" class="btn btn-primary">💾 Salvar Parametrização Fixa no Servidor</button>
                            </div>
                        </form>
                        <div style="margin-top:16px;">
                            <div class="code-box"><?= h($db->getConnectionStringPreview(true)) ?></div>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h3>Diagnóstico de Segurança, Drivers &amp; Auto-Setup</h3>
                    </div>
                    <div class="card-body">
                        <table class="data-table" style="margin-bottom:16px;">
                            <tbody>
                                <tr><td><strong>Persistência Global (`.cmdb_db_config.php`)</strong></td><td><?= is_file(CMDB_CONFIG_FILE) ? '<span class="badge badge-success">Fixada no Servidor (' . h($DB_CONFIG['updated_at'] ?? 'Ativa') . ')</span>' : '<span class="badge badge-info">Usando Padrão do Código</span>' ?></td></tr>
                                <tr><td><strong>SQL Server (`pdo_sqlsrv` / `sqlsrv`)</strong></td><td><?= (extension_loaded('pdo_sqlsrv') || function_exists('sqlsrv_connect')) ? '<span class="badge badge-success">Disponível</span>' : '<span class="badge badge-neutral">Ausente</span>' ?></td></tr>
                                <tr><td><strong>MySQL / MariaDB (`pdo_mysql` / `mysqli`)</strong></td><td><?= (extension_loaded('pdo_mysql') || function_exists('mysqli_connect')) ? '<span class="badge badge-success">Disponível</span>' : '<span class="badge badge-neutral">Ausente</span>' ?></td></tr>
                                <tr><td><strong>Status do Schema CMDB</strong></td><td><?= $schemaReady ? '<span class="badge badge-success">Pronto</span>' : '<span class="badge badge-warning">Pendente</span>' ?></td></tr>
                            </tbody>
                        </table>

                        <form method="post">
                            <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>">
                            <input type="hidden" name="_action" value="init_schema">
                            <input type="hidden" name="_redirect_page" value="dashboard">
                            <div style="display:flex; flex-direction:column; gap:6px; margin-bottom:12px;">
                                <label><input type="checkbox" name="with_seed" value="1" checked> Popular cadastros iniciais (`SQLQuery_cmdb_v1.sql`)</label>
                                <label><input type="checkbox" name="with_extra_assets" value="1" checked> Cadastrar ativos complementares (IDs 3 a 8)</label>
                            </div>
                            <button type="submit" class="btn btn-success">⚡ Criar Banco, Tabelas e Views no SGBD Fixado</button>
                        </form>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <?php
        // ====================================================================
        // PÁGINA [QUALQUER USUÁRIO LOGADO]: MINHA CONTA / ALTERAR PRÓPRIA SENHA
        // ====================================================================
        if ($currentPage === 'my_account'):
        ?>
            <div class="page-header">
                <div class="page-title">
                    <h2>🔑 Minha Conta &amp; Alteração de Senha</h2>
                    <p>Altere sua senha pessoal de acesso com verificação da senha atual.</p>
                </div>
            </div>
            <div class="grid-2">
                <div class="card">
                    <div class="card-header"><h3>Dados da Sessão Atual</h3></div>
                    <div class="card-body">
                        <table class="data-table">
                            <tbody>
                                <tr><td><strong>Nome de Exibição</strong></td><td><?= h($authUser['display_name']) ?></td></tr>
                                <tr><td><strong>Usuário (`Username`)</strong></td><td class="mono"><?= h($authUser['username']) ?></td></tr>
                                <tr><td><strong>Nível de Permissão (`Role`)</strong></td><td><span class="badge <?= $userIsAdmin ? 'badge-info' : 'badge-neutral' ?>"><?= $userIsAdmin ? 'Administrador Completo' : 'Operador de Suporte (Sem acesso a Banco/Usuários)' ?></span></td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
                <div class="card">
                    <div class="card-header"><h3>Alterar Minha Senha</h3></div>
                    <div class="card-body">
                        <form method="post" autocomplete="off">
                            <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>">
                            <input type="hidden" name="_action" value="change_own_password">
                            <input type="hidden" name="_redirect_page" value="my_account">
                            <div class="form-grid">
                                <div class="form-group full-width">
                                    <label>Senha Atual *</label>
                                    <input type="password" name="current_password" class="form-control" required>
                                </div>
                                <div class="form-group">
                                    <label>Nova Senha * (mín. 8 caracteres)</label>
                                    <input type="password" name="new_password" class="form-control" required minlength="8">
                                </div>
                                <div class="form-group">
                                    <label>Confirmar Nova Senha *</label>
                                    <input type="password" name="confirm_password" class="form-control" required minlength="8">
                                </div>
                            </div>
                            <div style="margin-top:16px;">
                                <button type="submit" class="btn btn-primary">💾 Atualizar Minha Senha</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <?php
        if ($db->isConnected() && $schemaReady):

            // ================================================================
            // PÁGINA: IMPORTADOR DE BASE (EXCEL .XLSX/.XLS, .CSV E .TXT)
            // ================================================================
            if ($currentPage === 'import'):
        ?>
            <div class="page-header">
                <div class="page-title">
                    <h2>📥 Importação Segura via Excel (`.xlsx` / `.xls`), CSV (`.csv`) e TXT (`.txt`)</h2>
                    <p>Importe planilhas completas com proteção anti-XXE/ZipBomb e resolução automática de chaves estrangeiras.</p>
                </div>
            </div>

            <div class="grid-2">
                <div class="card">
                    <div class="card-header">
                        <h3>Enviar Arquivo para Importação (Máx. 10 MB)</h3>
                    </div>
                    <div class="card-body">
                        <form method="post" enctype="multipart/form-data">
                            <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>">
                            <input type="hidden" name="_action" value="import_file">
                            <input type="hidden" name="_redirect_page" value="import">

                            <div class="form-grid">
                                <div class="form-group full-width">
                                    <label>1. Tabela de Destino</label>
                                    <select name="target_table" class="form-control" required>
                                        <option value="assets">💻 Ativos de TI (Assets)</option>
                                        <option value="users">👥 Usuários / Colaboradores (Users)</option>
                                        <option value="locations">🏢 Localidades / Sites (Locations)</option>
                                        <option value="software">🧩 Inventário de Software (SoftwareInventory)</option>
                                        <option value="ports">🔌 Portas de Rede (NetworkPorts)</option>
                                        <option value="maintenance">🛠️ Histórico de Manutenções (MaintenanceHistory)</option>
                                    </select>
                                </div>
                                <div class="form-group full-width">
                                    <label>2. Arquivo de Dados (`.xlsx`, `.xls`, `.csv` ou `.txt`)</label>
                                    <input type="file" name="import_file" class="form-control" accept=".xlsx,.xls,.csv,.txt" required>
                                </div>
                                <div class="form-group full-width" style="gap:8px;">
                                    <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
                                        <input type="checkbox" name="upsert_mode" value="1" checked>
                                        <strong>Atualizar existentes (Upsert):</strong> se o <code>AssetTag</code> já existir em <code>Assets</code>, atualiza os dados
                                    </label>
                                    <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
                                        <input type="checkbox" name="auto_create_fk" value="1" checked>
                                        <strong>Auto-cadastrar referências novas:</strong> cria Tipo, Fabricante, Status, Usuário ou Localidade caso não existam
                                    </label>
                                </div>
                            </div>

                            <div style="margin-top:18px;">
                                <button type="submit" class="btn btn-primary">🚀 Processar e Importar Arquivo</button>
                            </div>
                        </form>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h3>Modelos Prontos para Download (Templates)</h3>
                    </div>
                    <div class="card-body">
                        <p class="text-muted" style="margin-bottom:14px;">
                            Baixe um modelo pré-formatado nos formatos <strong>Excel (`.xls`)</strong>, <strong>CSV (`.csv`)</strong> ou <strong>Texto Tabulado (`.txt`)</strong>:
                        </p>
                        <table class="data-table">
                            <thead>
                                <tr><th>Cadastro</th><th>Formatos de Modelo</th></tr>
                            </thead>
                            <tbody>
                                <?php
                                $tplLabels = [
                                    'assets'      => '💻 Ativos (Assets)',
                                    'users'       => '👥 Usuários (Users)',
                                    'locations'   => '🏢 Localidades (Locations)',
                                    'software'    => '🧩 Softwares (SoftwareInventory)',
                                    'ports'       => '🔌 Portas de Rede (NetworkPorts)',
                                    'maintenance' => '🛠️ Manutenções (MaintenanceHistory)',
                                ];
                                foreach ($tplLabels as $tKey => $tName):
                                ?>
                                    <tr>
                                        <td><strong><?= h($tName) ?></strong></td>
                                        <td class="actions-cell">
                                            <a href="?download_template=<?= $tKey ?>&fmt=xls" class="btn btn-secondary btn-sm">📊 Excel (.xls)</a>
                                            <a href="?download_template=<?= $tKey ?>&fmt=csv" class="btn btn-secondary btn-sm">📄 CSV (.csv)</a>
                                            <a href="?download_template=<?= $tKey ?>&fmt=txt" class="btn btn-secondary btn-sm">📝 TXT (.txt)</a>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

        <?php
            // ================================================================
            // PÁGINA [SOMENTE ADMIN]: SEGURANÇA & OPERADORES
            // ================================================================
            elseif ($currentPage === 'operators' && $userIsAdmin):
                $editId = isset($_GET['edit']) ? (int)$_GET['edit'] : null;
                $editOp = ($editId && $adminTableReady) ? $db->fetchOne('SELECT * FROM CMDBAdmins WHERE AdminID = ?', [$editId]) : null;
                $opsList = $adminTableReady ? $db->fetchAll('SELECT AdminID, Username, DisplayName, Role, Active, LastLogin, CreatedDate FROM CMDBAdmins ORDER BY AdminID ASC') : [];
        ?>
            <div class="page-header">
                <div class="page-title">
                    <h2>🔐 Segurança &amp; Operadores do Sistema (Exclusivo Administrador)</h2>
                    <p>Gerencie contas de acesso. Usuários com perfil <strong>Operador de Suporte</strong> não têm acesso à troca de banco de dados nem a esta tela.</p>
                </div>
            </div>

            <div class="grid-2">
                <div class="card">
                    <div class="card-header">
                        <h3><?= $editOp ? ('✏️ Editando Operador #' . (int)$editOp['AdminID']) : '➕ Cadastrar Novo Operador' ?></h3>
                    </div>
                    <div class="card-body">
                        <form method="post" autocomplete="off">
                            <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>">
                            <input type="hidden" name="_action" value="save_operator">
                            <input type="hidden" name="_redirect_page" value="operators">
                            <?php if ($editOp): ?>
                                <input type="hidden" name="AdminID" value="<?= (int)$editOp['AdminID'] ?>">
                            <?php endif; ?>
                            <div class="form-grid">
                                <div class="form-group">
                                    <label>Login (`Username`) *</label>
                                    <input type="text" name="Username" class="form-control" required value="<?= h($editOp['Username'] ?? '') ?>" placeholder="Ex: joao.suporte">
                                </div>
                                <div class="form-group">
                                    <label>Nome de Exibição (`DisplayName`) *</label>
                                    <input type="text" name="DisplayName" class="form-control" required value="<?= h($editOp['DisplayName'] ?? '') ?>" placeholder="Ex: João Analista">
                                </div>
                                <div class="form-group">
                                    <label>Perfil de Acesso (`Role`)</label>
                                    <select name="Role" class="form-control">
                                        <option value="operator" <?= ($editOp['Role'] ?? 'operator') === 'operator' ? 'selected' : '' ?>>Operador de Suporte (Apenas CRUD / Sem acesso ao Banco)</option>
                                        <option value="admin" <?= ($editOp['Role'] ?? '') === 'admin' ? 'selected' : '' ?>>Administrador Completo (Acesso Total + Banco)</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label><?= $editOp ? 'Nova Senha (em branco p/ manter)' : 'Senha * (mín. 8 caracteres)' ?></label>
                                    <input type="password" name="Password" class="form-control" <?= $editOp ? '' : 'required minlength="8"' ?> placeholder="••••••••">
                                </div>
                                <div class="form-group full-width">
                                    <label style="display:flex; align-items:center; gap:8px;">
                                        <input type="checkbox" name="Active" value="1" <?= (!isset($editOp['Active']) || (int)$editOp['Active'] === 1) ? 'checked' : '' ?>>
                                        Conta Ativa (Permite login no sistema)
                                    </label>
                                </div>
                            </div>
                            <div style="margin-top:16px; display:flex; gap:8px;">
                                <button type="submit" class="btn btn-primary"><?= $editOp ? '💾 Salvar Alterações' : '➕ Criar Conta' ?></button>
                                <?php if ($editOp): ?>
                                    <a href="?page=operators" class="btn btn-secondary">Cancelar</a>
                                <?php endif; ?>
                            </div>
                        </form>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h3>Contas Cadastradas (<?= count($opsList) ?>)</h3>
                    </div>
                    <div class="table-responsive">
                        <table class="data-table">
                            <thead>
                                <tr><th>ID</th><th>Login</th><th>Nome</th><th>Perfil</th><th>Status</th><th>Último Login</th><th>Ações</th></tr>
                            </thead>
                            <tbody>
                                <?php foreach ($opsList as $op): ?>
                                    <tr>
                                        <td>#<?= (int)$op['AdminID'] ?></td>
                                        <td class="mono"><strong><?= h($op['Username']) ?></strong></td>
                                        <td><?= h($op['DisplayName']) ?></td>
                                        <td><span class="badge <?= ($op['Role'] ?? '') === 'admin' ? 'badge-info' : 'badge-neutral' ?>"><?= ($op['Role'] ?? '') === 'admin' ? 'Admin Completo' : 'Operador' ?></span></td>
                                        <td><?= (int)($op['Active'] ?? 1) === 1 ? '<span class="badge badge-success">Ativo</span>' : '<span class="badge badge-danger">Bloqueado</span>' ?></td>
                                        <td><?= formatDateBr($op['LastLogin'] ?? null, true) ?></td>
                                        <td class="actions-cell">
                                            <a href="?page=operators&edit=<?= (int)$op['AdminID'] ?>" class="btn btn-secondary btn-sm">✏️ Editar</a>
                                            <?php if ((int)$op['AdminID'] !== (int)$authUser['id']): ?>
                                                <form method="post" onsubmit="return confirm('Remover este operador?');" style="display:inline;">
                                                    <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>">
                                                    <input type="hidden" name="_action" value="delete_operator">
                                                    <input type="hidden" name="_redirect_page" value="operators">
                                                    <input type="hidden" name="AdminID" value="<?= (int)$op['AdminID'] ?>">
                                                    <button type="submit" class="btn btn-danger btn-sm">🗑️</button>
                                                </form>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

        <?php
            // ================================================================
            // PÁGINA: DASHBOARD & VIEWS
            // ================================================================
            elseif ($currentPage === 'dashboard'):
                $totalAssets    = (int)$db->fetchScalar('SELECT COUNT(*) FROM Assets');
                $assetsInUse    = (int)$db->fetchScalar("SELECT COUNT(*) FROM Assets A INNER JOIN Status S ON A.StatusID = S.StatusID WHERE S.StatusName = 'Em Uso'");
                $expiringCount  = (int)$db->fetchScalar('SELECT COUNT(*) FROM Assets WHERE WarrantyEnd IS NOT NULL AND WarrantyEnd <= DATEADD(DAY,90,GETDATE())');
                $totalMaintCost = (float)$db->fetchScalar('SELECT COALESCE(SUM(Cost), 0) FROM MaintenanceHistory');
                $totalSoftwares = (int)$db->fetchScalar('SELECT COUNT(*) FROM SoftwareInventory');
                $totalPorts     = (int)$db->fetchScalar('SELECT COUNT(*) FROM NetworkPorts');

                $vwDashboard    = $db->fetchAll('SELECT AssetTypeName, Total FROM vw_CMDB_Dashboard ORDER BY Total DESC');
                $vwWarranty     = $db->fetchAll('SELECT AssetTag, Hostname, Model, WarrantyEnd FROM vw_WarrantyExpiration ORDER BY WarrantyEnd ASC');
                $byLocation     = $db->fetchAll('SELECT L.SiteName, COUNT(*) AS Total FROM Assets A JOIN Locations L ON A.LocationID = L.LocationID GROUP BY L.SiteName ORDER BY Total DESC');
                $byUser         = $db->fetchAll('SELECT U.DisplayName, COUNT(*) AS TotalAssets FROM Assets A JOIN Users U ON A.AssignedUserID = U.UserID GROUP BY U.DisplayName ORDER BY TotalAssets DESC');
                $vwAssetsRows   = $db->fetchAll('SELECT * FROM vw_Assets ORDER BY AssetID DESC');
        ?>
            <div class="page-header">
                <div class="page-title">
                    <h2>📊 Dashboard CMDB &amp; Views Consolidadas</h2>
                    <p>Indicadores extraídos das views <code>vw_CMDB_Dashboard</code>, <code>vw_WarrantyExpiration</code> e <code>vw_Assets</code>.</p>
                </div>
                <div style="display:flex; gap:8px;">
                    <?php if ($userIsAdmin && $totalAssets <= 2): ?>
                        <form method="post">
                            <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>">
                            <input type="hidden" name="_action" value="seed_missing_assets">
                            <input type="hidden" name="_redirect_page" value="dashboard">
                            <button type="submit" class="btn btn-secondary btn-sm">➕ Popular Ativos IDs 3 a 8</button>
                        </form>
                    <?php endif; ?>
                    <a href="?page=import" class="btn btn-primary btn-sm">📥 Importar Planilha</a>
                </div>
            </div>

            <div class="kpi-grid">
                <div class="kpi-card"><span class="kpi-label">Total de Ativos</span><span class="kpi-value"><?= $totalAssets ?></span><span class="kpi-sub"><?= $assetsInUse ?> em uso</span></div>
                <div class="kpi-card"><span class="kpi-label">Garantias ≤ 90 Dias</span><span class="kpi-value" style="color:<?= $expiringCount > 0 ? 'var(--warning)' : 'var(--success)' ?>"><?= $expiringCount ?></span><span class="kpi-sub">View <code>vw_WarrantyExpiration</code></span></div>
                <div class="kpi-card"><span class="kpi-label">Softwares / Licenças</span><span class="kpi-value"><?= $totalSoftwares ?></span><span class="kpi-sub">Em <code>SoftwareInventory</code></span></div>
                <div class="kpi-card"><span class="kpi-label">Portas de Rede</span><span class="kpi-value"><?= $totalPorts ?></span><span class="kpi-sub">Em <code>NetworkPorts</code></span></div>
                <div class="kpi-card"><span class="kpi-label">Custo Manutenções</span><span class="kpi-value"><?= formatCurrencyBr($totalMaintCost) ?></span><span class="kpi-sub">Em <code>MaintenanceHistory</code></span></div>
            </div>

            <div class="grid-3">
                <div class="card">
                    <div class="card-header"><h3>🏷️ Por Tipo (<code>vw_CMDB_Dashboard</code>)</h3></div>
                    <div class="card-body">
                        <?php foreach ($vwDashboard as $r): $pct = $totalAssets > 0 ? min(100, round(((int)$r['Total'] / $totalAssets) * 100)) : 0; ?>
                            <div style="margin-bottom:10px;">
                                <div style="display:flex; justify-content:space-between; font-size:13px; font-weight:600;">
                                    <span><?= h($r['AssetTypeName']) ?></span><span><?= (int)$r['Total'] ?> (<?= $pct ?>%)</span>
                                </div>
                                <div class="progress-bar-bg"><div class="progress-bar-fill" style="width:<?= $pct ?>%"></div></div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header"><h3>🏢 Ativos por Localidade</h3></div>
                    <div class="card-body">
                        <table class="data-table">
                            <thead><tr><th>SiteName</th><th class="text-right">Total</th></tr></thead>
                            <tbody>
                                <?php foreach ($byLocation as $loc): ?>
                                    <tr><td><strong><?= h($loc['SiteName']) ?></strong></td><td class="text-right"><span class="badge badge-info"><?= (int)$loc['Total'] ?></span></td></tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header"><h3>👥 Ativos por Usuário</h3></div>
                    <div class="card-body">
                        <table class="data-table">
                            <thead><tr><th>DisplayName</th><th class="text-right">TotalAssets</th></tr></thead>
                            <tbody>
                                <?php foreach ($byUser as $u): ?>
                                    <tr><td><strong><?= h($u['DisplayName']) ?></strong></td><td class="text-right"><span class="badge badge-success"><?= (int)$u['TotalAssets'] ?></span></td></tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h3>⚠️ Garantias Vencendo em até 90 Dias (<code>vw_WarrantyExpiration</code>)</h3>
                    <span class="badge <?= empty($vwWarranty) ? 'badge-success' : 'badge-warning' ?>"><?= count($vwWarranty) ?> ativo(s)</span>
                </div>
                <div class="table-responsive">
                    <table class="data-table">
                        <thead><tr><th>AssetTag</th><th>Hostname</th><th>Modelo</th><th>WarrantyEnd</th></tr></thead>
                        <tbody>
                            <?php if (empty($vwWarranty)): ?>
                                <tr><td colspan="4" class="text-muted">Nenhum ativo com garantia próxima do vencimento.</td></tr>
                            <?php else: foreach ($vwWarranty as $w): ?>
                                <tr><td><strong><?= h($w['AssetTag']) ?></strong></td><td class="mono"><?= h($w['Hostname'] ?? '—') ?></td><td><?= h($w['Model'] ?? '—') ?></td><td><?= warrantyBadgeHtml($w['WarrantyEnd'] ?? null) ?></td></tr>
                            <?php endforeach; endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h3>📋 Visão Consolidada (<code>vw_Assets</code>)</h3>
                    <a href="?page=assets" class="btn btn-primary btn-sm">Gerenciar Ativos</a>
                </div>
                <div class="table-responsive">
                    <table class="data-table">
                        <thead><tr><th>ID</th><th>AssetTag</th><th>Hostname</th><th>Tipo</th><th>Fabricante</th><th>Modelo</th><th>Status</th><th>Usuário</th><th>Site</th><th>IP</th><th>SO</th><th>Garantia</th><th>Ações</th></tr></thead>
                        <tbody>
                            <?php foreach ($vwAssetsRows as $r): ?>
                                <tr>
                                    <td>#<?= (int)$r['AssetID'] ?></td>
                                    <td><strong><?= h($r['AssetTag']) ?></strong></td>
                                    <td class="mono"><?= h($r['Hostname'] ?? '—') ?></td>
                                    <td><?= h($r['AssetTypeName'] ?? '—') ?></td>
                                    <td><?= h($r['ManufacturerName'] ?? '—') ?></td>
                                    <td><?= h($r['Model'] ?? '—') ?></td>
                                    <td><?= statusBadgeHtml($r['StatusName'] ?? null) ?></td>
                                    <td><?= h($r['AssignedUser'] ?? '—') ?></td>
                                    <td><?= h($r['SiteName'] ?? '—') ?></td>
                                    <td class="mono"><?= h($r['IPAddress'] ?? '—') ?></td>
                                    <td><?= h($r['OperatingSystem'] ?? '—') ?></td>
                                    <td><?= warrantyBadgeHtml($r['WarrantyEnd'] ?? null) ?></td>
                                    <td class="actions-cell">
                                        <a href="?page=asset_detail&id=<?= (int)$r['AssetID'] ?>" class="btn btn-secondary btn-sm">🔍 360º</a>
                                        <a href="?page=assets&edit=<?= (int)$r['AssetID'] ?>#form-asset" class="btn btn-secondary btn-sm">✏️</a>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

        <?php
            // ================================================================
            // PÁGINA: VISÃO 360º DO ATIVO
            // ================================================================
            elseif ($currentPage === 'asset_detail'):
                $assetId = (int)($_GET['id'] ?? 0);
                $asset = $db->fetchOne(
                    "SELECT A.*, AT.AssetTypeName, M.ManufacturerName, S.StatusName, U.DisplayName AS AssignedUserName, L.SiteName, L.Room
                     FROM Assets A
                     LEFT JOIN AssetTypes AT ON A.AssetTypeID = AT.AssetTypeID
                     LEFT JOIN Manufacturers M ON A.ManufacturerID = M.ManufacturerID
                     LEFT JOIN Status S ON A.StatusID = S.StatusID
                     LEFT JOIN Users U ON A.AssignedUserID = U.UserID
                     LEFT JOIN Locations L ON A.LocationID = L.LocationID
                     WHERE A.AssetID = ?",
                    [$assetId]
                );
                if ($asset):
                    $assetSw   = $db->fetchAll('SELECT * FROM SoftwareInventory WHERE AssetID = ? ORDER BY SoftwareID DESC', [$assetId]);
                    $assetPts  = $db->fetchAll('SELECT * FROM NetworkPorts WHERE AssetID = ? OR ConnectedAssetID = ? ORDER BY PortID ASC', [$assetId, $assetId]);
                    $assetMnt  = $db->fetchAll('SELECT * FROM MaintenanceHistory WHERE AssetID = ? ORDER BY MaintenanceDate DESC', [$assetId]);
                    $assetHist = $db->fetchAll(
                        "SELECT AH.*, U1.DisplayName AS PrevUser, U2.DisplayName AS NewUser, L1.SiteName AS PrevLoc, L2.SiteName AS NewLoc
                         FROM AssetHistory AH
                         LEFT JOIN Users U1 ON AH.PreviousUserID = U1.UserID
                         LEFT JOIN Users U2 ON AH.NewUserID = U2.UserID
                         LEFT JOIN Locations L1 ON AH.PreviousLocationID = L1.LocationID
                         LEFT JOIN Locations L2 ON AH.NewLocationID = L2.LocationID
                         WHERE AH.AssetID = ? ORDER BY AH.HistoryID DESC",
                        [$assetId]
                    );
        ?>
            <div class="page-header">
                <div class="page-title">
                    <h2>🔍 Visão 360º: <?= h($asset['AssetTag']) ?> (<?= h($asset['Hostname'] ?? 'Sem Hostname') ?>)</h2>
                </div>
                <div style="display:flex; gap:8px;">
                    <a href="?page=assets&edit=<?= (int)$asset['AssetID'] ?>#form-asset" class="btn btn-primary btn-sm">✏️ Editar Ativo</a>
                    <a href="?page=assets" class="btn btn-secondary btn-sm">← Voltar</a>
                </div>
            </div>

            <div class="card">
                <div class="card-header"><h3>Ficha Técnica (#<?= (int)$asset['AssetID'] ?>)</h3><?= statusBadgeHtml($asset['StatusName'] ?? null) ?></div>
                <div class="card-body">
                    <div class="form-grid">
                        <div><span class="text-muted">Tag / Serial:</span><br><strong><?= h($asset['AssetTag']) ?> / <?= h($asset['SerialNumber'] ?? '—') ?></strong></div>
                        <div><span class="text-muted">Tipo / Modelo:</span><br><strong><?= h(($asset['AssetTypeName'] ?? '—') . ' • ' . ($asset['ManufacturerName'] ?? '') . ' ' . ($asset['Model'] ?? '')) ?></strong></div>
                        <div><span class="text-muted">IP / MAC:</span><br><strong class="mono"><?= h(($asset['IPAddress'] ?? '—') . ' / ' . ($asset['MACAddress'] ?? '—')) ?></strong></div>
                        <div><span class="text-muted">Usuário / Local:</span><br><strong><?= h(($asset['AssignedUserName'] ?? '—') . ' @ ' . ($asset['SiteName'] ?? '—')) ?></strong></div>
                        <div><span class="text-muted">Garantia:</span><br><?= warrantyBadgeHtml($asset['WarrantyEnd'] ?? null) ?></div>
                        <div><span class="text-muted">Notas:</span><br><strong><?= h($asset['Notes'] ?? '—') ?></strong></div>
                    </div>
                </div>
            </div>

            <div class="grid-2">
                <div class="card">
                    <div class="card-header"><h3>🧩 Softwares (<?= count($assetSw) ?>)</h3><a href="?page=software&asset_id=<?= $assetId ?>" class="btn btn-secondary btn-sm">+ Novo</a></div>
                    <table class="data-table"><thead><tr><th>Software</th><th>Versão</th><th>Licença</th></tr></thead><tbody>
                        <?php foreach ($assetSw as $s): ?><tr><td><strong><?= h($s['SoftwareName']) ?></strong></td><td><?= h($s['Version'] ?? '—') ?></td><td class="mono"><?= h($s['LicenseKey'] ?? '—') ?></td></tr><?php endforeach; ?>
                    </tbody></table>
                </div>
                <div class="card">
                    <div class="card-header"><h3>🔌 Portas de Rede (<?= count($assetPts) ?>)</h3><a href="?page=ports&asset_id=<?= $assetId ?>" class="btn btn-secondary btn-sm">+ Nova</a></div>
                    <table class="data-table"><thead><tr><th>Porta</th><th>VLAN</th><th>Conectado a</th></tr></thead><tbody>
                        <?php foreach ($assetPts as $p): ?><tr><td class="mono"><strong><?= h($p['PortName']) ?></strong></td><td><?= h($p['VLAN'] ?? '—') ?></td><td><?= h($p['ConnectedDevice'] ?? '—') ?></td></tr><?php endforeach; ?>
                    </tbody></table>
                </div>
                <div class="card">
                    <div class="card-header"><h3>🛠️ Manutenções (<?= count($assetMnt) ?>)</h3><a href="?page=maintenance&asset_id=<?= $assetId ?>" class="btn btn-secondary btn-sm">+ Nova</a></div>
                    <table class="data-table"><thead><tr><th>Data</th><th>Tipo</th><th>Custo</th></tr></thead><tbody>
                        <?php foreach ($assetMnt as $m): ?><tr><td><?= formatDateBr($m['MaintenanceDate'] ?? null) ?></td><td><?= h($m['MaintenanceType']) ?></td><td><?= formatCurrencyBr($m['Cost'] ?? 0) ?></td></tr><?php endforeach; ?>
                    </tbody></table>
                </div>
                <div class="card">
                    <div class="card-header"><h3>🕓 Histórico (<?= count($assetHist) ?>)</h3><a href="?page=history&asset_id=<?= $assetId ?>" class="btn btn-secondary btn-sm">+ Novo</a></div>
                    <table class="data-table"><thead><tr><th>Data</th><th>Usuário</th><th>Local</th><th>Por</th></tr></thead><tbody>
                        <?php foreach ($assetHist as $ah): ?><tr><td><?= formatDateBr($ah['ChangeDate'] ?? null, true) ?></td><td><?= h(($ah['PrevUser'] ?? '—') . '→' . ($ah['NewUser'] ?? '—')) ?></td><td><?= h(($ah['PrevLoc'] ?? '—') . '→' . ($ah['NewLoc'] ?? '—')) ?></td><td><?= h($ah['ChangedBy'] ?? '—') ?></td></tr><?php endforeach; ?>
                    </tbody></table>
                </div>
            </div>

        <?php
                endif;

            // ================================================================
            // PÁGINA: CRUD DE ATIVOS (ASSETS)
            // ================================================================
            elseif ($currentPage === 'assets'):
                $editId = isset($_GET['edit']) ? (int)$_GET['edit'] : null;
                $editAsset = $editId ? $db->fetchOne('SELECT * FROM Assets WHERE AssetID = ?', [$editId]) : null;
                $q = trim((string)($_GET['q'] ?? ''));
                $whereSql = $q !== '' ? 'WHERE (A.AssetTag LIKE ? OR A.Hostname LIKE ? OR A.SerialNumber LIKE ? OR A.Model LIKE ? OR A.IPAddress LIKE ?)' : '';
                $params = $q !== '' ? array_fill(0, 5, '%' . $q . '%') : [];
                $assetsList = $db->fetchAll(
                    "SELECT A.*, AT.AssetTypeName, M.ManufacturerName, S.StatusName, U.DisplayName AS AssignedUser, L.SiteName
                     FROM Assets A
                     LEFT JOIN AssetTypes AT ON A.AssetTypeID = AT.AssetTypeID
                     LEFT JOIN Manufacturers M ON A.ManufacturerID = M.ManufacturerID
                     LEFT JOIN Status S ON A.StatusID = S.StatusID
                     LEFT JOIN Users U ON A.AssignedUserID = U.UserID
                     LEFT JOIN Locations L ON A.LocationID = L.LocationID
                     {$whereSql} ORDER BY A.AssetID DESC",
                    $params
                );
        ?>
            <div class="page-header">
                <div class="page-title"><h2>💻 Cadastro de Ativos (<code>Assets</code>)</h2></div>
                <a href="?page=import" class="btn btn-secondary btn-sm">📥 Importar Planilha de Ativos</a>
            </div>

            <div class="card" id="form-asset">
                <div class="card-header">
                    <h3><?= $editAsset ? ('✏️ Editando Ativo #' . (int)$editAsset['AssetID']) : '➕ Novo Ativo' ?></h3>
                    <?php if ($editAsset): ?><a href="?page=assets" class="btn btn-secondary btn-sm">Cancelar</a><?php endif; ?>
                </div>
                <div class="card-body">
                    <form method="post">
                        <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>">
                        <input type="hidden" name="_action" value="save_asset">
                        <input type="hidden" name="_redirect_page" value="assets">
                        <?php if ($editAsset): ?><input type="hidden" name="AssetID" value="<?= (int)$editAsset['AssetID'] ?>"><?php endif; ?>
                        <div class="form-grid">
                            <div class="form-group"><label>Asset Tag *</label><input type="text" name="AssetTag" class="form-control" required value="<?= h($editAsset['AssetTag'] ?? '') ?>"></div>
                            <div class="form-group"><label>SerialNumber</label><input type="text" name="SerialNumber" class="form-control" value="<?= h($editAsset['SerialNumber'] ?? '') ?>"></div>
                            <div class="form-group"><label>Hostname</label><input type="text" name="Hostname" class="form-control" value="<?= h($editAsset['Hostname'] ?? '') ?>"></div>
                            <div class="form-group"><label>Tipo (`AssetTypeID`)</label><select name="AssetTypeID" class="form-control"><option value="">— Selecionar —</option><?php foreach ($lookupTypes as $t): ?><option value="<?= (int)$t['AssetTypeID'] ?>" <?= ((int)($editAsset['AssetTypeID'] ?? 0) === (int)$t['AssetTypeID']) ? 'selected' : '' ?>><?= h($t['AssetTypeName']) ?></option><?php endforeach; ?></select></div>
                            <div class="form-group"><label>Fabricante (`ManufacturerID`)</label><select name="ManufacturerID" class="form-control"><option value="">— Selecionar —</option><?php foreach ($lookupManufacturers as $m): ?><option value="<?= (int)$m['ManufacturerID'] ?>" <?= ((int)($editAsset['ManufacturerID'] ?? 0) === (int)$m['ManufacturerID']) ? 'selected' : '' ?>><?= h($m['ManufacturerName']) ?></option><?php endforeach; ?></select></div>
                            <div class="form-group"><label>Modelo (`Model`)</label><input type="text" name="Model" class="form-control" value="<?= h($editAsset['Model'] ?? '') ?>"></div>
                            <div class="form-group"><label>Status (`StatusID`)</label><select name="StatusID" class="form-control"><option value="">— Selecionar —</option><?php foreach ($lookupStatus as $s): ?><option value="<?= (int)$s['StatusID'] ?>" <?= ((int)($editAsset['StatusID'] ?? 0) === (int)$s['StatusID']) ? 'selected' : '' ?>><?= h($s['StatusName']) ?></option><?php endforeach; ?></select></div>
                            <div class="form-group"><label>Usuário (`AssignedUserID`)</label><select name="AssignedUserID" class="form-control"><option value="">— Sem Usuário —</option><?php foreach ($lookupUsers as $u): ?><option value="<?= (int)$u['UserID'] ?>" <?= ((int)($editAsset['AssignedUserID'] ?? 0) === (int)$u['UserID']) ? 'selected' : '' ?>><?= h($u['DisplayName']) ?></option><?php endforeach; ?></select></div>
                            <div class="form-group"><label>Localidade (`LocationID`)</label><select name="LocationID" class="form-control"><option value="">— Selecionar —</option><?php foreach ($lookupLocations as $l): ?><option value="<?= (int)$l['LocationID'] ?>" <?= ((int)($editAsset['LocationID'] ?? 0) === (int)$l['LocationID']) ? 'selected' : '' ?>><?= h($l['SiteName']) ?></option><?php endforeach; ?></select></div>
                            <div class="form-group"><label>Compra (`PurchaseDate`)</label><input type="date" name="PurchaseDate" class="form-control" value="<?= h(formatDateInput($editAsset['PurchaseDate'] ?? null)) ?>"></div>
                            <div class="form-group"><label>Fim Garantia (`WarrantyEnd`)</label><input type="date" name="WarrantyEnd" class="form-control" value="<?= h(formatDateInput($editAsset['WarrantyEnd'] ?? null)) ?>"></div>
                            <div class="form-group"><label>IP (`IPAddress`)</label><input type="text" name="IPAddress" class="form-control" value="<?= h($editAsset['IPAddress'] ?? '') ?>"></div>
                            <div class="form-group"><label>MAC (`MACAddress`)</label><input type="text" name="MACAddress" class="form-control" value="<?= h($editAsset['MACAddress'] ?? '') ?>"></div>
                            <div class="form-group"><label>Sistema Operacional</label><input type="text" name="OperatingSystem" class="form-control" value="<?= h($editAsset['OperatingSystem'] ?? '') ?>"></div>
                            <div class="form-group full-width"><label>Observações (`Notes`)</label><textarea name="Notes" class="form-control"><?= h($editAsset['Notes'] ?? '') ?></textarea></div>
                        </div>
                        <div style="margin-top:14px;"><button type="submit" class="btn btn-primary"><?= $editAsset ? '💾 Atualizar Ativo' : '➕ Cadastrar Ativo' ?></button></div>
                    </form>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h3>Lista de Ativos (<?= count($assetsList) ?>)</h3>
                    <form method="get" style="display:flex; gap:8px;">
                        <input type="hidden" name="page" value="assets">
                        <input type="text" name="q" class="form-control" style="width:240px;" value="<?= h($q) ?>" placeholder="Buscar Tag, Hostname, Serial, IP...">
                        <button type="submit" class="btn btn-secondary btn-sm">Buscar</button>
                    </form>
                </div>
                <div class="table-responsive">
                    <table class="data-table">
                        <thead><tr><th>ID</th><th>Tag</th><th>Hostname / Serial</th><th>Tipo / Modelo</th><th>Status</th><th>Usuário</th><th>Local</th><th>IP / SO</th><th>Garantia</th><th>Ações</th></tr></thead>
                        <tbody>
                            <?php foreach ($assetsList as $a): ?>
                                <tr>
                                    <td>#<?= (int)$a['AssetID'] ?></td>
                                    <td><strong><?= h($a['AssetTag']) ?></strong></td>
                                    <td class="mono"><?= h($a['Hostname'] ?? '—') ?><br><span class="text-muted"><?= h($a['SerialNumber'] ?? '') ?></span></td>
                                    <td><?= h($a['AssetTypeName'] ?? '—') ?><br><span class="text-muted"><?= h(($a['ManufacturerName'] ?? '') . ' ' . ($a['Model'] ?? '')) ?></span></td>
                                    <td><?= statusBadgeHtml($a['StatusName'] ?? null) ?></td>
                                    <td><?= h($a['AssignedUser'] ?? '—') ?></td>
                                    <td><?= h($a['SiteName'] ?? '—') ?></td>
                                    <td class="mono"><?= h($a['IPAddress'] ?? '—') ?><br><span class="text-muted"><?= h($a['OperatingSystem'] ?? '') ?></span></td>
                                    <td><?= warrantyBadgeHtml($a['WarrantyEnd'] ?? null) ?></td>
                                    <td class="actions-cell">
                                        <a href="?page=asset_detail&id=<?= (int)$a['AssetID'] ?>" class="btn btn-secondary btn-sm">🔍 360º</a>
                                        <a href="?page=assets&edit=<?= (int)$a['AssetID'] ?>#form-asset" class="btn btn-secondary btn-sm">✏️</a>
                                        <form method="post" onsubmit="return confirm('Excluir ativo?');" style="display:inline;">
                                            <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>">
                                            <input type="hidden" name="_action" value="delete_asset">
                                            <input type="hidden" name="AssetID" value="<?= (int)$a['AssetID'] ?>">
                                            <button type="submit" class="btn btn-danger btn-sm">🗑️</button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

        <?php
            // ================================================================
            // PÁGINAS: SOFTWARE, PORTAS, MANUTENÇÃO, HISTÓRICO E TABELAS BASE
            // ================================================================
            elseif ($currentPage === 'software'):
                $editId = isset($_GET['edit']) ? (int)$_GET['edit'] : null;
                $editSw = $editId ? $db->fetchOne('SELECT * FROM SoftwareInventory WHERE SoftwareID = ?', [$editId]) : null;
                $swList = $db->fetchAll('SELECT SI.*, A.AssetTag, A.Hostname FROM SoftwareInventory SI LEFT JOIN Assets A ON SI.AssetID = A.AssetID ORDER BY SI.SoftwareID DESC');
        ?>
            <div class="page-header"><div class="page-title"><h2>🧩 Inventário de Software (<code>SoftwareInventory</code>)</h2></div></div>
            <div class="card">
                <div class="card-header"><h3><?= $editSw ? '✏️ Editar Software' : '➕ Novo Software' ?></h3></div>
                <div class="card-body">
                    <form method="post">
                        <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>">
                        <input type="hidden" name="_action" value="save_software">
                        <input type="hidden" name="_redirect_page" value="software">
                        <?php if ($editSw): ?><input type="hidden" name="SoftwareID" value="<?= (int)$editSw['SoftwareID'] ?>"><?php endif; ?>
                        <div class="form-grid">
                            <div class="form-group"><label>Ativo (`AssetID`)</label><select name="AssetID" class="form-control"><?= renderAssetOptions($assetsMap, $editSw['AssetID'] ?? ($_GET['asset_id'] ?? null)) ?></select></div>
                            <div class="form-group"><label>SoftwareName *</label><input type="text" name="SoftwareName" class="form-control" required value="<?= h($editSw['SoftwareName'] ?? '') ?>"></div>
                            <div class="form-group"><label>Version</label><input type="text" name="Version" class="form-control" value="<?= h($editSw['Version'] ?? '') ?>"></div>
                            <div class="form-group"><label>LicenseKey</label><input type="text" name="LicenseKey" class="form-control" value="<?= h($editSw['LicenseKey'] ?? '') ?>"></div>
                            <div class="form-group"><label>InstallDate</label><input type="date" name="InstallDate" class="form-control" value="<?= h(formatDateInput($editSw['InstallDate'] ?? date('Y-m-d'))) ?>"></div>
                        </div>
                        <div style="margin-top:14px;"><button type="submit" class="btn btn-primary">💾 Salvar Software</button></div>
                    </form>
                </div>
            </div>
            <div class="card"><div class="table-responsive"><table class="data-table">
                <thead><tr><th>ID</th><th>Ativo</th><th>Software</th><th>Versão</th><th>Chave</th><th>Instalação</th><th>Ações</th></tr></thead>
                <tbody><?php foreach ($swList as $sw): ?><tr>
                    <td>#<?= (int)$sw['SoftwareID'] ?></td>
                    <td><?= !empty($sw['AssetTag']) ? h($sw['AssetTag'] . ' (' . ($sw['Hostname'] ?? '') . ')') : ('AssetID #' . (int)$sw['AssetID']) ?></td>
                    <td><strong><?= h($sw['SoftwareName']) ?></strong></td><td><?= h($sw['Version'] ?? '—') ?></td><td class="mono"><?= h($sw['LicenseKey'] ?? '—') ?></td><td><?= formatDateBr($sw['InstallDate'] ?? null) ?></td>
                    <td class="actions-cell">
                        <a href="?page=software&edit=<?= (int)$sw['SoftwareID'] ?>" class="btn btn-secondary btn-sm">✏️</a>
                        <form method="post" style="display:inline;"><input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>"><input type="hidden" name="_action" value="delete_software"><input type="hidden" name="SoftwareID" value="<?= (int)$sw['SoftwareID'] ?>"><button type="submit" class="btn btn-danger btn-sm">🗑️</button></form>
                    </td>
                </tr><?php endforeach; ?></tbody>
            </table></div></div>

        <?php elseif ($currentPage === 'ports'):
                $editId = isset($_GET['edit']) ? (int)$_GET['edit'] : null;
                $editPt = $editId ? $db->fetchOne('SELECT * FROM NetworkPorts WHERE PortID = ?', [$editId]) : null;
                $ptList = $db->fetchAll('SELECT NP.*, A1.AssetTag AS SwitchTag FROM NetworkPorts NP LEFT JOIN Assets A1 ON NP.AssetID = A1.AssetID ORDER BY NP.PortID ASC');
        ?>
            <div class="page-header"><div class="page-title"><h2>🔌 Portas de Rede (<code>NetworkPorts</code>)</h2></div></div>
            <div class="card"><div class="card-body">
                <form method="post">
                    <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>"><input type="hidden" name="_action" value="save_port"><input type="hidden" name="_redirect_page" value="ports">
                    <?php if ($editPt): ?><input type="hidden" name="PortID" value="<?= (int)$editPt['PortID'] ?>"><?php endif; ?>
                    <div class="form-grid">
                        <div class="form-group"><label>Switch / Ativo (`AssetID`)</label><select name="AssetID" class="form-control"><?= renderAssetOptions($assetsMap, $editPt['AssetID'] ?? ($_GET['asset_id'] ?? null)) ?></select></div>
                        <div class="form-group"><label>PortName *</label><input type="text" name="PortName" class="form-control" required value="<?= h($editPt['PortName'] ?? '') ?>"></div>
                        <div class="form-group"><label>VLAN</label><input type="text" name="VLAN" class="form-control" value="<?= h($editPt['VLAN'] ?? '') ?>"></div>
                        <div class="form-group"><label>ConnectedDevice</label><input type="text" name="ConnectedDevice" class="form-control" value="<?= h($editPt['ConnectedDevice'] ?? '') ?>"></div>
                        <div class="form-group"><label>ConnectedAssetID</label><select name="ConnectedAssetID" class="form-control"><?= renderAssetOptions($assetsMap, $editPt['ConnectedAssetID'] ?? null, '— Opcional —') ?></select></div>
                        <div class="form-group"><label>Description</label><input type="text" name="Description" class="form-control" value="<?= h($editPt['Description'] ?? '') ?>"></div>
                    </div>
                    <div style="margin-top:14px;"><button type="submit" class="btn btn-primary">💾 Salvar Porta</button></div>
                </form>
            </div></div>
            <div class="card"><div class="table-responsive"><table class="data-table">
                <thead><tr><th>ID</th><th>Ativo</th><th>PortName</th><th>VLAN</th><th>ConnectedDevice</th><th>Descrição</th><th>Ações</th></tr></thead>
                <tbody><?php foreach ($ptList as $pt): ?><tr>
                    <td>#<?= (int)$pt['PortID'] ?></td><td><?= !empty($pt['SwitchTag']) ? h($pt['SwitchTag']) : ('AssetID #' . (int)$pt['AssetID']) ?></td>
                    <td class="mono"><strong><?= h($pt['PortName']) ?></strong></td><td><span class="badge badge-info">VLAN <?= h($pt['VLAN'] ?? '—') ?></span></td>
                    <td class="mono"><?= h($pt['ConnectedDevice'] ?? '—') ?></td><td><?= h($pt['Description'] ?? '—') ?></td>
                    <td class="actions-cell">
                        <a href="?page=ports&edit=<?= (int)$pt['PortID'] ?>" class="btn btn-secondary btn-sm">✏️</a>
                        <form method="post" style="display:inline;"><input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>"><input type="hidden" name="_action" value="delete_port"><input type="hidden" name="PortID" value="<?= (int)$pt['PortID'] ?>"><button type="submit" class="btn btn-danger btn-sm">🗑️</button></form>
                    </td>
                </tr><?php endforeach; ?></tbody>
            </table></div></div>

        <?php elseif ($currentPage === 'maintenance'):
                $editId = isset($_GET['edit']) ? (int)$_GET['edit'] : null;
                $editMt = $editId ? $db->fetchOne('SELECT * FROM MaintenanceHistory WHERE MaintenanceID = ?', [$editId]) : null;
                $mtList = $db->fetchAll('SELECT MH.*, A.AssetTag FROM MaintenanceHistory MH LEFT JOIN Assets A ON MH.AssetID = A.AssetID ORDER BY MH.MaintenanceDate DESC');
        ?>
            <div class="page-header"><div class="page-title"><h2>🛠️ Histórico de Manutenções (<code>MaintenanceHistory</code>)</h2></div></div>
            <div class="card"><div class="card-body">
                <form method="post">
                    <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>"><input type="hidden" name="_action" value="save_maintenance"><input type="hidden" name="_redirect_page" value="maintenance">
                    <?php if ($editMt): ?><input type="hidden" name="MaintenanceID" value="<?= (int)$editMt['MaintenanceID'] ?>"><?php endif; ?>
                    <div class="form-grid">
                        <div class="form-group"><label>Ativo (`AssetID`)</label><select name="AssetID" class="form-control"><?= renderAssetOptions($assetsMap, $editMt['AssetID'] ?? ($_GET['asset_id'] ?? null)) ?></select></div>
                        <div class="form-group"><label>MaintenanceDate</label><input type="date" name="MaintenanceDate" class="form-control" value="<?= h(formatDateInput($editMt['MaintenanceDate'] ?? date('Y-m-d'))) ?>"></div>
                        <div class="form-group"><label>MaintenanceType *</label><input type="text" name="MaintenanceType" class="form-control" required value="<?= h($editMt['MaintenanceType'] ?? '') ?>"></div>
                        <div class="form-group"><label>Vendor</label><input type="text" name="Vendor" class="form-control" value="<?= h($editMt['Vendor'] ?? '') ?>"></div>
                        <div class="form-group"><label>Cost (R$)</label><input type="number" step="0.01" name="Cost" class="form-control" value="<?= h((string)($editMt['Cost'] ?? '0.00')) ?>"></div>
                        <div class="form-group"><label>Description</label><input type="text" name="Description" class="form-control" value="<?= h($editMt['Description'] ?? '') ?>"></div>
                    </div>
                    <div style="margin-top:14px;"><button type="submit" class="btn btn-primary">💾 Salvar Manutenção</button></div>
                </form>
            </div></div>
            <div class="card"><div class="table-responsive"><table class="data-table">
                <thead><tr><th>ID</th><th>Ativo</th><th>Data</th><th>Tipo</th><th>Fornecedor</th><th>Custo</th><th>Descrição</th><th>Ações</th></tr></thead>
                <tbody><?php foreach ($mtList as $m): ?><tr>
                    <td>#<?= (int)$m['MaintenanceID'] ?></td><td><?= !empty($m['AssetTag']) ? h($m['AssetTag']) : ('AssetID #' . (int)$m['AssetID']) ?></td>
                    <td><?= formatDateBr($m['MaintenanceDate'] ?? null) ?></td><td><strong><?= h($m['MaintenanceType']) ?></strong></td><td><?= h($m['Vendor'] ?? '—') ?></td>
                    <td><strong><?= formatCurrencyBr($m['Cost'] ?? 0) ?></strong></td><td><?= h($m['Description'] ?? '—') ?></td>
                    <td class="actions-cell">
                        <a href="?page=maintenance&edit=<?= (int)$m['MaintenanceID'] ?>" class="btn btn-secondary btn-sm">✏️</a>
                        <form method="post" style="display:inline;"><input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>"><input type="hidden" name="_action" value="delete_maintenance"><input type="hidden" name="MaintenanceID" value="<?= (int)$m['MaintenanceID'] ?>"><button type="submit" class="btn btn-danger btn-sm">🗑️</button></form>
                    </td>
                </tr><?php endforeach; ?></tbody>
            </table></div></div>

        <?php elseif ($currentPage === 'history'):
                $editId = isset($_GET['edit']) ? (int)$_GET['edit'] : null;
                $editH = $editId ? $db->fetchOne('SELECT * FROM AssetHistory WHERE HistoryID = ?', [$editId]) : null;
                $hList = $db->fetchAll(
                    "SELECT AH.*, A.AssetTag, U1.DisplayName AS PrevU, U2.DisplayName AS NewU, L1.SiteName AS PrevL, L2.SiteName AS NewL
                     FROM AssetHistory AH
                     LEFT JOIN Assets A ON AH.AssetID = A.AssetID
                     LEFT JOIN Users U1 ON AH.PreviousUserID = U1.UserID
                     LEFT JOIN Users U2 ON AH.NewUserID = U2.UserID
                     LEFT JOIN Locations L1 ON AH.PreviousLocationID = L1.LocationID
                     LEFT JOIN Locations L2 ON AH.NewLocationID = L2.LocationID
                     ORDER BY AH.HistoryID DESC"
                );
        ?>
            <div class="page-header"><div class="page-title"><h2>🕓 Histórico de Movimentação (<code>AssetHistory</code>)</h2></div></div>
            <div class="card"><div class="card-body">
                <form method="post">
                    <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>"><input type="hidden" name="_action" value="save_history"><input type="hidden" name="_redirect_page" value="history">
                    <?php if ($editH): ?><input type="hidden" name="HistoryID" value="<?= (int)$editH['HistoryID'] ?>"><?php endif; ?>
                    <div class="form-grid">
                        <div class="form-group"><label>Ativo *</label><select name="AssetID" class="form-control" required><?= renderAssetOptions($assetsMap, $editH['AssetID'] ?? ($_GET['asset_id'] ?? null)) ?></select></div>
                        <div class="form-group"><label>Usuário Anterior</label><select name="PreviousUserID" class="form-control"><option value="">— Nenhum —</option><?php foreach ($lookupUsers as $u): ?><option value="<?= (int)$u['UserID'] ?>" <?= ((int)($editH['PreviousUserID'] ?? 0) === (int)$u['UserID']) ? 'selected' : '' ?>><?= h($u['DisplayName']) ?></option><?php endforeach; ?></select></div>
                        <div class="form-group"><label>Novo Usuário</label><select name="NewUserID" class="form-control"><option value="">— Nenhum —</option><?php foreach ($lookupUsers as $u): ?><option value="<?= (int)$u['UserID'] ?>" <?= ((int)($editH['NewUserID'] ?? 0) === (int)$u['UserID']) ? 'selected' : '' ?>><?= h($u['DisplayName']) ?></option><?php endforeach; ?></select></div>
                        <div class="form-group"><label>Local Anterior</label><select name="PreviousLocationID" class="form-control"><option value="">— Nenhum —</option><?php foreach ($lookupLocations as $l): ?><option value="<?= (int)$l['LocationID'] ?>" <?= ((int)($editH['PreviousLocationID'] ?? 0) === (int)$l['LocationID']) ? 'selected' : '' ?>><?= h($l['SiteName']) ?></option><?php endforeach; ?></select></div>
                        <div class="form-group"><label>Novo Local</label><select name="NewLocationID" class="form-control"><option value="">— Nenhum —</option><?php foreach ($lookupLocations as $l): ?><option value="<?= (int)$l['LocationID'] ?>" <?= ((int)($editH['NewLocationID'] ?? 0) === (int)$l['LocationID']) ? 'selected' : '' ?>><?= h($l['SiteName']) ?></option><?php endforeach; ?></select></div>
                        <div class="form-group"><label>Registrado Automaticamente Por</label><input type="text" class="form-control" disabled value="<?= h($authUser['display_name'] . ' (' . $authUser['username'] . ')') ?>"></div>
                        <div class="form-group full-width"><label>Notas</label><input type="text" name="Notes" class="form-control" value="<?= h($editH['Notes'] ?? '') ?>"></div>
                        <?php if (!$editH): ?><div class="form-group full-width"><label><input type="checkbox" name="apply_to_asset" value="1" checked> Atualizar também o cadastro atual do Ativo</label></div><?php endif; ?>
                    </div>
                    <div style="margin-top:14px;"><button type="submit" class="btn btn-primary">💾 Registrar Movimentação</button></div>
                </form>
            </div></div>
            <div class="card"><div class="table-responsive"><table class="data-table">
                <thead><tr><th>ID</th><th>Data</th><th>Ativo</th><th>Usuário (De → Para)</th><th>Local (De → Para)</th><th>Por</th><th>Notas</th><th>Ações</th></tr></thead>
                <tbody><?php foreach ($hList as $ah): ?><tr>
                    <td>#<?= (int)$ah['HistoryID'] ?></td><td><?= formatDateBr($ah['ChangeDate'] ?? null, true) ?></td>
                    <td><strong><?= h($ah['AssetTag'] ?? ('#' . $ah['AssetID'])) ?></strong></td>
                    <td><?= h(($ah['PrevU'] ?? '—') . ' → ' . ($ah['NewU'] ?? '—')) ?></td>
                    <td><?= h(($ah['PrevL'] ?? '—') . ' → ' . ($ah['NewL'] ?? '—')) ?></td>
                    <td><?= h($ah['ChangedBy'] ?? '—') ?></td><td><?= h($ah['Notes'] ?? '—') ?></td>
                    <td class="actions-cell">
                        <a href="?page=history&edit=<?= (int)$ah['HistoryID'] ?>" class="btn btn-secondary btn-sm">✏️</a>
                        <form method="post" style="display:inline;"><input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>"><input type="hidden" name="_action" value="delete_history"><input type="hidden" name="HistoryID" value="<?= (int)$ah['HistoryID'] ?>"><button type="submit" class="btn btn-danger btn-sm">🗑️</button></form>
                    </td>
                </tr><?php endforeach; ?></tbody>
            </table></div></div>

        <?php elseif ($currentPage === 'users'):
                $editId = isset($_GET['edit']) ? (int)$_GET['edit'] : null;
                $editU = $editId ? $db->fetchOne('SELECT * FROM Users WHERE UserID = ?', [$editId]) : null;
                $uList = $db->fetchAll('SELECT U.*, (SELECT COUNT(*) FROM Assets A WHERE A.AssignedUserID = U.UserID) AS Cnt FROM Users U ORDER BY U.UserID ASC');
        ?>
            <div class="page-header"><div class="page-title"><h2>👥 Usuários (<code>Users</code>)</h2></div></div>
            <div class="card"><div class="card-body">
                <form method="post">
                    <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>"><input type="hidden" name="_action" value="save_user"><input type="hidden" name="_redirect_page" value="users">
                    <?php if ($editU): ?><input type="hidden" name="UserID" value="<?= (int)$editU['UserID'] ?>"><?php endif; ?>
                    <div class="form-grid">
                        <div class="form-group"><label>DisplayName *</label><input type="text" name="DisplayName" class="form-control" required value="<?= h($editU['DisplayName'] ?? '') ?>"></div>
                        <div class="form-group"><label>Email</label><input type="email" name="Email" class="form-control" value="<?= h($editU['Email'] ?? '') ?>"></div>
                        <div class="form-group"><label>Department</label><input type="text" name="Department" class="form-control" value="<?= h($editU['Department'] ?? '') ?>"></div>
                        <div class="form-group"><label>Manager</label><input type="text" name="Manager" class="form-control" value="<?= h($editU['Manager'] ?? '') ?>"></div>
                    </div>
                    <div style="margin-top:14px;"><button type="submit" class="btn btn-primary">💾 Salvar Usuário</button></div>
                </form>
            </div></div>
            <div class="card"><div class="table-responsive"><table class="data-table">
                <thead><tr><th>ID</th><th>DisplayName</th><th>Email</th><th>Department</th><th>Manager</th><th>Ativos</th><th>Ações</th></tr></thead>
                <tbody><?php foreach ($uList as $u): ?><tr>
                    <td>#<?= (int)$u['UserID'] ?></td><td><strong><?= h($u['DisplayName']) ?></strong></td><td><?= h($u['Email'] ?? '—') ?></td><td><?= h($u['Department'] ?? '—') ?></td><td><?= h($u['Manager'] ?? '—') ?></td>
                    <td><span class="badge badge-info"><?= (int)$u['Cnt'] ?></span></td>
                    <td class="actions-cell">
                        <a href="?page=users&edit=<?= (int)$u['UserID'] ?>" class="btn btn-secondary btn-sm">✏️</a>
                        <form method="post" style="display:inline;"><input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>"><input type="hidden" name="_action" value="delete_user"><input type="hidden" name="UserID" value="<?= (int)$u['UserID'] ?>"><button type="submit" class="btn btn-danger btn-sm">🗑️</button></form>
                    </td>
                </tr><?php endforeach; ?></tbody>
            </table></div></div>

        <?php elseif ($currentPage === 'locations'):
                $editId = isset($_GET['edit']) ? (int)$_GET['edit'] : null;
                $editL = $editId ? $db->fetchOne('SELECT * FROM Locations WHERE LocationID = ?', [$editId]) : null;
                $lList = $db->fetchAll('SELECT L.*, (SELECT COUNT(*) FROM Assets A WHERE A.LocationID = L.LocationID) AS Cnt FROM Locations L ORDER BY L.LocationID ASC');
        ?>
            <div class="page-header"><div class="page-title"><h2>🏢 Localidades (<code>Locations</code>)</h2></div></div>
            <div class="card"><div class="card-body">
                <form method="post">
                    <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>"><input type="hidden" name="_action" value="save_location"><input type="hidden" name="_redirect_page" value="locations">
                    <?php if ($editL): ?><input type="hidden" name="LocationID" value="<?= (int)$editL['LocationID'] ?>"><?php endif; ?>
                    <div class="form-grid">
                        <div class="form-group"><label>SiteName *</label><input type="text" name="SiteName" class="form-control" required value="<?= h($editL['SiteName'] ?? '') ?>"></div>
                        <div class="form-group"><label>Country</label><input type="text" name="Country" class="form-control" value="<?= h($editL['Country'] ?? 'Brasil') ?>"></div>
                        <div class="form-group"><label>State</label><input type="text" name="State" class="form-control" value="<?= h($editL['State'] ?? '') ?>"></div>
                        <div class="form-group"><label>City</label><input type="text" name="City" class="form-control" value="<?= h($editL['City'] ?? '') ?>"></div>
                        <div class="form-group"><label>Room</label><input type="text" name="Room" class="form-control" value="<?= h($editL['Room'] ?? '') ?>"></div>
                    </div>
                    <div style="margin-top:14px;"><button type="submit" class="btn btn-primary">💾 Salvar Localidade</button></div>
                </form>
            </div></div>
            <div class="card"><div class="table-responsive"><table class="data-table">
                <thead><tr><th>ID</th><th>SiteName</th><th>Country</th><th>State</th><th>City</th><th>Room</th><th>Ativos</th><th>Ações</th></tr></thead>
                <tbody><?php foreach ($lList as $l): ?><tr>
                    <td>#<?= (int)$l['LocationID'] ?></td><td><strong><?= h($l['SiteName']) ?></strong></td><td><?= h($l['Country'] ?? '—') ?></td><td><?= h($l['State'] ?? '—') ?></td><td><?= h($l['City'] ?? '—') ?></td><td><?= h($l['Room'] ?? '—') ?></td>
                    <td><span class="badge badge-info"><?= (int)$l['Cnt'] ?></span></td>
                    <td class="actions-cell">
                        <a href="?page=locations&edit=<?= (int)$l['LocationID'] ?>" class="btn btn-secondary btn-sm">✏️</a>
                        <form method="post" style="display:inline;"><input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>"><input type="hidden" name="_action" value="delete_location"><input type="hidden" name="LocationID" value="<?= (int)$l['LocationID'] ?>"><button type="submit" class="btn btn-danger btn-sm">🗑️</button></form>
                    </td>
                </tr><?php endforeach; ?></tbody>
            </table></div></div>

        <?php elseif (in_array($currentPage, ['asset_types', 'manufacturers', 'status'], true)):
                $metaMap = [
                    'asset_types'   => ['title' => '🏷️ Tipos de Ativo (AssetTypes)',   'table' => 'AssetTypes',    'pk' => 'AssetTypeID',    'col' => 'AssetTypeName',    'save' => 'save_asset_type',   'del' => 'delete_asset_type'],
                    'manufacturers' => ['title' => '🏭 Fabricantes (Manufacturers)',   'table' => 'Manufacturers', 'pk' => 'ManufacturerID', 'col' => 'ManufacturerName', 'save' => 'save_manufacturer', 'del' => 'delete_manufacturer'],
                    'status'        => ['title' => '🚦 Status Operacional (Status)',   'table' => 'Status',        'pk' => 'StatusID',       'col' => 'StatusName',       'save' => 'save_status',       'del' => 'delete_status'],
                ];
                $m = $metaMap[$currentPage];
                $editId = isset($_GET['edit']) ? (int)$_GET['edit'] : null;
                $editRow = $editId ? $db->fetchOne("SELECT * FROM {$m['table']} WHERE {$m['pk']} = ?", [$editId]) : null;
                $rows = $db->fetchAll("SELECT T.*, (SELECT COUNT(*) FROM Assets A WHERE A.{$m['pk']} = T.{$m['pk']}) AS Cnt FROM {$m['table']} T ORDER BY T.{$m['pk']} ASC");
        ?>
            <div class="page-header"><div class="page-title"><h2><?= h($m['title']) ?></h2></div></div>
            <div class="grid-2">
                <div class="card"><div class="card-body">
                    <form method="post">
                        <input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>"><input type="hidden" name="_action" value="<?= h($m['save']) ?>"><input type="hidden" name="_redirect_page" value="<?= h($currentPage) ?>">
                        <?php if ($editRow): ?><input type="hidden" name="<?= h($m['pk']) ?>" value="<?= (int)$editRow[$m['pk']] ?>"><?php endif; ?>
                        <div class="form-group"><label><?= h($m['col']) ?> *</label><input type="text" name="<?= h($m['col']) ?>" class="form-control" required value="<?= h($editRow[$m['col']] ?? '') ?>"></div>
                        <div style="margin-top:14px;"><button type="submit" class="btn btn-primary">💾 Salvar</button></div>
                    </form>
                </div></div>
                <div class="card"><div class="table-responsive"><table class="data-table">
                    <thead><tr><th>ID</th><th><?= h($m['col']) ?></th><th>Ativos</th><th>Ações</th></tr></thead>
                    <tbody><?php foreach ($rows as $r): ?><tr>
                        <td>#<?= (int)$r[$m['pk']] ?></td><td><strong><?= h($r[$m['col']]) ?></strong></td><td><span class="badge badge-info"><?= (int)$r['Cnt'] ?></span></td>
                        <td class="actions-cell">
                            <a href="?page=<?= h($currentPage) ?>&edit=<?= (int)$r[$m['pk']] ?>" class="btn btn-secondary btn-sm">✏️</a>
                            <form method="post" style="display:inline;"><input type="hidden" name="_csrf" value="<?= h($CSRF_TOKEN) ?>"><input type="hidden" name="_action" value="<?= h($m['del']) ?>"><input type="hidden" name="<?= h($m['pk']) ?>" value="<?= (int)$r[$m['pk']] ?>"><button type="submit" class="btn btn-danger btn-sm">🗑️</button></form>
                        </td>
                    </tr><?php endforeach; ?></tbody>
                </table></div></div>
            </div>
        <?php
            endif;
        endif;
        ?>
    </main>
</div>
</body>
</html>