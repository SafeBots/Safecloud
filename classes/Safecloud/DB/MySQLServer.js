'use strict';
/**
 * MySQLServer — exposes the Safecloud/DB engine as a MySQL-protocol TCP server.
 *
 * Any client that speaks the MySQL wire protocol — PHP (PDO_MySQL, mysqli),
 * Python (mysql-connector-python, PyMySQL), Ruby, Go, WordPress, ORMs, etc. —
 * can connect without code changes.
 *
 * Usage (standalone):
 *   node classes/Safecloud/DB/mysql-server.js --db ./mydata.sc --port 3306
 *
 * Usage (embedded):
 *   const MySQLServer = require('./classes/Safecloud/DB/MySQLServer');
 *   const db  = new Database('./mydata.sc');
 *   const srv = new MySQLServer(db, { port: 3306, host: '127.0.0.1' });
 *   srv.listen(function (err) { if (!err) console.log('MySQL server up'); });
 *
 * Jets.js config (Safecloud 3.7+):
 *   Q.Config.set(['Safecloud', 'db', 'mysql'], { port: 3306 });
 *   // host defaults to 127.0.0.1, password defaults to null (no auth)
 *
 * Authentication:
 *   password: null (default) — accepts any client, no challenge check
 *   password: 'secret'       — enforces mysql_native_password SHA1 challenge
 *
 * PHP example (PDO):
 *   $pdo = new PDO('mysql:host=127.0.0.1;port=3306;dbname=safecloud', 'root', '');
 *
 * PHP example (mysqli):
 *   $m = new mysqli('127.0.0.1', 'root', '', 'safecloud', 3306);
 */

var net    = require('net');
var crypto = require('crypto');
var MySQLToSQLite = require('./MySQLToSQLite');

// ── MySQL capability flags ────────────────────────────────────────────────────
var CLIENT_LONG_PASSWORD              = 0x00000001;
var CLIENT_LONG_FLAG                  = 0x00000004;
var CLIENT_CONNECT_WITH_DB            = 0x00000008;
var CLIENT_PROTOCOL_41                = 0x00000200;
var CLIENT_SECURE_CONNECTION          = 0x00008000;
var CLIENT_PLUGIN_AUTH                = 0x00080000;
var CLIENT_PLUGIN_AUTH_LENENC_DATA    = 0x00200000;
var CLIENT_MULTI_STATEMENTS           = 0x00010000;
var CLIENT_MULTI_RESULTS              = 0x00020000;
// CLIENT_SSL = 0x00000800 — NOT advertised (we can't do TLS); we detect and
// reject SSL switch packets gracefully so drivers get a clear error message.

var SERVER_CAPS = CLIENT_LONG_PASSWORD
                | CLIENT_LONG_FLAG
                | CLIENT_CONNECT_WITH_DB
                | CLIENT_PROTOCOL_41
                | CLIENT_SECURE_CONNECTION
                | CLIENT_PLUGIN_AUTH
                | CLIENT_MULTI_STATEMENTS
                | CLIENT_MULTI_RESULTS;

var SERVER_STATUS_AUTOCOMMIT = 0x0002;

/**
 * Estimate password entropy in bits using charset-pool method.
 * Counts which character classes are present, computes pool size,
 * returns log2(pool^length).
 * @param {string} pw
 * @returns {number} estimated bits of entropy
 */
function _estimateEntropy(pw) {
    var pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
    if (pool === 0) pool = 26; // fallback
    return pw.length * Math.log2(pool);
}

// MySQL column type codes
var TYPE_VARCHAR  = 0xfd;
var TYPE_LONG     = 0x03; // INT
var TYPE_DOUBLE   = 0x05;

// COM command bytes
var COM_QUIT             = 0x01;
var COM_INIT_DB          = 0x02;
var COM_QUERY            = 0x03;
var COM_FIELD_LIST       = 0x04;
var COM_PING             = 0x0e;
var COM_STMT_PREPARE     = 0x16;
var COM_STMT_EXECUTE     = 0x17;
var COM_STMT_SEND_LONG_DATA = 0x18;
var COM_STMT_CLOSE       = 0x19;
var COM_STMT_RESET       = 0x1a;

// ── Constructor ───────────────────────────────────────────────────────────────

/**
 * @param {Database} database   An open Safecloud/DB Database instance.
 * @param {object}   options
 * @param {string}   [options.host='127.0.0.1']   Bind address.
 * @param {number}   [options.port=3306]           TCP port.
 * @param {string}   options.password               Required auth password. Must be at least 12
 *                                                  characters with >= 40 bits of entropy (mixed
 *                                                  case + digits + specials). No default — the
 *                                                  server refuses to start without one.
 * @param {string}   [options.dbName='safecloud']  Logical DB name sent to clients.
 */
function MySQLServer(database, options) {
    options       = options || {};
    this._db      = database;
    this._host    = options.host     || '127.0.0.1';
    // Allow port 0 (OS-assigned ephemeral port) — don't treat 0 as falsy.
    this._port    = (options.port !== undefined && options.port !== null) ? options.port : 3306;

    // Password is required. Validate length and entropy.
    var pw = options.password;
    if (!pw || typeof pw !== 'string') {
        throw new Error('MySQLServer: password is required. Set Safecloud.db.mysql.password in your config.');
    }
    if (pw.length < 12) {
        throw new Error('MySQLServer: password must be at least 12 characters (got ' + pw.length + ').');
    }
    var entropy = _estimateEntropy(pw);
    if (entropy < 40) {
        throw new Error('MySQLServer: password entropy too low (' + entropy.toFixed(1) + ' bits, need >= 40). Use mixed case, digits, and special characters.');
    }
    this._password = pw;
    this._dbName  = options.dbName   || 'safecloud';
    this._server  = null;
    this._nextConnId = 1;
    this._lastInsertId = 0;   // tracks last auto-increment ID for LAST_INSERT_ID()
    this._lastRowCount = 0;   // tracks last DML affected rows for ROW_COUNT()
    this._foundRows    = 0;   // tracks SQL_CALC_FOUND_ROWS result for FOUND_ROWS()
}

/** Start listening. callback(err) is called once the server is bound. */
MySQLServer.prototype.listen = function (callback) {
    var self = this;
    callback = callback || function () {};

    // Register MySQL scalar UDFs on the underlying database so translated queries
    // that still call NOW(), CONCAT(), DATE_FORMAT(), etc. work without further rewriting.
    try { MySQLToSQLite.registerUDFs(this._db._db || this._db); } catch (e) { /* non-fatal */ }

    this._server = net.createServer(function (socket) {
        self._handleConn(socket);
    });
    this._server.on('error', callback);
    this._server.listen(this._port, this._host, function () {
        callback(null);
    });
    return this;
};

MySQLServer.prototype.close = function (callback) {
    if (this._server) this._server.close(callback || function () {});
};

MySQLServer.prototype.address = function () {
    return this._server ? this._server.address() : null;
};

// ── Connection state machine ──────────────────────────────────────────────────

MySQLServer.prototype._handleConn = function (socket) {
    var self   = this;
    var connId = this._nextConnId++;
    var buf    = Buffer.alloc(0);
    var state  = 'handshake';     // 'handshake' | 'command'
    var scramble = crypto.randomBytes(20);
    var stmts     = {};  // stmtId -> { sql, numParams, types, longData }
    var nextStmtId = 1;

    // Send initial handshake packet (seq 0)
    socket.write(wrapPacket(_buildHandshake(connId, scramble, 'Safecloud/3.7'), 0));

    socket.on('data', function (chunk) {
        buf = Buffer.concat([buf, chunk]);

        // Parse complete packets from the stream
        while (buf.length >= 4) {
            var pktLen = buf[0] | (buf[1] << 8) | (buf[2] << 16);
            if (buf.length < 4 + pktLen) break;
            var clientSeq = buf[3];
            var payload   = buf.slice(4, 4 + pktLen);
            buf = buf.slice(4 + pktLen);

            var replySeq = (clientSeq + 1) & 0xff;

            if (state === 'handshake') {
                // Detect SSL switch request: exactly 32 bytes (caps+maxpkt+charset+reserved)
                // with the CLIENT_SSL bit set — client wants TLS but we don't support it.
                var sslCaps = payload.length >= 4 ? payload.readUInt32LE(0) : 0;
                if (payload.length <= 32 && (sslCaps & 0x00000800 /* CLIENT_SSL */)) {
                    socket.write(wrapPacket(_buildERR(1159, '08S01',
                        'SSL/TLS is not supported by this server. ' +
                        'Set ssl-mode=DISABLED (MySQL CLI) or useSSL=false (JDBC).'), replySeq));
                    socket.destroy();
                    return;
                }
                // Parse HandshakeResponse41; returns 'native', 'sha2', or false
                var authResult = self._checkAuth(payload, scramble);
                if (authResult) {
                    state = 'command';
                    if (authResult === 'sha2') {
                        // caching_sha2_password: send AuthMoreData(fast-auth OK) before the OK packet
                        socket.write(wrapPacket(Buffer.from([0x01, 0x03]), replySeq));
                        replySeq = (replySeq + 1) & 0xff;
                    }
                    socket.write(wrapPacket(_buildOK(0, 0), replySeq));
                } else {
                    socket.write(wrapPacket(_buildERR(1045, '28000', 'Access denied'), replySeq));
                    socket.destroy();
                }

            } else {
                // Command phase — MySQL resets seq to 0 on each command
                var cmd  = payload[0];
                var body = payload.slice(1);

                if (cmd === COM_QUIT) {
                    socket.destroy();

                } else if (cmd === COM_PING) {
                    socket.write(wrapPacket(_buildOK(0, 0), 1));

                } else if (cmd === COM_INIT_DB) {
                    // USE <dbname> — accept any
                    socket.write(wrapPacket(_buildOK(0, 0), 1));

                } else if (cmd === COM_FIELD_LIST) {
                    socket.write(wrapPacket(_buildERR(1096, 'HY000', 'COM_FIELD_LIST not supported'), 1));

                } else if (cmd === COM_QUERY) {
                    var sql = body.toString('utf8');
                    self._handleQuery(socket, sql);

                } else if (cmd === COM_STMT_PREPARE) {
                    var stmtSql = body.toString('utf8');
                    var stmtId  = nextStmtId++;
                    self._handleStmtPrepare(socket, stmtSql, stmts, stmtId);

                } else if (cmd === COM_STMT_EXECUTE) {
                    self._handleStmtExecute(socket, body, stmts);

                } else if (cmd === COM_STMT_SEND_LONG_DATA) {
                    // Accumulate blob/text data for a param — no response required
                    if (body.length >= 6) {
                        var ldId  = body.readUInt32LE(0);
                        var ldPrm = body.readUInt16LE(4);
                        var ldBuf = body.slice(6);
                        if (stmts[ldId]) {
                            if (!stmts[ldId].longData) stmts[ldId].longData = {};
                            var prev = stmts[ldId].longData[ldPrm] || Buffer.alloc(0);
                            stmts[ldId].longData[ldPrm] = Buffer.concat([prev, ldBuf]);
                        }
                    }

                } else if (cmd === COM_STMT_CLOSE) {
                    // Free statement resources — no response
                    var closeId = body.length >= 4 ? body.readUInt32LE(0) : -1;
                    delete stmts[closeId];

                } else if (cmd === COM_STMT_RESET) {
                    // Clear accumulated long data — respond with OK
                    var resetId = body.length >= 4 ? body.readUInt32LE(0) : -1;
                    if (stmts[resetId]) {
                        stmts[resetId].longData = {};
                        stmts[resetId].types    = [];
                    }
                    socket.write(wrapPacket(_buildOK(0, 0), 1));

                } else {
                    socket.write(wrapPacket(_buildERR(1047, '08S01', 'Unknown command ' + cmd), 1));
                }
            }
        }
    });

    socket.on('error', function () { socket.destroy(); });
};

// ── Authentication ────────────────────────────────────────────────────────────

// _checkAuth returns: 'native' | 'sha2' on success, false on failure.
// 'sha2' means the caller must send AuthMoreData(0x03) before the OK packet.
MySQLServer.prototype._checkAuth = function (payload, scramble) {
    if (!this._password) return 'native';   // no password configured → accept all

    // Parse HandshakeResponse41: caps(4) + max_pkt(4) + charset(1) + reserved(23) = 32
    if (payload.length < 33) return false;
    var caps   = payload.readUInt32LE(0);
    var offset = 32;

    // username — null-terminated
    var userEnd = payload.indexOf(0, offset);
    if (userEnd < 0) return false;
    offset = userEnd + 1;

    // auth response — length-prefixed (lenenc or fixed 1-byte length)
    var authLen;
    if (caps & CLIENT_PLUGIN_AUTH_LENENC_DATA) {
        authLen = payload[offset++];   // lenenc (simplified: handles < 251)
    } else if (caps & CLIENT_SECURE_CONNECTION) {
        authLen = payload[offset++];
    } else {
        authLen = 0;
        while (offset + authLen < payload.length && payload[offset + authLen] !== 0) authLen++;
    }
    var authResp = payload.slice(offset, offset + authLen);
    offset += authLen;

    // auth_plugin_name — null-terminated (present when CLIENT_PLUGIN_AUTH set)
    var pluginName = 'mysql_native_password';
    if ((caps & CLIENT_PLUGIN_AUTH) && offset < payload.length) {
        var pEnd = payload.indexOf(0, offset);
        if (pEnd > offset) {
            pluginName = payload.slice(offset, pEnd).toString('utf8');
        }
    }

    // ── caching_sha2_password (MySQL 8.0 default) ────────────────────────────
    if (pluginName === 'caching_sha2_password') {
        return this._checkCachingSha2(authResp, scramble) ? 'sha2' : false;
    }

    // ── mysql_native_password (SHA1) ──────────────────────────────────────────
    //   expected = SHA1(password) XOR SHA1(scramble || SHA1(SHA1(password)))
    var sha1Pass = crypto.createHash('sha1').update(this._password).digest();
    var sha1sha1 = crypto.createHash('sha1').update(sha1Pass).digest();
    var sha1mix  = crypto.createHash('sha1').update(Buffer.concat([scramble, sha1sha1])).digest();
    var expected = Buffer.allocUnsafe(20);
    for (var i = 0; i < 20; i++) expected[i] = sha1Pass[i] ^ sha1mix[i];

    return (authResp.length === 20 && authResp.equals(expected)) ? 'native' : false;
};

// caching_sha2_password verification:
//   A = SHA256(password)
//   B = SHA256(A)              — the "hash hash" that MySQL caches
//   C = SHA256(concat(B, scramble))
//   client sends: XOR(A, C)
MySQLServer.prototype._checkCachingSha2 = function (authResp, scramble) {
    if (authResp.length !== 32) return false;
    var sha256A = crypto.createHash('sha256').update(this._password).digest();
    var sha256B = crypto.createHash('sha256').update(sha256A).digest();
    var sha256C = crypto.createHash('sha256').update(Buffer.concat([sha256B, scramble])).digest();
    var expected = Buffer.allocUnsafe(32);
    for (var i = 0; i < 32; i++) expected[i] = sha256A[i] ^ sha256C[i];
    return authResp.equals(expected);
};

// ── Query dispatch ────────────────────────────────────────────────────────────

MySQLServer.prototype._handleQuery = function (socket, sql) {
    var self = this;

    // Strip leading/trailing whitespace and trailing semicolons
    var trimmed = sql.replace(/^\s+|\s+$/g, '').replace(/;+\s*$/, '');
    if (!trimmed) {
        return socket.write(wrapPacket(_buildOK(0, 0), 1));
    }

    // ── 1. SET — accept silently (charset, sql_mode, time_zone, etc.) ─────────
    if (/^SET\s+/i.test(trimmed)) {
        return socket.write(wrapPacket(_buildOK(0, 0), 1));
    }

    // ── 2. USE — switch database (we only have one) ───────────────────────────
    if (/^USE\s+/i.test(trimmed)) {
        return socket.write(wrapPacket(_buildOK(0, 0), 1));
    }

    // ── 3. Transaction control ────────────────────────────────────────────────
    if (/^(BEGIN|START\s+TRANSACTION)/i.test(trimmed)) {
        return socket.write(wrapPacket(_buildOK(0, 0), 1));
    }
    if (/^COMMIT/i.test(trimmed)) {
        return socket.write(wrapPacket(_buildOK(0, 0), 1));
    }
    if (/^ROLLBACK/i.test(trimmed)) {
        return socket.write(wrapPacket(_buildOK(0, 0), 1));
    }
    if (/^(SAVEPOINT|RELEASE\s+SAVEPOINT|ROLLBACK\s+TO)/i.test(trimmed)) {
        return socket.write(wrapPacket(_buildOK(0, 0), 1));
    }

    // ── 4. Lock / unlock (we don't enforce locks) ────────────────────────────
    if (/^(LOCK|UNLOCK)\s+TABLES?/i.test(trimmed)) {
        return socket.write(wrapPacket(_buildOK(0, 0), 1));
    }
    if (/^FLUSH\s+/i.test(trimmed)) {
        return socket.write(wrapPacket(_buildOK(0, 0), 1));
    }

    // ── 5. SELECT scalar functions / variables ────────────────────────────────

    // SELECT @@[global.|session.]var [AS alias], ... — system variables
    if (/^SELECT\s+@@/i.test(trimmed)) {
        return self._handleSysVars(socket, trimmed);
    }

    // SELECT DATABASE()
    if (/^SELECT\s+DATABASE\s*\(\s*\)/i.test(trimmed)) {
        var dbAlias = (trimmed.match(/AS\s+[`'"]?(\w+)[`'"]?/i) || [])[1] || 'DATABASE()';
        var r = {}; r[dbAlias] = self._dbName;
        return _writeResultSet(socket, [r], [{name: dbAlias, type: TYPE_VARCHAR}]);
    }

    // SELECT VERSION()
    if (/^SELECT\s+VERSION\s*\(\s*\)/i.test(trimmed)) {
        var vAlias = (trimmed.match(/AS\s+[`'"]?(\w+)[`'"]?/i) || [])[1] || 'VERSION()';
        var vr = {}; vr[vAlias] = 'Safecloud/3.7';
        return _writeResultSet(socket, [vr], [{name: vAlias, type: TYPE_VARCHAR}]);
    }

    // SELECT USER() / CURRENT_USER()
    if (/^SELECT\s+(CURRENT_USER|USER)\s*\(\s*\)/i.test(trimmed)) {
        var uAlias = (trimmed.match(/AS\s+[`'"]?(\w+)[`'"]?/i) || [])[1] || 'USER()';
        var ur = {}; ur[uAlias] = 'root@localhost';
        return _writeResultSet(socket, [ur], [{name: uAlias, type: TYPE_VARCHAR}]);
    }

    // SELECT FOUND_ROWS()
    if (/^SELECT\s+FOUND_ROWS\s*\(\s*\)/i.test(trimmed)) {
        return _writeResultSet(socket,
            [{'FOUND_ROWS()': String(self._foundRows)}],
            [{name: 'FOUND_ROWS()', type: TYPE_LONG}]);
    }

    // SELECT ROW_COUNT()
    if (/^SELECT\s+ROW_COUNT\s*\(\s*\)/i.test(trimmed)) {
        return _writeResultSet(socket,
            [{'ROW_COUNT()': String(self._lastRowCount)}],
            [{name: 'ROW_COUNT()', type: TYPE_LONG}]);
    }

    // SELECT LAST_INSERT_ID()
    if (/^SELECT\s+LAST_INSERT_ID\s*\(\s*\)/i.test(trimmed)) {
        return _writeResultSet(socket,
            [{'LAST_INSERT_ID()': String(self._lastInsertId)}],
            [{name: 'LAST_INSERT_ID()', type: TYPE_LONG}]);
    }

    // SELECT CONNECTION_ID()
    if (/^SELECT\s+CONNECTION_ID\s*\(\s*\)/i.test(trimmed)) {
        return _writeResultSet(socket,
            [{'CONNECTION_ID()': '1'}],
            [{name: 'CONNECTION_ID()', type: TYPE_LONG}]);
    }

    // SELECT 1 / SELECT 1+1 / SELECT NULL / SELECT 'literal'
    if (/^SELECT\s+(\d+(\s*[+\-*\/]\s*\d+)?|NULL|'[^']*'|"[^"]*")(\s+AS\s+\w+)?\s*$/i.test(trimmed)) {
        var litM   = trimmed.match(/^SELECT\s+([\d+\-*/\s.]+|NULL|'[^']*'|"[^"]*")(?:\s+AS\s+[`'"]?(\w+)[`'"]?)?\s*$/i);
        var litCol = (litM && litM[2]) ? litM[2] : (litM ? litM[1].trim() : '1');
        var litVal;
        if (!litM || /^NULL$/i.test(litM[1])) {
            litVal = null;
        } else if (/^'[^']*'$|^"[^"]*"$/.test(litM[1])) {
            litVal = litM[1].slice(1, -1);
        } else {
            /* jshint evil:true */ litVal = String(Function('return (' + litM[1] + ')')());
        }
        var litr = {}; litr[litCol] = litVal;
        return _writeResultSet(socket, [litr], [{name: litCol, type: TYPE_VARCHAR}]);
    }

    // ── 6. SHOW commands ──────────────────────────────────────────────────────

    // SHOW DATABASES
    if (/^SHOW\s+DATABASES/i.test(trimmed)) {
        return _writeResultSet(socket,
            [{Database: self._dbName}],
            [{name: 'Database', type: TYPE_VARCHAR}]);
    }

    // SHOW [FULL] TABLES [FROM <db>] [LIKE ...]
    if (/^SHOW\s+(?:FULL\s+)?TABLES/i.test(trimmed)) {
        var isFull  = /FULL/i.test(trimmed);
        var colName = 'Tables_in_' + self._dbName;
        var likeP   = _extractLike(trimmed);
        var tables  = self._db._catalog.listTables();
        if (likeP) tables = tables.filter(function (t) { return _likeMatch(t, likeP); });
        var rows = tables.map(function (t) {
            var row = {}; row[colName] = t;
            if (isFull) row.Table_type = 'BASE TABLE';
            return row;
        });
        var cols = [{name: colName, type: TYPE_VARCHAR}];
        if (isFull) cols.push({name: 'Table_type', type: TYPE_VARCHAR});
        return _writeResultSet(socket, rows, cols);
    }

    // SHOW TABLE STATUS [FROM db] [LIKE 'pattern' | WHERE ...]
    if (/^SHOW\s+TABLE\s+STATUS/i.test(trimmed)) {
        return self._handleShowTableStatus(socket, trimmed);
    }

    // SHOW [GLOBAL|SESSION] VARIABLES [LIKE 'pattern']
    if (/^SHOW\s+(GLOBAL\s+|SESSION\s+)?VARIABLES/i.test(trimmed)) {
        return self._handleShowVariables(socket, trimmed);
    }

    // SHOW COLUMNS FROM <table> / DESCRIBE <table>
    var descMatch = trimmed.match(/^(?:SHOW\s+(?:FULL\s+)?COLUMNS\s+FROM\s+|DESC(?:RIBE)?\s+)(`?)(\w+)\1/i);
    if (descMatch) {
        return self._handleDescribe(socket, descMatch[2]);
    }

    // SHOW INDEX FROM <table>
    var idxMatch = trimmed.match(/^SHOW\s+(?:KEYS|INDEX(?:ES)?)\s+FROM\s+(`?)(\w+)\1/i);
    if (idxMatch) {
        return self._handleShowIndex(socket, idxMatch[2]);
    }

    // SHOW CREATE TABLE <table>
    var sctMatch = trimmed.match(/^SHOW\s+CREATE\s+TABLE\s+(`?)(\w+)\1/i);
    if (sctMatch) {
        return self._handleShowCreateTable(socket, sctMatch[2]);
    }

    // SHOW [GLOBAL|SESSION] STATUS [LIKE 'pattern']
    if (/^SHOW\s+(GLOBAL\s+|SESSION\s+)?STATUS/i.test(trimmed)) {
        return _writeResultSet(socket, [], [
            {name: 'Variable_name', type: TYPE_VARCHAR},
            {name: 'Value',         type: TYPE_VARCHAR}
        ]);
    }

    // SHOW WARNINGS / SHOW ERRORS
    if (/^SHOW\s+(WARNINGS|ERRORS)/i.test(trimmed)) {
        return _writeResultSet(socket, [], [
            {name: 'Level',   type: TYPE_VARCHAR},
            {name: 'Code',    type: TYPE_LONG},
            {name: 'Message', type: TYPE_VARCHAR}
        ]);
    }

    // SHOW ENGINES
    if (/^SHOW\s+ENGINES/i.test(trimmed)) {
        return _writeResultSet(socket, [
            {Engine: 'SafecloudDB', Support: 'DEFAULT', Comment: 'Safecloud pure-JS engine',
             Transactions: 'YES', XA: 'NO', Savepoints: 'NO'},
            {Engine: 'MEMORY',     Support: 'YES', Comment: 'Hash based, stored in memory',
             Transactions: 'NO',  XA: 'NO', Savepoints: 'NO'}
        ], ['Engine','Support','Comment','Transactions','XA','Savepoints']
            .map(function(n) { return {name: n, type: TYPE_VARCHAR}; }));
    }

    // SHOW CHARACTER SET / SHOW CHARSET
    if (/^SHOW\s+(CHARACTER\s+SET|CHARSET)/i.test(trimmed)) {
        return _writeResultSet(socket, [
            {Charset: 'utf8mb4', Description: 'UTF-8 Unicode',
             'Default collation': 'utf8mb4_general_ci', Maxlen: '4'}
        ], [
            {name: 'Charset',           type: TYPE_VARCHAR},
            {name: 'Description',       type: TYPE_VARCHAR},
            {name: 'Default collation', type: TYPE_VARCHAR},
            {name: 'Maxlen',            type: TYPE_LONG}
        ]);
    }

    // SHOW COLLATION [LIKE 'pattern']
    if (/^SHOW\s+COLLATION/i.test(trimmed)) {
        return _writeResultSet(socket, [
            {Collation: 'utf8mb4_general_ci', Charset: 'utf8mb4', Id: '45',
             'Default': 'Yes', Compiled: 'Yes', Sortlen: '1', Pad_attribute: 'PAD SPACE'}
        ], ['Collation','Charset','Id','Default','Compiled','Sortlen','Pad_attribute']
            .map(function(n) { return {name: n, type: TYPE_VARCHAR}; }));
    }

    // SHOW PROCESSLIST / FULL PROCESSLIST
    if (/^SHOW\s+(FULL\s+)?PROCESSLIST/i.test(trimmed)) {
        return _writeResultSet(socket, [], [
            {name: 'Id',      type: TYPE_LONG},
            {name: 'User',    type: TYPE_VARCHAR},
            {name: 'Host',    type: TYPE_VARCHAR},
            {name: 'db',      type: TYPE_VARCHAR},
            {name: 'Command', type: TYPE_VARCHAR},
            {name: 'Time',    type: TYPE_LONG},
            {name: 'State',   type: TYPE_VARCHAR},
            {name: 'Info',    type: TYPE_VARCHAR}
        ]);
    }

    // SHOW BINARY LOGS / MASTER STATUS / SLAVE STATUS
    if (/^SHOW\s+(BINARY\s+LOGS|MASTER\s+STATUS|SLAVE\s+STATUS|REPLICA\s+STATUS)/i.test(trimmed)) {
        return _writeResultSet(socket, [], []);
    }

    // SHOW OPEN TABLES
    if (/^SHOW\s+OPEN\s+TABLES/i.test(trimmed)) {
        return _writeResultSet(socket, [], [
            {name: 'Database', type: TYPE_VARCHAR},
            {name: 'Table',    type: TYPE_VARCHAR},
            {name: 'In_use',   type: TYPE_LONG},
            {name: 'Name_locked', type: TYPE_LONG}
        ]);
    }

    // ── 7. information_schema queries ─────────────────────────────────────────
    if (/\binformation_schema\b/i.test(trimmed)) {
        return self._handleInfoSchema(socket, trimmed);
    }

    // ── 8. TRUNCATE [TABLE] <name> ────────────────────────────────────────────
    var truncMatch = trimmed.match(/^TRUNCATE\s+(?:TABLE\s+)?(`?)(\w+)\1\s*$/i);
    if (truncMatch) {
        try {
            var truncInfo = self._db.prepare('DELETE FROM `' + truncMatch[2] + '`').run();
            self._lastRowCount = truncInfo.changes || 0;
            return socket.write(wrapPacket(_buildOK(self._lastRowCount, 0), 1));
        } catch (e) {
            return socket.write(wrapPacket(_buildERR(1064, '42000', e.message), 1));
        }
    }

    // ── 9. Real SQL through the engine ────────────────────────────────────────
    try {
        // Strip SQL_CALC_FOUND_ROWS hint (we approximate FOUND_ROWS via row count)
        var calcRows = /SQL_CALC_FOUND_ROWS/i.test(trimmed);
        var sqlToRun = trimmed.replace(/SQL_CALC_FOUND_ROWS\s+/gi, '');

        // Translate MySQL dialect → SQLite dialect before execution
        var translated = MySQLToSQLite.translate(sqlToRun);
        sqlToRun = translated.sql;

        var stmt = self._db.prepare(sqlToRun);
        var upper = sqlToRun.replace(/\/\*[\s\S]*?\*\//g, '').trim().toUpperCase();

        if (/^(SELECT|WITH|EXPLAIN)\b/.test(upper)) {
            var rows2 = stmt.all();
            if (calcRows) self._foundRows = rows2.length;
            if (!rows2 || rows2.length === 0) {
                return _writeResultSet(socket, [], []);
            }
            // Filter out "HAVING helper" expression keys (e.g. 'count(*)', 'avg(v)')
            // that the Engine stores alongside alias keys for aggregate support.
            // Keep expression keys only when no plain alias exists for them.
            var allKeys2 = Object.keys(rows2[0]);
            var exprKeys2 = allKeys2.filter(function(k) { return k.indexOf('(') !== -1; });
            var plainKeys2 = allKeys2.filter(function(k) { return k.indexOf('(') === -1; });
            var visibleKeys2 = plainKeys2.length > 0
                ? plainKeys2  // prefer the alias columns; skip expression duplicates
                : allKeys2;   // no aliases → keep everything (e.g. SELECT count(*) with no alias)
            var cols2 = visibleKeys2.map(function (k) {
                return {name: k, type: _inferType(rows2[0][k])};
            });
            _writeResultSet(socket, rows2, cols2);
        } else {
            var info = stmt.run();
            self._lastRowCount  = info.changes        || 0;
            self._lastInsertId  = info.lastInsertRowid || self._lastInsertId;
            self._foundRows     = self._lastRowCount;
            socket.write(wrapPacket(_buildOK(self._lastRowCount, self._lastInsertId), 1));
        }
    } catch (e) {
        socket.write(wrapPacket(_buildERR(1064, '42000', e.message || 'SQL error'), 1));
    }
};

// ── Special query handlers ────────────────────────────────────────────────────

MySQLServer.prototype._handleSysVars = function (socket, sql) {
    // e.g. SELECT @@version, @@global.sql_mode AS mode, @@session.character_set_client
    // Collect everything after the first @@ up to FROM/WHERE/end
    var after = sql.slice(sql.search(/@@/i));
    // Strip a trailing FROM clause drivers sometimes add
    after = after.replace(/\s+FROM\s+.*/i, '');
    var items = after.split(',');
    var row = {};
    var cols = [];
    items.forEach(function (item) {
        item = item.trim();
        // Handle @@[global.|session.]varname [AS alias]
        var m = item.match(/@@(?:global\.|session\.)?(\w+)(?:\s+AS\s+[`'"]?(\w+)[`'"]?)?/i);
        if (!m) return;
        var varName = m[1].toLowerCase();
        var colName = m[2] || ('@@' + varName);
        cols.push({name: colName, type: TYPE_VARCHAR});
        row[colName] = _sysVar(varName);
    });
    if (!cols.length) {
        // Fallback: single empty string column
        return _writeResultSet(socket, [{'': ''}], [{name: '', type: TYPE_VARCHAR}]);
    }
    _writeResultSet(socket, [row], cols);
};

function _sysVar(name) {
    var map = {
        version:                        'Safecloud/3.7',
        version_comment:                'Safecloud DB (MySQL compatible)',
        version_compile_os:             'nodejs',
        version_compile_machine:        process.arch,
        sql_mode:                       'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION',
        character_set_client:           'utf8mb4',
        character_set_connection:       'utf8mb4',
        character_set_database:         'utf8mb4',
        character_set_results:          'utf8mb4',
        character_set_server:           'utf8mb4',
        character_set_system:           'utf8',
        collation_connection:           'utf8mb4_general_ci',
        collation_database:             'utf8mb4_general_ci',
        collation_server:               'utf8mb4_general_ci',
        time_zone:                      '+00:00',
        system_time_zone:               'UTC',
        autocommit:                     '1',
        max_allowed_packet:             '67108864',
        lower_case_table_names:         '0',
        global_read_lock:               '',
        init_connect:                   '',
        interactive_timeout:            '28800',
        wait_timeout:                   '28800',
        net_read_timeout:               '30',
        net_write_timeout:              '60',
        max_connections:                '151',
        log_bin:                        'OFF',
        tx_isolation:                   'REPEATABLE-READ',
        transaction_isolation:          'REPEATABLE-READ',
        innodb_large_prefix:            'ON',
        innodb_strict_mode:             'ON',
        performance_schema:             'OFF',
        explicit_defaults_for_timestamp:'ON',
        foreign_key_checks:             '1',
        unique_checks:                  '1',
        group_concat_max_len:           '1024',
        default_storage_engine:         'SafecloudDB',
        hostname:                       'localhost',
        license:                        'Apache',
        read_only:                      'OFF'
    };
    return name in map ? map[name] : '';
}

MySQLServer.prototype._handleShowVariables = function (socket, sql) {
    var likeP = _extractLike(sql);
    var allVars = {
        auto_increment_increment:        '1',
        auto_increment_offset:           '1',
        autocommit:                      'ON',
        character_set_client:            'utf8mb4',
        character_set_connection:        'utf8mb4',
        character_set_database:          'utf8mb4',
        character_set_results:           'utf8mb4',
        character_set_server:            'utf8mb4',
        character_set_system:            'utf8',
        collation_connection:            'utf8mb4_general_ci',
        collation_database:              'utf8mb4_general_ci',
        collation_server:                'utf8mb4_general_ci',
        default_storage_engine:          'SafecloudDB',
        event_scheduler:                 'OFF',
        explicit_defaults_for_timestamp: 'ON',
        foreign_key_checks:              'ON',
        group_concat_max_len:            '1024',
        hostname:                        'localhost',
        init_connect:                    '',
        innodb_large_prefix:             'ON',
        innodb_strict_mode:              'ON',
        interactive_timeout:             '28800',
        license:                         'Apache',
        log_bin:                         'OFF',
        lower_case_table_names:          '0',
        max_allowed_packet:              '67108864',
        max_connections:                 '151',
        net_read_timeout:                '30',
        net_write_timeout:               '60',
        performance_schema:              'OFF',
        read_only:                       'OFF',
        sql_mode:                        'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION',
        system_time_zone:                'UTC',
        time_zone:                       '+00:00',
        transaction_isolation:           'REPEATABLE-READ',
        tx_isolation:                    'REPEATABLE-READ',
        unique_checks:                   'ON',
        version:                         'Safecloud/3.7',
        version_comment:                 'Safecloud DB (MySQL compatible)',
        version_compile_machine:         process.arch,
        version_compile_os:              'nodejs',
        wait_timeout:                    '28800'
    };
    var rows = [];
    Object.keys(allVars).forEach(function (name) {
        if (!likeP || _likeMatch(name, likeP)) {
            rows.push({Variable_name: name, Value: allVars[name]});
        }
    });
    _writeResultSet(socket, rows, [
        {name: 'Variable_name', type: TYPE_VARCHAR},
        {name: 'Value',         type: TYPE_VARCHAR}
    ]);
};

MySQLServer.prototype._handleShowTableStatus = function (socket, sql) {
    var likeP  = _extractLike(sql);
    // Also handle WHERE name = 'x'
    var whereN = (sql.match(/WHERE\s+(?:`?name`?\s*=\s*'([^']+)'|`?name`?\s*=\s*"([^"]+)")/i) || []);
    var nameEq = whereN[1] || whereN[2] || null;

    var tables = this._db._catalog.listTables();
    if (likeP)  tables = tables.filter(function (t) { return _likeMatch(t, likeP); });
    if (nameEq) tables = tables.filter(function (t) { return t.toLowerCase() === nameEq.toLowerCase(); });

    var rows = tables.map(function (t) {
        return {
            Name: t, Engine: 'SafecloudDB', Version: '10', Row_format: 'Dynamic',
            Rows: null, Avg_row_length: '0', Data_length: '0',
            Max_data_length: '0', Index_length: '0', Data_free: '0',
            Auto_increment: null, Create_time: null, Update_time: null,
            Check_time: null, Collation: 'utf8mb4_general_ci',
            Checksum: null, Create_options: '', Comment: ''
        };
    });
    _writeResultSet(socket, rows,
        ['Name','Engine','Version','Row_format','Rows','Avg_row_length',
         'Data_length','Max_data_length','Index_length','Data_free',
         'Auto_increment','Create_time','Update_time','Check_time',
         'Collation','Checksum','Create_options','Comment']
        .map(function (n) { return {name: n, type: TYPE_VARCHAR}; }));
};

MySQLServer.prototype._handleDescribe = function (socket, tableName) {
    var schema = this._db._catalog.getTable(tableName);
    if (!schema) {
        return socket.write(wrapPacket(
            _buildERR(1146, '42S02', "Table '" + this._dbName + '.' + tableName + "' doesn't exist"), 1));
    }
    var rows = schema.columns.filter(function (c) {
        return c.name !== '__rowid__';
    }).map(function (c) {
        return {
            Field:   c.name,
            Type:    c.type   || 'TEXT',
            'Null':  c.notNull ? 'NO' : 'YES',
            Key:     c.primaryKey ? 'PRI' : '',
            Default: c.defaultValue !== null && c.defaultValue !== undefined ? String(c.defaultValue) : 'NULL',
            Extra:   c.autoIncrement ? 'auto_increment' : ''
        };
    });
    _writeResultSet(socket, rows, [
        {name: 'Field',   type: TYPE_VARCHAR},
        {name: 'Type',    type: TYPE_VARCHAR},
        {name: 'Null',    type: TYPE_VARCHAR},
        {name: 'Key',     type: TYPE_VARCHAR},
        {name: 'Default', type: TYPE_VARCHAR},
        {name: 'Extra',   type: TYPE_VARCHAR}
    ]);
};

MySQLServer.prototype._handleShowIndex = function (socket, tableName) {
    var schema = this._db._catalog.getTable(tableName);
    if (!schema) {
        return socket.write(wrapPacket(
            _buildERR(1146, '42S02', "Table '" + tableName + "' doesn't exist"), 1));
    }
    var indexes = this._db._catalog.getTableIndexes(tableName);
    var rows = [];
    // Primary key
    if (schema.primaryKey && schema.primaryKey.length && !schema.autoRowid) {
        schema.primaryKey.forEach(function (col, i) {
            rows.push({
                Table: tableName, Non_unique: '0', Key_name: 'PRIMARY',
                Seq_in_index: String(i + 1), Column_name: col,
                Collation: 'A', Cardinality: '0', Sub_part: null,
                Packed: null, 'Null': '', Index_type: 'BTREE', Comment: ''
            });
        });
    }
    indexes.forEach(function (idx) {
        idx.columns.forEach(function (col, i) {
            rows.push({
                Table: tableName, Non_unique: idx.unique ? '0' : '1',
                Key_name: idx.name, Seq_in_index: String(i + 1),
                Column_name: col.name, Collation: col.desc ? 'D' : 'A',
                Cardinality: '0', Sub_part: null, Packed: null,
                'Null': '', Index_type: 'BTREE', Comment: ''
            });
        });
    });
    _writeResultSet(socket, rows,
        ['Table','Non_unique','Key_name','Seq_in_index','Column_name',
         'Collation','Cardinality','Sub_part','Packed','Null','Index_type','Comment']
        .map(function (n) { return {name: n, type: TYPE_VARCHAR}; }));
};

MySQLServer.prototype._handleShowCreateTable = function (socket, tableName) {
    var schema = this._db._catalog.getTable(tableName);
    if (!schema) {
        return socket.write(wrapPacket(
            _buildERR(1146, '42S02', "Table '" + tableName + "' doesn't exist"), 1));
    }
    var colDefs = schema.columns.filter(function (c) {
        return c.name !== '__rowid__';
    }).map(function (c) {
        var def = '  `' + c.name + '` ' + (c.type || 'TEXT');
        if (c.notNull || c.primaryKey) def += ' NOT NULL';
        if (c.autoIncrement) def += ' AUTO_INCREMENT';
        if (c.defaultValue !== null && c.defaultValue !== undefined) def += " DEFAULT '" + c.defaultValue + "'";
        return def;
    });
    if (schema.primaryKey && schema.primaryKey.length && !schema.autoRowid) {
        colDefs.push('  PRIMARY KEY (`' + schema.primaryKey.join('`,`') + '`)');
    }
    var ddl = 'CREATE TABLE `' + tableName + '` (\n' + colDefs.join(',\n') + '\n) ENGINE=SafecloudDB DEFAULT CHARSET=utf8mb4';
    _writeResultSet(socket, [{Table: tableName, 'Create Table': ddl}], [
        {name: 'Table',        type: TYPE_VARCHAR},
        {name: 'Create Table', type: TYPE_VARCHAR}
    ]);
};

// ── information_schema handler ────────────────────────────────────────────────

MySQLServer.prototype._handleInfoSchema = function (socket, sql) {
    var self = this;
    var upper = sql.toUpperCase();

    // information_schema.tables
    if (/INFORMATION_SCHEMA\s*\.\s*TABLES\b/i.test(sql)) {
        var tblNameFilter = (sql.match(/table_name\s*=\s*'([^']+)'/i) || [])[1] || null;
        var tables = self._db._catalog.listTables();
        if (tblNameFilter) {
            tables = tables.filter(function (t) { return t.toLowerCase() === tblNameFilter.toLowerCase(); });
        }
        var rows = tables.map(function (t) {
            return {
                TABLE_CATALOG: 'def', TABLE_SCHEMA: self._dbName, TABLE_NAME: t,
                TABLE_TYPE: 'BASE TABLE', ENGINE: 'SafecloudDB', VERSION: '10',
                ROW_FORMAT: 'Dynamic', TABLE_ROWS: null, AVG_ROW_LENGTH: '0',
                DATA_LENGTH: '0', MAX_DATA_LENGTH: '0', INDEX_LENGTH: '0',
                DATA_FREE: '0', AUTO_INCREMENT: null, CREATE_TIME: null,
                UPDATE_TIME: null, CHECK_TIME: null,
                TABLE_COLLATION: 'utf8mb4_general_ci', CHECKSUM: null,
                CREATE_OPTIONS: '', TABLE_COMMENT: ''
            };
        });
        // If SELECT clause names specific columns, project to those
        rows = _projectInfoSchema(sql, rows);
        var cols = _inferCols(rows);
        return _writeResultSet(socket, rows, cols);
    }

    // information_schema.columns
    if (/INFORMATION_SCHEMA\s*\.\s*COLUMNS\b/i.test(sql)) {
        var tblM = (sql.match(/table_name\s*=\s*'([^']+)'/i) || [])[1] || null;
        if (!tblM) return _writeResultSet(socket, [], [{name: 'COLUMN_NAME', type: TYPE_VARCHAR}]);
        var schema = self._db._catalog.getTable(tblM);
        if (!schema) return _writeResultSet(socket, [], [{name: 'COLUMN_NAME', type: TYPE_VARCHAR}]);
        var colRows = schema.columns.filter(function (c) {
            return c.name !== '__rowid__';
        }).map(function (c, i) {
            return {
                TABLE_CATALOG: 'def', TABLE_SCHEMA: self._dbName, TABLE_NAME: tblM,
                COLUMN_NAME: c.name, ORDINAL_POSITION: String(i + 1),
                COLUMN_DEFAULT: (c.defaultValue !== null && c.defaultValue !== undefined)
                    ? String(c.defaultValue) : null,
                IS_NULLABLE: c.notNull ? 'NO' : 'YES',
                DATA_TYPE: (c.type || 'TEXT').toLowerCase(),
                CHARACTER_MAXIMUM_LENGTH: (c.type || '').match(/^(TEXT|VARCHAR|CHAR|BLOB)/i) ? '65535' : null,
                CHARACTER_OCTET_LENGTH:   (c.type || '').match(/^(TEXT|VARCHAR|CHAR|BLOB)/i) ? '65535' : null,
                NUMERIC_PRECISION: null, NUMERIC_SCALE: null, DATETIME_PRECISION: null,
                CHARACTER_SET_NAME: 'utf8mb4', COLLATION_NAME: 'utf8mb4_general_ci',
                COLUMN_TYPE: (c.type || 'TEXT').toLowerCase(),
                COLUMN_KEY: c.primaryKey ? 'PRI' : '',
                EXTRA: c.autoIncrement ? 'auto_increment' : '',
                PRIVILEGES: 'select,insert,update,references',
                COLUMN_COMMENT: '', GENERATION_EXPRESSION: '', SRS_ID: null
            };
        });
        colRows = _projectInfoSchema(sql, colRows);
        return _writeResultSet(socket, colRows, _inferCols(colRows));
    }

    // information_schema.key_column_usage
    if (/INFORMATION_SCHEMA\s*\.\s*KEY_COLUMN_USAGE\b/i.test(sql)) {
        return _writeResultSet(socket, [], [
            {name: 'CONSTRAINT_NAME', type: TYPE_VARCHAR},
            {name: 'TABLE_NAME',      type: TYPE_VARCHAR},
            {name: 'COLUMN_NAME',     type: TYPE_VARCHAR}
        ]);
    }

    // information_schema.table_constraints
    if (/INFORMATION_SCHEMA\s*\.\s*TABLE_CONSTRAINTS\b/i.test(sql)) {
        return _writeResultSet(socket, [], [
            {name: 'CONSTRAINT_NAME', type: TYPE_VARCHAR},
            {name: 'TABLE_NAME',      type: TYPE_VARCHAR},
            {name: 'CONSTRAINT_TYPE', type: TYPE_VARCHAR}
        ]);
    }

    // information_schema.statistics
    if (/INFORMATION_SCHEMA\s*\.\s*STATISTICS\b/i.test(sql)) {
        return _writeResultSet(socket, [], [
            {name: 'INDEX_NAME',  type: TYPE_VARCHAR},
            {name: 'COLUMN_NAME', type: TYPE_VARCHAR}
        ]);
    }

    // Other information_schema tables — empty result
    return _writeResultSet(socket, [], [{name: 'TABLE_NAME', type: TYPE_VARCHAR}]);
};

// Project rows to the columns named in a SELECT clause (best-effort)
function _projectInfoSchema(sql, rows) {
    if (!rows.length) return rows;
    var selM = sql.match(/^SELECT\s+([\s\S]+?)\s+FROM\b/i);
    if (!selM || selM[1].trim() === '*') return rows;
    var wanted = selM[1].split(',').map(function (c) {
        c = c.trim();
        var m = c.match(/(?:[\w.]+\.)?(\w+)(?:\s+AS\s+[`'"]?(\w+)[`'"]?)?/i);
        if (!m) return null;
        return {src: m[1].toUpperCase(), dst: (m[2] || m[1]).toUpperCase()};
    }).filter(Boolean);
    if (!wanted.length) return rows;
    return rows.map(function (row) {
        var newRow = {};
        wanted.forEach(function (w) {
            // Case-insensitive key lookup
            var key = Object.keys(row).find(function (k) { return k.toUpperCase() === w.src; });
            newRow[w.dst] = key !== undefined ? row[key] : null;
        });
        return newRow;
    });
}

function _inferCols(rows) {
    if (!rows.length) return [{name: 'col', type: TYPE_VARCHAR}];
    return Object.keys(rows[0]).map(function (k) {
        return {name: k, type: _inferType(rows[0][k])};
    });
}

// ── MySQL packet builders ─────────────────────────────────────────────────────

function _buildHandshake(connId, scramble, version) {
    var verBuf     = Buffer.from(version + '\0', 'utf8');
    var scramble1  = scramble.slice(0, 8);    // 8 bytes
    var scramble2  = Buffer.alloc(13, 0);     // 12 bytes + null
    scramble.slice(8).copy(scramble2);        // copy 12 bytes of scramble

    var authPluginName = 'mysql_native_password\0';
    var pluginBuf = Buffer.from(authPluginName);

    var parts = [
        Buffer.from([10]),         // protocol version
        verBuf,                    // server version
        _uint32le(connId),         // connection id
        scramble1,                 // auth-plugin-data-part-1
        Buffer.from([0]),          // filler
        _uint16le(SERVER_CAPS & 0xffff),
        Buffer.from([0x21]),       // charset: utf8_general_ci
        _uint16le(SERVER_STATUS_AUTOCOMMIT),
        _uint16le((SERVER_CAPS >> 16) & 0xffff),
        Buffer.from([scramble.length + 1]),  // auth-plugin-data-len
        Buffer.alloc(10, 0),       // reserved
        scramble2,                 // auth-plugin-data-part-2 (13 bytes)
        pluginBuf                  // auth plugin name
    ];
    return Buffer.concat(parts);
}

function _buildOK(affectedRows, insertId) {
    // OK packet: 0x00 | lenenc(affectedRows) | lenenc(insertId) | status(2) | warnings(2)
    return Buffer.concat([
        Buffer.from([0x00]),
        _lenencInt(affectedRows),
        _lenencInt(insertId),
        _uint16le(SERVER_STATUS_AUTOCOMMIT),
        _uint16le(0)   // warnings
    ]);
}

function _buildERR(code, sqlState, msg) {
    var msgBuf = Buffer.from(String(msg || ''), 'utf8');
    return Buffer.concat([
        Buffer.from([0xff]),
        _uint16le(code),
        Buffer.from(['#' + (sqlState || 'HY000')], 'utf8'),  // SQL state (6 bytes incl '#')
        msgBuf
    ]);
}

function _buildEOF() {
    return Buffer.from([0xfe, 0x00, 0x00,
        SERVER_STATUS_AUTOCOMMIT & 0xff, (SERVER_STATUS_AUTOCOMMIT >> 8) & 0xff]);
}

function _buildColumnDef(col, dbName) {
    return Buffer.concat([
        _lenencStr('def'),
        _lenencStr(dbName || 'safecloud'),
        _lenencStr(''),          // table alias
        _lenencStr(''),          // org_table
        _lenencStr(col.name),    // column alias
        _lenencStr(col.name),    // org_name
        Buffer.from([
            0x0c,                // next-length (always 12)
            0x21, 0x00,          // charset: utf8_general_ci
            0xff, 0xff, 0xff, 0xff, // column display length
            col.type || TYPE_VARCHAR, // MySQL type code
            0x00, 0x00,          // flags
            0x00,                // decimals
            0x00, 0x00           // filler
        ])
    ]);
}

// ── Result set writer ─────────────────────────────────────────────────────────

function _writeResultSet(socket, rows, cols, dbName) {
    var seq = 1;

    // 1. Column count
    socket.write(wrapPacket(_lenencInt(cols.length), seq++));

    // 2. Column definitions
    cols.forEach(function (col) {
        socket.write(wrapPacket(_buildColumnDef(col, dbName), seq++));
    });

    // 3. EOF after columns
    socket.write(wrapPacket(_buildEOF(), seq++));

    // 4. Rows (text protocol: each field is a lenenc string; NULL = 0xfb)
    rows.forEach(function (row) {
        var parts = cols.map(function (col) {
            var v = row[col.name];
            return _lenencStr(v === null || v === undefined ? null : String(v));
        });
        socket.write(wrapPacket(Buffer.concat(parts), seq++));
    });

    // 5. EOF after rows
    socket.write(wrapPacket(_buildEOF(), seq++));
}

// Extract result column names from the SELECT clause of an already-translated
// (SQLite-compatible) SQL string.  Used to build column definitions for empty
// result sets where no row objects exist to derive names from.
// Handles: `SELECT a, b, t.c AS d FROM ...`  Skips `SELECT *` (returns []).
function _parseSelectCols(sql) {
    // Pull the token list between SELECT … FROM (non-greedy, case-insensitive)
    var m = sql.match(/^SELECT\s+([\s\S]+?)\s+FROM\b/i);
    if (!m) return [];

    var list   = m[1].trim();
    var parts  = [];
    var depth  = 0, start = 0;

    for (var i = 0; i < list.length; i++) {
        var ch = list[i];
        if (ch === '(' || ch === '[') depth++;
        else if (ch === ')' || ch === ']') depth--;
        else if (ch === ',' && depth === 0) {
            parts.push(list.slice(start, i).trim());
            start = i + 1;
        }
    }
    parts.push(list.slice(start).trim());

    var cols = [];
    parts.forEach(function (p) {
        if (p === '*' || p === '' ) return;              // star — unknown
        var asM = p.match(/\bAS\s+[`"']?(\w+)[`"']?\s*$/i);
        if (asM) { cols.push(asM[1]); return; }
        var dotM = p.match(/\.([`"']?\w+[`"']?)\s*$/);
        if (dotM) { cols.push(dotM[1].replace(/[`"']/g, '')); return; }
        var identM = p.match(/^[`"']?(\w+)[`"']?\s*$/);
        if (identM) { cols.push(identM[1]); return; }
        // Complex expression without alias — use a sanitised label
        cols.push(p.replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 32) || 'col');
    });
    return cols;
}

// Send a result set using the MySQL *binary* row protocol (used for COM_STMT_EXECUTE).
//
// Binary row format per column (after the 0x00 header + null bitmap):
//   NULL   → bit set in bitmap, nothing in the value stream
//   any    → length-encoded string of the stringified value
//            (using VARCHAR / lenenc-string is safe for all types because
//             mysql2 and Connector/J cast based on what the driver expects,
//             and we always declare columns as TYPE_VARCHAR here)
//
// Null bitmap:
//   size = ceil((numCols + 2) / 8) bytes
//   bit for column i is at byte floor((i+2)/8), bit (i+2)%8
//   (the first 2 bits are reserved for the response header)
function _writeBinaryResultSet(socket, rows, cols, dbName) {
    var seq = 1;

    // 1. Column count
    socket.write(wrapPacket(_lenencInt(cols.length), seq++));

    // 2. Column definitions — always declare as VARCHAR so the driver's binary
    //    row parser reads them as length-encoded strings.
    cols.forEach(function (col) {
        socket.write(wrapPacket(_buildColumnDef({ name: col.name, type: TYPE_VARCHAR }, dbName), seq++));
    });

    // 3. EOF after columns
    socket.write(wrapPacket(_buildEOF(), seq++));

    // 4. Binary protocol rows
    rows.forEach(function (row) {
        var n          = cols.length;
        var bitmapSize = Math.ceil((n + 2) / 8);
        var bitmap     = Buffer.alloc(bitmapSize, 0);

        // Mark NULL columns in the bitmap (bit i+2 for column i)
        cols.forEach(function (col, i) {
            var v = row[col.name];
            if (v === null || v === undefined) {
                bitmap[Math.floor((i + 2) / 8)] |= (1 << ((i + 2) % 8));
            }
        });

        // Build: 0x00 marker + null bitmap + lenenc strings for non-null values
        var parts = [Buffer.from([0x00]), bitmap];
        cols.forEach(function (col) {
            var v = row[col.name];
            if (v !== null && v !== undefined) {
                parts.push(_lenencStr(String(v)));
            }
        });

        socket.write(wrapPacket(Buffer.concat(parts), seq++));
    });

    // 5. EOF after rows
    socket.write(wrapPacket(_buildEOF(), seq++));
}

// ── Wire utilities ────────────────────────────────────────────────────────────

function wrapPacket(payload, seq) {
    var hdr = Buffer.allocUnsafe(4);
    var len = payload.length;
    hdr[0] = len & 0xff;
    hdr[1] = (len >> 8) & 0xff;
    hdr[2] = (len >> 16) & 0xff;
    hdr[3] = seq & 0xff;
    return Buffer.concat([hdr, payload]);
}

function _lenencInt(n) {
    n = n || 0;
    if (n < 251) {
        var b = Buffer.allocUnsafe(1); b[0] = n; return b;
    }
    if (n < 65536) {
        var b2 = Buffer.allocUnsafe(3); b2[0] = 0xfc; b2.writeUInt16LE(n, 1); return b2;
    }
    var b3 = Buffer.allocUnsafe(5); b3[0] = 0xfd; b3.writeUInt32LE(n, 1); return b3;
}

function _lenencStr(s) {
    if (s === null || s === undefined) {
        return Buffer.from([0xfb]); // NULL
    }
    var sbuf = Buffer.from(String(s), 'utf8');
    return Buffer.concat([_lenencInt(sbuf.length), sbuf]);
}

function _uint16le(n) {
    var b = Buffer.allocUnsafe(2); b.writeUInt16LE(n >>> 0, 0); return b;
}

function _uint32le(n) {
    var b = Buffer.allocUnsafe(4); b.writeUInt32LE(n >>> 0, 0); return b;
}

function _inferType(val) {
    if (typeof val === 'number') return Number.isInteger(val) ? TYPE_LONG : TYPE_DOUBLE;
    return TYPE_VARCHAR;
}

// Extract LIKE pattern from a SHOW/SELECT statement — returns null if none
function _extractLike(sql) {
    var m = sql.match(/LIKE\s+'([^']*)'/i) || sql.match(/LIKE\s+"([^"]*)"/i);
    return m ? m[1] : null;
}

// MySQL LIKE pattern → JS regex match (case-insensitive, % = wildcard, _ = single char)
function _likeMatch(str, pattern) {
    var re = '^' + pattern
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/%/g, '.*')
        .replace(/_/g, '.') + '$';
    return new RegExp(re, 'i').test(str);
}

// ── Prepared statement emulation ──────────────────────────────────────────────

MySQLServer.prototype._handleStmtPrepare = function (socket, sql, stmts, stmtId) {
    // Count '?' placeholders outside of string/identifier literals
    var numParams = 0;
    var inStr = false, strChar = '';
    for (var i = 0; i < sql.length; i++) {
        var c = sql[i];
        if (inStr) {
            if (c === strChar) {
                if (sql[i + 1] === strChar) { i++; continue; }   // doubled-quote escape
                inStr = false;
            }
        } else if (c === "'" || c === '"' || c === '`') {
            inStr = true; strChar = c;
        } else if (c === '?') {
            numParams++;
        }
    }

    stmts[stmtId] = { sql: sql, numParams: numParams, types: [], longData: {} };

    // COM_STMT_PREPARE_OK response (seq starts at 1)
    var seq    = 1;
    var status = Buffer.concat([
        Buffer.from([0x00]),      // OK marker
        _uint32le(stmtId),        // statement_id
        _uint16le(0),             // num_columns (unknown at prepare time — 0 is safe)
        _uint16le(numParams),     // num_params
        Buffer.from([0x00]),      // reserved
        _uint16le(0)              // warning_count
    ]);
    socket.write(wrapPacket(status, seq++));

    // Send dummy parameter column definitions followed by EOF (required if numParams > 0)
    if (numParams > 0) {
        for (var p = 0; p < numParams; p++) {
            socket.write(wrapPacket(_buildColumnDef({name: '?', type: TYPE_VARCHAR}), seq++));
        }
        socket.write(wrapPacket(_buildEOF(), seq++));
    }
    // num_columns = 0, so no column-definition block needed
};

MySQLServer.prototype._handleStmtExecute = function (socket, body, stmts) {
    if (body.length < 9) {
        return socket.write(wrapPacket(_buildERR(1105, 'HY000', 'Malformed COM_STMT_EXECUTE'), 1));
    }

    var stmtId = body.readUInt32LE(0);
    // body[4] = flags, body[5..8] = iteration-count (always 1) — both ignored

    var stmt = stmts[stmtId];
    if (!stmt) {
        return socket.write(wrapPacket(_buildERR(1243, 'HY000', 'Unknown prepared statement id'), 1));
    }

    var params = [];
    var offset = 9;  // skip stmt_id(4) + flags(1) + iteration-count(4)

    if (stmt.numParams > 0 && body.length > offset) {
        // Null bitmap: ceil(numParams / 8) bytes
        var nullBitmapLen = Math.ceil(stmt.numParams / 8);
        if (body.length < offset + nullBitmapLen + 1) {
            return socket.write(wrapPacket(_buildERR(1105, 'HY000', 'Malformed COM_STMT_EXECUTE null bitmap'), 1));
        }
        var nullBitmap = body.slice(offset, offset + nullBitmapLen);
        offset += nullBitmapLen;

        var newParamsBound = body[offset++];
        if (newParamsBound) {
            // Read type pair for each param: type_code(1) + unsigned_flag(1) = 2 bytes each
            stmt.types = [];
            for (var t = 0; t < stmt.numParams; t++) {
                if (offset + 2 > body.length) break;
                stmt.types.push(body.readUInt16LE(offset));
                offset += 2;
            }
        }

        // Decode param values in binary protocol format
        for (var p = 0; p < stmt.numParams; p++) {
            var isNull = (nullBitmap[Math.floor(p / 8)] >> (p % 8)) & 1;
            if (isNull) { params.push(null); continue; }

            // Was this param sent earlier via COM_STMT_SEND_LONG_DATA?
            if (stmt.longData && stmt.longData[p]) {
                params.push(stmt.longData[p].toString('utf8'));
                continue;
            }

            var ptype   = (stmt.types[p] || 0xfd) & 0xff;  // low byte is the type code
            var decoded = _decodeBinaryParam(body, offset, ptype);
            params.push(decoded.value);
            offset = decoded.offset;
        }
    }

    // Clear accumulated long data after each execute
    stmt.longData = {};

    // Substitute bound params into SQL, then respond with binary protocol rows.
    // mysql2 / Connector/J expect binary rows for COM_STMT_EXECUTE results.
    var execSql = _substituteParams(stmt.sql, params);
    this._handleQueryBinary(socket, execSql);
};

// Execute a query and send the result using the MySQL *binary* row protocol.
// COM_STMT_EXECUTE clients (mysql2, Connector/J, Go driver, …) expect binary rows
// for SELECT results.  DML / DDL / SET / SHOW responses are OK/ERR packets,
// which are protocol-independent, so we fall through to _handleQuery for those.
MySQLServer.prototype._handleQueryBinary = function (socket, sql) {
    var self    = this;
    var trimmed = sql.replace(/^\s+|\s+$/g, '').replace(/;+\s*$/, '');
    if (!trimmed) return socket.write(wrapPacket(_buildOK(0, 0), 1));

    var upper = trimmed.toUpperCase();

    // Non-SELECT: DML, DDL, SET, SHOW, USE, transaction control.
    // Their responses are OK/ERR — protocol-independent.
    if (!/^(SELECT|WITH)\b/.test(upper)) {
        return self._handleQuery(socket, sql);
    }

    // Special SELECT patterns that _handleQuery handles with custom logic.
    // These are almost never sent as prepared statements in practice.
    if (/^SELECT\s+@@/i.test(trimmed) ||
        /^SELECT\s+(DATABASE|VERSION|USER|CURRENT_USER|FOUND_ROWS|ROW_COUNT|LAST_INSERT_ID|CONNECTION_ID)\s*\(/i.test(trimmed) ||
        /\bINFORMATION_SCHEMA\b/i.test(trimmed)) {
        return self._handleQuery(socket, sql);
    }

    // Real data SELECT — run through the engine and return binary protocol rows.
    try {
        var calcRows   = /SQL_CALC_FOUND_ROWS/i.test(trimmed);
        var sqlToRun   = trimmed.replace(/SQL_CALC_FOUND_ROWS\s+/gi, '');
        var translated = MySQLToSQLite.translate(sqlToRun);
        var engStmt    = self._db.prepare(translated.sql);
        var rows2      = engStmt.all();

        if (calcRows) self._foundRows = rows2.length;

        var cols2;
        if (!rows2 || rows2.length === 0) {
            // No rows returned — but the client needs column definitions so it can
            // distinguish an empty SELECT from an OK/DML packet (a 0x00 column count
            // byte is indistinguishable from an OK packet header in the MySQL protocol).
            // Extract column aliases from the SELECT clause as a best-effort fallback.
            var parsedCols = _parseSelectCols(translated.sql);
            cols2 = parsedCols.length > 0
                ? parsedCols.map(function (n) { return { name: n, type: TYPE_VARCHAR }; })
                : [{ name: '_', type: TYPE_VARCHAR }]; // last-resort sentinel so count ≠ 0
        } else {
            var allKeys2  = Object.keys(rows2[0]);
            var plainKeys = allKeys2.filter(function (k) { return k.indexOf('(') === -1; });
            var visKeys   = plainKeys.length > 0 ? plainKeys : allKeys2;
            cols2 = visKeys.map(function (k) { return { name: k, type: TYPE_VARCHAR }; });
        }
        _writeBinaryResultSet(socket, rows2 || [], cols2);
    } catch (e) {
        socket.write(wrapPacket(_buildERR(1064, '42000', e.message || 'SQL error'), 1));
    }
};

// Substitute '?' markers in a prepared-statement SQL string with bound param values.
// Skips markers that appear inside string/identifier literals.
function _substituteParams(sql, params) {
    var idx    = 0;
    var result = '';
    var inStr  = false, strChar = '';
    for (var i = 0; i < sql.length; i++) {
        var c = sql[i];
        if (inStr) {
            result += c;
            if (c === strChar) {
                if (sql[i + 1] === strChar) { result += sql[++i]; continue; }
                inStr = false;
            }
        } else if (c === "'" || c === '"' || c === '`') {
            inStr = true; strChar = c;
            result += c;
        } else if (c === '?') {
            var val = params[idx++];
            if (val === null || val === undefined) {
                result += 'NULL';
            } else if (typeof val === 'number') {
                result += isFinite(val) ? String(val) : 'NULL';
            } else {
                // Safe-quote string: backslash-escape backslashes, double single-quotes
                result += "'" + String(val).replace(/\\/g, '\\\\').replace(/'/g, "''") + "'";
            }
        } else {
            result += c;
        }
    }
    return result;
}

// Decode one binary-protocol parameter from buf starting at offset.
// Returns { value, offset } with offset advanced past the consumed bytes.
function _decodeBinaryParam(buf, offset, type) {
    if (offset >= buf.length) return { value: null, offset: offset };
    switch (type) {
        case 0x01: /* TINY   */
            return { value: buf.readInt8(offset), offset: offset + 1 };
        case 0x02: /* SHORT  */ case 0x0d: /* YEAR */
            return { value: buf.readInt16LE(offset), offset: offset + 2 };
        case 0x03: /* LONG   */ case 0x09: /* INT24 */
            return { value: buf.readInt32LE(offset), offset: offset + 4 };
        case 0x08: /* LONGLONG */ {
            var lo = buf.readUInt32LE(offset);
            var hi = buf.readInt32LE(offset + 4);
            // JS numbers lose precision for very large int64 values, but it's
            // good enough for typical id/timestamp columns.
            return { value: hi * 4294967296 + lo, offset: offset + 8 };
        }
        case 0x04: /* FLOAT  */
            return { value: buf.readFloatLE(offset), offset: offset + 4 };
        case 0x05: /* DOUBLE */
            return { value: buf.readDoubleLE(offset), offset: offset + 8 };
        case 0x06: /* NULL   */
            return { value: null, offset: offset };
        default: { /* lenenc string — VARCHAR, BLOB, DECIMAL, DATE, TIME, DATETIME, … */
            var slen = buf[offset++];
            if (slen === 0xfc) { slen = buf.readUInt16LE(offset); offset += 2; }
            else if (slen === 0xfd) {
                slen = buf[offset] | (buf[offset + 1] << 8) | (buf[offset + 2] << 16);
                offset += 3;
            } else if (slen === 0xfe) { slen = buf.readUInt32LE(offset); offset += 8; } // 8-byte lenenc; hi 4 bytes ignored
            if (offset + slen > buf.length) slen = buf.length - offset;
            var str = buf.slice(offset, offset + slen).toString('utf8');
            return { value: str, offset: offset + slen };
        }
    }
}

module.exports = MySQLServer;
