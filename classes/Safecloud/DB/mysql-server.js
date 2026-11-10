#!/usr/bin/env node
'use strict';
/**
 * Standalone MySQL server for a Safecloud/DB database directory.
 *
 * Usage:
 *   node classes/Safecloud/DB/mysql-server.js [options]
 *
 * Options:
 *   --db       <path>    Database directory (required)
 *   --port     <number>  TCP port (default: 3306)
 *   --host     <addr>    Bind address (default: 127.0.0.1)
 *   --password <str>     Auth password; omit for no auth
 *   --name     <str>     Logical DB name shown to clients (default: safecloud)
 *
 * Example:
 *   node classes/Safecloud/DB/mysql-server.js --db ./local/rights.sc --port 3306
 *
 * Then connect from PHP:
 *   $pdo = new PDO('mysql:host=127.0.0.1;port=3306;dbname=safecloud', 'root', '');
 */

var path        = require('path');
var Database    = require('./Database');
var MySQLServer = require('./MySQLServer');

// ── Arg parsing ───────────────────────────────────────────────────────────────
var args = process.argv.slice(2);
var opts = { db: null, port: 3306, host: '127.0.0.1', password: null, name: 'safecloud' };

for (var i = 0; i < args.length; i++) {
    switch (args[i]) {
        case '--db':       opts.db       = args[++i]; break;
        case '--port':     opts.port     = parseInt(args[++i], 10); break;
        case '--host':     opts.host     = args[++i]; break;
        case '--password': opts.password = args[++i]; break;
        case '--name':     opts.name     = args[++i]; break;
        default:
            console.error('Unknown option:', args[i]);
            process.exit(1);
    }
}

if (!opts.db) {
    console.error('Usage: node mysql-server.js --db <path> [--port 3306] [--host 127.0.0.1] [--password <pw>]');
    process.exit(1);
}

// ── Open DB and start server ──────────────────────────────────────────────────
var dbPath = path.resolve(opts.db);
console.log('Opening database:', dbPath);

var db;
try {
    db = new Database(dbPath);
} catch (e) {
    console.error('Failed to open database:', e.message);
    process.exit(1);
}

var srv = new MySQLServer(db, {
    port:     opts.port,
    host:     opts.host,
    password: opts.password,
    dbName:   opts.name
});

srv.listen(function (err) {
    if (err) {
        console.error('Failed to start MySQL server:', err.message);
        db.close();
        process.exit(1);
    }
    var addr = srv.address();
    console.log('Safecloud/DB MySQL server listening on ' + addr.address + ':' + addr.port);
    console.log('Auth: ' + (opts.password ? 'mysql_native_password' : 'none (open)'));
    console.log('DB name: ' + opts.name);
    console.log('Tables:', db._catalog.listTables().join(', ') || '(none)');
    console.log('\nConnect with:');
    console.log('  mysql -h 127.0.0.1 -P ' + opts.port + ' -u root --password="" ' + opts.name);
    console.log('  $pdo = new PDO("mysql:host=127.0.0.1;port=' + opts.port + ';dbname=' + opts.name + '", "root", "");');
});

process.on('SIGINT',  function () { db.close(); process.exit(0); });
process.on('SIGTERM', function () { db.close(); process.exit(0); });
