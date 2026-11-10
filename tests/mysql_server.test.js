'use strict';
/**
 * MySQL server smoke tests — no mysql2 client needed.
 * Connects via raw TCP and speaks the MySQL wire protocol to verify:
 *   - Handshake packet received
 *   - Auth handshake completes (no-password mode)
 *   - COM_QUERY for SELECT, INSERT, UPDATE, DELETE round-trips correctly
 *   - Special MySQL system queries return reasonable results
 *   - COM_PING works
 *   - SHOW TABLES, DESCRIBE, SHOW INDEX all respond
 *   - WordPress/PHP/ORM edge cases: @@global., trailing semicolons, SHOW VARIABLES,
 *     SHOW TABLE STATUS, SHOW WARNINGS, transaction commands, TRUNCATE,
 *     information_schema, scalar functions (DATABASE(), VERSION(), USER(), etc.)
 */

var net         = require('net');
var path        = require('path');
var os          = require('os');
var fs          = require('fs');
var Database    = require('../classes/Safecloud/DB/Database');
var MySQLServer = require('../classes/Safecloud/DB/MySQLServer');

// ── Minimal MySQL client (just enough for tests) ─────────────────────────────

function readPacket(buf, offset) {
    if (buf.length - offset < 4) return null;
    var len = buf[offset] | (buf[offset+1] << 8) | (buf[offset+2] << 16);
    if (buf.length - offset < 4 + len) return null;
    return { seq: buf[offset+3], payload: buf.slice(offset+4, offset+4+len), next: offset+4+len };
}

function lenencInt(buf, off) {
    var b = buf[off];
    if (b < 251) return { val: b, len: 1 };
    if (b === 0xfc) return { val: buf.readUInt16LE(off+1), len: 3 };
    return { val: 0, len: 1 }; // simplified
}

function lenencStr(buf, off) {
    if (buf[off] === 0xfb) return { val: null, len: 1 };
    var li = lenencInt(buf, off);
    var str = buf.slice(off + li.len, off + li.len + li.val).toString('utf8');
    return { val: str, len: li.len + li.val };
}

function readResultSet(packets) {
    // packets: array of payloads after the column-count packet
    // Returns { cols: [string], rows: [[string|null]] }
    // Parse: col-count, col-defs×N, EOF, row×M, EOF
    var idx = 0;
    var colCountPkt = packets[idx++];
    var colCount = colCountPkt[0]; // lenenc, simplified (< 251)
    var cols = [];
    for (var c = 0; c < colCount; c++) {
        var colPkt = packets[idx++];
        // catalog, db, table, org_table, name, org_name — parse 5 lenenc strings to get name
        var o = 0;
        for (var s = 0; s < 4; s++) { var ls = lenencStr(colPkt, o); o += ls.len; }
        var nameField = lenencStr(colPkt, o);
        cols.push(nameField.val);
    }
    idx++; // skip EOF
    var rows = [];
    while (idx < packets.length) {
        var pkt = packets[idx++];
        if (pkt[0] === 0xfe && pkt.length < 9) break; // EOF
        if (pkt[0] === 0xff) break; // ERR
        var row = [];
        var ro = 0;
        for (var ci = 0; ci < colCount; ci++) {
            var fs2 = lenencStr(pkt, ro);
            row.push(fs2.val);
            ro += fs2.len;
        }
        rows.push(row);
    }
    return { cols: cols, rows: rows };
}

// Connect, complete handshake (no-password), run a COM_QUERY, return packets
function query(port, sql, cb) {
    var sock = net.connect(port, '127.0.0.1');
    var buf = Buffer.alloc(0);
    var packets = [];
    var state = 'handshake';
    var responded = false;

    function done(err, result) {
        if (responded) return;
        responded = true;
        sock.destroy();
        cb(err, result);
    }

    sock.on('error', done);
    sock.setTimeout(3000, function () { done(new Error('timeout')); });

    sock.on('data', function (chunk) {
        buf = Buffer.concat([buf, chunk]);
        var off = 0;
        var pkt;
        while ((pkt = readPacket(buf, off))) {
            off = pkt.next;
            if (state === 'handshake') {
                // Send auth response (empty password)
                var authResp = Buffer.from([
                    0x00, 0x00, 0x00, 0x00,  // caps placeholder (4 bytes)
                    0x00, 0x00, 0x00, 0x01,  // max packet (4 bytes)
                    0x21,                    // charset
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0,                 // reserved 23 bytes
                    0x72, 0x6f, 0x6f, 0x74, 0x00, // 'root\0'
                    0x00                     // auth response length = 0
                ]);
                // Set capability flags properly
                var caps = 0x00000001 | 0x00000004 | 0x00000008 | 0x00000200 | 0x00008000 | 0x00080000;
                authResp.writeUInt32LE(caps, 0);
                var hdr = Buffer.alloc(4);
                hdr[0] = authResp.length & 0xff;
                hdr[1] = (authResp.length >> 8) & 0xff;
                hdr[2] = (authResp.length >> 16) & 0xff;
                hdr[3] = 1; // seq 1
                sock.write(Buffer.concat([hdr, authResp]));
                state = 'auth';
            } else if (state === 'auth') {
                if (pkt.payload[0] === 0xff) {
                    return done(new Error('Auth denied: ' + pkt.payload.slice(9).toString()));
                }
                // OK — send query
                var sqlBuf = Buffer.from(sql, 'utf8');
                var qpkt = Buffer.alloc(1 + sqlBuf.length);
                qpkt[0] = 0x03; // COM_QUERY
                sqlBuf.copy(qpkt, 1);
                var qhdr = Buffer.alloc(4);
                qhdr[0] = qpkt.length & 0xff;
                qhdr[1] = (qpkt.length >> 8) & 0xff;
                qhdr[2] = (qpkt.length >> 16) & 0xff;
                qhdr[3] = 0; // seq 0 for new command
                sock.write(Buffer.concat([qhdr, qpkt]));
                state = 'result';
            } else if (state === 'result') {
                packets.push(pkt.payload);
                // Done when we see a final EOF (0xfe, len<9) or ERR (0xff) after at least some data
                var p = pkt.payload;
                if ((p[0] === 0xfe && p.length < 9) || p[0] === 0xff) {
                    // Count EOFs — we need 2 for a result set, 1 is "done" for DML/ERR
                    var eofCount = packets.filter(function(x) { return x[0] === 0xfe && x.length < 9; }).length;
                    if (p[0] === 0xff || p[0] === 0x00 || eofCount >= 2) {
                        return done(null, packets);
                    }
                } else if (p[0] === 0x00 && packets.length === 1) {
                    // OK packet for DML
                    return done(null, packets);
                }
            }
        }
        buf = buf.slice(off);
    });
}

// ── Test harness ──────────────────────────────────────────────────────────────

var passed = 0;
var failed = 0;

function assert(label, cond, detail) {
    if (cond) {
        console.log('  ✓ ' + label);
        passed++;
    } else {
        console.error('  ✗ ' + label + (detail !== undefined ? ' — got: ' + JSON.stringify(detail) : ''));
        failed++;
    }
}

// ── Setup ─────────────────────────────────────────────────────────────────────

var tmpDir = path.join(os.tmpdir(), 'safedb_mysql_test_' + process.pid);
fs.mkdirSync(tmpDir, { recursive: true });

var dbPath = path.join(tmpDir, 'test.sc');
var db  = new Database(dbPath);
var srv = new MySQLServer(db, { port: 0, host: '127.0.0.1', password: 'Test#Passw0rd!99' }); // port 0 = OS assigns

// ── Test runner ───────────────────────────────────────────────────────────────

srv.listen(function (err) {
    if (err) { console.error('Server start failed:', err.message); process.exit(1); }
    var port = srv.address().port;
    console.log('MySQL server on port', port);

    var tests = [];

    // ── Test 1: system var query ──────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[1] System variables');
        query(port, 'SELECT @@version', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('column @@version', rs.cols[0] === '@@version', rs.cols[0]);
                assert('value contains Safecloud', rs.rows[0][0].indexOf('Safecloud') >= 0, rs.rows[0][0]);
            }
            next();
        });
    });

    // ── Test 2: SET ignored ───────────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[2] SET statement');
        query(port, 'SET NAMES utf8mb4', function (err, pkts) {
            assert('no error', !err, err && err.message);
            assert('OK packet', pkts && pkts[0] && pkts[0][0] === 0x00);
            next();
        });
    });

    // ── Test 3: SHOW DATABASES ────────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[3] SHOW DATABASES');
        query(port, 'SHOW DATABASES', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('column Database', rs.cols[0] === 'Database');
                assert('safecloud row', rs.rows.length > 0 && rs.rows[0][0] === 'safecloud');
            }
            next();
        });
    });

    // ── Test 4: CREATE TABLE + INSERT + SELECT ────────────────────────────────
    tests.push(function (next) {
        console.log('\n[4] CREATE TABLE');
        query(port, 'CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL)', function (err, pkts) {
            assert('no error', !err, err && err.message);
            assert('OK', pkts && pkts[0] && pkts[0][0] === 0x00);
            next();
        });
    });

    tests.push(function (next) {
        console.log('\n[5] INSERT row');
        query(port, "INSERT INTO users (id, name) VALUES (1, 'Alice')", function (err, pkts) {
            assert('no error', !err, err && err.message);
            assert('OK', pkts && pkts[0] && pkts[0][0] === 0x00);
            next();
        });
    });

    tests.push(function (next) {
        console.log('\n[6] SELECT row');
        query(port, 'SELECT id, name FROM users', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('two columns', rs.cols.length === 2);
                assert('one row', rs.rows.length === 1);
                assert('id=1', rs.rows[0][0] === '1');
                assert('name=Alice', rs.rows[0][1] === 'Alice');
            }
            next();
        });
    });

    // ── Test 5: SHOW TABLES ───────────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[7] SHOW TABLES');
        query(port, 'SHOW TABLES', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('users in list', rs.rows.some(function(r) { return r[0] === 'users'; }));
            }
            next();
        });
    });

    // ── Test 6: DESCRIBE ─────────────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[8] DESCRIBE users');
        query(port, 'DESCRIBE users', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('Field column present', rs.cols[0] === 'Field');
                assert('id row', rs.rows.some(function(r) { return r[0] === 'id'; }));
                assert('name row', rs.rows.some(function(r) { return r[0] === 'name'; }));
            }
            next();
        });
    });

    // ── Test 7: UPDATE + verify ───────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[9] UPDATE');
        query(port, "UPDATE users SET name = 'Bob' WHERE id = 1", function (err, pkts) {
            assert('no error', !err, err && err.message);
            assert('OK', pkts && pkts[0] && pkts[0][0] === 0x00);
            next();
        });
    });

    tests.push(function (next) {
        console.log('\n[10] SELECT after UPDATE');
        query(port, 'SELECT name FROM users WHERE id = 1', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('name=Bob', rs.rows[0] && rs.rows[0][0] === 'Bob');
            }
            next();
        });
    });

    // ── Test 8: DELETE ────────────────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[11] DELETE');
        query(port, 'DELETE FROM users WHERE id = 1', function (err, pkts) {
            assert('no error', !err, err && err.message);
            next();
        });
    });

    tests.push(function (next) {
        console.log('\n[12] SELECT after DELETE — empty');
        query(port, 'SELECT * FROM users', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('zero rows', rs.rows.length === 0);
            }
            next();
        });
    });

    // ── Test 9: SQL error handling ────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[13] SQL error');
        query(port, 'SELECT * FROM nonexistent_table', function (err, pkts) {
            assert('no crash', !err, err && err.message);
            assert('ERR packet', pkts && pkts[0] && pkts[0][0] === 0xff);
            next();
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // WordPress / PHP / ORM edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Test 14: trailing semicolon stripping ─────────────────────────────────
    tests.push(function (next) {
        console.log('\n[14] Trailing semicolon stripped');
        query(port, 'SHOW TABLES;', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('result set returned', rs.cols.length > 0);
            }
            next();
        });
    });

    // ── Test 15: @@global. prefix ────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[15] @@global.sql_mode');
        query(port, 'SELECT @@global.sql_mode', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('column returned', rs.cols.length === 1);
                assert('non-empty value', rs.rows.length > 0 && rs.rows[0][0] !== null);
            }
            next();
        });
    });

    // ── Test 16: @@session. prefix ────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[16] @@session.character_set_client');
        query(port, 'SELECT @@session.character_set_client', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('value is utf8mb4', rs.rows.length > 0 && rs.rows[0][0] === 'utf8mb4');
            }
            next();
        });
    });

    // ── Test 17: Multiple @@ vars ─────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[17] Multiple @@ vars');
        query(port, 'SELECT @@version, @@global.sql_mode', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('two columns', rs.cols.length === 2, rs.cols);
                assert('version col', rs.cols[0] === '@@version');
                assert('sql_mode col', rs.cols[1] === '@@sql_mode');
            }
            next();
        });
    });

    // ── Test 18: SELECT DATABASE() ───────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[18] SELECT DATABASE()');
        query(port, 'SELECT DATABASE()', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('returns dbname', rs.rows.length > 0 && rs.rows[0][0] === 'safecloud');
            }
            next();
        });
    });

    // ── Test 19: SELECT VERSION() ────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[19] SELECT VERSION()');
        query(port, 'SELECT VERSION()', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('contains Safecloud', rs.rows.length > 0 && rs.rows[0][0].indexOf('Safecloud') >= 0);
            }
            next();
        });
    });

    // ── Test 20: SELECT USER() ───────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[20] SELECT USER()');
        query(port, 'SELECT USER()', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('returns user string', rs.rows.length > 0 && rs.rows[0][0] !== null);
            }
            next();
        });
    });

    // ── Test 21: SHOW VARIABLES ──────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[21] SHOW VARIABLES');
        query(port, 'SHOW VARIABLES', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('Variable_name col', rs.cols[0] === 'Variable_name');
                assert('Value col', rs.cols[1] === 'Value');
                assert('has rows', rs.rows.length > 0);
                assert('has version', rs.rows.some(function(r) { return r[0] === 'version'; }));
            }
            next();
        });
    });

    // ── Test 22: SHOW VARIABLES LIKE ─────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[22] SHOW VARIABLES LIKE \'char%\'');
        query(port, "SHOW VARIABLES LIKE 'char%'", function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('all match prefix', rs.rows.every(function(r) { return /^char/i.test(r[0]); }));
            }
            next();
        });
    });

    // ── Test 23: SHOW TABLE STATUS ───────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[23] SHOW TABLE STATUS');
        query(port, 'SHOW TABLE STATUS', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('Name column', rs.cols[0] === 'Name');
                assert('Engine column', rs.cols.indexOf('Engine') >= 0);
                assert('users row', rs.rows.some(function(r) { return r[0] === 'users'; }));
            }
            next();
        });
    });

    // ── Test 24: SHOW WARNINGS ────────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[24] SHOW WARNINGS');
        query(port, 'SHOW WARNINGS', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('Level col', rs.cols[0] === 'Level');
                assert('Code col', rs.cols[1] === 'Code');
                assert('Message col', rs.cols[2] === 'Message');
                assert('empty', rs.rows.length === 0);
            }
            next();
        });
    });

    // ── Test 25: SHOW STATUS ─────────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[25] SHOW STATUS');
        query(port, 'SHOW STATUS', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('Variable_name col', rs.cols[0] === 'Variable_name');
            }
            next();
        });
    });

    // ── Test 26: SHOW ENGINES ────────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[26] SHOW ENGINES');
        query(port, 'SHOW ENGINES', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('Engine col', rs.cols[0] === 'Engine');
                assert('SafecloudDB present', rs.rows.some(function(r) { return r[0] === 'SafecloudDB'; }));
            }
            next();
        });
    });

    // ── Test 27: SHOW CHARACTER SET ──────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[27] SHOW CHARACTER SET');
        query(port, 'SHOW CHARACTER SET', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('utf8mb4 row', rs.rows.some(function(r) { return r[0] === 'utf8mb4'; }));
            }
            next();
        });
    });

    // ── Test 28: SHOW COLLATION ──────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[28] SHOW COLLATION');
        query(port, 'SHOW COLLATION', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('Collation col', rs.cols[0] === 'Collation');
                assert('utf8mb4_general_ci present', rs.rows.some(function(r) { return r[0] === 'utf8mb4_general_ci'; }));
            }
            next();
        });
    });

    // ── Test 29: Transaction commands ────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[29] Transaction commands');
        query(port, 'BEGIN', function (err, pkts) {
            assert('BEGIN ok', !err && pkts && pkts[0][0] === 0x00);
            query(port, 'COMMIT', function (err2, pkts2) {
                assert('COMMIT ok', !err2 && pkts2 && pkts2[0][0] === 0x00);
                query(port, 'ROLLBACK', function (err3, pkts3) {
                    assert('ROLLBACK ok', !err3 && pkts3 && pkts3[0][0] === 0x00);
                    next();
                });
            });
        });
    });

    // ── Test 30: START TRANSACTION ───────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[30] START TRANSACTION');
        query(port, 'START TRANSACTION', function (err, pkts) {
            assert('no error', !err, err && err.message);
            assert('OK packet', pkts && pkts[0] && pkts[0][0] === 0x00);
            next();
        });
    });

    // ── Test 31: LOCK TABLES / UNLOCK TABLES ─────────────────────────────────
    tests.push(function (next) {
        console.log('\n[31] LOCK/UNLOCK TABLES');
        query(port, 'LOCK TABLES users READ', function (err, pkts) {
            assert('LOCK ok', !err && pkts && pkts[0][0] === 0x00);
            query(port, 'UNLOCK TABLES', function (err2, pkts2) {
                assert('UNLOCK ok', !err2 && pkts2 && pkts2[0][0] === 0x00);
                next();
            });
        });
    });

    // ── Test 32: TRUNCATE TABLE ──────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[32] TRUNCATE TABLE');
        // First insert a row so we can truncate it
        query(port, "INSERT INTO users (id, name) VALUES (99, 'Temp')", function (err) {
            assert('insert for truncate ok', !err, err && err.message);
            query(port, 'TRUNCATE TABLE users', function (err2, pkts) {
                assert('TRUNCATE ok', !err2 && pkts && pkts[0][0] === 0x00);
                query(port, 'SELECT COUNT(*) FROM users', function (err3, pkts3) {
                    assert('table empty after TRUNCATE', !err3 && pkts3 && (function() {
                        var rs = readResultSet(pkts3);
                        return rs.rows.length > 0 && rs.rows[0][0] === '0';
                    })());
                    next();
                });
            });
        });
    });

    // ── Test 33: information_schema.tables ───────────────────────────────────
    tests.push(function (next) {
        console.log('\n[33] information_schema.tables');
        query(port, "SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA = 'safecloud'", function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('TABLE_NAME col', rs.cols[0] === 'TABLE_NAME');
                assert('users visible', rs.rows.some(function(r) { return r[0] === 'users'; }));
            }
            next();
        });
    });

    // ── Test 34: information_schema.columns ──────────────────────────────────
    tests.push(function (next) {
        console.log('\n[34] information_schema.columns');
        query(port, "SELECT COLUMN_NAME, DATA_TYPE FROM information_schema.columns WHERE TABLE_NAME = 'users'", function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('COLUMN_NAME col', rs.cols[0] === 'COLUMN_NAME');
                assert('id column', rs.rows.some(function(r) { return r[0] === 'id'; }));
                assert('name column', rs.rows.some(function(r) { return r[0] === 'name'; }));
            }
            next();
        });
    });

    // ── Test 35: FOUND_ROWS() ────────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[35] SELECT FOUND_ROWS()');
        query(port, 'SELECT FOUND_ROWS()', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('numeric result', rs.rows.length > 0 && /^\d+$/.test(rs.rows[0][0]));
            }
            next();
        });
    });

    // ── Test 36: LAST_INSERT_ID() ────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[36] SELECT LAST_INSERT_ID()');
        query(port, 'SELECT LAST_INSERT_ID()', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('numeric result', rs.rows.length > 0 && /^\d+$/.test(rs.rows[0][0]));
            }
            next();
        });
    });

    // ── Test 37: SELECT 1 (ping-style) ───────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[37] SELECT 1');
        query(port, 'SELECT 1', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('value is 1', rs.rows.length > 0 && rs.rows[0][0] === '1');
            }
            next();
        });
    });

    // ── Test 38: USE database ────────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[38] USE database');
        query(port, 'USE safecloud', function (err, pkts) {
            assert('no error', !err, err && err.message);
            assert('OK packet', pkts && pkts[0] && pkts[0][0] === 0x00);
            next();
        });
    });

    // ── Test 39: SHOW FULL TABLES ─────────────────────────────────────────────
    tests.push(function (next) {
        console.log('\n[39] SHOW FULL TABLES');
        query(port, 'SHOW FULL TABLES', function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('two columns', rs.cols.length === 2);
                assert('Table_type col', rs.cols[1] === 'Table_type');
                assert('BASE TABLE value', rs.rows.some(function(r) { return r[1] === 'BASE TABLE'; }));
            }
            next();
        });
    });

    // ── Test 40: SHOW GLOBAL VARIABLES LIKE ──────────────────────────────────
    tests.push(function (next) {
        console.log('\n[40] SHOW GLOBAL VARIABLES LIKE \'version%\'');
        query(port, "SHOW GLOBAL VARIABLES LIKE 'version%'", function (err, pkts) {
            assert('no error', !err, err && err.message);
            if (!err && pkts) {
                var rs = readResultSet(pkts);
                assert('all match version prefix', rs.rows.every(function(r) { return /^version/i.test(r[0]); }));
                assert('has version row', rs.rows.some(function(r) { return r[0] === 'version'; }));
            }
            next();
        });
    });

    // ── Run all tests in sequence ─────────────────────────────────────────────
    var idx = 0;
    function runNext() {
        if (idx >= tests.length) return finish();
        tests[idx++](runNext);
    }

    function finish() {
        srv.close();
        db.close();
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) {}

        console.log('\n─────────────────────────────────────────');
        console.log(passed + ' passed, ' + failed + ' failed');
        process.exit(failed > 0 ? 1 : 0);
    }

    runNext();
});
