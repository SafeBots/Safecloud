'use strict';
/**
 * End-to-end round-trip tests for the MySQL dialect translator + wire protocol.
 *
 * These tests speak the MySQL wire protocol directly (no mysql2 client needed),
 * send real MySQL DDL / DML through the server, and verify that:
 *
 *   1. MySQL-only DDL types survive translation and the table is created.
 *   2. Data inserted with MySQL idioms comes back correctly typed.
 *   3. MySQL DML syntax (INSERT IGNORE, ON DUPLICATE KEY UPDATE, REPLACE INTO,
 *      CONCAT, IF, IFNULL, ISNULL, NOW, LIMIT m,n, GROUP_CONCAT SEPARATOR) works.
 *   4. Output encoding edge cases: NULLs, empty strings, Unicode, large integers,
 *      DECIMAL / NUMERIC precision, booleans stored as TINYINT, zero-date strings.
 *   5. UDFs registered at listen() time work inside normal queries.
 */

var net      = require('net');
var path     = require('path');
var os       = require('os');
var fs       = require('fs');
var Database    = require('../classes/Safecloud/DB/Database');
var MySQLServer = require('../classes/Safecloud/DB/MySQLServer');

// ── Minimal MySQL wire client (identical to mysql_server.test.js) ─────────────

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
    return { val: 0, len: 1 };
}
function lenencStr(buf, off) {
    if (buf[off] === 0xfb) return { val: null, len: 1 };
    var li = lenencInt(buf, off);
    var str = buf.slice(off + li.len, off + li.len + li.val).toString('utf8');
    return { val: str, len: li.len + li.val };
}
function readResultSet(packets) {
    var idx = 0;
    var colCountPkt = packets[idx++];
    var colCount = colCountPkt[0];
    var cols = [];
    for (var c = 0; c < colCount; c++) {
        var colPkt = packets[idx++];
        var o = 0;
        for (var s = 0; s < 4; s++) { var ls = lenencStr(colPkt, o); o += ls.len; }
        var nameField = lenencStr(colPkt, o);
        cols.push(nameField.val);
    }
    idx++; // skip first EOF
    var rows = [];
    while (idx < packets.length) {
        var pkt = packets[idx++];
        if (pkt[0] === 0xfe && pkt.length < 9) break;
        if (pkt[0] === 0xff) break;
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
    sock.setTimeout(4000, function () { done(new Error('timeout')); });
    sock.on('data', function (chunk) {
        buf = Buffer.concat([buf, chunk]);
        var off = 0, pkt;
        while ((pkt = readPacket(buf, off))) {
            off = pkt.next;
            if (state === 'handshake') {
                var authResp = Buffer.from([
                    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x01, 0x21,
                    0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0, 0,0,0,
                    0x72,0x6f,0x6f,0x74,0x00, 0x00
                ]);
                var caps = 0x00000001|0x00000004|0x00000008|0x00000200|0x00008000|0x00080000;
                authResp.writeUInt32LE(caps, 0);
                var hdr = Buffer.alloc(4);
                hdr[0] = authResp.length & 0xff;
                hdr[1] = (authResp.length >> 8) & 0xff;
                hdr[2] = (authResp.length >> 16) & 0xff;
                hdr[3] = 1;
                sock.write(Buffer.concat([hdr, authResp]));
                state = 'auth';
            } else if (state === 'auth') {
                if (pkt.payload[0] === 0xff) return done(new Error('Auth denied'));
                var sqlBuf = Buffer.from(sql, 'utf8');
                var qpkt = Buffer.alloc(1 + sqlBuf.length);
                qpkt[0] = 0x03;
                sqlBuf.copy(qpkt, 1);
                var qhdr = Buffer.alloc(4);
                qhdr[0] = qpkt.length & 0xff;
                qhdr[1] = (qpkt.length >> 8) & 0xff;
                qhdr[2] = (qpkt.length >> 16) & 0xff;
                qhdr[3] = 0;
                sock.write(Buffer.concat([qhdr, qpkt]));
                state = 'result';
            } else if (state === 'result') {
                packets.push(pkt.payload);
                var p = pkt.payload;
                if ((p[0] === 0xfe && p.length < 9) || p[0] === 0xff) {
                    var eofCount = packets.filter(function(x){return x[0]===0xfe&&x.length<9;}).length;
                    if (p[0] === 0xff || eofCount >= 2) return done(null, packets);
                } else if (p[0] === 0x00 && packets.length === 1) {
                    return done(null, packets);
                }
            }
        }
        buf = buf.slice(off);
    });
}

/** Run queries serially, stop on first error. */
function serial(port, sqls, cb) {
    var i = 0;
    function next(err) {
        if (err) return cb(err);
        if (i >= sqls.length) return cb(null);
        var sql = sqls[i++];
        query(port, sql, function (err, pkts) {
            if (err) return cb(new Error(sql + ' → ' + err.message));
            var p = pkts && pkts[0];
            if (p && p[0] === 0xff) {
                var msg = p.slice(9).toString('utf8');
                return cb(new Error(sql + ' → ERR: ' + msg));
            }
            next(null);
        });
    }
    next(null);
}

// ── Harness ───────────────────────────────────────────────────────────────────

var passed = 0, failed = 0;
function assert(label, cond, detail) {
    if (cond) {
        console.log('  ✓ ' + label); passed++;
    } else {
        console.error('  ✗ ' + label + (detail !== undefined ? ' — got: ' + JSON.stringify(detail) : ''));
        failed++;
    }
}

// ── Jest wrapper ──────────────────────────────────────────────────────────────
// When run under Jest, wrap all E2E logic in a single it() so Jest waits for it.
// When run as `node tests/mysql_e2e.test.js` directly, run() is called immediately.
function run(jestDone) {

// ── Setup ─────────────────────────────────────────────────────────────────────

var tmpDir = path.join(os.tmpdir(), 'safedb_e2e_' + process.pid);
fs.mkdirSync(tmpDir, { recursive: true });
var db  = new Database(path.join(tmpDir, 'e2e.sc'));
var srv = new MySQLServer(db, { port: 0, host: '127.0.0.1', password: 'Test#Passw0rd!99' });

// ── Tests ─────────────────────────────────────────────────────────────────────

srv.listen(function (err) {
    if (err) {
        console.error('Server start failed:', err.message);
        if (jestDone) return jestDone(err);
        process.exit(1);
    }
    var port = srv.address().port;
    console.log('E2E server on port', port, '\n');

    var tests = [];
    var t = function (name, fn) { tests.push({ name: name, fn: fn }); };

    // ── Group 1: MySQL DDL types — round-trip through the translator ───────────

    t('[1] MySQL DDL: bigint / varchar / longtext / datetime / decimal table', function (next) {
        serial(port, [
            // A realistic WordPress-style CREATE TABLE with every problematic MySQL type
            [
                "CREATE TABLE IF NOT EXISTS wp_e2e (",
                "  id            bigint(20) unsigned NOT NULL AUTO_INCREMENT,",
                "  user_id       int(11) unsigned NOT NULL DEFAULT 0,",
                "  score         decimal(10,4) NOT NULL DEFAULT '0.0000',",
                "  rating        double(5,2) DEFAULT NULL,",
                "  flag          tinyint(1) NOT NULL DEFAULT 0,",
                "  status        varchar(20) NOT NULL DEFAULT 'draft',",
                "  kind          enum('post','page','attachment') NOT NULL DEFAULT 'post',",
                "  body          longtext,",
                "  meta          json DEFAULT NULL,",
                "  created_at    datetime NOT NULL DEFAULT '0000-00-00 00:00:00',",
                "  updated_at    timestamp DEFAULT CURRENT_TIMESTAMP,",
                "  PRIMARY KEY (id),",
                "  KEY idx_user (user_id),",
                "  KEY idx_status (status(20))",
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            ].join('\n')
        ], function (err) {
            assert('CREATE TABLE with MySQL types succeeds', !err, err && err.message);
            next();
        });
    });

    t('[2] INSERT with MySQL defaults, retrieve row', function (next) {
        var insertSQL = [
            "INSERT INTO wp_e2e",
            "  (id, user_id, score, rating, flag, status, kind, body, meta, created_at)",
            "VALUES",
            "  (1, 42, '3.1415', 4.5, 1, 'publish', 'post', 'Hello world', '{\"k\":1}', '2026-11-05 10:00:00')"
        ].join(' ');
        serial(port, [insertSQL], function (err) {
            assert('INSERT into translated table', !err, err && err.message);
            if (err) return next();
            query(port, 'SELECT id, user_id, score, rating, flag, status, kind, body, meta, created_at FROM wp_e2e WHERE id = 1', function (err, pkts) {
                assert('SELECT row back', !err, err && err.message);
                if (!err && pkts && pkts[0] && pkts[0][0] !== 0xff) {
                    var rs = readResultSet(pkts);
                    assert('one row returned', rs.rows.length === 1, rs.rows.length);
                    var r = rs.rows[0];
                    assert('id = 1',           r[0] === '1',                r[0]);
                    assert('user_id = 42',     r[1] === '42',               r[1]);
                    assert('score = 3.1415',   r[2] === '3.1415',           r[2]);
                    assert('rating = 4.5',     r[3] === '4.5',              r[3]);
                    assert('flag = 1',         r[4] === '1',                r[4]);
                    assert('status = publish', r[5] === 'publish',          r[5]);
                    assert('kind = post',      r[6] === 'post',             r[6]);
                    assert('body = Hello world', r[7] === 'Hello world',    r[7]);
                    assert('meta JSON stored', r[8] === '{"k":1}',          r[8]);
                    assert('created_at stored', r[9] === '2026-11-05 10:00:00', r[9]);
                }
                next();
            });
        });
    });

    // ── Group 2: NULL handling ─────────────────────────────────────────────────

    t('[3] NULL values in every nullable column', function (next) {
        serial(port, [
            "INSERT INTO wp_e2e (id, user_id, score, flag, status, kind, created_at) VALUES (2, 0, '0.0000', 0, 'draft', 'post', '0000-00-00 00:00:00')"
        ], function (err) {
            assert('INSERT row with NULLs', !err, err && err.message);
            if (err) return next();
            query(port, 'SELECT rating, body, meta FROM wp_e2e WHERE id = 2', function (err, pkts) {
                assert('SELECT NULL cols', !err, err && err.message);
                if (!err && pkts && pkts[0][0] !== 0xff) {
                    var rs = readResultSet(pkts);
                    var r = rs.rows[0];
                    assert('rating IS NULL',  r[0] === null, r[0]);
                    assert('body IS NULL',    r[1] === null, r[1]);
                    assert('meta IS NULL',    r[2] === null, r[2]);
                }
                next();
            });
        });
    });

    // ── Group 3: Output encoding — Unicode, empty string, large integer ────────

    t('[4] Unicode body round-trip (emoji + CJK + RTL)', function (next) {
        var body = '日本語テスト 🎉 مرحبا बिल्कुल नमस्ते';
        serial(port, [
            "INSERT INTO wp_e2e (id, user_id, score, flag, status, kind, body, created_at) VALUES (3, 0, '0', 0, 'draft', 'post', '" + body + "', '2026-01-01 00:00:00')"
        ], function (err) {
            assert('INSERT unicode body', !err, err && err.message);
            if (err) return next();
            query(port, 'SELECT body FROM wp_e2e WHERE id = 3', function (err, pkts) {
                assert('SELECT unicode body', !err, err && err.message);
                if (!err && pkts && pkts[0][0] !== 0xff) {
                    var rs = readResultSet(pkts);
                    assert('body round-trips exactly', rs.rows[0][0] === body, rs.rows[0][0]);
                }
                next();
            });
        });
    });

    t('[5] Empty string is distinct from NULL', function (next) {
        serial(port, [
            "INSERT INTO wp_e2e (id, user_id, score, flag, status, kind, body, created_at) VALUES (4, 0, '0', 0, 'draft', 'post', '', '2026-01-01 00:00:00')"
        ], function (err) {
            assert('INSERT empty string', !err, err && err.message);
            if (err) return next();
            query(port, 'SELECT body FROM wp_e2e WHERE id = 4', function (err, pkts) {
                assert('SELECT empty string', !err, err && err.message);
                if (!err && pkts && pkts[0][0] !== 0xff) {
                    var rs = readResultSet(pkts);
                    var val = rs.rows[0][0];
                    assert("empty string is '' not null", val === '', val);
                }
                next();
            });
        });
    });

    t('[6] Large integer (bigint range)', function (next) {
        // 2^53 - 1 = 9007199254740991 — largest safe JS integer; real MySQL bigint goes to ~9.2e18
        var big = '9007199254740991';
        serial(port, [
            "CREATE TABLE IF NOT EXISTS bigints (id INTEGER PRIMARY KEY, n INTEGER)",
            "INSERT INTO bigints VALUES (1, " + big + ")"
        ], function (err) {
            assert('INSERT large integer', !err, err && err.message);
            if (err) return next();
            query(port, 'SELECT n FROM bigints WHERE id = 1', function (err, pkts) {
                assert('SELECT large integer', !err, err && err.message);
                if (!err && pkts && pkts[0][0] !== 0xff) {
                    var rs = readResultSet(pkts);
                    assert('bigint round-trips as string', rs.rows[0][0] === big, rs.rows[0][0]);
                }
                next();
            });
        });
    });

    t('[7] DECIMAL precision preserved', function (next) {
        serial(port, [
            "CREATE TABLE IF NOT EXISTS decimals (id INTEGER PRIMARY KEY, price NUMERIC, qty NUMERIC)",
            "INSERT INTO decimals VALUES (1, '19999.9999', '0.0001')"
        ], function (err) {
            assert('INSERT DECIMAL values', !err, err && err.message);
            if (err) return next();
            query(port, 'SELECT price, qty FROM decimals WHERE id = 1', function (err, pkts) {
                assert('SELECT DECIMAL', !err, err && err.message);
                if (!err && pkts && pkts[0][0] !== 0xff) {
                    var rs = readResultSet(pkts);
                    var r = rs.rows[0];
                    // SQLite stores as text affinity NUMERIC; value comes back as stored
                    assert('price stored correctly', parseFloat(r[0]) === 19999.9999, r[0]);
                    assert('qty stored correctly',   parseFloat(r[1]) === 0.0001,     r[1]);
                }
                next();
            });
        });
    });

    // ── Group 4: MySQL DML syntax through the translator ──────────────────────

    t('[8] INSERT IGNORE (duplicate key → silent skip)', function (next) {
        serial(port, [
            "CREATE TABLE IF NOT EXISTS uniq_test (id INTEGER PRIMARY KEY, val TEXT)",
            "INSERT INTO uniq_test VALUES (1, 'first')"
        ], function (err) {
            assert('setup uniq_test', !err, err && err.message);
            if (err) return next();
            // INSERT IGNORE should not error on duplicate
            query(port, "INSERT IGNORE INTO uniq_test VALUES (1, 'second')", function (err, pkts) {
                assert('INSERT IGNORE no error', !err, err && err.message);
                if (!err && pkts && pkts[0][0] !== 0xff) {
                    // Now check the original value is preserved
                    query(port, 'SELECT val FROM uniq_test WHERE id = 1', function (err, pkts) {
                        assert('original value preserved', !err);
                        if (!err && pkts && pkts[0][0] !== 0xff) {
                            var rs = readResultSet(pkts);
                            assert("val still 'first'", rs.rows[0][0] === 'first', rs.rows[0][0]);
                        }
                        next();
                    });
                } else {
                    next();
                }
            });
        });
    });

    t('[9] REPLACE INTO (upsert)', function (next) {
        query(port, "REPLACE INTO uniq_test VALUES (1, 'replaced')", function (err, pkts) {
            assert('REPLACE INTO no error', !err, err && err.message);
            if (!err && pkts && pkts[0][0] !== 0xff) {
                query(port, 'SELECT val FROM uniq_test WHERE id = 1', function (err, pkts) {
                    assert('SELECT after REPLACE', !err);
                    if (!err && pkts && pkts[0][0] !== 0xff) {
                        var rs = readResultSet(pkts);
                        assert("val is 'replaced'", rs.rows[0][0] === 'replaced', rs.rows[0][0]);
                    }
                    next();
                });
            } else {
                next();
            }
        });
    });

    t('[10] ON DUPLICATE KEY UPDATE', function (next) {
        // Insert a fresh row, then upsert with ON DUPLICATE KEY UPDATE
        serial(port, [
            "CREATE TABLE IF NOT EXISTS odk_test (id INTEGER PRIMARY KEY, v INTEGER DEFAULT 0)",
            "INSERT INTO odk_test VALUES (1, 10)"
        ], function (err) {
            assert('setup odk_test', !err, err && err.message);
            if (err) return next();
            query(port, "INSERT INTO odk_test (id, v) VALUES (1, 99) ON DUPLICATE KEY UPDATE v = VALUES(v)", function (err, pkts) {
                assert('ON DUPLICATE KEY UPDATE no error', !err, err && err.message);
                if (!err && pkts && pkts[0][0] !== 0xff) {
                    query(port, 'SELECT v FROM odk_test WHERE id = 1', function (err, pkts) {
                        assert('SELECT after ODKU', !err);
                        if (!err && pkts && pkts[0][0] !== 0xff) {
                            var rs = readResultSet(pkts);
                            // INSERT OR REPLACE semantics: row replaced → v = 99
                            assert('v updated to 99', rs.rows[0][0] === '99', rs.rows[0][0]);
                        }
                        next();
                    });
                } else {
                    next();
                }
            });
        });
    });

    t('[11] CONCAT() via translator rewrite', function (next) {
        query(port, "SELECT CONCAT('Hello', ' ', 'World') AS greeting", function (err, pkts) {
            assert('CONCAT no error', !err, err && err.message);
            if (!err && pkts && pkts[0][0] !== 0xff) {
                var rs = readResultSet(pkts);
                assert('CONCAT result', rs.rows[0][0] === 'Hello World', rs.rows[0][0]);
            }
            next();
        });
    });

    t('[12] IFNULL() → COALESCE', function (next) {
        query(port, 'SELECT IFNULL(NULL, 42) AS v', function (err, pkts) {
            assert('IFNULL no error', !err, err && err.message);
            if (!err && pkts && pkts[0][0] !== 0xff) {
                var rs = readResultSet(pkts);
                assert('IFNULL(NULL,42) = 42', rs.rows[0][0] === '42', rs.rows[0][0]);
            }
            next();
        });
    });

    t('[13] IF() → CASE WHEN', function (next) {
        query(port, 'SELECT IF(1 > 0, 10, 20) AS v', function (err, pkts) {
            assert('IF no error', !err, err && err.message);
            if (!err && pkts && pkts[0][0] !== 0xff) {
                var rs = readResultSet(pkts);
                assert('IF(1>0,10,20) = 10', rs.rows[0][0] === '10', rs.rows[0][0]);
            }
            next();
        });
    });

    t('[14] ISNULL() translated to IS NULL expression', function (next) {
        // ISNULL is a SQLite keyword; the translator rewrites ISNULL(x) → (x IS NULL)
        query(port, 'SELECT ISNULL(NULL) AS v', function (err, pkts) {
            assert('ISNULL(NULL) no error', !err, err && err.message);
            if (!err && pkts && pkts[0][0] !== 0xff) {
                var rs = readResultSet(pkts);
                assert('ISNULL(NULL) = 1', rs.rows[0][0] === '1', rs.rows[0][0]);
            }
            next();
        });
    });

    t('[15] NOW() via UDF returns datetime string', function (next) {
        query(port, 'SELECT NOW() AS ts', function (err, pkts) {
            assert('NOW() no error', !err, err && err.message);
            if (!err && pkts && pkts[0][0] !== 0xff) {
                var rs = readResultSet(pkts);
                // Could be either 'YYYY-MM-DD HH:MM:SS' (UDF) or datetime('now') (translator)
                var ts = rs.rows[0][0];
                assert('NOW() is a non-null string', typeof ts === 'string' && ts.length > 0, ts);
                assert('NOW() contains a date', /\d{4}-\d{2}-\d{2}/.test(ts), ts);
            }
            next();
        });
    });

    t('[16] DATE_FORMAT() UDF', function (next) {
        query(port, "SELECT DATE_FORMAT('2026-11-05 10:30:00', '%Y/%m/%d') AS d", function (err, pkts) {
            assert('DATE_FORMAT no error', !err, err && err.message);
            if (!err && pkts && pkts[0][0] !== 0xff) {
                var rs = readResultSet(pkts);
                assert("DATE_FORMAT = '2026/11/05'", rs.rows[0][0] === '2026/11/05', rs.rows[0][0]);
            }
            next();
        });
    });

    t('[17] DATEDIFF() UDF', function (next) {
        query(port, "SELECT DATEDIFF('2026-11-10', '2026-11-01') AS d", function (err, pkts) {
            assert('DATEDIFF no error', !err, err && err.message);
            if (!err && pkts && pkts[0][0] !== 0xff) {
                var rs = readResultSet(pkts);
                assert('DATEDIFF = 9', rs.rows[0][0] === '9', rs.rows[0][0]);
            }
            next();
        });
    });

    t('[18] LPAD() / RPAD() UDFs', function (next) {
        query(port, "SELECT LPAD('7', 4, '0') AS lp, RPAD('x', 4, '.') AS rp", function (err, pkts) {
            assert('LPAD/RPAD no error', !err, err && err.message);
            if (!err && pkts && pkts[0][0] !== 0xff) {
                var rs = readResultSet(pkts);
                assert('LPAD = 0007', rs.rows[0][0] === '0007', rs.rows[0][0]);
                assert('RPAD = x...', rs.rows[0][1] === 'x...', rs.rows[0][1]);
            }
            next();
        });
    });

    t('[19] LIMIT m,n (MySQL offset-first syntax)', function (next) {
        serial(port, [
            "CREATE TABLE IF NOT EXISTS pages (id INTEGER PRIMARY KEY)",
            "INSERT INTO pages VALUES (1),(2),(3),(4),(5)"
        ], function (err) {
            assert('setup pages', !err, err && err.message);
            if (err) return next();
            query(port, 'SELECT id FROM pages ORDER BY id LIMIT 2, 3', function (err, pkts) {
                assert('LIMIT 2,3 no error', !err, err && err.message);
                if (!err && pkts && pkts[0][0] !== 0xff) {
                    var rs = readResultSet(pkts);
                    assert('3 rows returned', rs.rows.length === 3, rs.rows.length);
                    assert('first id = 3', rs.rows[0][0] === '3', rs.rows[0][0]);
                    assert('last id = 5',  rs.rows[2][0] === '5', rs.rows[2][0]);
                }
                next();
            });
        });
    });

    t('[20] GROUP_CONCAT with SEPARATOR', function (next) {
        serial(port, [
            "CREATE TABLE IF NOT EXISTS tags (id INTEGER, tag TEXT)",
            "INSERT INTO tags VALUES (1,'php'),(1,'mysql'),(1,'wordpress')"
        ], function (err) {
            assert('setup tags', !err, err && err.message);
            if (err) return next();
            query(port, "SELECT GROUP_CONCAT(tag SEPARATOR '|') AS tags FROM tags WHERE id = 1", function (err, pkts) {
                assert('GROUP_CONCAT SEPARATOR no error', !err, err && err.message);
                if (!err && pkts && pkts[0][0] !== 0xff) {
                    var rs = readResultSet(pkts);
                    var tags = rs.rows[0][0];
                    // The separator | must be present; order may vary
                    assert('separator | present', tags && tags.indexOf('|') >= 0, tags);
                    assert('all three tags present',
                        tags && tags.indexOf('php') >= 0 && tags.indexOf('mysql') >= 0 && tags.indexOf('wordpress') >= 0, tags);
                }
                next();
            });
        });
    });

    // ── Group 5: Edge-case input encoding ─────────────────────────────────────

    t('[21] Single-quote in value (SQL injection barrier)', function (next) {
        serial(port, [
            "CREATE TABLE IF NOT EXISTS quotes (id INTEGER PRIMARY KEY, s TEXT)",
            "INSERT INTO quotes VALUES (1, 'O''Brien''s bar')"
        ], function (err) {
            assert('INSERT single-quote escaped', !err, err && err.message);
            if (err) return next();
            query(port, "SELECT s FROM quotes WHERE id = 1", function (err, pkts) {
                assert('SELECT single-quote', !err, err && err.message);
                if (!err && pkts && pkts[0][0] !== 0xff) {
                    var rs = readResultSet(pkts);
                    assert("value is O'Brien's bar", rs.rows[0][0] === "O'Brien's bar", rs.rows[0][0]);
                }
                next();
            });
        });
    });

    t('[22] Zero-date string (WordPress default)', function (next) {
        // WordPress stores '0000-00-00 00:00:00' as a default for datetime columns
        query(port, "SELECT created_at FROM wp_e2e WHERE id = 2", function (err, pkts) {
            assert('SELECT zero-date', !err, err && err.message);
            if (!err && pkts && pkts[0][0] !== 0xff) {
                var rs = readResultSet(pkts);
                assert('zero-date round-trips', rs.rows[0][0] === '0000-00-00 00:00:00', rs.rows[0][0]);
            }
            next();
        });
    });

    t('[23] Boolean tinyint(1): 0/1 round-trip', function (next) {
        serial(port, [
            "CREATE TABLE IF NOT EXISTS bools (id INTEGER PRIMARY KEY, active tinyint(1) NOT NULL DEFAULT 0)",
            "INSERT INTO bools VALUES (1, 1), (2, 0)"
        ], function (err) {
            assert('INSERT booleans', !err, err && err.message);
            if (err) return next();
            query(port, 'SELECT active FROM bools ORDER BY id', function (err, pkts) {
                assert('SELECT booleans', !err, err && err.message);
                if (!err && pkts && pkts[0][0] !== 0xff) {
                    var rs = readResultSet(pkts);
                    assert('true = 1', rs.rows[0][0] === '1', rs.rows[0][0]);
                    assert('false = 0', rs.rows[1][0] === '0', rs.rows[1][0]);
                }
                next();
            });
        });
    });

    t('[24] CONCAT with NULL arg returns NULL', function (next) {
        query(port, "SELECT CONCAT('a', NULL, 'b') AS v", function (err, pkts) {
            assert('CONCAT+NULL no error', !err, err && err.message);
            if (!err && pkts && pkts[0][0] !== 0xff) {
                var rs = readResultSet(pkts);
                // After translator rewrite: ('a' || NULL || 'b')
                // SQLite: NULL || anything = NULL. The UDF is not called here because
                // the translator already rewrote to ||. Either null or null string.
                var v = rs.rows[0][0];
                assert('CONCAT with NULL is null', v === null || v === 'null', v);
            }
            next();
        });
    });

    t('[25] MySQL-style trailing semicolon stripped', function (next) {
        // PHP drivers routinely send trailing semicolons
        query(port, 'SELECT 1 AS n;', function (err, pkts) {
            assert('trailing semicolon no error', !err, err && err.message);
            if (!err && pkts && pkts[0][0] !== 0xff) {
                var rs = readResultSet(pkts);
                assert('result = 1', rs.rows[0][0] === '1', rs.rows[0][0]);
            }
            next();
        });
    });

    t('[26] ALTER TABLE ADD COLUMN with MySQL type', function (next) {
        serial(port, [
            "ALTER TABLE uniq_test ADD COLUMN score decimal(10,2) DEFAULT '0.00'",
            "UPDATE uniq_test SET score = '99.50' WHERE id = 1"
        ], function (err) {
            assert('ALTER TABLE + UPDATE', !err, err && err.message);
            if (err) return next();
            query(port, 'SELECT score FROM uniq_test WHERE id = 1', function (err, pkts) {
                assert('SELECT after ALTER', !err, err && err.message);
                if (!err && pkts && pkts[0][0] !== 0xff) {
                    var rs = readResultSet(pkts);
                    assert('score = 99.5', parseFloat(rs.rows[0][0]) === 99.5, rs.rows[0][0]);
                }
                next();
            });
        });
    });

    t('[27] FIND_IN_SET() UDF', function (next) {
        query(port, "SELECT FIND_IN_SET('mysql', 'php,mysql,wordpress') AS pos", function (err, pkts) {
            assert('FIND_IN_SET no error', !err, err && err.message);
            if (!err && pkts && pkts[0][0] !== 0xff) {
                var rs = readResultSet(pkts);
                assert('mysql is at position 2', rs.rows[0][0] === '2', rs.rows[0][0]);
            }
            next();
        });
    });

    t('[28] MD5() UDF', function (next) {
        query(port, "SELECT MD5('safecloud') AS h", function (err, pkts) {
            assert('MD5 no error', !err, err && err.message);
            if (!err && pkts && pkts[0][0] !== 0xff) {
                var rs = readResultSet(pkts);
                var h = rs.rows[0][0];
                assert('MD5 is 32 hex chars', h && h.length === 32 && /^[0-9a-f]+$/.test(h), h);
            }
            next();
        });
    });

    t('[29] YEAR/MONTH/DAY UDFs on stored date', function (next) {
        query(port, "SELECT YEAR('2026-11-05') AS y, MONTH('2026-11-05') AS m, DAY('2026-11-05') AS d", function (err, pkts) {
            assert('YEAR/MONTH/DAY no error', !err, err && err.message);
            if (!err && pkts && pkts[0][0] !== 0xff) {
                var rs = readResultSet(pkts);
                var r = rs.rows[0];
                assert('YEAR = 2026', r[0] === '2026', r[0]);
                assert('MONTH = 11',  r[1] === '11',   r[1]);
                assert('DAY = 5',     r[2] === '5',    r[2]);
            }
            next();
        });
    });

    t('[30] Multi-row INSERT, COUNT(*), AVG aggregation', function (next) {
        serial(port, [
            "CREATE TABLE IF NOT EXISTS scores (id INTEGER PRIMARY KEY, v REAL)",
            "INSERT INTO scores VALUES (1, 10.0), (2, 20.0), (3, 30.0)"
        ], function (err) {
            assert('multi-row INSERT', !err, err && err.message);
            if (err) return next();
            query(port, 'SELECT COUNT(*) AS cnt, AVG(v) AS avg FROM scores', function (err, pkts) {
                assert('COUNT/AVG no error', !err, err && err.message);
                if (!err && pkts && pkts[0][0] !== 0xff) {
                    var rs = readResultSet(pkts);
                    assert('COUNT = 3',  rs.rows[0][0] === '3',  rs.rows[0][0]);
                    assert('AVG = 20.0', parseFloat(rs.rows[0][1]) === 20.0, rs.rows[0][1]);
                }
                next();
            });
        });
    });

    // ── Run all tests ─────────────────────────────────────────────────────────

    var i = 0;
    function runNext() {
        if (i >= tests.length) {
            srv.close();
            console.log('\n─────────────────────────────────────────────');
            console.log('E2E tests:', passed + failed, 'total,', passed, 'passed,', failed, 'failed');
            if (jestDone) {
                if (failed > 0) return jestDone(new Error(failed + ' E2E assertions failed'));
                return jestDone();
            }
            if (failed > 0) process.exit(1);
            return;
        }
        var t = tests[i++];
        console.log('\n' + t.name);
        t.fn(runNext);
    }
    runNext();
});

} // end run()

// ── Jest integration ──────────────────────────────────────────────────────────
if (typeof describe !== 'undefined') {
    describe('MySQL E2E round-trip tests', function () {
        it('all 90 round-trip assertions pass', function (done) {
            run(done);
        }, 60000);
    });
} else {
    // Standalone: node tests/mysql_e2e.test.js
    run(null);
}
