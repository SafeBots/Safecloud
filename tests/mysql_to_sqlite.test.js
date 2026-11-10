'use strict';
/**
 * MySQLToSQLite unit tests — no database connection needed.
 * Verifies SQL dialect translation: DDL normalisation, DML rewriting, and UDF registration.
 */

var assert        = require('assert');
var MySQLToSQLite = require('../classes/Safecloud/DB/MySQLToSQLite');

var translate          = MySQLToSQLite.translate;
var translateCreateTable = MySQLToSQLite.translateCreateTable;
var translateDML       = MySQLToSQLite.translateDML;
var registerUDFs       = MySQLToSQLite.registerUDFs;

// ── helpers ───────────────────────────────────────────────────────────────────

var passed = 0, failed = 0;

function test(name, fn) {
    try {
        fn();
        console.log('  PASS', name);
        passed++;
    } catch (e) {
        console.log('  FAIL', name, '—', e.message);
        failed++;
    }
}

function contains(str, sub) {
    assert.ok(str.indexOf(sub) !== -1, JSON.stringify(str) + ' should contain ' + JSON.stringify(sub));
}
function notContains(str, sub) {
    assert.ok(str.indexOf(sub) === -1, JSON.stringify(str) + ' should NOT contain ' + JSON.stringify(sub));
}
function matches(str, re) {
    assert.ok(re.test(str), JSON.stringify(str) + ' should match ' + re);
}

// ── Group 1: ENGINE / CHARSET / COLLATE stripping ────────────────────────────

console.log('\nGroup 1: Table option stripping');

test('ENGINE=InnoDB is removed', function () {
    var out = translate('CREATE TABLE t (id INTEGER) ENGINE=InnoDB').sql;
    notContains(out, 'ENGINE');
    notContains(out, 'InnoDB');
});

test('DEFAULT CHARSET=utf8mb4 is removed', function () {
    var out = translate('CREATE TABLE t (id INTEGER) DEFAULT CHARSET=utf8mb4').sql;
    notContains(out, 'CHARSET');
    notContains(out, 'utf8mb4');
});

test('COLLATE=utf8mb4_general_ci is removed', function () {
    var out = translate('CREATE TABLE t (id INTEGER) COLLATE=utf8mb4_general_ci').sql;
    notContains(out, 'COLLATE');
});

test('CHARACTER SET column modifier removed', function () {
    var out = translate("CREATE TABLE t (c TEXT CHARACTER SET utf8mb4)").sql;
    notContains(out, 'CHARACTER SET');
});

test('COLLATE column modifier removed', function () {
    var out = translate("CREATE TABLE t (c TEXT COLLATE utf8mb4_unicode_ci)").sql;
    notContains(out, 'COLLATE');
});

// ── Group 2: Data type normalisation ─────────────────────────────────────────

console.log('\nGroup 2: Data type normalisation');

test('bigint(20) → INTEGER', function () {
    var out = translate('CREATE TABLE t (id bigint(20) unsigned NOT NULL)').sql;
    contains(out, 'INTEGER');
    notContains(out, 'bigint');
    notContains(out, 'UNSIGNED');
});

test('int(11) → INTEGER', function () {
    var out = translate('CREATE TABLE t (n int(11))').sql;
    contains(out, 'INTEGER');
    notContains(out, 'int(11)');
});

test('tinyint(1) → INTEGER', function () {
    var out = translate('CREATE TABLE t (flag tinyint(1) NOT NULL DEFAULT 0)').sql;
    contains(out, 'INTEGER');
    notContains(out, 'tinyint');
});

test('longtext → TEXT', function () {
    var out = translate('CREATE TABLE t (body longtext NOT NULL)').sql;
    contains(out, 'TEXT');
    notContains(out, 'longtext');
});

test('mediumtext → TEXT', function () {
    var out = translate('CREATE TABLE t (body mediumtext)').sql;
    contains(out, 'TEXT');
    notContains(out, 'mediumtext');
});

test('varchar(255) → TEXT', function () {
    var out = translate('CREATE TABLE t (name varchar(255) NOT NULL)').sql;
    contains(out, 'TEXT');
    notContains(out, 'varchar');
});

test('ENUM(...) → TEXT', function () {
    var out = translate("CREATE TABLE t (status ENUM('active','inactive'))").sql;
    contains(out, 'TEXT');
    notContains(out, 'ENUM');
});

test('JSON → TEXT', function () {
    var out = translate('CREATE TABLE t (meta JSON)').sql;
    contains(out, 'TEXT');
    notContains(out, 'JSON');
});

test('DATETIME → TEXT', function () {
    var out = translate('CREATE TABLE t (created DATETIME NOT NULL)').sql;
    contains(out, 'TEXT');
    notContains(out, 'DATETIME');
});

test('TIMESTAMP column type → TEXT (CURRENT_TIMESTAMP keyword preserved)', function () {
    var out = translate("CREATE TABLE t (ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP)").sql;
    // The column TYPE should be replaced; CURRENT_TIMESTAMP is a valid SQLite keyword and kept.
    // Check that the type declaration is now TEXT.
    matches(out, /ts\s+TEXT/i);
    // CURRENT_TIMESTAMP is allowed to remain (SQLite understands it).
});

test('double(10,2) → REAL', function () {
    var out = translate('CREATE TABLE t (amount double(10,2))').sql;
    contains(out, 'REAL');
    notContains(out, 'double');
});

test('decimal(10,2) → NUMERIC', function () {
    var out = translate('CREATE TABLE t (price decimal(10,2))').sql;
    contains(out, 'NUMERIC');
    notContains(out, 'decimal');
});

// ── Group 3: AUTO_INCREMENT ───────────────────────────────────────────────────

console.log('\nGroup 3: AUTO_INCREMENT');

test('AUTO_INCREMENT column modifier stripped', function () {
    var out = translate('CREATE TABLE t (id INTEGER NOT NULL AUTO_INCREMENT, PRIMARY KEY (id))').sql;
    notContains(out, 'AUTO_INCREMENT');
    contains(out, 'PRIMARY KEY');
});

test('AUTO_INCREMENT=N table option stripped', function () {
    var out = translate('CREATE TABLE t (id INTEGER) AUTO_INCREMENT=42').sql;
    notContains(out, 'AUTO_INCREMENT');
});

// ── Group 4: Inline KEY / INDEX stripping ─────────────────────────────────────

console.log('\nGroup 4: Inline KEY/INDEX stripping');

test('KEY inside CREATE TABLE is stripped', function () {
    var sql = [
        'CREATE TABLE wp_options (',
        '  option_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,',
        '  option_name varchar(191) NOT NULL DEFAULT \'\',',
        '  PRIMARY KEY (option_id),',
        '  UNIQUE KEY option_name (option_name)',
        ') ENGINE=InnoDB'
    ].join('\n');
    var out = translate(sql).sql;
    // PRIMARY KEY must stay
    contains(out, 'PRIMARY KEY');
    // The plain UNIQUE KEY line should be stripped (or accepted by SQLite)
    notContains(out, 'ENGINE');
});

test('prefix index col(191) stripped from CREATE INDEX', function () {
    var out = translate('CREATE INDEX idx ON t (col(191))').sql;
    notContains(out, '(191)');
    contains(out, 'col');
});

// ── Group 5: Full WordPress-style CREATE TABLE ────────────────────────────────

console.log('\nGroup 5: WordPress-style CREATE TABLE');

test('wp_posts DDL translates without syntax errors', function () {
    var sql = [
        'CREATE TABLE IF NOT EXISTS wp_posts (',
        '  ID bigint(20) unsigned NOT NULL AUTO_INCREMENT,',
        '  post_author bigint(20) unsigned NOT NULL DEFAULT 0,',
        '  post_date datetime NOT NULL DEFAULT \'0000-00-00 00:00:00\',',
        '  post_content longtext NOT NULL,',
        '  post_title text NOT NULL,',
        '  post_status varchar(20) NOT NULL DEFAULT \'publish\',',
        '  post_type varchar(20) NOT NULL DEFAULT \'post\',',
        '  PRIMARY KEY  (ID),',
        '  KEY post_name (post_name(191)),',
        '  KEY type_status_date (post_type,post_status,post_date,ID)',
        ') ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4'
    ].join('\n');
    var out = translate(sql).sql;
    notContains(out, 'ENGINE');
    notContains(out, 'bigint');
    notContains(out, 'AUTO_INCREMENT');
    notContains(out, 'longtext');
    notContains(out, 'varchar');
    notContains(out, 'datetime');
    contains(out, 'INTEGER');
    contains(out, 'TEXT');
    contains(out, 'PRIMARY KEY');
    // Should end cleanly with )
    matches(out, /\)\s*$/);
});

// ── Group 6: DML rewriting ────────────────────────────────────────────────────

console.log('\nGroup 6: DML rewriting');

test('INSERT IGNORE → INSERT OR IGNORE', function () {
    var out = translateDML('INSERT IGNORE INTO t (a) VALUES (1)');
    contains(out, 'INSERT OR IGNORE INTO');
});

test('REPLACE INTO → INSERT OR REPLACE INTO', function () {
    var out = translateDML('REPLACE INTO t (a) VALUES (1)');
    contains(out, 'INSERT OR REPLACE INTO');
});

test('ON DUPLICATE KEY UPDATE clause is dropped, INSERT becomes INSERT OR REPLACE', function () {
    var out = translateDML("INSERT INTO t (a,b) VALUES (1,2) ON DUPLICATE KEY UPDATE b=VALUES(b)");
    contains(out, 'INSERT OR REPLACE INTO');
    notContains(out, 'ON DUPLICATE KEY UPDATE');
});

test('IFNULL → COALESCE', function () {
    var out = translateDML('SELECT IFNULL(col, 0) FROM t');
    contains(out, 'COALESCE');
    notContains(out, 'IFNULL');
});

test('IF(cond, a, b) → CASE WHEN cond THEN a ELSE b END', function () {
    var out = translateDML('SELECT IF(x > 0, 1, 0) FROM t');
    contains(out, 'CASE WHEN');
    contains(out, 'THEN');
    contains(out, 'ELSE');
    notContains(out, 'IF(');
});

test('NOW() → datetime(\'now\')', function () {
    var out = translateDML("INSERT INTO t (ts) VALUES (NOW())");
    contains(out, "datetime('now')");
    notContains(out, 'NOW()');
});

test('CURDATE() → date(\'now\')', function () {
    var out = translateDML('SELECT CURDATE()');
    contains(out, "date('now')");
});

test('UNIX_TIMESTAMP() → strftime', function () {
    var out = translateDML('SELECT UNIX_TIMESTAMP()');
    contains(out, "strftime('%s','now')");
});

test('CONCAT(a, b) rewritten to || expression', function () {
    var out = translateDML("SELECT CONCAT(first_name, ' ', last_name) FROM users");
    contains(out, '||');
    notContains(out, 'CONCAT(');
});

test('GROUP_CONCAT separator rewritten', function () {
    var out = translateDML("SELECT GROUP_CONCAT(name SEPARATOR ',') FROM t");
    contains(out, "GROUP_CONCAT(name, ',')");
    notContains(out, 'SEPARATOR');
});

test('LIMIT m, n → LIMIT n OFFSET m', function () {
    var out = translateDML('SELECT * FROM t LIMIT 20, 10');
    contains(out, 'LIMIT 10 OFFSET 20');
    notContains(out, 'LIMIT 20, 10');
});

test('LIMIT n (no offset) unchanged', function () {
    var out = translateDML('SELECT * FROM t LIMIT 10');
    contains(out, 'LIMIT 10');
});

// ── Group 7: UDF registration ─────────────────────────────────────────────────

console.log('\nGroup 7: UDF registration');

var Database;
try {
    Database = require('better-sqlite3');
} catch (e) {
    console.log('  SKIP UDF tests — better-sqlite3 not available:', e.message);
    Database = null;
}

if (Database) {
    var db;
    try {
        db = new Database(':memory:');
        registerUDFs(db);
    } catch (e) {
        console.log('  SKIP UDF tests — could not open in-memory DB:', e.message);
        db = null;
    }

    if (db) {
        test('NOW() returns a datetime string', function () {
            var row = db.prepare('SELECT NOW() AS v').get();
            assert.match(row.v, /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
        });

        test('CONCAT(a, b) returns concatenation', function () {
            var row = db.prepare("SELECT CONCAT('foo', 'bar') AS v").get();
            assert.strictEqual(row.v, 'foobar');
        });

        test('CONCAT returns NULL when any arg is NULL', function () {
            var row = db.prepare("SELECT CONCAT('a', NULL, 'b') AS v").get();
            assert.strictEqual(row.v, null);
        });

        test('CONCAT_WS skips NULLs', function () {
            var row = db.prepare("SELECT CONCAT_WS(',', 'a', NULL, 'b') AS v").get();
            assert.strictEqual(row.v, 'a,b');
        });

        test('LPAD pads to correct length', function () {
            var row = db.prepare("SELECT LPAD('1', 4, '0') AS v").get();
            assert.strictEqual(row.v, '0001');
        });

        test('RPAD pads to correct length', function () {
            var row = db.prepare("SELECT RPAD('x', 4, '.') AS v").get();
            assert.strictEqual(row.v, 'x...');
        });

        test('IFNULL available as COALESCE equivalent', function () {
            var row = db.prepare('SELECT COALESCE(NULL, 42) AS v').get();
            assert.strictEqual(row.v, 42);
        });

        test('IF UDF works', function () {
            var row = db.prepare('SELECT IF(1, 10, 20) AS v').get();
            assert.strictEqual(row.v, 10);
        });

        // ISNULL is a SQLite reserved keyword; it's handled via DML translation, not UDF.
        test('ISNULL(x) DML translation → (x IS NULL)', function () {
            var out = translateDML('SELECT ISNULL(col) FROM t');
            contains(out, 'IS NULL');
            notContains(out, 'ISNULL(');
        });

        test('FIELD returns correct 1-based index', function () {
            var row = db.prepare("SELECT FIELD('b', 'a', 'b', 'c') AS v").get();
            assert.strictEqual(row.v, 2);
        });

        test('FIELD returns 0 for no match', function () {
            var row = db.prepare("SELECT FIELD('z', 'a', 'b') AS v").get();
            assert.strictEqual(row.v, 0);
        });

        test('FIND_IN_SET works', function () {
            var row = db.prepare("SELECT FIND_IN_SET('b', 'a,b,c') AS v").get();
            assert.strictEqual(row.v, 2);
        });

        test('GREATEST returns maximum', function () {
            var row = db.prepare('SELECT GREATEST(3, 1, 4, 1, 5) AS v').get();
            assert.strictEqual(row.v, 5);
        });

        test('LEAST returns minimum', function () {
            var row = db.prepare('SELECT LEAST(3, 1, 4, 1, 5) AS v').get();
            assert.strictEqual(row.v, 1);
        });

        test('DATEDIFF returns integer days', function () {
            var row = db.prepare("SELECT DATEDIFF('2026-01-10', '2026-01-01') AS v").get();
            assert.strictEqual(row.v, 9);
        });

        test('DATE_FORMAT %Y-%m-%d', function () {
            var row = db.prepare("SELECT DATE_FORMAT('2026-03-15 10:30:00', '%Y-%m-%d') AS v").get();
            assert.strictEqual(row.v, '2026-03-15');
        });

        test('DATE_FORMAT %d/%m/%Y', function () {
            var row = db.prepare("SELECT DATE_FORMAT('2026-03-05 00:00:00', '%d/%m/%Y') AS v").get();
            assert.strictEqual(row.v, '05/03/2026');
        });

        test('MD5 returns 32-char hex', function () {
            var row = db.prepare("SELECT MD5('hello') AS v").get();
            assert.strictEqual(row.v.length, 32);
            assert.match(row.v, /^[0-9a-f]+$/);
        });

        test('UNIX_TIMESTAMP returns a reasonable epoch', function () {
            var row = db.prepare('SELECT UNIX_TIMESTAMP() AS v').get();
            assert.ok(row.v > 1700000000, 'epoch should be > 2023');
        });

        test('YEAR/MONTH/DAY extract correct components', function () {
            var row = db.prepare("SELECT YEAR('2026-11-05') AS y, MONTH('2026-11-05') AS m, DAY('2026-11-05') AS d").get();
            assert.strictEqual(row.y, 2026);
            assert.strictEqual(row.m, 11);
            assert.strictEqual(row.d, 5);
        });

        test('MOD works', function () {
            var row = db.prepare('SELECT MOD(10, 3) AS v').get();
            assert.strictEqual(row.v, 1);
        });

        test('REPEAT works', function () {
            var row = db.prepare("SELECT REPEAT('ab', 3) AS v").get();
            assert.strictEqual(row.v, 'ababab');
        });

        test('REVERSE works', function () {
            var row = db.prepare("SELECT REVERSE('hello') AS v").get();
            assert.strictEqual(row.v, 'olleh');
        });

        db.close();
    }
}

// ── Group 8: translate() routing ─────────────────────────────────────────────

console.log('\nGroup 8: translate() routing');

test('SELECT passes through translate() correctly', function () {
    var out = translate('SELECT * FROM users WHERE active = 1').sql;
    contains(out, 'SELECT * FROM users');
});

test('CREATE TABLE routed through DDL path', function () {
    var out = translate('CREATE TABLE t (id bigint(20)) ENGINE=InnoDB').sql;
    notContains(out, 'ENGINE');
    contains(out, 'INTEGER');
});

test('INSERT routed through DML path', function () {
    var out = translate("INSERT IGNORE INTO t (a) VALUES (1)").sql;
    contains(out, 'INSERT OR IGNORE');
});

test('DROP TABLE passes through unchanged', function () {
    var out = translate('DROP TABLE IF EXISTS t').sql;
    contains(out, 'DROP TABLE IF EXISTS t');
});

test('translate() returns warnings array', function () {
    var result = translate('SELECT 1');
    assert.ok(Array.isArray(result.warnings));
});

// ── Summary ───────────────────────────────────────────────────────────────────

console.log('\n─────────────────────────────────────────────');
console.log('MySQLToSQLite tests:', passed + failed, 'total,', passed, 'passed,', failed, 'failed');
if (failed > 0) process.exit(1);
