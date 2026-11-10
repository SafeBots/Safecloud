'use strict';
/**
 * MySQLToSQLite — translates MySQL SQL dialect to SQLite-compatible SQL.
 *
 * Two entry points:
 *
 *   MySQLToSQLite.translate(sql)       → { sql, warnings[] }
 *   MySQLToSQLite.registerUDFs(db)     → registers MySQL scalar functions on a
 *                                        better-sqlite3 Database instance so that
 *                                        translated queries that still call NOW(),
 *                                        CONCAT(), etc. work without further rewriting.
 *
 * Translation happens in two passes:
 *   Pass 1 — DDL  (CREATE TABLE / ALTER TABLE / CREATE INDEX)
 *             String-level regex; MySQL DDL patterns are mechanical and well-defined.
 *   Pass 2 — DML  (SELECT / INSERT / UPDATE / DELETE)
 *             String-level for the common patterns WordPress / ORMs emit.
 *             Complex expressions (nested IF, DATE_FORMAT deep in subqueries) are
 *             handled by the registered UDFs, not by rewriting.
 *
 * Design decisions:
 *   - No external parser dependency; works from a bare Node.js install.
 *   - Rewriting is conservative: when a pattern is not recognised we leave the
 *     SQL unchanged and let the engine surface the error — better than silently
 *     mangling a query.
 *   - UDFs registered here shadow any built-in SQLite function with the same name,
 *     but SQLite has no NOW(), DATE_FORMAT(), LPAD(), etc., so there is no conflict.
 */

// ─── DDL translation ──────────────────────────────────────────────────────────

/**
 * Translate a CREATE TABLE statement from MySQL dialect to SQLite dialect.
 * Returns the translated string.
 */
function translateCreateTable(sql) {
    // 1. Remove table-level options that SQLite does not understand
    //    ENGINE=InnoDB, DEFAULT CHARSET=utf8mb4, COLLATE=..., ROW_FORMAT=...,
    //    AUTO_INCREMENT=N (table-level, not column-level), COMMENT='...',
    //    KEY_BLOCK_SIZE=N, STATS_PERSISTENT=N
    sql = sql.replace(/\bENGINE\s*=\s*\w+/gi, '');
    sql = sql.replace(/\bDEFAULT\s+CHARSET\s*=\s*[\w-]+/gi, '');
    sql = sql.replace(/\bCHARSET\s*=\s*[\w-]+/gi, '');
    sql = sql.replace(/\bCHARACTER\s+SET\s*=?\s*[\w-]+/gi, '');
    sql = sql.replace(/\bCOLLATE\s*=\s*[\w-]+/gi, '');
    sql = sql.replace(/\bROW_FORMAT\s*=\s*\w+/gi, '');
    sql = sql.replace(/\bKEY_BLOCK_SIZE\s*=\s*\d+/gi, '');
    sql = sql.replace(/\bSTATS_PERSISTENT\s*=\s*\d+/gi, '');
    sql = sql.replace(/\bSTATS_AUTO_RECALC\s*=\s*\d+/gi, '');
    sql = sql.replace(/\bAUTO_INCREMENT\s*=\s*\d+/gi, '');
    sql = sql.replace(/\bCOMMENT\s*=\s*'(?:[^'\\]|\\.)*'/gi, '');
    sql = sql.replace(/\bCOMMENT\s*=\s*"(?:[^"\\]|\\.)*"/gi, '');
    sql = sql.replace(/\bPACK_KEYS\s*=\s*\d+/gi, '');
    sql = sql.replace(/\bDELAY_KEY_WRITE\s*=\s*\d+/gi, '');

    // 2. Column-level character set / collation
    sql = sql.replace(/\bCHARACTER\s+SET\s+[\w-]+/gi, '');
    sql = sql.replace(/\bCOLLATE\s+[\w-]+/gi, '');

    // 3. Column-level COMMENT '...'
    sql = sql.replace(/\bCOMMENT\s+'(?:[^'\\]|\\.)*'/gi, '');
    sql = sql.replace(/\bCOMMENT\s+"(?:[^"\\]|\\.)*"/gi, '');

    // 4. Data type normalisation
    //    MySQL integers with display width: bigint(20), int(11), tinyint(1) → INTEGER
    sql = sql.replace(/\b(BIGINT|MEDIUMINT|SMALLINT|TINYINT|INT)\s*\(\s*\d+\s*\)/gi, 'INTEGER');
    sql = sql.replace(/\bBIGINT\b/gi, 'INTEGER');
    sql = sql.replace(/\bMEDIUMINT\b/gi, 'INTEGER');
    sql = sql.replace(/\bSMALLINT\b/gi, 'INTEGER');
    sql = sql.replace(/\bTINYINT\b/gi, 'INTEGER');
    //    UNSIGNED — SQLite has no unsigned; just strip the qualifier
    sql = sql.replace(/\bUNSIGNED\b/gi, '');
    //    FLOAT(m,d) / DOUBLE(m,d) — SQLite REAL is fine; strip precision
    sql = sql.replace(/\b(FLOAT|DOUBLE(?:\s+PRECISION)?)\s*\(\s*\d+\s*,\s*\d+\s*\)/gi, 'REAL');
    sql = sql.replace(/\bDOUBLE(?:\s+PRECISION)?\b/gi, 'REAL');
    sql = sql.replace(/\bFLOAT\b/gi, 'REAL');
    //    DECIMAL(m,d) / NUMERIC(m,d) — SQLite stores as NUMERIC (affinity); keep name, strip width
    sql = sql.replace(/\b(DECIMAL|NUMERIC)\s*\(\s*\d+\s*(?:,\s*\d+\s*)?\)/gi, 'NUMERIC');
    //    String types
    sql = sql.replace(/\bLONGTEXT\b/gi, 'TEXT');
    sql = sql.replace(/\bMEDIUMTEXT\b/gi, 'TEXT');
    sql = sql.replace(/\bTINYTEXT\b/gi, 'TEXT');
    sql = sql.replace(/\bLONGBLOB\b/gi, 'BLOB');
    sql = sql.replace(/\bMEDIUMBLOB\b/gi, 'BLOB');
    sql = sql.replace(/\bTINYBLOB\b/gi, 'BLOB');
    //    VARCHAR(n) → TEXT (SQLite TEXT has no length limit; the limit is cosmetic in MySQL)
    //    We keep it as TEXT so SQLite won't reject anything.
    sql = sql.replace(/\bVARCHAR\s*\(\s*\d+\s*\)/gi, 'TEXT');
    sql = sql.replace(/\bCHAR\s*\(\s*\d+\s*\)/gi, 'TEXT');
    //    BINARY / VARBINARY
    sql = sql.replace(/\bVARBINARY\s*\(\s*\d+\s*\)/gi, 'BLOB');
    sql = sql.replace(/\bBINARY\s*\(\s*\d+\s*\)/gi, 'BLOB');
    //    ENUM / SET → TEXT
    sql = sql.replace(/\bENUM\s*\([^)]+\)/gi, 'TEXT');
    sql = sql.replace(/\bSET\s*\([^)]+\)/gi, 'TEXT');
    //    DATETIME / TIMESTAMP → TEXT (SQLite has no native datetime type)
    //    We keep the name so the affinity is NUMERIC (a SQLite affinity rule),
    //    which is fine for ISO-8601 strings.  But MySQL TIMESTAMP(6) needs stripping.
    sql = sql.replace(/\b(DATETIME|TIMESTAMP)\s*\(\s*\d+\s*\)/gi, 'TEXT');
    sql = sql.replace(/\bTIMESTAMP\b/gi, 'TEXT');
    sql = sql.replace(/\bDATETIME\b/gi, 'TEXT');
    sql = sql.replace(/\bDATE\b/gi, 'TEXT');
    sql = sql.replace(/\bTIME\b/gi, 'TEXT');
    sql = sql.replace(/\bYEAR\b/gi, 'INTEGER');
    //    MySQL JSON type → TEXT
    sql = sql.replace(/\bJSON\b/gi, 'TEXT');

    // 5. AUTO_INCREMENT column modifier → (nothing; INTEGER PRIMARY KEY in SQLite
    //    is implicitly autoincrement via rowid aliasing)
    sql = sql.replace(/\bAUTO_INCREMENT\b/gi, '');

    // 6. Index definitions inside CREATE TABLE body
    //    MySQL allows KEY/INDEX/UNIQUE KEY inside the table body; SQLite does not.
    //    Strategy: remove them from the CREATE TABLE body entirely.
    //    PRIMARY KEY (...) is kept — SQLite understands it.

    //    6a. Strip prefix lengths from column specs before the KEY-stripping regex
    //        so that KEY idx (col(191)) becomes KEY idx (col) and matches cleanly.
    //        We've already replaced all type specs (INT(11), VARCHAR(n), etc.) above,
    //        so the only remaining col(N) patterns are inside KEY column lists.
    sql = sql.replace(/(`?\w+`?)\s*\(\s*\d+\s*\)/g, '$1');

    //    6b. Remove standalone KEY/INDEX lines.
    //        Require a named index (\w+ after KEY) so that PRIMARY KEY (col)
    //        — which has no name between KEY and ( — is NOT matched and preserved.
    sql = sql.replace(/,?\s*(?:(?:UNIQUE|FULLTEXT|SPATIAL)\s+)?(?:KEY|INDEX)\s+`?\w+`?\s*\([^)]+\)/gi, '');

    // Also handle CONSTRAINT ... FOREIGN KEY ... REFERENCES ... — SQLite parses but ignores FK
    // constraints; just leave them as-is for now (they're syntactically valid).

    // 7. IF NOT EXISTS — keep it; SQLite supports it.

    // 8. Clean up multiple trailing commas before the closing paren that result
    //    from stripping KEY lines. E.g. "col1 TEXT, , )" → "col1 TEXT)"
    //    This is the tricky part: we need to collapse repeated commas and remove
    //    a trailing comma just before the closing ")".
    //    We do several passes to handle the worst cases.
    var prev;
    do {
        prev = sql;
        sql = sql.replace(/,\s*,/g, ',');
    } while (sql !== prev);
    sql = sql.replace(/,\s*\)/g, ')');

    // 9. Strip stray trailing whitespace tokens left after replacements
    sql = sql.replace(/\s{2,}/g, ' ');
    sql = sql.replace(/\(\s+/g, '(');
    sql = sql.replace(/\s+\)/g, ')');

    return sql.trim();
}

/**
 * Translate a CREATE INDEX statement.
 * Handles prefix indexes: col(191) → col  (SQLite doesn't support prefix indexes)
 */
function translateCreateIndex(sql) {
    // Strip prefix lengths from indexed columns: `col`(191) → `col`
    sql = sql.replace(/(`?\w+`?)\s*\(\s*\d+\s*\)/g, '$1');
    return sql.trim();
}

/**
 * Translate an ALTER TABLE statement.
 * Most ALTER TABLE clauses that WordPress / migrations use can be passed through;
 * we strip the MySQL-specific ones.
 */
function translateAlterTable(sql) {
    // ALTER TABLE ... ENGINE=... — strip the ENGINE clause
    sql = sql.replace(/\bENGINE\s*=\s*\w+/gi, '');
    // ALTER TABLE ... DEFAULT CHARSET / CHARACTER SET
    sql = sql.replace(/\bDEFAULT\s+CHARSET\s*=\s*[\w-]+/gi, '');
    sql = sql.replace(/\bCHARACTER\s+SET\s*=?\s*[\w-]+/gi, '');
    sql = sql.replace(/\bCOLLATE\s*=?\s*[\w-]+/gi, '');
    // ALTER TABLE ... ADD INDEX ... / ADD KEY ... — prefix indexes
    sql = sql.replace(/(`?\w+`?)\s*\(\s*\d+\s*\)/g, '$1');
    // Data types in ADD COLUMN / MODIFY COLUMN
    sql = applyColumnTypeFixes(sql);
    sql = sql.replace(/\s{2,}/g, ' ');
    return sql.trim();
}

/** Apply the same column-type normalisation used in CREATE TABLE to any SQL fragment. */
function applyColumnTypeFixes(sql) {
    sql = sql.replace(/\b(BIGINT|MEDIUMINT|SMALLINT|TINYINT|INT)\s*\(\s*\d+\s*\)/gi, 'INTEGER');
    sql = sql.replace(/\bBIGINT\b/gi, 'INTEGER');
    sql = sql.replace(/\bMEDIUMINT\b/gi, 'INTEGER');
    sql = sql.replace(/\bSMALLINT\b/gi, 'INTEGER');
    sql = sql.replace(/\bTINYINT\b/gi, 'INTEGER');
    sql = sql.replace(/\bUNSIGNED\b/gi, '');
    sql = sql.replace(/\b(FLOAT|DOUBLE(?:\s+PRECISION)?)\s*\(\s*\d+\s*,\s*\d+\s*\)/gi, 'REAL');
    sql = sql.replace(/\bDOUBLE(?:\s+PRECISION)?\b/gi, 'REAL');
    sql = sql.replace(/\bFLOAT\b/gi, 'REAL');
    sql = sql.replace(/\b(DECIMAL|NUMERIC)\s*\(\s*\d+\s*(?:,\s*\d+\s*)?\)/gi, 'NUMERIC');
    sql = sql.replace(/\bLONGTEXT\b/gi, 'TEXT');
    sql = sql.replace(/\bMEDIUMTEXT\b/gi, 'TEXT');
    sql = sql.replace(/\bTINYTEXT\b/gi, 'TEXT');
    sql = sql.replace(/\bLONGBLOB\b/gi, 'BLOB');
    sql = sql.replace(/\bMEDIUMBLOB\b/gi, 'BLOB');
    sql = sql.replace(/\bTINYBLOB\b/gi, 'BLOB');
    sql = sql.replace(/\bVARCHAR\s*\(\s*\d+\s*\)/gi, 'TEXT');
    sql = sql.replace(/\bCHAR\s*\(\s*\d+\s*\)/gi, 'TEXT');
    sql = sql.replace(/\bVARBINARY\s*\(\s*\d+\s*\)/gi, 'BLOB');
    sql = sql.replace(/\bBINARY\s*\(\s*\d+\s*\)/gi, 'BLOB');
    sql = sql.replace(/\bENUM\s*\([^)]+\)/gi, 'TEXT');
    sql = sql.replace(/\bSET\s*\([^)]+\)/gi, 'TEXT');
    sql = sql.replace(/\b(DATETIME|TIMESTAMP)\s*\(\s*\d+\s*\)/gi, 'TEXT');
    sql = sql.replace(/\bTIMESTAMP\b/gi, 'TEXT');
    sql = sql.replace(/\bDATETIME\b/gi, 'TEXT');
    sql = sql.replace(/\bDATE\b/gi, 'TEXT');
    sql = sql.replace(/\bTIME\b/gi, 'TEXT');
    sql = sql.replace(/\bYEAR\b/gi, 'INTEGER');
    sql = sql.replace(/\bJSON\b/gi, 'TEXT');
    sql = sql.replace(/\bAUTO_INCREMENT\b/gi, '');
    sql = sql.replace(/\bCHARACTER\s+SET\s+[\w-]+/gi, '');
    sql = sql.replace(/\bCOLLATE\s+[\w-]+/gi, '');
    return sql;
}

// ─── DML translation ──────────────────────────────────────────────────────────

/**
 * Translate DML (SELECT / INSERT / UPDATE / DELETE) from MySQL dialect to SQLite.
 * Returns the translated string.
 *
 * We handle the most common patterns emitted by WordPress / Eloquent / SQLAlchemy.
 * Complex expressions are deferred to the UDFs registered via registerUDFs().
 */
function translateDML(sql) {
    // 1. ON DUPLICATE KEY UPDATE → INSERT OR REPLACE
    //    MySQL:  INSERT INTO t (a,b) VALUES (1,2) ON DUPLICATE KEY UPDATE b=VALUES(b)
    //    SQLite: INSERT OR REPLACE INTO t (a,b) VALUES (1,2)
    //    We drop the ON DUPLICATE KEY UPDATE clause; the INSERT OR REPLACE semantics
    //    delete-then-insert, which is the same net effect for single-unique-key cases.
    if (/\bON\s+DUPLICATE\s+KEY\s+UPDATE\b/i.test(sql)) {
        sql = sql.replace(/\bINSERT\s+(?:IGNORE\s+)?INTO\b/i, 'INSERT OR REPLACE INTO');
        sql = sql.replace(/\bON\s+DUPLICATE\s+KEY\s+UPDATE\b[\s\S]*/i, '');
    }

    // 2. INSERT IGNORE → INSERT OR IGNORE
    sql = sql.replace(/\bINSERT\s+IGNORE\s+INTO\b/i, 'INSERT OR IGNORE INTO');

    // 3. REPLACE INTO → INSERT OR REPLACE INTO  (MySQL REPLACE is a MySQL-ism)
    sql = sql.replace(/\bREPLACE\s+INTO\b/i, 'INSERT OR REPLACE INTO');

    // 4. CONCAT(a, b, c) → (a || b || c)
    //    Single-level only; nested CONCAT is handled by the UDF.
    sql = sql.replace(/\bCONCAT\s*\(([^()]+)\)/gi, function (_, args) {
        // Split on commas that are not inside quotes — rough heuristic
        var parts = splitArgs(args);
        return '(' + parts.join(' || ') + ')';
    });

    // 5. IFNULL(a, b) → COALESCE(a, b)  — SQLite has COALESCE natively
    sql = sql.replace(/\bIFNULL\s*\(/gi, 'COALESCE(');

    // 5a. ISNULL(x) → (x IS NULL)
    //     ISNULL is a reserved keyword in SQLite (used as a postfix operator),
    //     so it cannot be registered as a UDF; we rewrite it here instead.
    sql = sql.replace(/\bISNULL\s*\(([^)]+)\)/gi, function (_, x) {
        return '(' + x.trim() + ' IS NULL)';
    });

    // 6. IF(cond, a, b) → CASE WHEN cond THEN a ELSE b END
    //    Single-level only (no nested IF).
    sql = sql.replace(/\bIF\s*\(([^()]+),([^()]+),([^()]+)\)/gi, function (_, cond, a, b) {
        return 'CASE WHEN ' + cond.trim() + ' THEN ' + a.trim() + ' ELSE ' + b.trim() + ' END';
    });

    // 7. NOW() / SYSDATE() / CURRENT_TIMESTAMP() → datetime('now')
    sql = sql.replace(/\b(?:NOW|SYSDATE)\s*\(\s*\)/gi, "datetime('now')");
    sql = sql.replace(/\bCURRENT_TIMESTAMP\s*\(\s*\)/gi, "datetime('now')");

    // 8. CURDATE() / CURRENT_DATE() → date('now')
    sql = sql.replace(/\b(?:CURDATE|CURRENT_DATE)\s*\(\s*\)/gi, "date('now')");

    // 9. CURTIME() / CURRENT_TIME() → time('now')
    sql = sql.replace(/\b(?:CURTIME|CURRENT_TIME)\s*\(\s*\)/gi, "time('now')");

    // 10. UNIX_TIMESTAMP() → strftime('%s', 'now')
    sql = sql.replace(/\bUNIX_TIMESTAMP\s*\(\s*\)/gi, "strftime('%s','now')");
    // UNIX_TIMESTAMP(expr) — left for UDF

    // 11. GROUP_CONCAT separator syntax
    //     MySQL: GROUP_CONCAT(col ORDER BY col SEPARATOR ',')
    //     SQLite: GROUP_CONCAT(col, ',')
    sql = sql.replace(/\bGROUP_CONCAT\s*\(([^)]+?)\s+SEPARATOR\s+'([^']*)'\s*\)/gi,
        function (_, expr, sep) {
            // Drop ORDER BY clause inside GROUP_CONCAT — SQLite doesn't support it
            expr = expr.replace(/\s+ORDER\s+BY\s+[\w`,.\s]+/gi, '').trim();
            return 'GROUP_CONCAT(' + expr + ", '" + sep + "')";
        });
    // Also strip ORDER BY without SEPARATOR
    sql = sql.replace(/\bGROUP_CONCAT\s*\(([^)]+?)\s+ORDER\s+BY\s+[\w`,.\s]+\)/gi,
        function (_, expr) {
            expr = expr.trim();
            return 'GROUP_CONCAT(' + expr + ')';
        });

    // 12. FIELD(val, v1, v2, ...) — no built-in equivalent; leave for UDF

    // 13. `col` backtick quoting — SQLite accepts both backticks and double-quotes.
    //     SQLite actually accepts MySQL backtick quoting natively, so no change needed.

    // 14. LIMIT m, n  →  LIMIT n OFFSET m  (MySQL allows both syntaxes)
    sql = sql.replace(/\bLIMIT\s+(\d+)\s*,\s*(\d+)\b/gi, 'LIMIT $2 OFFSET $1');

    return sql.trim();
}

/** Rough comma-split that respects single-quoted strings. */
function splitArgs(str) {
    var parts = [];
    var depth = 0, start = 0, inStr = false, strChar = '';
    for (var i = 0; i < str.length; i++) {
        var c = str[i];
        if (inStr) {
            if (c === strChar && str[i - 1] !== '\\') inStr = false;
        } else if (c === "'" || c === '"') {
            inStr = true; strChar = c;
        } else if (c === '(') {
            depth++;
        } else if (c === ')') {
            depth--;
        } else if (c === ',' && depth === 0) {
            parts.push(str.slice(start, i).trim());
            start = i + 1;
        }
    }
    parts.push(str.slice(start).trim());
    return parts;
}

// ─── Top-level translate() ────────────────────────────────────────────────────

/**
 * Translate a single SQL statement.
 *
 * @param  {string} sql
 * @returns {{ sql: string, warnings: string[] }}
 */
function translate(sql) {
    var warnings = [];
    var upper = sql.replace(/\/\*[\s\S]*?\*\//g, '').trim().toUpperCase();

    if (/^CREATE\s+(TEMPORARY\s+)?TABLE\b/i.test(upper)) {
        sql = translateCreateTable(sql);
    } else if (/^CREATE\s+(UNIQUE\s+)?(FULLTEXT\s+)?(SPATIAL\s+)?INDEX\b/i.test(upper)) {
        sql = translateCreateIndex(sql);
    } else if (/^ALTER\s+TABLE\b/i.test(upper)) {
        sql = translateAlterTable(sql);
    } else if (/^(SELECT|INSERT|UPDATE|DELETE|REPLACE|WITH)\b/i.test(upper)) {
        sql = translateDML(sql);
    }
    // DDL we don't recognise (DROP TABLE, etc.) and other statements pass through unchanged.

    return { sql: sql, warnings: warnings };
}

// ─── UDF registration ─────────────────────────────────────────────────────────

/**
 * Register MySQL scalar functions on a better-sqlite3 Database instance.
 * Call once after opening the database, before running any queries.
 *
 * @param {import('better-sqlite3').Database} db
 */
function registerUDFs(db) {
    // ── String functions ──────────────────────────────────────────────────────

    // CONCAT(a, b, ...) — MySQL CONCAT returns NULL if any arg is NULL
    db.function('CONCAT', { varargs: true }, function () {
        for (var i = 0; i < arguments.length; i++) {
            if (arguments[i] === null) return null;
        }
        return Array.prototype.join.call(arguments, '');
    });

    // CONCAT_WS(sep, a, b, ...) — skips NULLs
    db.function('CONCAT_WS', { varargs: true }, function () {
        var sep = arguments[0];
        if (sep === null) return null;
        var parts = [];
        for (var i = 1; i < arguments.length; i++) {
            if (arguments[i] !== null) parts.push(String(arguments[i]));
        }
        return parts.join(String(sep));
    });

    // LPAD(str, len, pad)
    db.function('LPAD', function (str, len, pad) {
        if (str === null) return null;
        str = String(str); pad = String(pad || ' ');
        while (str.length < len) str = pad + str;
        return str.slice(-len);
    });

    // RPAD(str, len, pad)
    db.function('RPAD', function (str, len, pad) {
        if (str === null) return null;
        str = String(str); pad = String(pad || ' ');
        while (str.length < len) str = str + pad;
        return str.slice(0, len);
    });

    // LEFT(str, n)
    db.function('LEFT', function (str, n) {
        if (str === null) return null;
        return String(str).slice(0, n);
    });

    // RIGHT(str, n)
    db.function('RIGHT', function (str, n) {
        if (str === null) return null;
        var s = String(str);
        return s.slice(Math.max(0, s.length - n));
    });

    // FIELD(val, v1, v2, ...) — returns 1-based index or 0
    db.function('FIELD', { varargs: true }, function () {
        var val = arguments[0];
        for (var i = 1; i < arguments.length; i++) {
            if (arguments[i] === val) return i;
        }
        return 0;
    });

    // FIND_IN_SET(val, csv)
    db.function('FIND_IN_SET', function (val, csv) {
        if (val === null || csv === null) return null;
        var parts = String(csv).split(',');
        var idx = parts.indexOf(String(val));
        return idx === -1 ? 0 : idx + 1;
    });

    // ELT(n, v1, v2, ...)
    db.function('ELT', { varargs: true }, function () {
        var n = arguments[0];
        return (n >= 1 && n < arguments.length) ? arguments[n] : null;
    });

    // REPEAT(str, n)
    db.function('REPEAT', function (str, n) {
        if (str === null || n === null) return null;
        return String(str).repeat(Math.max(0, n));
    });

    // REVERSE(str)
    db.function('REVERSE', function (str) {
        if (str === null) return null;
        return String(str).split('').reverse().join('');
    });

    // ── Date/time functions ───────────────────────────────────────────────────

    // NOW() — returns current datetime
    db.function('NOW', function () { return new Date().toISOString().replace('T', ' ').slice(0, 19); });

    // SYSDATE() — same
    db.function('SYSDATE', function () { return new Date().toISOString().replace('T', ' ').slice(0, 19); });

    // CURDATE() / CURRENT_DATE()
    db.function('CURDATE', function () { return new Date().toISOString().slice(0, 10); });

    // CURTIME() / CURRENT_TIME()
    db.function('CURTIME', function () { return new Date().toISOString().slice(11, 19); });

    // UNIX_TIMESTAMP([expr]) — varargs so both 0-arg and 1-arg calls work
    db.function('UNIX_TIMESTAMP', { varargs: true }, function (expr) {
        if (expr === null || expr === undefined) return Math.floor(Date.now() / 1000);
        var d = new Date(expr);
        return isNaN(d.getTime()) ? null : Math.floor(d.getTime() / 1000);
    });

    // FROM_UNIXTIME(ts [, fmt])
    db.function('FROM_UNIXTIME', function (ts, fmt) {
        if (ts === null) return null;
        var d = new Date(Number(ts) * 1000);
        if (!fmt) return d.toISOString().replace('T', ' ').slice(0, 19);
        return _mysqlDateFormat(d, fmt);
    });

    // DATE_FORMAT(date, fmt)
    db.function('DATE_FORMAT', function (date, fmt) {
        if (date === null || fmt === null) return null;
        var d = new Date(date);
        if (isNaN(d.getTime())) return null;
        return _mysqlDateFormat(d, String(fmt));
    });

    // STR_TO_DATE(str, fmt) — partial implementation; full parsing is complex
    db.function('STR_TO_DATE', function (str, fmt) {
        if (str === null || fmt === null) return null;
        // Best-effort: if fmt matches a standard pattern, convert
        var d = new Date(String(str));
        if (isNaN(d.getTime())) return null;
        return d.toISOString().slice(0, 10);
    });

    // DATEDIFF(d1, d2) — returns integer days difference
    db.function('DATEDIFF', function (d1, d2) {
        if (d1 === null || d2 === null) return null;
        var t1 = new Date(d1).getTime(), t2 = new Date(d2).getTime();
        if (isNaN(t1) || isNaN(t2)) return null;
        return Math.round((t1 - t2) / 86400000);
    });

    // TIMESTAMPDIFF(unit, d1, d2)
    db.function('TIMESTAMPDIFF', function (unit, d1, d2) {
        if (d1 === null || d2 === null) return null;
        var t1 = new Date(d1).getTime(), t2 = new Date(d2).getTime();
        if (isNaN(t1) || isNaN(t2)) return null;
        var diff = t2 - t1;
        var u = String(unit).toUpperCase();
        if (u === 'SECOND') return Math.floor(diff / 1000);
        if (u === 'MINUTE') return Math.floor(diff / 60000);
        if (u === 'HOUR')   return Math.floor(diff / 3600000);
        if (u === 'DAY')    return Math.floor(diff / 86400000);
        if (u === 'WEEK')   return Math.floor(diff / 604800000);
        if (u === 'MONTH')  return Math.floor(diff / 2592000000);
        if (u === 'YEAR')   return Math.floor(diff / 31536000000);
        return null;
    });

    // DATE_ADD / DATE_SUB via ADDDATE / SUBDATE patterns are rewritten at query level;
    // the interval syntax is too complex to handle as a UDF.

    // DAY / MONTH / YEAR / HOUR / MINUTE / SECOND extractors
    db.function('DAY',     function (d) { return d ? new Date(d).getUTCDate()          : null; });
    db.function('MONTH',   function (d) { return d ? new Date(d).getUTCMonth() + 1     : null; });
    db.function('YEAR',    function (d) { return d ? new Date(d).getUTCFullYear()       : null; });
    db.function('HOUR',    function (d) { return d ? new Date(d).getUTCHours()          : null; });
    db.function('MINUTE',  function (d) { return d ? new Date(d).getUTCMinutes()        : null; });
    db.function('SECOND',  function (d) { return d ? new Date(d).getUTCSeconds()        : null; });
    db.function('DAYOFWEEK', function (d) { return d ? new Date(d).getUTCDay() + 1      : null; });
    db.function('WEEKDAY', function (d)  { return d ? (new Date(d).getUTCDay() + 6) % 7 : null; });
    db.function('WEEK',    function (d)  {
        if (!d) return null;
        var dt = new Date(d);
        var start = new Date(dt.getUTCFullYear(), 0, 1);
        return Math.floor((dt - start) / 604800000);
    });

    // ── Math / numeric functions ──────────────────────────────────────────────

    // GREATEST / LEAST
    db.function('GREATEST', { varargs: true }, function () {
        var vals = Array.prototype.slice.call(arguments).filter(function (v) { return v !== null; });
        return vals.length ? Math.max.apply(null, vals) : null;
    });
    db.function('LEAST', { varargs: true }, function () {
        var vals = Array.prototype.slice.call(arguments).filter(function (v) { return v !== null; });
        return vals.length ? Math.min.apply(null, vals) : null;
    });

    // MOD(a, b) — same as a % b
    db.function('MOD', function (a, b) { return b === 0 ? null : a % b; });

    // DIV(a, b) — integer division
    db.function('DIV', function (a, b) { return b === 0 ? null : Math.trunc(a / b); });

    // ── Misc ──────────────────────────────────────────────────────────────────

    // NOTE: ISNULL is a reserved keyword in SQLite (postfix operator `expr ISNULL`),
    // so it cannot be registered as a UDF here.  The DML translator rewrites
    // ISNULL(x) → (x IS NULL) before the query reaches the engine.

    // NVL(a, b) — Oracle-ism that some ORMs emit
    db.function('NVL', function (a, b) { return a !== null ? a : b; });

    // NULLIF(a, b)
    db.function('NULLIF', function (a, b) { return a === b ? null : a; });

    // IF(cond, a, b)
    db.function('IF', function (cond, a, b) { return cond ? a : b; });

    // IIF(cond, a, b) — SQLite has this natively in 3.32+, but let's be safe
    db.function('IIF', function (cond, a, b) { return cond ? a : b; });

    // CONVERT(val, type) — basic: just return val
    db.function('CONVERT', function (val) { return val; });

    // CAST is a SQL keyword, not a function — no UDF needed.

    // MD5(str) / SHA1(str) — only if crypto is available (Node.js always has it)
    var crypto = require('crypto');
    db.function('MD5', function (s) {
        if (s === null) return null;
        return crypto.createHash('md5').update(String(s)).digest('hex');
    });
    db.function('SHA1', function (s) {
        if (s === null) return null;
        return crypto.createHash('sha1').update(String(s)).digest('hex');
    });
    db.function('SHA2', function (s, bits) {
        if (s === null) return null;
        return crypto.createHash('sha' + (bits || 256)).update(String(s)).digest('hex');
    });

    // UUID() — MySQL-style UUID
    db.function('UUID', function () {
        return crypto.randomUUID ? crypto.randomUUID()
            : [4, 2, 2, 2, 6].map(function (n) {
                return crypto.randomBytes(n).toString('hex');
            }).join('-');
    });
}

// ─── DATE_FORMAT helper ───────────────────────────────────────────────────────

/**
 * Convert a Date object to a MySQL DATE_FORMAT string.
 * Handles the most common format specifiers; unknown specifiers are left as-is.
 */
function _mysqlDateFormat(d, fmt) {
    var pad2 = function (n) { return String(n).padStart(2, '0'); };
    var pad3 = function (n) { return String(n).padStart(3, '0'); };
    var MONTHS  = ['January','February','March','April','May','June',
                   'July','August','September','October','November','December'];
    var DAYS    = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
    var MONTHS3 = MONTHS.map(function (m) { return m.slice(0, 3); });
    var DAYS3   = DAYS.map(function (d) { return d.slice(0, 3); });

    return fmt.replace(/%./g, function (spec) {
        switch (spec) {
            case '%Y': return String(d.getUTCFullYear());
            case '%y': return String(d.getUTCFullYear()).slice(-2);
            case '%m': return pad2(d.getUTCMonth() + 1);
            case '%c': return String(d.getUTCMonth() + 1);
            case '%d': return pad2(d.getUTCDate());
            case '%e': return String(d.getUTCDate());
            case '%H': return pad2(d.getUTCHours());
            case '%k': return String(d.getUTCHours());
            case '%h': return pad2((d.getUTCHours() % 12) || 12);
            case '%l': return String((d.getUTCHours() % 12) || 12);
            case '%i': return pad2(d.getUTCMinutes());
            case '%s': return pad2(d.getUTCSeconds());
            case '%f': return pad3(d.getUTCMilliseconds()) + '000';
            case '%p': return d.getUTCHours() < 12 ? 'AM' : 'PM';
            case '%M': return MONTHS[d.getUTCMonth()];
            case '%b': return MONTHS3[d.getUTCMonth()];
            case '%W': return DAYS[d.getUTCDay()];
            case '%a': return DAYS3[d.getUTCDay()];
            case '%w': return String(d.getUTCDay());
            case '%j': {
                var start = new Date(Date.UTC(d.getUTCFullYear(), 0, 0));
                return pad3(Math.floor((d - start) / 86400000));
            }
            case '%U': return String(Math.floor((d.getUTCDate() + 6 * d.getUTCDay()) / 7));
            case '%u': return String(Math.floor((d.getUTCDate() + (d.getUTCDay() + 6) % 7) / 7));
            case '%r': {
                var hh = d.getUTCHours(), mm = d.getUTCMinutes(), ss = d.getUTCSeconds();
                var ampm = hh < 12 ? 'AM' : 'PM';
                return pad2((hh % 12) || 12) + ':' + pad2(mm) + ':' + pad2(ss) + ' ' + ampm;
            }
            case '%T': return pad2(d.getUTCHours()) + ':' + pad2(d.getUTCMinutes()) + ':' + pad2(d.getUTCSeconds());
            case '%D': {
                var day = d.getUTCDate();
                var suffix = day === 1 || day === 21 || day === 31 ? 'st'
                           : day === 2 || day === 22 ? 'nd'
                           : day === 3 || day === 23 ? 'rd' : 'th';
                return day + suffix;
            }
            case '%%': return '%';
            default:   return spec;
        }
    });
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
    translate:    translate,
    registerUDFs: registerUDFs,
    // Exported for direct use in tests or standalone tooling:
    translateCreateTable:  translateCreateTable,
    translateCreateIndex:  translateCreateIndex,
    translateAlterTable:   translateAlterTable,
    translateDML:          translateDML,
};
