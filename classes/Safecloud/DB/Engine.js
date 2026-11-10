'use strict';
/**
 * Engine — SQL parser + executor.
 *
 * Parses SQL with node-sql-parser (MySQL dialect, which is close enough to
 * SQLite for common DDL/DML), walks the AST, and executes against TableStore
 * instances managed by the Catalog.
 *
 * Supports:
 *   DDL:  CREATE TABLE / DROP TABLE / CREATE INDEX / DROP INDEX
 *   DML:  INSERT / SELECT (with WHERE, GROUP BY, HAVING, ORDER BY, LIMIT/OFFSET,
 *         JOINs, subqueries in FROM) / UPDATE / DELETE
 *   TCL:  BEGIN / COMMIT / ROLLBACK
 *   Expr: =, !=/<>, <, >, <=, >=, AND, OR, NOT, IN, NOT IN, BETWEEN, LIKE,
 *         IS NULL, IS NOT NULL, +, -, *, /, ||, CASE/WHEN, scalar functions
 *   Agg:  COUNT, SUM, AVG, MIN, MAX, GROUP_CONCAT
 */

var fs         = require('fs');
var path       = require('path');
var crypto     = require('crypto');   // needed for MD5/SHA1; hoist to avoid late-require under Jest
var TableStore = require('./TableStore');
var Catalog    = require('./Catalog');
var KC         = require('./KeyCodec');

var Parser;
try { Parser = require('node-sql-parser').Parser; }
catch (e) { throw new Error('node-sql-parser is required: npm install node-sql-parser'); }

var _parser = new Parser();

// ─── SQL type coercion ────────────────────────────────────────────────────────

function coerce(v, colDef) {
    if (v === null || v === undefined) return null;
    if (!colDef) return v;
    var t = (colDef.type || '').toUpperCase().split('(')[0].trim();
    if (t === 'INTEGER' || t === 'INT' || t === 'BIGINT' || t === 'SMALLINT' || t === 'TINYINT') {
        var n = Number(v);
        return isNaN(n) ? null : Math.trunc(n);
    }
    if (t === 'REAL' || t === 'FLOAT' || t === 'DOUBLE' || t === 'NUMERIC' || t === 'DECIMAL') {
        var n = Number(v);
        return isNaN(n) ? null : n;
    }
    if (t === 'TEXT' || t === 'VARCHAR' || t === 'CHAR' || t === 'CLOB' || t === 'STRING') {
        return String(v);
    }
    if (t === 'BLOB') {
        return Buffer.isBuffer(v) ? v : Buffer.from(String(v));
    }
    return v;
}

// ─── LIKE pattern → RegExp ───────────────────────────────────────────────────

function likeRx(pattern, ci) {
    var rx = pattern
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/%/g, '.*')
        .replace(/_/g, '.');
    return new RegExp('^' + rx + '$', ci ? 'i' : '');
}

// ─── Expression evaluator ─────────────────────────────────────────────────────

function evalExpr(node, row, params, pi) {
    if (!node) return null;
    switch (node.type) {

        case 'column_ref': {
            var col = node.column;
            if (typeof col === 'object' && col !== null) col = col.column || col.value || '';
            col = String(col);
            // Table-qualified lookup first
            if (node.table) {
                var tqLower = node.table + '.' + col.toLowerCase();
                var keys = Object.keys(row);
                for (var i = 0; i < keys.length; i++) {
                    if (keys[i].toLowerCase() === tqLower) return row[keys[i]];
                }
            }
            // Direct (case-insensitive) lookup
            var colLower = col.toLowerCase();
            if (Object.prototype.hasOwnProperty.call(row, col)) return row[col];
            var rkeys = Object.keys(row);
            for (var i = 0; i < rkeys.length; i++) {
                var k = rkeys[i];
                var kLast = k.includes('.') ? k.slice(k.lastIndexOf('.') + 1) : k;
                if (kLast.toLowerCase() === colLower) return row[k];
            }
            return null;
        }

        case 'number':      return node.value;
        case 'bool':        return node.value ? 1 : 0;
        case 'null':        return null;

        case 'string':
        case 'double_quote_string':
            return node.value;
        case 'single_quote_string':
            // node-sql-parser preserves SQL '' escapes literally; unescape them here.
            return typeof node.value === 'string' ? node.value.replace(/''/g, "'") : node.value;

        case 'origin':
            if (node.value === '?') { var i2 = pi.i++; return params && i2 < params.length ? params[i2] : null; }
            return node.value;

        case 'param':
            if (params && typeof params === 'object' && !Array.isArray(params)) {
                var v = params[node.value];
                return v !== undefined ? v : null;
            }
            if (Array.isArray(params) && /^\d+$/.test(node.value)) {
                return params[parseInt(node.value, 10) - 1];
            }
            return null;

        case 'unary_expr': {
            var op = node.operator;
            if (op === '-') { var _uv = evalExpr(node.expr, row, params, pi); return _uv === null ? null : -Number(_uv); }
            if (op === '+') { var _uv2 = evalExpr(node.expr, row, params, pi); return _uv2 === null ? null : +Number(_uv2); }
            if (op === 'NOT') { var _nv = evalExpr(node.expr, row, params, pi); return _nv === null ? null : (_nv ? 0 : 1); }
            if (op === 'IS NULL')     return evalExpr(node.expr, row, params, pi) === null ? 1 : 0;
            if (op === 'IS NOT NULL') return evalExpr(node.expr, row, params, pi) !== null ? 1 : 0;
            return evalExpr(node.expr, row, params, pi);
        }

        case 'binary_expr': return evalBinary(node, row, params, pi);

        case 'aggr_func': {
            // If row already has the pre-computed aggregate (e.g. in HAVING), return it
            var _aggrKey = exprAlias(node);
            if (row && typeof row === 'object' && _aggrKey in row) return row[_aggrKey];
            // Aggregate sentinel — resolved by _groupRows, not here
            return { __aggr: node.name.toUpperCase(), node: node };
        }

        case 'function': return evalFunc(node, row, params, pi);

        case 'case':  return evalCase(node, row, params, pi);

        case 'cast': {
            var _cv = evalExpr(node.expr, row, params, pi);
            if (_cv === null) return null;
            var _ct = '';
            if (node.target) {
                _ct = (typeof node.target === 'string' ? node.target
                    : (node.target.dataType || node.target.type || '')).toUpperCase().split('(')[0].trim();
            }
            if (_ct === 'INTEGER' || _ct === 'INT' || _ct === 'BIGINT' || _ct === 'SMALLINT' || _ct === 'TINYINT' ||
                _ct === 'SIGNED' || _ct === 'UNSIGNED') {
                var _cn = Number(_cv); return isNaN(_cn) ? null : Math.trunc(_cn);
            }
            if (_ct === 'REAL' || _ct === 'FLOAT' || _ct === 'DOUBLE' || _ct === 'NUMERIC' || _ct === 'DECIMAL') {
                var _cn = Number(_cv); return isNaN(_cn) ? null : _cn;
            }
            if (_ct === 'TEXT' || _ct === 'VARCHAR' || _ct === 'CHAR' || _ct === 'CHARACTER' || _ct === 'NCHAR' || _ct === 'CLOB') {
                return String(_cv);
            }
            if (_ct === 'BLOB' || _ct === 'BINARY' || _ct === 'VARBINARY') {
                return Buffer.isBuffer(_cv) ? _cv : Buffer.from(String(_cv));
            }
            return _cv;  // unknown target type — pass through
        }

        case 'star':  return '*';

        case 'expr_list':
            return (node.value || []).map(function (e) { return evalExpr(e, row, params, pi); });

        case 'select':
            // Correlated subquery (simple — evaluate without outer row bindings)
            return null;

        default:
            if (node.value !== undefined) return node.value;
            return null;
    }
}

function evalBinary(node, row, params, pi) {
    var op = node.operator;

    // Short-circuit boolean ops
    if (op === 'AND') {
        var l = evalExpr(node.left, row, params, pi);
        if (l === null) {
            var r = evalExpr(node.right, row, params, pi);
            return (r === null || r) ? null : 0;
        }
        if (!l) return 0;
        var r = evalExpr(node.right, row, params, pi);
        if (r === null) return null;
        return r ? 1 : 0;
    }
    if (op === 'OR') {
        var l = evalExpr(node.left, row, params, pi);
        if (l) return 1;
        var r = evalExpr(node.right, row, params, pi);
        if (r) return 1;
        if (l === null || r === null) return null;
        return 0;
    }

    // BETWEEN/NOT BETWEEN: node.right is expr_list{value:[lo,hi]} — handle before pre-eval
    if (op === 'BETWEEN' || op === 'NOT BETWEEN') {
        var _bl  = evalExpr(node.left,           row, params, pi);
        var _blo = evalExpr(node.right.value[0], row, params, pi);
        var _bhi = evalExpr(node.right.value[1], row, params, pi);
        if (_bl === null || _blo === null || _bhi === null) return null;
        var _in  = _bl >= _blo && _bl <= _bhi;
        return op === 'BETWEEN' ? (_in ? 1 : 0) : (_in ? 0 : 1);
    }

    var left  = evalExpr(node.left,  row, params, pi);
    var right = evalExpr(node.right, row, params, pi);

    switch (op) {
        case '=':
            if (left === null || right === null) return null;
            return (left == right) ? 1 : 0;  // intentional ==
        case '!=': case '<>':
            if (left === null || right === null) return null;
            return (left != right) ? 1 : 0;
        case '<':   return (left === null || right === null) ? null : (left < right  ? 1 : 0);
        case '>':   return (left === null || right === null) ? null : (left > right  ? 1 : 0);
        case '<=':  return (left === null || right === null) ? null : (left <= right ? 1 : 0);
        case '>=':  return (left === null || right === null) ? null : (left >= right ? 1 : 0);

        case '+': return (left === null || right === null) ? null : Number(left) + Number(right);
        case '-': return (left === null || right === null) ? null : Number(left) - Number(right);
        case '*': return (left === null || right === null) ? null : Number(left) * Number(right);
        case '/': return (left === null || right === null) ? null : (Number(right) !== 0 ? Number(left) / Number(right) : null);
        case '%': return (left === null || right === null) ? null : Number(left) % Number(right);

        case '||': return (left === null || right === null) ? null : String(left) + String(right);

        case 'IS':
            if (right === null) return left === null ? 1 : 0;
            return (left === right) ? 1 : 0;
        case 'IS NOT':
            if (right === null) return left !== null ? 1 : 0;
            return (left !== right) ? 1 : 0;

        case 'IN': {
            if (left === null) return null;
            var list = Array.isArray(right) ? right
                : (right && right.value ? right.value : [right]);
            var hasNullIn = false;
            for (var i = 0; i < list.length; i++) {
                var item = (list[i] && typeof list[i] === 'object' && list[i].value !== undefined)
                    ? list[i].value : list[i];
                if (item === null || item === undefined) { hasNullIn = true; continue; }
                if (left == item) return 1;
            }
            return hasNullIn ? null : 0;
        }
        case 'NOT IN': {
            if (left === null) return null;
            var list = Array.isArray(right) ? right
                : (right && right.value ? right.value : [right]);
            var hasNullNot = false;
            for (var i = 0; i < list.length; i++) {
                var item = (list[i] && typeof list[i] === 'object' && list[i].value !== undefined)
                    ? list[i].value : list[i];
                if (item === null || item === undefined) { hasNullNot = true; continue; }
                if (left == item) return 0;
            }
            return hasNullNot ? null : 1;
        }

        case 'LIKE':     if (left === null || right === null) return null; return likeRx(String(right), false).test(String(left)) ? 1 : 0;
        case 'NOT LIKE': if (left === null || right === null) return null; return !likeRx(String(right), false).test(String(left)) ? 1 : 0;
        case 'ILIKE':    if (left === null || right === null) return null; return likeRx(String(right), true).test(String(left)) ? 1 : 0;

        default: return 0;
    }
}

function evalFunc(node, row, params, pi) {
    var name = (node.name || '').toUpperCase();
    var args = (node.args && node.args.value) ? node.args.value : [];
    var a0 = function () { return args[0] ? evalExpr(args[0], row, params, pi) : null; };
    var a1 = function () { return args[1] ? evalExpr(args[1], row, params, pi) : null; };
    var a2 = function () { return args[2] ? evalExpr(args[2], row, params, pi) : null; };

    switch (name) {
        case 'COALESCE': {
            for (var i = 0; i < args.length; i++) {
                var v = evalExpr(args[i], row, params, pi);
                if (v !== null) return v;
            }
            return null;
        }
        case 'IFNULL': case 'NVL': case 'ISNULL': {
            var v = a0(); return v !== null ? v : a1();
        }
        case 'NULLIF': {
            var v = a0(), w = a1(); return v == w ? null : v;
        }
        case 'IIF': case 'IF': {
            var cond = a0(); return cond ? a1() : a2();
        }
        case 'LENGTH': case 'LEN': {
            var v = a0(); return v !== null ? String(v).length : null;
        }
        case 'UPPER': { var v = a0(); return v !== null ? String(v).toUpperCase() : null; }
        case 'LOWER': { var v = a0(); return v !== null ? String(v).toLowerCase() : null; }
        case 'TRIM':  { var v = a0(); return v !== null ? String(v).trim() : null; }
        case 'LTRIM': { var v = a0(); return v !== null ? String(v).trimStart() : null; }
        case 'RTRIM': { var v = a0(); return v !== null ? String(v).trimEnd() : null; }
        case 'SUBSTR': case 'SUBSTRING': {
            var s = String(a0() || '');
            var start = Number(a1() || 1) - 1; // SQL is 1-based
            var len = args[2] ? Number(a2()) : undefined;
            return len !== undefined ? s.substr(start, len) : s.slice(start);
        }
        case 'REPLACE': {
            var s = String(a0() || ''), find = String(a1() || ''), rep = String(a2() || '');
            return s.split(find).join(rep);
        }
        case 'INSTR': {
            var s = String(a0() || ''), needle = String(a1() || '');
            var idx = s.indexOf(needle);
            return idx >= 0 ? idx + 1 : 0;
        }
        case 'ABS':    { var v = a0(); return v !== null ? Math.abs(Number(v)) : null; }
        case 'ROUND': {
            var v = a0(), d = args[1] ? Number(a1()) : 0;
            if (v === null) return null;
            var f = Math.pow(10, d);
            return Math.round(Number(v) * f) / f;
        }
        case 'FLOOR':  { var v = a0(); return v !== null ? Math.floor(Number(v))  : null; }
        case 'CEIL': case 'CEILING': { var v = a0(); return v !== null ? Math.ceil(Number(v)) : null; }
        case 'MOD':    { var a = Number(a0()), b = Number(a1()); return b ? a % b : null; }
        case 'MAX':    { return args.reduce(function (m, e) { var v = evalExpr(e, row, params, pi); return (v !== null && (m === null || v > m)) ? v : m; }, null); }
        case 'MIN':    { return args.reduce(function (m, e) { var v = evalExpr(e, row, params, pi); return (v !== null && (m === null || v < m)) ? v : m; }, null); }
        case 'TYPEOF': {
            var v = a0();
            if (v === null) return 'null';
            if (typeof v === 'number') return Number.isInteger(v) ? 'integer' : 'real';
            if (typeof v === 'string') return 'text';
            if (Buffer.isBuffer(v)) return 'blob';
            return 'text';
        }
        case 'CAST': {
            // CAST may appear as function node in some parser variants
            var _castExpr = (node.args && node.args.expr) ? node.args.expr : args[0];
            var _cv2 = evalExpr(_castExpr, row, params, pi);
            if (_cv2 === null) return null;
            var _castTarget = (node.args && node.args.target) ? node.args.target : null;
            var _ct2 = _castTarget
                ? (typeof _castTarget === 'string' ? _castTarget
                    : (_castTarget.dataType || _castTarget.type || '')).toUpperCase().split('(')[0].trim()
                : '';
            if (_ct2 === 'INTEGER' || _ct2 === 'INT' || _ct2 === 'BIGINT' || _ct2 === 'SMALLINT' || _ct2 === 'TINYINT' ||
                _ct2 === 'SIGNED' || _ct2 === 'UNSIGNED') {
                var _cn2 = Number(_cv2); return isNaN(_cn2) ? null : Math.trunc(_cn2);
            }
            if (_ct2 === 'REAL' || _ct2 === 'FLOAT' || _ct2 === 'DOUBLE' || _ct2 === 'NUMERIC' || _ct2 === 'DECIMAL') {
                var _cn2 = Number(_cv2); return isNaN(_cn2) ? null : _cn2;
            }
            if (_ct2 === 'TEXT' || _ct2 === 'VARCHAR' || _ct2 === 'CHAR' || _ct2 === 'CHARACTER' || _ct2 === 'CLOB') {
                return String(_cv2);
            }
            if (_ct2 === 'BLOB' || _ct2 === 'BINARY' || _ct2 === 'VARBINARY') {
                return Buffer.isBuffer(_cv2) ? _cv2 : Buffer.from(String(_cv2));
            }
            return _cv2;
        }
        case 'HEX': {
            var v = a0();
            if (v === null) return null;
            if (Buffer.isBuffer(v)) return v.toString('hex').toUpperCase();
            return Buffer.from(String(v), 'utf8').toString('hex').toUpperCase();
        }
        case 'PRINTF': case 'FORMAT': {
            // Very basic: just return first arg stringified
            return a0() !== null ? String(a0()) : null;
        }
        case 'DATE': {
            var _dv = a0();
            var _d = (_dv === null || _dv === 'now') ? new Date() : new Date(_dv);
            if (isNaN(_d.getTime())) return null;
            return _d.toISOString().slice(0, 10);
        }
        case 'TIME': {
            var _dv = a0();
            var _d = (_dv === null || _dv === 'now') ? new Date() : new Date(_dv);
            if (isNaN(_d.getTime())) return null;
            return _d.toISOString().slice(11, 19);
        }
        case 'DATETIME': {
            var _dv = a0();
            var _d = (_dv === null || _dv === 'now') ? new Date() : new Date(_dv);
            if (isNaN(_d.getTime())) return null;
            return _d.toISOString().slice(0, 19).replace('T', ' ');
        }
        case 'JULIANDAY': {
            var _dv = a0();
            var _d = (_dv === null || _dv === 'now') ? new Date() : new Date(_dv);
            if (isNaN(_d.getTime())) return null;
            // Julian Day Number: days since noon January 1, 4713 BC
            return _d.getTime() / 86400000 + 2440587.5;
        }
        case 'STRFTIME': {
            // STRFTIME(format, timestr, ...)
            var _fmt = a0(), _dv = a1();
            if (_fmt === null) return null;
            var _d = (_dv === null || _dv === 'now') ? new Date() : new Date(_dv);
            if (isNaN(_d.getTime())) return null;
            var _iso = _d.toISOString();
            return String(_fmt)
                .replace('%Y', _iso.slice(0, 4))
                .replace('%m', _iso.slice(5, 7))
                .replace('%d', _iso.slice(8, 10))
                .replace('%H', _iso.slice(11, 13))
                .replace('%M', _iso.slice(14, 16))
                .replace('%S', _iso.slice(17, 19))
                .replace('%f', _iso.slice(17, 23))
                .replace('%j', String(Math.floor((_d - new Date(_d.getFullYear(), 0, 0)) / 86400000)).padStart(3, '0'))
                .replace('%s', String(Math.floor(_d.getTime() / 1000)));
        }
        // ── MySQL scalar functions not in SQLite ──────────────────────────────
        case 'LPAD': {
            var _s = a0(); if (_s === null) return null;
            _s = String(_s); var _len = Number(a1()), _pad = String(a2() || ' ');
            while (_s.length < _len) _s = _pad + _s;
            return _s.slice(-_len);
        }
        case 'RPAD': {
            var _s = a0(); if (_s === null) return null;
            _s = String(_s); var _len = Number(a1()), _pad = String(a2() || ' ');
            while (_s.length < _len) _s = _s + _pad;
            return _s.slice(0, _len);
        }
        case 'FIELD': {
            var _fv = a0();
            for (var _fi = 1; _fi < args.length; _fi++) {
                if (evalExpr(args[_fi], row, params, pi) == _fv) return _fi;
            }
            return 0;
        }
        case 'FIND_IN_SET': {
            var _fv = a0(), _csv = a1();
            if (_fv === null || _csv === null) return null;
            var _parts = String(_csv).split(',');
            var _idx = _parts.indexOf(String(_fv));
            return _idx === -1 ? 0 : _idx + 1;
        }
        case 'IF': {
            var _cond = a0(); return _cond && _cond !== '0' && _cond !== 0 ? a1() : a2();
        }
        case 'IFNULL': case 'NVL2': {
            var _v = a0(); return _v !== null ? _v : a1();
        }
        case 'NOW': case 'SYSDATE': {
            return new Date().toISOString().replace('T', ' ').slice(0, 19);
        }
        case 'CURDATE': case 'CURRENT_DATE': {
            return new Date().toISOString().slice(0, 10);
        }
        case 'CURTIME': case 'CURRENT_TIME': {
            return new Date().toISOString().slice(11, 19);
        }
        case 'YEAR': { var _dv = a0(); if (!_dv) return null; var _d = new Date(_dv); return isNaN(_d) ? null : _d.getUTCFullYear(); }
        case 'MONTH': { var _dv = a0(); if (!_dv) return null; var _d = new Date(_dv); return isNaN(_d) ? null : _d.getUTCMonth() + 1; }
        case 'DAY': case 'DAYOFMONTH': { var _dv = a0(); if (!_dv) return null; var _d = new Date(_dv); return isNaN(_d) ? null : _d.getUTCDate(); }
        case 'HOUR': { var _dv = a0(); if (!_dv) return null; var _d = new Date(_dv); return isNaN(_d) ? null : _d.getUTCHours(); }
        case 'MINUTE': { var _dv = a0(); if (!_dv) return null; var _d = new Date(_dv); return isNaN(_d) ? null : _d.getUTCMinutes(); }
        case 'SECOND': { var _dv = a0(); if (!_dv) return null; var _d = new Date(_dv); return isNaN(_d) ? null : _d.getUTCSeconds(); }
        case 'DAYOFWEEK': { var _dv = a0(); if (!_dv) return null; var _d = new Date(_dv); return isNaN(_d) ? null : _d.getUTCDay() + 1; }
        case 'WEEKDAY': { var _dv = a0(); if (!_dv) return null; var _d = new Date(_dv); return isNaN(_d) ? null : (_d.getUTCDay() + 6) % 7; }
        case 'UNIX_TIMESTAMP': {
            if (!args.length) return Math.floor(Date.now() / 1000);
            var _dv = a0(); if (_dv === null) return null;
            var _d = new Date(_dv); return isNaN(_d) ? null : Math.floor(_d.getTime() / 1000);
        }
        case 'FROM_UNIXTIME': {
            var _ts = a0(); if (_ts === null) return null;
            var _d = new Date(Number(_ts) * 1000);
            return _d.toISOString().replace('T', ' ').slice(0, 19);
        }
        case 'DATEDIFF': {
            var _d1 = a0(), _d2 = a1();
            if (_d1 === null || _d2 === null) return null;
            var _t1 = new Date(_d1).getTime(), _t2 = new Date(_d2).getTime();
            return (isNaN(_t1) || isNaN(_t2)) ? null : Math.round((_t1 - _t2) / 86400000);
        }
        case 'DATE_FORMAT': {
            var _dfdate = a0(), _dffmt = a1();
            if (_dfdate === null || _dffmt === null) return null;
            var _d = new Date(_dfdate);
            if (isNaN(_d.getTime())) return null;
            function _pad2(n) { return String(n).padStart(2, '0'); }
            return String(_dffmt).replace(/%./g, function(spec) {
                switch(spec) {
                    case '%Y': return String(_d.getUTCFullYear());
                    case '%y': return String(_d.getUTCFullYear()).slice(-2);
                    case '%m': return _pad2(_d.getUTCMonth() + 1);
                    case '%c': return String(_d.getUTCMonth() + 1);
                    case '%d': return _pad2(_d.getUTCDate());
                    case '%e': return String(_d.getUTCDate());
                    case '%H': return _pad2(_d.getUTCHours());
                    case '%i': return _pad2(_d.getUTCMinutes());
                    case '%s': return _pad2(_d.getUTCSeconds());
                    case '%p': return _d.getUTCHours() < 12 ? 'AM' : 'PM';
                    case '%T': return _pad2(_d.getUTCHours())+':'+_pad2(_d.getUTCMinutes())+':'+_pad2(_d.getUTCSeconds());
                    case '%%': return '%';
                    default:   return spec;
                }
            });
        }
        case 'TIMESTAMPDIFF': {
            var _unit = a0(), _d1 = a1(), _d2 = a2();
            if (_d1 === null || _d2 === null) return null;
            var _t1 = new Date(_d1).getTime(), _t2 = new Date(_d2).getTime();
            if (isNaN(_t1) || isNaN(_t2)) return null;
            var _diff = _t2 - _t1;
            var _u = String(_unit).toUpperCase();
            if (_u === 'SECOND') return Math.floor(_diff / 1000);
            if (_u === 'MINUTE') return Math.floor(_diff / 60000);
            if (_u === 'HOUR')   return Math.floor(_diff / 3600000);
            if (_u === 'DAY')    return Math.floor(_diff / 86400000);
            if (_u === 'MONTH')  return Math.floor(_diff / 2592000000);
            if (_u === 'YEAR')   return Math.floor(_diff / 31536000000);
            return null;
        }
        case 'GREATEST': {
            var _vals = args.map(function(e) { return evalExpr(e, row, params, pi); }).filter(function(v) { return v !== null; });
            return _vals.length ? Math.max.apply(null, _vals) : null;
        }
        case 'LEAST': {
            var _vals = args.map(function(e) { return evalExpr(e, row, params, pi); }).filter(function(v) { return v !== null; });
            return _vals.length ? Math.min.apply(null, _vals) : null;
        }
        case 'REPEAT': {
            var _sv = a0(), _n = a1();
            if (_sv === null || _n === null) return null;
            return String(_sv).repeat(Math.max(0, Number(_n)));
        }
        case 'REVERSE': {
            var _sv = a0(); return _sv === null ? null : String(_sv).split('').reverse().join('');
        }
        case 'CONCAT': {
            var _parts = args.map(function(e) { return evalExpr(e, row, params, pi); });
            for (var _pi = 0; _pi < _parts.length; _pi++) { if (_parts[_pi] === null) return null; }
            return _parts.join('');
        }
        case 'CONCAT_WS': {
            var _sep = a0(); if (_sep === null) return null;
            var _parts = args.slice(1).map(function(e) { return evalExpr(e, row, params, pi); })
                            .filter(function(v) { return v !== null; });
            return _parts.map(String).join(String(_sep));
        }
        case 'MD5': {
            var _sv = a0(); if (_sv === null) return null;
            return crypto.createHash('md5').update(String(_sv)).digest('hex');
        }
        case 'SHA1': case 'SHA': {
            var _sv = a0(); if (_sv === null) return null;
            return crypto.createHash('sha1').update(String(_sv)).digest('hex');
        }
        case 'UUID': {
            // Simple RFC 4122 v4 UUID
            return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                var r = Math.random() * 16 | 0;
                return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
            });
        }
        case 'ISNULL': {
            // MySQL scalar ISNULL(x) → 1 if x IS NULL, else 0
            var _v = a0(); return _v === null ? 1 : 0;
        }
        case 'NULLIF': {
            var _v = a0(), _w = a1(); return _v == _w ? null : _v;
        }
        case 'ELT': {
            var _n = Number(a0());
            return (_n >= 1 && args.length > _n) ? evalExpr(args[_n], row, params, pi) : null;
        }
        case 'LEFT': {
            var _sv = a0(); return _sv === null ? null : String(_sv).slice(0, Number(a1()));
        }
        case 'RIGHT': {
            var _sv = a0(), _n = Number(a1()); if (_sv === null) return null;
            var _ss = String(_sv); return _ss.slice(Math.max(0, _ss.length - _n));
        }

        // Aggregates fall through to sentinel
        case 'COUNT': case 'SUM': case 'AVG': case 'GROUP_CONCAT':
            return { __aggr: name, node: node };
        default:
            return null;
    }
}

function evalCase(node, row, params, pi) {
    var args = node.args || [];
    // Simple CASE: CASE expr WHEN val THEN result ... END
    // Searched CASE: CASE WHEN cond THEN result ... END
    // node-sql-parser puts the simple-CASE operand in node.expr (not node.operand)
    var isSimple = node.expr !== undefined && node.expr !== null;
    var operand  = isSimple ? evalExpr(node.expr, row, params, pi) : undefined;

    for (var i = 0; i < args.length; i++) {
        var clause = args[i];
        if (clause.type === 'when') {
            var cond = evalExpr(clause.cond, row, params, pi);
            var match;
            if (isSimple) {
                // NULL in operand or cond → never matches
                match = (operand !== null && cond !== null && operand == cond);
            } else {
                match = (cond !== null && cond !== 0 && cond !== false);
            }
            if (match) return evalExpr(clause.result, row, params, pi);
        } else if (clause.type === 'else') {
            return evalExpr(clause.result, row, params, pi);
        }
    }
    return null;
}

// ─── Aggregate evaluation (over a group of rows) ─────────────────────────────

function evalAggr(node, rows, params, pi) {
    var name    = node.name.toUpperCase();
    var argExpr = node.args && node.args.expr;

    switch (name) {
        case 'COUNT': {
            if (!argExpr || argExpr.type === 'star') return rows.length;
            if (node.args && node.args.distinct) {
                var seen = new Set();
                rows.forEach(function (r) {
                    var v = evalExpr(argExpr, r, params, pi);
                    if (v !== null) seen.add(JSON.stringify(v));
                });
                return seen.size;
            }
            return rows.filter(function (r) { return evalExpr(argExpr, r, params, pi) !== null; }).length;
        }
        case 'SUM': {
            var vals = rows.map(function (r) { return evalExpr(argExpr, r, params, pi); }).filter(function (v) { return v !== null; });
            return vals.length ? vals.reduce(function (a, b) { return a + Number(b); }, 0) : null;
        }
        case 'AVG': {
            var vals = rows.map(function (r) { return evalExpr(argExpr, r, params, pi); }).filter(function (v) { return v !== null; });
            return vals.length ? vals.reduce(function (a, b) { return a + Number(b); }, 0) / vals.length : null;
        }
        case 'MIN': {
            var vals = rows.map(function (r) { return evalExpr(argExpr, r, params, pi); }).filter(function (v) { return v !== null; });
            return vals.length ? vals.reduce(function (a, b) { return b < a ? b : a; }) : null;
        }
        case 'MAX': {
            var vals = rows.map(function (r) { return evalExpr(argExpr, r, params, pi); }).filter(function (v) { return v !== null; });
            return vals.length ? vals.reduce(function (a, b) { return b > a ? b : a; }) : null;
        }
        case 'GROUP_CONCAT': {
            var sep = (node.args && node.args.separator) ? node.args.separator : ',';
            return rows
                .map(function (r) { return evalExpr(argExpr, r, params, pi); })
                .filter(function (v) { return v !== null; })
                .join(sep);
        }
        default: return null;
    }
}

function hasAggr(columns) {
    if (!columns || columns === '*') return false;
    if (!Array.isArray(columns)) return false;
    return columns.some(function (c) {
        return c && c.expr && (c.expr.type === 'aggr_func' ||
            (c.expr.type === 'function' && ['COUNT','SUM','AVG','MIN','MAX','GROUP_CONCAT'].indexOf((c.expr.name||'').toUpperCase()) >= 0));
    });
}

// ─── AST helpers ─────────────────────────────────────────────────────────────

function tblName(t) {
    if (!t) return '';
    if (typeof t === 'string') return t;
    if (Array.isArray(t)) return tblName(t[0]);
    return t.table || t.name || t.value || '';
}

function colName(c) {
    if (!c) return '';
    if (typeof c === 'string') return c;
    if (c.column) return typeof c.column === 'string' ? c.column : (c.column.column || c.column.value || '');
    return c.value || '';
}

// ─── Engine ───────────────────────────────────────────────────────────────────

function Engine(dbPath, catalog) {
    this._dbPath  = dbPath;
    this._catalog = catalog;
    this._stores  = Object.create(null); // name → TableStore  (prefix __idx__ for indexes)
    this._txSnaps = null;
    this._inTx    = false;
}

Engine.prototype._store = function (tableName) {
    if (!this._stores[tableName]) {
        var p = path.join(this._dbPath, 'tables', tableName + '.json');
        fs.mkdirSync(path.dirname(p), { recursive: true });
        var s = new TableStore(p);
        s.load();
        this._stores[tableName] = s;
    }
    return this._stores[tableName];
};

Engine.prototype._idxStore = function (indexName) {
    var key = '__idx__' + indexName;
    if (!this._stores[key]) {
        var p = path.join(this._dbPath, 'indexes', indexName + '.json');
        fs.mkdirSync(path.dirname(p), { recursive: true });
        var s = new TableStore(p);
        s.load();
        this._stores[key] = s;
    }
    return this._stores[key];
};

Engine.prototype.flush = function () {
    var stores = this._stores;
    Object.keys(stores).forEach(function (k) { stores[k].flush(); });
    this._catalog.save();
};

Engine.prototype.close = function () { this.flush(); };

// ─── SQL preprocessor ─────────────────────────────────────────────────────────

Engine.prototype._preprocessSQL = function (sql) {
    // REAL → FLOAT  (MySQL dialect doesn't recognise REAL as a data-type keyword)
    sql = sql.replace(/\bREAL\b/g, 'FLOAT');
    // AUTOINCREMENT → AUTO_INCREMENT  (SQLite spells it without the underscore)
    sql = sql.replace(/\bAUTOINCREMENT\b/gi, 'AUTO_INCREMENT');
    return sql;
};

// ─── Transactions ─────────────────────────────────────────────────────────────

Engine.prototype.beginTx = function () {
    var snap = Object.create(null);
    var stores = this._stores;
    Object.keys(stores).forEach(function (k) {
        snap[k] = { keys: stores[k]._keys.slice(), data: Object.assign(Object.create(null), stores[k]._data) };
    });
    this._txSnaps = snap;
    this._inTx    = true;
};

Engine.prototype.commitTx = function () {
    this._txSnaps = null;
    this._inTx    = false;
    this.flush();
};

Engine.prototype.rollbackTx = function () {
    var snap = this._txSnaps;
    var stores = this._stores;
    if (snap) {
        Object.keys(snap).forEach(function (k) {
            if (stores[k]) {
                stores[k]._keys  = snap[k].keys;
                stores[k]._data  = snap[k].data;
                stores[k]._dirty = false;
            }
        });
    }
    this._txSnaps = null;
    this._inTx    = false;
};

// ─── Public execute entry point ───────────────────────────────────────────────

Engine.prototype.execute = function (sql, params) {
    params = params || [];
    sql    = sql.trim();

    // Transaction control (before parsing, since node-sql-parser chokes on these)
    var up = sql.toUpperCase().replace(/\s+/g, ' ');
    if (up === 'BEGIN' || up === 'BEGIN TRANSACTION' || up === 'BEGIN DEFERRED TRANSACTION' || up === 'BEGIN IMMEDIATE' || up === 'BEGIN EXCLUSIVE') {
        this.beginTx();
        return { rows: [], changes: 0, lastInsertRowid: null };
    }
    if (up === 'COMMIT' || up === 'COMMIT TRANSACTION' || up === 'END' || up === 'END TRANSACTION') {
        this.commitTx();
        return { rows: [], changes: 0, lastInsertRowid: null };
    }
    if (up === 'ROLLBACK' || up === 'ROLLBACK TRANSACTION') {
        this.rollbackTx();
        return { rows: [], changes: 0, lastInsertRowid: null };
    }
    if (up.startsWith('PRAGMA') || up.startsWith('VACUUM') || up.startsWith('ANALYZE')) {
        return { rows: [], changes: 0, lastInsertRowid: null };
    }

    // ── Intercept DROP INDEX without ON clause (SQLite style, MySQL parser requires ON)
    var dropIdxM = /^\s*DROP\s+INDEX\s+(IF\s+EXISTS\s+)?(\w+)\s*;?\s*$/i.exec(sql);
    if (dropIdxM) {
        var _ie  = !!dropIdxM[1];
        var _idn = dropIdxM[2];
        this._catalog.dropIndex(_idn, _ie);
        try { fs.unlinkSync(path.join(this._dbPath, 'indexes', _idn + '.json')); } catch (e) {}
        delete this._stores['__idx__' + _idn];
        return { rows: [], changes: 0, lastInsertRowid: null };
    }

    // ── Detect CREATE INDEX IF NOT EXISTS (unsupported in MySQL dialect) before stripping
    var _createIdxIfNot = /\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+IF\s+NOT\s+EXISTS\b/i.test(sql);
    if (_createIdxIfNot) {
        sql = sql.replace(/\bCREATE\s+(UNIQUE\s+)?INDEX\s+IF\s+NOT\s+EXISTS\b/gi,
            function (m, u) { return 'CREATE ' + (u || '') + 'INDEX'; });
    }

    // ── Dialect preprocessing (REAL→FLOAT, AUTOINCREMENT→AUTO_INCREMENT, …)
    sql = this._preprocessSQL(sql);

    var ast;
    try {
        ast = _parser.astify(sql, { database: 'MySQL' });
    } catch (e) {
        throw new Error('SQL parse error: ' + e.message + '\n  SQL: ' + sql.slice(0, 200));
    }
    if (Array.isArray(ast)) ast = ast[0];
    if (!ast) return { rows: [], changes: 0, lastInsertRowid: null };

    // ── Re-inject IF NOT EXISTS flag for CREATE INDEX (was stripped for parser compatibility)
    if (_createIdxIfNot && ast.type === 'create' && (ast.keyword || '').toLowerCase() === 'index') {
        ast.if_not_exists = true;
    }

    var type = (ast.type || '').toLowerCase();
    if (type === 'create')   return this._create(ast, params);
    if (type === 'drop')     return this._drop(ast, params);
    if (type === 'select')   return { rows: this._select(ast, params), changes: 0, lastInsertRowid: null };
    if (type === 'insert')   return this._insert(ast, params);
    if (type === 'update')   return this._update(ast, params);
    if (type === 'delete')   return this._delete(ast, params);
    if (type === 'truncate') return this._truncate(ast, params);
    if (type === 'alter')    return { rows: [], changes: 0, lastInsertRowid: null };

    throw new Error('Unsupported SQL type: ' + ast.type);
};

// ─── DDL ──────────────────────────────────────────────────────────────────────

Engine.prototype._create = function (ast, params) {
    var kw = (ast.keyword || '').toLowerCase();

    if (kw === 'table') {
        var name     = tblName(ast.table);
        var ifNot    = ast.if_not_exists;
        if (this._catalog.getTable(name)) {
            if (ifNot) return { rows: [], changes: 0, lastInsertRowid: null };
            throw new Error('Table already exists: ' + name);
        }
        var cols = [], constraints = [];
        (ast.create_definitions || []).forEach(function (d) {
            // Column definition
            if (d.column && d.definition) {
                var cn   = colName(d.column);
                var type = (d.definition.dataType || d.definition.data_type || 'TEXT');
                var pk   = !!(d.primary_key || d.unique_or_primary === 'primary key');
                var nn   = !!(d.nullable && (d.nullable.value === 'not null' || d.nullable.value === 'NOT NULL')) || pk;
                var ai   = !!(d.auto_increment || (d.definition && d.definition.autoIncrement));
                // SQLite convention: INTEGER PRIMARY KEY is implicitly auto-increment
                if (!ai && pk && /^(INTEGER|INT|BIGINT)$/i.test(type.split('(')[0].trim())) ai = true;
                var def  = null;
                if (d.default_val) {
                    // default_val = {type:'default', value:<expr node>}
                    var _dv = (d.default_val.value !== undefined) ? d.default_val.value : d.default_val;
                    if (_dv && typeof _dv === 'object' && _dv.type) {
                        try { def = evalExpr(_dv, {}, [], {i: 0}); } catch (e) { def = null; }
                    } else {
                        def = (_dv !== null && _dv !== undefined) ? _dv : null;
                    }
                }
                cols.push({ name: cn, type: type, notNull: nn, defaultValue: def, primaryKey: pk, autoIncrement: ai });
            }
            // Table-level constraints
            else if (d.constraint_type) {
                var ct = (d.constraint_type || '').toLowerCase();
                var getCols = function (src) {
                    return (src || []).map(function (c) {
                        if (typeof c === 'string') return c;
                        return c.column || (c.expr && c.expr.column) || c.value || '';
                    });
                };
                if (ct === 'primary key' || ct === 'primary') {
                    constraints.push({ type: 'primary_key', columns: getCols(d.definition || d.index_columns) });
                } else if (ct === 'unique') {
                    constraints.push({ type: 'unique', columns: getCols(d.definition || d.index_columns) });
                }
            }
        });
        this._catalog.createTable(name, cols, constraints);
        this._store(name); // pre-init
        return { rows: [], changes: 0, lastInsertRowid: null };
    }

    if (kw === 'index') {
        var idxName   = ast.index;
        if (typeof idxName === 'object' && idxName !== null) idxName = idxName.value || idxName.name || '';
        var tableName = tblName(ast.on || ast.table);
        var unique    = !!(ast.index_type === 'unique' || ast.unique);
        var idxCols   = (ast.index_columns || []).map(function (c) {
            var n = typeof c === 'string' ? c : (c.column || (c.expr && (c.expr.column || c.expr.value)) || c.value || '');
            return { name: n, desc: !!(c.order && c.order.toUpperCase() === 'DESC') };
        });
        var ifNot2 = ast.if_not_exists;
        if (this._catalog.getIndex(idxName)) {
            if (ifNot2) return { rows: [], changes: 0, lastInsertRowid: null };
            throw new Error('Index already exists: ' + idxName);
        }
        this._catalog.createIndex(idxName, tableName, idxCols, unique);
        // Build index from existing data
        var tbl      = this._catalog.getTable(tableName);
        var store    = this._store(tableName);
        var idxStore = this._idxStore(idxName);
        var self     = this;
        store.all().forEach(function (e) {
            idxStore.set(self._idxKey(idxCols, e.value, tbl, e.key), { pk: e.key });
        });
        idxStore.flush();
        return { rows: [], changes: 0, lastInsertRowid: null };
    }

    throw new Error('Unsupported CREATE ' + ast.keyword);
};

Engine.prototype._drop = function (ast, params) {
    var kw = (ast.keyword || '').toLowerCase();

    if (kw === 'table') {
        var name = tblName(ast.name || ast.table);
        // ast.prefix = 'if exists' (confirmed by AST probe); ast.if_exists is undefined
        var ie = ast.if_exists || (ast.prefix && /if\s+exists/i.test(ast.prefix));
        this._catalog.dropTable(name, ie);
        var storePath = path.join(this._dbPath, 'tables', name + '.json');
        try { fs.unlinkSync(storePath); } catch (e) {}
        delete this._stores[name];
        return { rows: [], changes: 0, lastInsertRowid: null };
    }

    if (kw === 'index') {
        // ast.name may be {type:'column_ref', column:'idx'} — extract the string name
        var nameRaw = ast.name || ast.index;
        var name;
        if (typeof nameRaw === 'string') {
            name = nameRaw;
        } else if (nameRaw && typeof nameRaw === 'object') {
            name = nameRaw.column || nameRaw.name || nameRaw.value || nameRaw.table || '';
            if (typeof name === 'object') name = name.column || name.value || '';
        } else {
            name = '';
        }
        var ie = ast.if_exists || (ast.prefix && /if\s+exists/i.test(ast.prefix));
        this._catalog.dropIndex(name, ie);
        try { fs.unlinkSync(path.join(this._dbPath, 'indexes', name + '.json')); } catch (e) {}
        delete this._stores['__idx__' + name];
        return { rows: [], changes: 0, lastInsertRowid: null };
    }

    throw new Error('Unsupported DROP ' + ast.keyword);
};

Engine.prototype._truncate = function (ast) {
    var name  = tblName(ast.name || ast.table);
    var store = this._store(name);
    store.clear();
    store.flush();
    return { rows: [], changes: 0, lastInsertRowid: null };
};

// ─── INSERT ───────────────────────────────────────────────────────────────────

Engine.prototype._insert = function (ast, params) {
    var tableName = tblName(ast.table);
    var tbl       = this._catalog.getTable(tableName);
    if (!tbl) throw new Error('Table not found: ' + tableName);

    var suppliedCols = (ast.columns || []).map(colName);
    if (!suppliedCols.length) suppliedCols = tbl.columns.map(function (c) { return c.name; });

    var store   = this._store(tableName);
    var indexes = this._catalog.getTableIndexes(tableName);
    var pi      = { i: 0 };
    var self    = this;
    var changes = 0, lastId = null;

    (ast.values || []).forEach(function (valRow) {
        var vals = Array.isArray(valRow) ? valRow : (valRow.value || []);
        var row  = Object.create(null);

        // Fill defaults
        tbl.columns.forEach(function (col) {
            row[col.name] = col.defaultValue !== undefined ? col.defaultValue : null;
        });

        // Fill from supplied values
        suppliedCols.forEach(function (cn, i) {
            var expr = vals[i];
            row[cn] = expr ? evalExpr(expr, {}, params, pi) : null;
        });

        // Handle autoincrement
        if (tbl.autoRowid) {
            if (row['__rowid__'] == null) row['__rowid__'] = self._catalog.nextRowid(tableName);
            else self._catalog.bumpRowid(tableName, row['__rowid__']);
        } else {
            var pkCol = tbl.columns.find(function (c) { return c.primaryKey && c.autoIncrement; });
            if (pkCol && row[pkCol.name] == null) {
                row[pkCol.name] = self._catalog.nextRowid(tableName);
            } else if (pkCol && row[pkCol.name] != null) {
                self._catalog.bumpRowid(tableName, row[pkCol.name]);
            }
        }

        // Coerce types
        tbl.columns.forEach(function (col) {
            if (row[col.name] !== null && row[col.name] !== undefined) {
                row[col.name] = coerce(row[col.name], col);
            } else if (col.notNull && !col.autoIncrement && !tbl.autoRowid) {
                throw new Error('NOT NULL constraint failed: ' + tableName + '.' + col.name);
            }
        });

        // Build primary key
        var pk = tbl.autoRowid
            ? KC.encodeTuple([row['__rowid__']])
            : KC.encodeTuple(tbl.primaryKey.map(function (cn) { return row[cn]; }));

        // Check primary key uniqueness (store.set silently overwrites without this)
        if (store.get(pk) !== undefined) {
            var pkCols = tbl.autoRowid ? ['rowid'] : tbl.primaryKey;
            throw new Error('UNIQUE constraint failed: ' + tableName + '.' + pkCols.join(', '));
        }

        // Check unique constraints
        self._checkUnique(tableName, tbl, store, row, pk, null);

        store.set(pk, row);

        // Update secondary indexes
        indexes.forEach(function (idx) {
            self._idxStore(idx.name).set(self._idxKey(idx.columns, row, tbl, pk), { pk: pk });
        });

        lastId = tbl.autoRowid ? row['__rowid__']
               : (typeof row[tbl.primaryKey[0]] === 'number' ? row[tbl.primaryKey[0]] : null);
        changes++;
    });

    return { rows: [], changes: changes, lastInsertRowid: lastId };
};

Engine.prototype._checkUnique = function (tableName, tbl, store, newRow, newPk, oldPk) {
    // Check UNIQUE constraints
    tbl.constraints.forEach(function (c) {
        if (c.type !== 'unique') return;
        var key = KC.encodeTuple(c.columns.map(function (cn) { return newRow[cn]; }));
        // Linear scan for duplicate (will be replaced by unique index lookup)
        var all = store.all();
        for (var i = 0; i < all.length; i++) {
            if (all[i].key === oldPk) continue; // skip the row being replaced
            var existingKey = KC.encodeTuple(c.columns.map(function (cn) { return all[i].value[cn]; }));
            if (existingKey === key) {
                // Check for NULLs — UNIQUE ignores NULLs
                var hasNull = c.columns.some(function (cn) { return newRow[cn] === null || newRow[cn] === undefined; });
                if (!hasNull) throw new Error('UNIQUE constraint failed: ' + tableName + '(' + c.columns.join(',') + ')');
            }
        }
    });

    // Also check secondary UNIQUE indexes (from CREATE UNIQUE INDEX)
    var self = this;
    self._catalog.getTableIndexes(tableName).forEach(function (idx) {
        if (!idx.unique) return;
        // idx.columns is [{name, desc}] objects (stored as-is from CREATE INDEX)
        var colNames = idx.columns.map(function (c) { return typeof c === 'string' ? c : c.name; });
        var hasNull = colNames.some(function (cn) { return newRow[cn] == null; });
        if (hasNull) return; // UNIQUE allows NULLs
        // Build the value-only prefix (without pk) to scan index entries
        var valPrefix = KC.encodeTuple(colNames.map(function (cn) { return newRow[cn]; }));
        var idxStore = self._idxStore(idx.name);
        var all = idxStore.all();
        for (var j = 0; j < all.length; j++) {
            var entryPk = all[j].value.pk;
            if (entryPk === newPk || entryPk === oldPk) continue;
            // The stored key is encodeTuple([...colValues, pk]); check value prefix
            if (all[j].key.indexOf(valPrefix) === 0) {
                throw new Error('UNIQUE constraint failed: ' + tableName + '.' + colNames.join(', '));
            }
        }
    });
};

// ─── SELECT ───────────────────────────────────────────────────────────────────

Engine.prototype._select = function (ast, params) {
    var pi = { i: 0 };

    // FROM + JOINs
    var rows = this._fromClause(ast.from, params, pi);

    // WHERE — reset pi.i before each row so positional ? are not exhausted across rows
    if (ast.where) {
        var _whereStart = pi.i;
        rows = rows.filter(function (r) { pi.i = _whereStart; return evalExpr(ast.where, r, params, pi); });
    }

    // GROUP BY / aggregates
    var needGroup = ast.groupby || hasAggr(ast.columns);
    if (needGroup) {
        rows = this._groupRows(rows, ast, params, pi);
        if (ast.having) {
            var _havStart = pi.i;
            rows = rows.filter(function (r) { pi.i = _havStart; return evalExpr(ast.having, r, params, pi); });
        }
        if (ast.orderby && ast.orderby.length) rows = this._orderBy(rows, ast.orderby, params, pi);
    } else {
        // ORDER BY before _project so sort columns not in SELECT are still available
        if (ast.orderby && ast.orderby.length) rows = this._orderBy(rows, ast.orderby, params, pi);
        rows = this._project(rows, ast.columns, params, pi);
        if (ast.having) {
            var _havStart2 = pi.i;
            rows = rows.filter(function (r) { pi.i = _havStart2; return evalExpr(ast.having, r, params, pi); });
        }
    }

    // DISTINCT — must happen before LIMIT so LIMIT applies to the distinct set
    if (ast.distinct === 'DISTINCT') {
        var seen = new Set();
        rows = rows.filter(function (r) {
            var k = JSON.stringify(r);
            if (seen.has(k)) return false;
            seen.add(k); return true;
        });
    }

    // LIMIT / OFFSET
    if (ast.limit) {
        var offset = 0, limit = Infinity;
        var lv = ast.limit;
        if (Array.isArray(lv.value)) {
            if (lv.value.length === 2) {
                var _lv0 = evalExpr(lv.value[0], {}, params, pi);
                var _lv1 = evalExpr(lv.value[1], {}, params, pi);
                if ((lv.seperator || '').toLowerCase() === 'offset') {
                    // LIMIT count OFFSET offset  (value[0]=count, value[1]=offset)
                    limit  = (_lv0 !== null && _lv0 !== undefined) ? Number(_lv0) : Infinity;
                    offset = (_lv1 !== null && _lv1 !== undefined) ? Number(_lv1) : 0;
                } else {
                    // MySQL comma form: LIMIT offset, count
                    offset = (_lv0 !== null && _lv0 !== undefined) ? Number(_lv0) : 0;
                    limit  = (_lv1 !== null && _lv1 !== undefined) ? Number(_lv1) : Infinity;
                }
            } else {
                var _lv0s = evalExpr(lv.value[0], {}, params, pi);
                limit = (_lv0s !== null && _lv0s !== undefined) ? Number(_lv0s) : Infinity;
            }
        } else {
            var _lvn = evalExpr(lv, {}, params, pi);
            limit = (_lvn !== null && _lvn !== undefined) ? Number(_lvn) : Infinity;
        }
        if (ast.offset) offset = Number(evalExpr(ast.offset, {}, params, pi) || 0);
        // Negative LIMIT = no limit (SQLite semantics)
        if (limit < 0) limit = Infinity;
        rows = rows.slice(offset, isFinite(limit) ? offset + limit : undefined);
    }

    return rows;
};

Engine.prototype._fromClause = function (fromArr, params, pi) {
    if (!fromArr || !fromArr.length) return [{}];
    var rows = null;
    var self = this;

    fromArr.forEach(function (item) {
        if (!item) return;
        var joinType  = item.join;
        var tableName = item.table || item.name;
        if (typeof tableName === 'object' && tableName !== null)
            tableName = tableName.table || tableName.value || tableName.name;
        var alias = item.as || tableName;

        // Subquery in FROM
        if (item.expr && item.expr.type === 'select') {
            var sub = self._select(item.expr, params);
            var pref = sub.map(function (r) { return prefixRow(r, alias); });
            rows = rows ? innerJoin(rows, pref, item.on, params, pi) : pref;
            return;
        }

        if (!tableName) return;
        var tbl = self._catalog.getTable(tableName);
        if (!tbl) throw new Error('Table not found: ' + tableName);
        var store    = self._store(tableName);
        var tableRows = store.all().map(function (e) { return prefixRow(e.value, alias); });

        if (!rows) {
            rows = tableRows;
        } else if (!joinType || joinType.toUpperCase() === 'INNER JOIN' || joinType.toUpperCase() === 'JOIN' || joinType.toUpperCase() === 'CROSS JOIN') {
            rows = item.on ? innerJoin(rows, tableRows, item.on, params, pi) : crossJoin(rows, tableRows);
        } else if (joinType.toUpperCase() === 'LEFT JOIN' || joinType.toUpperCase() === 'LEFT OUTER JOIN') {
            rows = leftJoin(rows, tableRows, item.on, params, pi);
        } else {
            rows = item.on ? innerJoin(rows, tableRows, item.on, params, pi) : crossJoin(rows, tableRows);
        }
    });
    return rows || [];
};

function prefixRow(row, alias) {
    if (!alias) return row;
    var r = Object.create(null);
    var keys = Object.keys(row);
    for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        r[k] = row[k];                   // bare name (for single-table queries)
        r[alias + '.' + k] = row[k];     // qualified name (for joins)
    }
    return r;
}

function crossJoin(left, right) {
    var out = [];
    for (var i = 0; i < left.length; i++)
        for (var j = 0; j < right.length; j++)
            out.push(Object.assign(Object.create(null), left[i], right[j]));
    return out;
}

function innerJoin(left, right, on, params, pi) {
    var out = [];
    for (var i = 0; i < left.length; i++) {
        for (var j = 0; j < right.length; j++) {
            var combined = Object.assign(Object.create(null), left[i], right[j]);
            if (!on || evalExpr(on, combined, params, pi)) out.push(combined);
        }
    }
    return out;
}

function leftJoin(left, right, on, params, pi) {
    var out = [];
    var nullRight = Object.create(null);
    if (right.length > 0) Object.keys(right[0]).forEach(function (k) { nullRight[k] = null; });
    for (var i = 0; i < left.length; i++) {
        var matched = false;
        for (var j = 0; j < right.length; j++) {
            var combined = Object.assign(Object.create(null), left[i], right[j]);
            if (!on || evalExpr(on, combined, params, pi)) { out.push(combined); matched = true; }
        }
        if (!matched) out.push(Object.assign(Object.create(null), left[i], nullRight));
    }
    return out;
}

Engine.prototype._project = function (rows, columns, params, pi) {
    function isStarExpr(expr) {
        return expr && (expr.type === 'star' ||
            (expr.type === 'column_ref' && expr.column === '*' && !expr.table));
    }
    if (!columns || columns === '*' ||
        (Array.isArray(columns) && columns.length === 1 && columns[0].expr && isStarExpr(columns[0].expr))) {
        return rows.map(stripQualified);
    }
    return rows.map(function (row) {
        var r = Object.create(null);
        columns.forEach(function (col) {
            if (!col || !col.expr) return;
            if (isStarExpr(col.expr)) { Object.assign(r, stripQualified(row)); return; }
            var v    = evalExpr(col.expr, row, params, pi);
            var name = col.as || (col.expr.type === 'column_ref' ? String(col.expr.column || '') : null)
                    || exprAlias(col.expr);
            r[name] = v;
        });
        return r;
    });
};

function stripQualified(row) {
    var r = Object.create(null);
    Object.keys(row).forEach(function (k) {
        if (!k.includes('.')) r[k] = row[k];
    });
    return r;
}

function exprAlias(expr) {
    if (!expr) return 'expr';
    if (expr.type === 'aggr_func') {
        var argStr = expr.args && expr.args.expr
            ? (expr.args.expr.type === 'star' ? '*' : (expr.args.expr.column || ''))
            : '';
        return expr.name.toLowerCase() + '(' + argStr + ')';
    }
    if (expr.type === 'function') return (expr.name || 'expr').toLowerCase() + '()';
    return 'expr';
}

function extractAggrExprs(expr) {
    if (!expr) return [];
    if (expr.type === 'aggr_func') return [expr];
    var out = [];
    ['left', 'right', 'args', 'expr', 'condition', 'result'].forEach(function (k) {
        var v = expr[k];
        if (!v) return;
        if (Array.isArray(v)) {
            v.forEach(function (e) { if (e && typeof e === 'object') extractAggrExprs(e).forEach(function (r) { out.push(r); }); });
        } else if (typeof v === 'object') {
            extractAggrExprs(v).forEach(function (r) { out.push(r); });
        }
    });
    return out;
}

Engine.prototype._groupRows = function (rows, ast, params, pi) {
    var columns    = ast.columns;
    var groupByArr = ast.groupby || [];
    var groups     = Object.create(null);
    var order      = [];

    rows.forEach(function (row) {
        var key = groupByArr.length
            ? JSON.stringify(groupByArr.map(function (g) { return evalExpr(g, row, params, pi); }))
            : '__all__';
        if (!groups[key]) { groups[key] = []; order.push(key); }
        groups[key].push(row);
    });

    return order.map(function (key) {
        var group = groups[key];
        var rep   = group[0] || {};
        var r     = Object.create(null);

        // Group-by values into result
        groupByArr.forEach(function (g) {
            var n = (g.type === 'column_ref')
                ? (typeof g.column === 'string' ? g.column : (g.column.column || g.column.value || 'grp'))
                : 'grp';
            r[n] = evalExpr(g, rep, params, pi);
        });

        // Project SELECT columns with aggregate evaluation
        if (!columns || columns === '*') {
            r['count(*)'] = group.length;
        } else {
            columns.forEach(function (col) {
                if (!col || !col.expr) return;
                var v;
                var isAggFn = col.expr.type === 'aggr_func' ||
                    (col.expr.type === 'function' &&
                     ['COUNT','SUM','AVG','MIN','MAX','GROUP_CONCAT'].indexOf((col.expr.name||'').toUpperCase()) >= 0);
                if (col.expr.type === 'aggr_func') {
                    v = evalAggr(col.expr, group, params, pi);
                } else if (col.expr.type === 'function' &&
                           ['COUNT','SUM','AVG','MIN','MAX','GROUP_CONCAT'].indexOf((col.expr.name||'').toUpperCase()) >= 0) {
                    // node-sql-parser sometimes uses 'function' for aggregate functions
                    var aggrNode = { name: col.expr.name, args: col.expr.args };
                    v = evalAggr(aggrNode, group, params, pi);
                } else {
                    v = evalExpr(col.expr, rep, params, pi);
                }
                var name = col.as || (col.expr.type === 'column_ref'
                    ? String(col.expr.column || '')
                    : exprAlias(col.expr));
                r[name] = v;
                // Also store by expression alias so HAVING can find the pre-computed value
                if (isAggFn) {
                    var _eAlias = exprAlias(col.expr.type === 'aggr_func' ? col.expr
                        : { name: col.expr.name, args: col.expr.args });
                    if (_eAlias !== name) r[_eAlias] = v;
                }
            });
        }

        // Pre-compute aggregates referenced in HAVING but not in SELECT
        if (ast.having) {
            extractAggrExprs(ast.having).forEach(function (aggrNode) {
                var _ek = exprAlias(aggrNode);
                if (!(_ek in r)) r[_ek] = evalAggr(aggrNode, group, params, pi);
            });
        }

        return r;
    });

};

// Wrap _groupRows to inject the empty-table-aggregate sentinel after the map
(function () {
    var _orig = Engine.prototype._groupRows;
    Engine.prototype._groupRows = function (rows, ast, params, pi) {
        var result = _orig.call(this, rows, ast, params, pi);
        var columns = ast.columns;
        var groupByArr = ast.groupby || [];
        if (result.length === 0 && groupByArr.length === 0 && rows.length === 0 && hasAggr(columns)) {
            var emptyRow = Object.create(null);
            if (columns && columns !== '*') {
                columns.forEach(function (col) {
                    if (!col || !col.expr) return;
                    var v;
                    if (col.expr.type === 'aggr_func') {
                        v = evalAggr(col.expr, [], params, pi);
                    } else if (col.expr.type === 'function' &&
                        ['COUNT','SUM','AVG','MIN','MAX','GROUP_CONCAT'].indexOf((col.expr.name||'').toUpperCase()) >= 0) {
                        v = evalAggr({ name: col.expr.name, args: col.expr.args }, [], params, pi);
                    } else {
                        v = null;
                    }
                    var name = col.as || (col.expr.type === 'column_ref'
                        ? String(col.expr.column || '')
                        : exprAlias(col.expr));
                    emptyRow[name] = v;
                    if (col.expr.type === 'aggr_func') {
                        var _ek = exprAlias(col.expr);
                        if (_ek !== name) emptyRow[_ek] = v;
                    }
                });
            } else {
                emptyRow['count(*)'] = 0;
            }
            return [emptyRow];
        }
        return result;
    };
}());

Engine.prototype._orderBy = function (rows, orderby, params, pi) {
    return rows.slice().sort(function (a, b) {
        for (var i = 0; i < orderby.length; i++) {
            var o    = orderby[i];
            var av   = evalExpr(o.expr, a, params, pi);
            var bv   = evalExpr(o.expr, b, params, pi);
            var desc = (o.type || '').toUpperCase() === 'DESC';
            if (av === null && bv === null) continue;
            if (av === null) return desc ? 1 : -1;
            if (bv === null) return desc ? -1 : 1;
            var cmp = av < bv ? -1 : av > bv ? 1 : 0;
            if (cmp) return desc ? -cmp : cmp;
        }
        return 0;
    });
};

// ─── UPDATE ───────────────────────────────────────────────────────────────────

Engine.prototype._update = function (ast, params) {
    var tableName = tblName(ast.table);
    var tbl       = this._catalog.getTable(tableName);
    if (!tbl) throw new Error('Table not found: ' + tableName);

    var store   = this._store(tableName);
    var indexes = this._catalog.getTableIndexes(tableName);
    var pi      = { i: 0 };
    var self    = this;

    var _updWhereStart = pi.i;
    var candidates = ast.where
        ? store.all().filter(function (e) { pi.i = _updWhereStart; return evalExpr(ast.where, e.value, params, pi); })
        : store.all().slice();

    var changes = 0;
    candidates.forEach(function (entry) {
        var old = entry.value;
        var row = Object.assign(Object.create(null), old);

        (ast.set || []).forEach(function (s) {
            var cn = colName(s.column);
            row[cn] = evalExpr(s.value, row, params, pi);
        });

        tbl.columns.forEach(function (col) {
            if (row[col.name] !== null && row[col.name] !== undefined)
                row[col.name] = coerce(row[col.name], col);
        });

        // Check unique
        self._checkUnique(tableName, tbl, store, row, entry.key, entry.key);

        // Remove old index entries
        indexes.forEach(function (idx) {
            self._idxStore(idx.name).delete(self._idxKey(idx.columns, old, tbl, entry.key));
        });

        store.set(entry.key, row);

        indexes.forEach(function (idx) {
            self._idxStore(idx.name).set(self._idxKey(idx.columns, row, tbl, entry.key), { pk: entry.key });
        });
        changes++;
    });

    return { rows: [], changes: changes, lastInsertRowid: null };
};

// ─── DELETE ───────────────────────────────────────────────────────────────────

Engine.prototype._delete = function (ast, params) {
    var tableName = tblName(ast.from || ast.table);
    var tbl       = this._catalog.getTable(tableName);
    if (!tbl) throw new Error('Table not found: ' + tableName);

    var store   = this._store(tableName);
    var indexes = this._catalog.getTableIndexes(tableName);
    var pi      = { i: 0 };
    var self    = this;

    var _delWhereStart = pi.i;
    var candidates = ast.where
        ? store.all().filter(function (e) { pi.i = _delWhereStart; return evalExpr(ast.where, e.value, params, pi); })
        : store.all().slice();

    candidates.forEach(function (entry) {
        indexes.forEach(function (idx) {
            self._idxStore(idx.name).delete(self._idxKey(idx.columns, entry.value, tbl, entry.key));
        });
        store.delete(entry.key);
    });

    return { rows: [], changes: candidates.length, lastInsertRowid: null };
};

// ─── Index key helper ─────────────────────────────────────────────────────────

Engine.prototype._idxKey = function (idxCols, row, tbl, pkKey) {
    var parts = idxCols.map(function (c) { return row[c.name]; });
    parts.push(pkKey); // append PK to make secondary-index key unique
    return KC.encodeTuple(parts);
};

module.exports = Engine;
