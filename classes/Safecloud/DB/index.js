'use strict';
/**
 * Safecloud/DB — drop-in replacement for better-sqlite3
 *
 * Usage (identical to better-sqlite3):
 *
 *   const Database = require('./classes/Safecloud/DB');
 *   const db = new Database('path/to/mydb');
 *   db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)');
 *   const insert = db.prepare('INSERT INTO users (name) VALUES (?)');
 *   insert.run('Alice');
 *   const all = db.prepare('SELECT * FROM users').all();
 *   db.close();
 */

var Database = require('./Database');

// Expose sub-modules for direct access when needed
Database.Engine      = require('./Engine');
Database.Catalog     = require('./Catalog');
Database.TableStore  = require('./TableStore');
Database.KeyCodec    = require('./KeyCodec');
Database.Statement   = require('./Statement');
Database.MySQLServer = require('./MySQLServer');

module.exports = Database;
