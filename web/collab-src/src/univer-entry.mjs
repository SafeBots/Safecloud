/**
 * univer-entry.mjs
 *
 * Bundled as UniverBundle IIFE.  Exposes:
 *   UniverBundle.createUniverSheets(containerId, ydoc, opts) → { univerAPI, destroy }
 *   UniverBundle.createUniverDocs(containerId, ydoc, opts)   → { univerAPI, destroy }
 *
 * opts = { logFn }  (optional function(msg, level))
 *
 * Yjs sync:
 *   Sheets → Y.Map('cells'), key="row:col" (0-based), value=JSON cell data string
 *   Docs   → Y.Map('doc'),   key='snapshot', value=JSON IDocumentBody string (debounced)
 */

// ── CSS imports (inlined as text via esbuild loader: {'.css':'text'}) ──────
import sheetsCss from '@univerjs/preset-sheets-core/lib/index.css';
import docsCss   from '@univerjs/preset-docs-core/lib/index.css';

// ── Univer ──────────────────────────────────────────────────────────────────
import { createUniver, LocaleType, merge } from '@univerjs/presets';
import { UniverSheetsCorePreset } from '@univerjs/preset-sheets-core';
import enSheetsLocale from '@univerjs/preset-sheets-core/locales/en-US';
import { UniverDocsCorePreset } from '@univerjs/preset-docs-core';
import enDocsLocale   from '@univerjs/preset-docs-core/locales/en-US';

// ── CSS injection helper ─────────────────────────────────────────────────────
let _cssInjected = { sheets: false, docs: false };
function injectCss(key, cssText) {
    if (_cssInjected[key]) return;
    _cssInjected[key] = true;
    var el = document.createElement('style');
    el.dataset.univerId = key;
    el.textContent = cssText;
    document.head.appendChild(el);
}

// ── Sheets: set-range-values command ID ─────────────────────────────────────
const SET_RANGE_VALUES_CMD = 'sheet.command.set-range-values';

/**
 * createUniverSheets — creates a Univer spreadsheet editor bound to a Yjs doc.
 *
 * @param {string} containerId  id of the DOM element to mount into
 * @param {Y.Doc}  ydoc         Yjs document (use ydoc.getMap('cells'))
 * @param {object} opts         { logFn, initialData }
 * @returns {{ univerAPI, destroy }}
 */
export function createUniverSheets(containerId, ydoc, opts) {
    opts = opts || {};
    var logFn = opts.logFn || function(){};
    injectCss('sheets', sheetsCss);

    var ycells = ydoc.getMap('cells');  // key="row:col", value=JSON string

    var { univer, univerAPI } = createUniver({
        locale: LocaleType.EN_US,
        locales: { [LocaleType.EN_US]: merge({}, enSheetsLocale) },
        collaboration: true,   // disables built-in undo/redo (Yjs manages history)
        presets: [
            UniverSheetsCorePreset({
                container: containerId,
                disableAutoFocus: true,
            }),
        ],
    });

    // Create the initial workbook
    var workbook = univerAPI.createWorkbook({
        name: 'Sheet1',
        sheets: [{
            id: 'sheet1',
            name: 'Sheet1',
            cellData: {},
            rowCount: 200,
            columnCount: 50,
        }]
    });

    var _applyingRemote = false;

    // ── LOCAL → Y.Map ────────────────────────────────────────────────────────
    // Listen to SetRangeValuesCommand, extract changed cells, write to Y.Map
    univerAPI.addEvent(univerAPI.Event.CommandExecuted, function(event) {
        if (_applyingRemote) return;
        if (event.id !== SET_RANGE_VALUES_CMD) return;

        var params = event.params;
        if (!params) return;

        // params.range = { startRow, startColumn, endRow, endColumn }
        // params.value = { relRow: { relCol: ICellData } }  (relative to range start)
        var range = params.range;
        var value = params.value;
        if (!range || !value) return;

        var startRow = range.startRow || 0;
        var startCol = range.startColumn || 0;

        // After command runs, re-read actual cell values from workbook for safety
        // This avoids format ambiguity with the params.value matrix
        try {
            var wb = univerAPI.getActiveWorkbook();
            if (!wb) return;
            var ws = wb.getActiveSheet();
            if (!ws) return;

            var endRow = range.endRow;
            var endCol = range.endColumn;

            ydoc.transact(function() {
                for (var r = startRow; r <= endRow; r++) {
                    for (var c = startCol; c <= endCol; c++) {
                        var key = r + ':' + c;
                        // getRange(row, col, numRows, numCols)
                        var fRange = ws.getRange(r, c, 1, 1);
                        // getCellData() on a 1×1 range returns the ICellData object
                        var cellData = fRange.getCellData ? fRange.getCellData() : null;
                        if (cellData && Object.keys(cellData).length > 0) {
                            ycells.set(key, JSON.stringify(cellData));
                        } else {
                            ycells.delete(key);
                        }
                    }
                }
            });
            logFn('cells → Y.Map [' + startRow + ':' + startCol + '..' + endRow + ':' + endCol + ']', 'info');
        } catch(e) {
            // Fallback: use params.value directly with relative offset
            try {
                ydoc.transact(function() {
                    Object.keys(value).forEach(function(relRowStr) {
                        var rowObj = value[relRowStr];
                        if (!rowObj) return;
                        var absRow = startRow + parseInt(relRowStr, 10);
                        Object.keys(rowObj).forEach(function(relColStr) {
                            var cell = rowObj[relColStr];
                            var absCol = startCol + parseInt(relColStr, 10);
                            var key = absRow + ':' + absCol;
                            if (cell && Object.keys(cell).length > 0) {
                                ycells.set(key, JSON.stringify(cell));
                            } else {
                                ycells.delete(key);
                            }
                        });
                    });
                });
            } catch(e2) {
                logFn('cells sync error: ' + e2.message, 'warn');
            }
        }
    });

    // ── Y.Map → LOCAL ────────────────────────────────────────────────────────
    ycells.observe(function(event) {
        if (event.transaction.local) return;
        _applyingRemote = true;
        try {
            var wb = univerAPI.getActiveWorkbook();
            if (!wb) return;
            var ws = wb.getActiveSheet();
            if (!ws) return;

            event.changes.keys.forEach(function(change, key) {
                var parts = key.split(':');
                var row = parseInt(parts[0], 10);
                var col = parseInt(parts[1], 10);
                if (isNaN(row) || isNaN(col)) return;

                if (change.action === 'delete') {
                    // Clear the cell
                    ws.getRange(row, col, 1, 1).setValues([[null]]);
                } else {
                    var rawVal = ycells.get(key);
                    if (!rawVal) return;
                    try {
                        var cellData = JSON.parse(rawVal);
                        // setValues with a 2D array: [[value]]
                        // For plain values, extract 'v'
                        var v = (cellData && cellData.v !== undefined) ? cellData.v : null;
                        ws.getRange(row, col, 1, 1).setValues([[v]]);
                    } catch(e) {
                        // If parse fails, treat as plain string
                        ws.getRange(row, col, 1, 1).setValues([[rawVal]]);
                    }
                }
            });
            logFn('← remote cells applied', 'info');
        } catch(e) {
            logFn('remote cells error: ' + e.message, 'warn');
        } finally {
            _applyingRemote = false;
        }
    });

    // Apply any initial state from Y.Map
    var allKeys = Array.from(ycells.keys());
    if (allKeys.length > 0) {
        try {
            var wb = univerAPI.getActiveWorkbook();
            var ws = wb && wb.getActiveSheet();
            if (ws) {
                _applyingRemote = true;
                allKeys.forEach(function(key) {
                    var parts = key.split(':');
                    var r = parseInt(parts[0], 10);
                    var c = parseInt(parts[1], 10);
                    if (isNaN(r) || isNaN(c)) return;
                    var raw = ycells.get(key);
                    if (!raw) return;
                    try {
                        var cell = JSON.parse(raw);
                        var v = cell && cell.v !== undefined ? cell.v : null;
                        ws.getRange(r, c, 1, 1).setValues([[v]]);
                    } catch(e) {}
                });
                _applyingRemote = false;
            }
        } catch(e) {}
    }

    logFn('Univer Sheets ready', 'ok');

    return {
        univerAPI: univerAPI,
        destroy: function() {
            try { univer.dispose(); } catch(e) {}
        }
    };
}

// ── Docs: snapshot-based sync ────────────────────────────────────────────────
const RICH_TEXT_MUTATION = 'doc.mutation.rich-text-editing';
const DOC_SNAPSHOT_KEY   = 'snapshot';

/**
 * createUniverDocs — creates a Univer document editor bound to a Yjs doc.
 *
 * @param {string} containerId
 * @param {Y.Doc}  ydoc         Yjs document — uses ydoc.getMap('doc')
 * @param {object} opts         { logFn }
 * @returns {{ univerAPI, destroy }}
 */
export function createUniverDocs(containerId, ydoc, opts) {
    opts = opts || {};
    var logFn = opts.logFn || function(){};
    injectCss('docs', docsCss);

    var ydocMap = ydoc.getMap('doc');  // key='snapshot', value=JSON string

    var { univer, univerAPI } = createUniver({
        locale: LocaleType.EN_US,
        locales: { [LocaleType.EN_US]: merge({}, enDocsLocale) },
        collaboration: true,
        presets: [
            UniverDocsCorePreset({
                container: containerId,
            }),
        ],
    });

    // Create an initial document
    univerAPI.createDocument({
        id: 'doc1',
        body: {
            dataStream: '\r\n',
            textRuns: [],
            paragraphs: [{ startIndex: 0 }],
        },
        documentStyle: {},
    });

    var _applyingRemote = false;
    var _debounceTimer = null;

    // ── LOCAL → Y.Map (debounced snapshot) ──────────────────────────────────
    univerAPI.addEvent(univerAPI.Event.CommandExecuted, function(event) {
        if (_applyingRemote) return;
        // Capture any doc-related command (typing, formatting, etc.)
        if (!event.id || event.id.indexOf('doc') === -1) return;

        clearTimeout(_debounceTimer);
        _debounceTimer = setTimeout(function() {
            try {
                var doc = univerAPI.getActiveDocument
                    ? univerAPI.getActiveDocument()
                    : null;
                if (!doc) return;

                // Serialize the document body to JSON
                var snapshot = null;
                if (doc.getSnapshot) {
                    snapshot = JSON.stringify(doc.getSnapshot());
                } else if (doc.getBody) {
                    snapshot = JSON.stringify({ body: doc.getBody() });
                }
                if (!snapshot) return;

                ydoc.transact(function() {
                    ydocMap.set(DOC_SNAPSHOT_KEY, snapshot);
                });
                logFn('doc → Y.Map snapshot', 'info');
            } catch(e) {
                logFn('doc snapshot error: ' + e.message, 'warn');
            }
        }, 300);
    });

    // ── Y.Map → LOCAL (apply snapshot) ──────────────────────────────────────
    ydocMap.observe(function(event) {
        if (event.transaction.local) return;
        if (!event.changes.keys.has(DOC_SNAPSHOT_KEY)) return;

        clearTimeout(_debounceTimer);
        _applyingRemote = true;
        try {
            var raw = ydocMap.get(DOC_SNAPSHOT_KEY);
            if (!raw) return;
            var snapshot = JSON.parse(raw);

            var doc = univerAPI.getActiveDocument
                ? univerAPI.getActiveDocument()
                : null;
            if (!doc) return;

            // Apply snapshot — use setContent if available, else replaceBody
            if (doc.setContent) {
                doc.setContent(snapshot);
            } else if (doc.replaceBody && snapshot.body) {
                doc.replaceBody(snapshot.body);
            }
            logFn('← remote doc snapshot applied', 'info');
        } catch(e) {
            logFn('remote doc error: ' + e.message, 'warn');
        } finally {
            _applyingRemote = false;
        }
    });

    // Apply initial snapshot if present
    var existingSnap = ydocMap.get(DOC_SNAPSHOT_KEY);
    if (existingSnap) {
        try {
            var snapObj = JSON.parse(existingSnap);
            var doc = univerAPI.getActiveDocument ? univerAPI.getActiveDocument() : null;
            if (doc) {
                _applyingRemote = true;
                if (doc.setContent) doc.setContent(snapObj);
                else if (doc.replaceBody && snapObj.body) doc.replaceBody(snapObj.body);
                _applyingRemote = false;
            }
        } catch(e) {}
    }

    logFn('Univer Docs ready', 'ok');

    return {
        univerAPI: univerAPI,
        destroy: function() {
            clearTimeout(_debounceTimer);
            try { univer.dispose(); } catch(e) {}
        }
    };
}
