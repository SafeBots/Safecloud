/**
 * Q.Safecloud.Drops.getStats — return live Drop performance statistics.
 *
 * All values are derived from in-memory state accumulated since the last
 * page load. Call periodically (e.g. every second) from a dashboard.
 *
 * @method getStats
 * @return {Object} {
 *   servedBytes   {Number}  total bytes served via GET (ciphertext estimate)
 *   servedMB      {Number}  servedBytes / 1048576
 *   servedChunks  {Number}  total chunks served
 *   storedChunks  {Number}  total chunks written
 *   storedBytes   {Number}  usedBytes (current storage footprint)
 *   storedMB      {Number}  usedBytes / 1048576
 *   safebuxEarned {Number}  estimated SBUX at 0.02 per MB served
 *   dropId        {String|null}
 *   evmAddress    {String|null}
 *   prollyRoot    {String|null}
 *   uptime        {Number}  ms since _initTime (if set)
 * }
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Drops_getStats() {
        var s = _._state;
        var servedBytes = s.servedBytes  || 0;
        var storedBytes = s.usedBytes    || 0;
        return {
            servedBytes:   servedBytes,
            servedMB:      servedBytes / 1048576,
            servedChunks:  s.servedChunks  || 0,
            storedChunks:  s.storedChunks  || 0,
            storedBytes:   storedBytes,
            storedMB:      storedBytes / 1048576,
            safebuxEarned: s.safebuxEarned || 0,
            dropId:        s.dropId        || null,
            evmAddress:    s.evmAddress    || null,
            prollyRoot:    s.prollyRoot    || null,
            uptime:        s._initTime ? (Date.now() - s._initTime) : null
        };
    };
});
