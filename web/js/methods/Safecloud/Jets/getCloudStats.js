/**
 * Q.Safecloud.Jets.getCloudStats — live Cloud payer statistics.
 *
 * Accumulated in memory since page load by Jets.get()/put(). Poll from a
 * dashboard (e.g. the demo page's payer strip).
 *
 * @method getCloudStats
 * @return {Object} {
 *   chunksFetched, bytesFetched, fetchedMB,
 *   chunksUploaded, bytesUploaded, uploadedMB,
 *   paymentsSigned,
 *   paidWei   {String}  total authorised across signed tokens (wei, decimal string)
 *   paidSbux  {Number}  paidWei / 1e6 (Safebux has 6 decimals)
 *   payerAddress {String|null}
 * }
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Jets_getCloudStats() {
        var s = _.cloudStats;
        var paidSbux = 0;
        try { paidSbux = Number(BigInt(s.paidWei)) / 1e6; } catch (e) {}
        return {
            chunksFetched:  s.chunksFetched,
            bytesFetched:   s.bytesFetched,
            fetchedMB:      s.bytesFetched / 1048576,
            chunksUploaded: s.chunksUploaded,
            bytesUploaded:  s.bytesUploaded,
            uploadedMB:     s.bytesUploaded / 1048576,
            paymentsSigned: s.paymentsSigned,
            paidWei:        s.paidWei,
            paidSbux:       paidSbux,
            payerAddress:   Q.Safecloud.Jets.cloudEvmAddress || null
        };
    };
});
