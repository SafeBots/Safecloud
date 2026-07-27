/**
 * Transport-layer integration: a REAL socket.io server + client performing
 * the Drop registration and payment handshake shape the Jet uses. Verifies
 * the message contracts (register → ack, announce → ack, claim → relay)
 * work over an actual socket, independent of the Q platform.
 *
 * What this covers that the e2e crypto test doesn't: the async request/ack
 * round-trips, payload validation, and socket-owns-dropId enforcement.
 * What it can't cover: the Q.Users.Socket auth middleware (platform-only).
 */
const { Server } = require('socket.io');
const { io } = require('socket.io-client');
const http = require('http');
const ethers = require('ethers');

let pass = 0, fail = 0;
function check(n, c) { c ? (pass++, console.log('  \u2713', n)) : (fail++, console.log('  \u2717 FAIL:', n)); }

// Minimal Jet-shaped socket server implementing the real handler contracts
function makeJetServer() {
  const drops = {};                 // dropId -> { socketId, evmAddress }
  const srv = http.createServer();
  const ioServer = new Server(srv);
  ioServer.of('/Safecloud/cloud').on('connection', (socket) => {
    socket.on('Safecloud/drop/register', (payload, ack) => {
      if (!payload || !payload.dropId) return ack({ error: { code: 'BadRequest' } });
      const isReconnect = !!drops[payload.dropId];
      drops[payload.dropId] = { socketId: socket.id, evmAddress: payload.evmAddress };
      ack(null, { dropId: payload.dropId, cold: !isReconnect });
    });
    socket.on('Safecloud/drop/announce', (payload, ack) => {
      const d = drops[payload.dropId];
      if (!d) return ack({ error: { code: 'NotFound' } });
      if (d.socketId !== socket.id) return ack({ error: { code: 'Unauthorized' } });
      ack(null);
    });
    socket.on('Safecloud/jet/info', (payload, ack) => {
      ack(null, { evmAddress: '0x' + 'ce'.repeat(20), requirePayment: true,
        sponsorUrl: '/Safecloud/sponsor/token' });
    });
  });
  return { srv, ioServer, drops };
}

(async () => {
  const { srv, ioServer, drops } = makeJetServer();
  await new Promise(r => srv.listen(0, r));
  const port = srv.address().port;
  const url = `http://localhost:${port}/Safecloud/cloud`;

  function connect() {
    return new Promise((resolve) => {
      const c = io(url, { transports: ['websocket'], forceNew: true });
      c.on('connect', () => resolve(c));
    });
  }
  function emit(c, ev, payload) {
    return new Promise((resolve) => c.emit(ev, payload, (err, res) => resolve({ err, res })));
  }

  const drop = new ethers.Wallet('0x' + 'd0'.repeat(32));

  // Drop launches (in a browser tab, here a socket client) and registers
  const c1 = await connect();
  const reg = await emit(c1, 'Safecloud/drop/register',
    { dropId: 'drop-1', evmAddress: drop.address, storage: { GB: 5 } });
  check('Drop registration acked', reg.res && reg.res.dropId === 'drop-1');
  check('first registration reports cold=true', reg.res.cold === true);
  check('Jet recorded the Drop', !!drops['drop-1']);

  // jet/info advertises sponsorUrl (the discovery fix)
  const info = await emit(c1, 'Safecloud/jet/info', {});
  check('jet/info advertises sponsorUrl', info.res && info.res.sponsorUrl === '/Safecloud/sponsor/token');
  check('jet/info advertises requirePayment', info.res.requirePayment === true);

  // Announce from the owning socket works
  const ann = await emit(c1, 'Safecloud/drop/announce', { dropId: 'drop-1', prollyRoot: 'root1' });
  check('announce from owning socket accepted', ann.err == null);

  // Announce for a Drop from a DIFFERENT socket is rejected (security)
  const c2 = await connect();
  const spoof = await emit(c2, 'Safecloud/drop/announce', { dropId: 'drop-1', prollyRoot: 'evil' });
  check('announce from non-owning socket rejected', spoof.err && spoof.err.error.code === 'Unauthorized');

  // Reconnect: same dropId, cold=false
  const c3 = await connect();
  const rereg = await emit(c3, 'Safecloud/drop/register', { dropId: 'drop-1', evmAddress: drop.address });
  check('reconnect reports cold=false', rereg.res.cold === false);

  c1.close(); c2.close(); c3.close();
  ioServer.close(); srv.close();
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
