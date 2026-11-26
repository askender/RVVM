/*
netjslib.js - Emscripten JS library: minimal blocking primitive for the
WASM networking backend (net_wasm.c). All socket state lives in the
shared wasm linear memory; the embedder's main thread drives real I/O
(relay WebSockets, DoH) and wakes blocked threads via Atomics.notify.
*/

mergeInto(LibraryManager.library, {
  netjs_poll_wait__deps: [],
  netjs_poll_wait__sig: 'iii',
  netjs_poll_wait: function(wakeBytePtr, oldVal, timeoutMs) {
    const r = Atomics.wait(HEAP32, wakeBytePtr >> 2, oldVal|0, timeoutMs|0);
    return r === 'timed-out' ? 1 : (r === 'ok' ? 0 : 2);
  },

  netjs_notify__deps: [],
  netjs_notify__sig: 'vi',
  netjs_notify: function(wakeBytePtr) {
    Atomics.notify(HEAP32, wakeBytePtr >> 2, 99);
  },

  netjs_dns_submit__deps: [],
  netjs_dns_submit__sig: 'v',
  netjs_dns_submit: function() {
    // The embedder polls the DNS mailbox periodically; nothing to do here.
  },
});
function rvvmNetShm() { return 0; }
