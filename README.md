# ipv4-packet-utils

Decode an IPv4 datagram buffer into version, IHL, total length, protocol, addresses, options, and payload offset.

```js
import { parseIPv4Packet } from 'ipv4-packet-utils';

const buf = Buffer.from([
  0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x40, 0x00,
  0x40, 0x06, 0x00, 0x00, 0xc0, 0x00, 0x02, 0x01,
  0xc6, 0x33, 0x64, 0x02, 0xde, 0xad, 0xbe, 0xef,
  0x00, 0x00, 0x00, 0x00,
]);

const packet = parseIPv4Packet(buf);
console.log(packet.source);       // '192.0.2.1'
console.log(packet.destination);  // '198.51.100.2'
console.log(packet.protocol);     // 6
console.log(packet.payloadOffset); // 20
console.log(packet.payload.length); // 8
```

The parser is strict: it throws on truncated buffers, unsupported versions, an IHL below 5, and a total length that does not fit the buffer. It never returns a partially decoded packet.

## Why this exists

Most packet-capture tooling hands you a raw buffer and a length. Before you can look at the transport header you need to know where the IP header ends and how long the datagram claims to be. Doing that by hand is a handful of shifts and masks, but it is easy to get the IHL units wrong or to read past the end of a short buffer.

This library makes one trade-off: it validates eagerly and throws on anything malformed, rather than returning a partial result with a flag. Callers that want to inspect damaged packets can catch the error, but the default path is safe to use without re-checking every field.

The payload is returned as a `Buffer` subarray of the input, not a copy, so it is zero-copy. That means mutating the original buffer after parsing is visible through `payload`. If you need an independent copy, call `Buffer.from(packet.payload)`.

## Exports

- `parseIPv4Packet(buf)` — returns an object with `version`, `ihl`, `dscp`, `ecn`, `totalLength`, `identification`, `flags` (`reserved`, `dontFragment`, `moreFragments`), `fragmentOffset`, `ttl`, `protocol`, `headerChecksum`, `source`, `destination`, `options`, `payloadOffset`, and `payload`.

## Edge cases

Options are returned as a raw `Buffer` of the bytes between the fixed header and the payload. They are not parsed into individual option records, because option semantics differ per option and most callers only need the byte count. `payloadOffset` is the offset where the payload begins, which is also `ihl * 4`.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

