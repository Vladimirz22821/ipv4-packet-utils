import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseIPv4Packet } from '../src/index.js';

/**
 * Build a minimal IPv4 header for tests. Defaults produce a 20-byte header
 * with no options and an empty payload.
 */
function buildHeader({
  version = 4,
  ihl = 5,
  dscp = 0,
  ecn = 0,
  totalLength = 20,
  identification = 0,
  flags = 0,
  fragmentOffset = 0,
  ttl = 64,
  protocol = 6,
  checksum = 0,
  source = [192, 0, 2, 1],
  destination = [198, 51, 100, 2],
  options = Buffer.alloc(0),
  payload = Buffer.alloc(0),
} = {}) {
  const headerLength = ihl * 4;
  const buf = Buffer.alloc(headerLength + payload.length);
  buf[0] = (version << 4) | ihl;
  buf[1] = (dscp << 2) | ecn;
  buf.writeUInt16BE(totalLength, 2);
  buf.writeUInt16BE(identification, 4);
  buf.writeUInt16BE((flags << 13) | fragmentOffset, 6);
  buf[8] = ttl;
  buf[9] = protocol;
  buf.writeUInt16BE(checksum, 10);
  for (let i = 0; i < 4; i += 1) {
    buf[12 + i] = source[i];
    buf[16 + i] = destination[i];
  }
  options.copy(buf, 20);
  payload.copy(buf, headerLength);
  return buf;
}

test('parses a minimal header with no payload', () => {
  const buf = buildHeader();
  const p = parseIPv4Packet(buf);
  assert.equal(p.version, 4);
  assert.equal(p.ihl, 5);
  assert.equal(p.totalLength, 20);
  assert.equal(p.protocol, 6);
  assert.equal(p.source, '192.0.2.1');
  assert.equal(p.destination, '198.51.100.2');
  assert.equal(p.payloadOffset, 20);
  assert.equal(p.payload.length, 0);
  assert.equal(p.options.length, 0);
});

test('parses DSCP and ECN separately', () => {
  const buf = buildHeader({ dscp: 46, ecn: 3 });
  const p = parseIPv4Packet(buf);
  assert.equal(p.dscp, 46);
  assert.equal(p.ecn, 3);
});

test('parses identification and fragmentation fields', () => {
  const buf = buildHeader({
    identification: 0xbeef,
    flags: 0b010, // don't fragment
    fragmentOffset: 0x1abc,
  });
  const p = parseIPv4Packet(buf);
  assert.equal(p.identification, 0xbeef);
  assert.equal(p.flags.reserved, false);
  assert.equal(p.flags.dontFragment, true);
  assert.equal(p.flags.moreFragments, false);
  assert.equal(p.fragmentOffset, 0x1abc);
});

test('parses TTL, protocol, and checksum', () => {
  const buf = buildHeader({ ttl: 1, protocol: 17, checksum: 0x1234 });
  const p = parseIPv4Packet(buf);
  assert.equal(p.ttl, 1);
  assert.equal(p.protocol, 17);
  assert.equal(p.headerChecksum, 0x1234);
});

test('returns payload as a subarray of the original buffer', () => {
  const payload = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  const buf = buildHeader({ totalLength: 24, payload });
  const p = parseIPv4Packet(buf);
  assert.equal(p.payloadOffset, 20);
  assert.equal(p.payload.length, 4);
  assert.deepEqual([...p.payload], [0xde, 0xad, 0xbe, 0xef]);
  // Mutating the original buffer should be visible through the payload view.
  buf[20] = 0x00;
  assert.equal(p.payload[0], 0x00);
});

test('decodes options and advances payloadOffset', () => {
  const options = Buffer.from([0x01, 0x01, 0x01, 0x00]);
  const payload = Buffer.from([0xaa, 0xbb]);
  const buf = buildHeader({
    ihl: 6,
    totalLength: 24 + 2,
    options,
    payload,
  });
  const p = parseIPv4Packet(buf);
  assert.equal(p.ihl, 6);
  assert.equal(p.payloadOffset, 24);
  assert.deepEqual([...p.options], [0x01, 0x01, 0x01, 0x00]);
  assert.deepEqual([...p.payload], [0xaa, 0xbb]);
});

test('rejects unsupported IP versions', () => {
  const buf = buildHeader({ version: 6 });
  assert.throws(() => parseIPv4Packet(buf), /unsupported IP version: 6/);
});

test('rejects IHL below the 5-word minimum', () => {
  // buildHeader writes the low nibble, but the buffer is only 16 bytes when
  // ihl is 4, which triggers the length check first. Use a raw buffer to hit
  // the IHL check specifically.
  const raw = Buffer.alloc(20);
  raw[0] = (4 << 4) | 4;
  raw.writeUInt16BE(20, 2);
  assert.throws(() => parseIPv4Packet(raw), /invalid IHL: 4/);
});

test('rejects a buffer shorter than 20 bytes', () => {
  assert.throws(() => parseIPv4Packet(Buffer.alloc(19)), /too short/);
});

test('rejects totalLength smaller than the header', () => {
  const buf = buildHeader({ totalLength: 4 });
  assert.throws(() => parseIPv4Packet(buf), /smaller than header length/);
});

test('rejects totalLength larger than the buffer', () => {
  const buf = buildHeader({ totalLength: 100 });
  assert.throws(() => parseIPv4Packet(buf), /exceeds buffer length/);
});

test('rejects non-Buffer input', () => {
  assert.throws(() => parseIPv4Packet('not a buffer'), /expects a Buffer/);
});

test('handles a maximum-size IHL of 15', () => {
  const options = Buffer.alloc(40, 0x01);
  const buf = buildHeader({ ihl: 15, totalLength: 60, options });
  const p = parseIPv4Packet(buf);
  assert.equal(p.ihl, 15);
  assert.equal(p.payloadOffset, 60);
  assert.equal(p.options.length, 40);
  assert.equal(p.payload.length, 0);
});
