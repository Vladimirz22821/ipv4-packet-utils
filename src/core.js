// Core IPv4 datagram parsing logic.
//
// The parser is deliberately strict: it validates every field it exposes and
// refuses to guess. A truncated buffer or an impossible header length returns
// an Error instead of a partially filled object. That keeps callers from
// acting on half-decoded packets.

/**
 * Parse an IPv4 datagram from a Buffer.
 *
 * Only the IPv4 header is decoded; the payload is returned as a subarray of
 * the original buffer so callers can zero-copy it. Options are decoded into
 * the raw byte array because option semantics vary and most callers only need
 * to know how many bytes to skip.
 *
 * @param {Buffer} buf
 * @returns {{
 *   version: number,
 *   ihl: number,
 *   dscp: number,
 *   ecn: number,
 *   totalLength: number,
 *   identification: number,
 *   flags: { reserved: boolean, dontFragment: boolean, moreFragments: boolean },
 *   fragmentOffset: number,
 *   ttl: number,
 *   protocol: number,
 *   headerChecksum: number,
 *   source: string,
 *   destination: string,
 *   options: Buffer,
 *   payloadOffset: number,
 *   payload: Buffer
 * }}
 */
export function parseIPv4Packet(buf) {
  if (!Buffer.isBuffer(buf)) {
    throw new TypeError('parseIPv4Packet expects a Buffer');
  }
  // The fixed IPv4 header is 20 bytes. Anything shorter cannot even hold the
  // minimum header, so reject it before reading fields.
  if (buf.length < 20) {
    throw new Error(`IPv4 packet too short: ${buf.length} bytes`);
  }

  const version = buf[0] >> 4;
  const ihl = buf[0] & 0x0f;

  if (version !== 4) {
    throw new Error(`unsupported IP version: ${version}`);
  }
  // IHL counts 32-bit words. The minimum legal value is 5 (20 bytes).
  if (ihl < 5) {
    throw new Error(`invalid IHL: ${ihl}`);
  }

  const headerLength = ihl * 4;
  if (buf.length < headerLength) {
    throw new Error(
      `buffer too short for header: need ${headerLength}, have ${buf.length}`
    );
  }

  const totalLength = buf.readUInt16BE(2);
  // totalLength includes the header. It must be at least the header length and
  // no larger than the buffer we were handed.
  if (totalLength < headerLength) {
    throw new Error(
      `total length ${totalLength} smaller than header length ${headerLength}`
    );
  }
  if (totalLength > buf.length) {
    throw new Error(
      `total length ${totalLength} exceeds buffer length ${buf.length}`
    );
  }

  const dscp = buf[1] >> 2;
  const ecn = buf[1] & 0x03;
  const identification = buf.readUInt16BE(4);

  const flagsAndOffset = buf.readUInt16BE(6);
  const reserved = (flagsAndOffset & 0x8000) !== 0;
  const dontFragment = (flagsAndOffset & 0x4000) !== 0;
  const moreFragments = (flagsAndOffset & 0x2000) !== 0;
  const fragmentOffset = flagsAndOffset & 0x1fff;

  const ttl = buf[8];
  const protocol = buf[9];
  const headerChecksum = buf.readUInt16BE(10);

  const source = formatIPv4(buf, 12);
  const destination = formatIPv4(buf, 16);

  // Options live between the fixed header and the payload. Copy them so the
  // returned object does not alias a mutable region of the caller's buffer
  // once the payload subarray is taken.
  const options = Buffer.from(buf.subarray(20, headerLength));

  const payload = buf.subarray(headerLength, totalLength);

  return {
    version,
    ihl,
    dscp,
    ecn,
    totalLength,
    identification,
    flags: { reserved, dontFragment, moreFragments },
    fragmentOffset,
    ttl,
    protocol,
    headerChecksum,
    source,
    destination,
    options,
    payloadOffset: headerLength,
    payload,
  };
}

/**
 * Format four bytes as a dotted-quad IPv4 string.
 *
 * @param {Buffer} buf
 * @param {number} offset
 * @returns {string}
 */
function formatIPv4(buf, offset) {
  return `${buf[offset]}.${buf[offset + 1]}.${buf[offset + 2]}.${buf[offset + 3]}`;
}
