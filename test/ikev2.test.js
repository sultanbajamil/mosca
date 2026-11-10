/**
 * IKEv2 is a binary protocol with a compact but unforgiving layout. These
 * tests verify the request we emit, the parser we use on the responder, and
 * the ADDKE interpretation that decides whether a VPN can be hybrid.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  IKE_EXCHANGE,
  IKE_PAYLOAD,
  TRANSFORM,
  buildIkeSaInit,
  buildSaBody,
  buildProposal,
  buildTransform,
  parseIkeMessage,
  parseSaPayload,
  interpretIkeResponse,
  deriveIkeFindings,
} from '../src/net/ikev2.js';

const u8 = (n) => Buffer.from([n & 0xff]);
const u16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n & 0xffff);
  return b;
};

function ikePayload(next, body) {
  return Buffer.concat([u8(next), u8(0), u16(body.length + 4), body]);
}

function responsePacket({ nextPayload, payload }) {
  const header = Buffer.alloc(28);
  crypto.randomBytes(8).copy(header, 0); // initiator SPI
  crypto.randomBytes(8).copy(header, 8); // responder SPI
  header[16] = nextPayload;
  header[17] = 0x20;
  header[18] = IKE_EXCHANGE.IKE_SA_INIT;
  header[19] = 0x20; // response flag
  header.writeUInt32BE(0, 20);
  header.writeUInt32BE(28 + payload.length, 24);
  return Buffer.concat([header, payload]);
}

test('IKE_SA_INIT has the RFC 7296 header and payload chain', () => {
  const { packet, initiatorSpi } = buildIkeSaInit({ dhId: 31 });
  assert.equal(packet.length >= 28, true);
  assert.deepEqual(packet.subarray(0, 8), initiatorSpi);
  assert.equal(packet.readUInt32BE(8), 0, 'responder SPI must be zero in a request');
  assert.equal(packet[16], IKE_PAYLOAD.SA);
  assert.equal(packet[17], 0x20, 'IKEv2 major version');
  assert.equal(packet[18], IKE_EXCHANGE.IKE_SA_INIT);
  assert.equal(packet[19], 0x08, 'initiator flag');
  assert.equal(packet.readUInt32BE(24), packet.length);

  const parsed = parseIkeMessage(packet);
  assert.deepEqual(parsed.payloads.map((p) => p.type), [IKE_PAYLOAD.SA, IKE_PAYLOAD.KE, IKE_PAYLOAD.NONCE]);
});

test('a proposal contains encryption, PRF, integrity and DH transforms', () => {
  const body = buildSaBody({ dhId: 31 });
  const proposals = parseSaPayload(body);
  assert.equal(proposals.length, 1);
  assert.deepEqual(
    proposals[0].transforms.map((t) => t.type),
    [TRANSFORM.ENCR, TRANSFORM.PRF, TRANSFORM.INTEG, TRANSFORM.DH],
  );
  assert.equal(proposals[0].transforms[3].id, 31);
});

test('an ADDKE transform is type 6 and carries the provisional id', () => {
  const proposal = buildProposal({ addkeId: 35 });
  const parsed = parseSaPayload(proposal);
  const addke = parsed[0].transforms.find((t) => t.type === TRANSFORM.ADDKE);
  assert.ok(addke);
  assert.equal(addke.id, 35);
  assert.equal(buildTransform(TRANSFORM.ADDKE, 41).length, 8);
});

test('a responder SA with ADDKE is interpreted as hybrid support', () => {
  const sa = ikePayload(0, buildSaBody({ addkeId: 35 }));
  const parsed = interpretIkeResponse(responsePacket({ nextPayload: IKE_PAYLOAD.SA, payload: sa }));
  assert.equal(parsed.accepted, true);
  assert.equal(parsed.addkeSupported, true);
  assert.equal(parsed.addke[0].id, 35);
  assert.equal(parsed.noProposal, false);
});

test('NO_PROPOSAL_CHOSEN is interpreted as no hybrid support', () => {
  const body = Buffer.concat([u8(0), u8(0), u16(14), Buffer.alloc(0)]);
  const notify = ikePayload(0, body);
  const parsed = interpretIkeResponse(responsePacket({ nextPayload: IKE_PAYLOAD.NOTIFY, payload: notify }));
  assert.equal(parsed.noProposal, true);
  assert.equal(parsed.addkeSupported, false);
  assert.equal(parsed.notifies[0].name, 'NO_PROPOSAL_CHOSEN');
});

test('INVALID_KE_PAYLOAD is surfaced as a distinct notify', () => {
  const body = Buffer.concat([u8(0), u8(0), u16(17), u16(31)]);
  const notify = ikePayload(0, body);
  const parsed = interpretIkeResponse(responsePacket({ nextPayload: IKE_PAYLOAD.NOTIFY, payload: notify }));
  assert.equal(parsed.invalidKe, true);
  assert.equal(parsed.notifies[0].name, 'INVALID_KE_PAYLOAD');
});

test('findings reward ADDKE and flag classical-only gateways', () => {
  const hybrid = deriveIkeFindings({
    reachable: true,
    host: 'vpn.example.com',
    port: 500,
    target: 'ikev2://vpn.example.com',
    addke: { supported: true, transformId: 35, notifies: [] },
    classic: { dh: [31], notifies: [] },
  });
  assert.equal(hybrid[0].id, 'ikev2-addke-supported');
  assert.equal(hybrid[0].positive, true);

  const classical = deriveIkeFindings({
    reachable: true,
    host: 'vpn.example.com',
    port: 500,
    target: 'ikev2://vpn.example.com',
    addke: { supported: false, attempts: 6, notifies: ['NO_PROPOSAL_CHOSEN'] },
    classic: { dh: [31], notifies: [] },
  });
  assert.equal(classical[0].id, 'ikev2-classical-kex');
  assert.equal(classical[0].algorithm, 'x25519');
});
