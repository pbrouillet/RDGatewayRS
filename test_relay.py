"""Test the full TSG handshake + RDP relay through our gateway."""
import asyncio, struct, ssl, base64, socket
import websockets

HEADER_SIZE = 8

def make_header(msg_type, payload_len):
    return struct.pack('<HHI', msg_type, 0, HEADER_SIZE + payload_len)

def parse_header(data):
    return struct.unpack_from('<HHI', data, 0)

def ntlm_type3():
    return b'NTLMSSP\x00' + struct.pack('<I', 3) + struct.pack('<HHI', 0, 0, 72) * 6 + struct.pack('<I', 0xe2088297) + b'\x00' * 16

async def test():
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    type3_b64 = base64.b64encode(ntlm_type3()).decode()

    async with websockets.connect(
        'wss://localhost/remoteDesktopGateway/',
        ssl=ssl_ctx,
        additional_headers={'Authorization': f'Negotiate {type3_b64}'},
    ) as ws:
        print('[+] WebSocket connected')

        # Phase 1: HandshakeRequest (type=0x01)
        # Payload: majorVersion=1(u8), minorVersion=0(u8), version=0(u16), extAuth=0(u16)
        hs = make_header(0x01, 6) + struct.pack('<BBHH', 1, 0, 0, 0)
        await ws.send(hs)
        r = await ws.recv()
        mt, _, ln = parse_header(r)
        assert mt == 0x02, f"Expected HandshakeResponse(0x02), got 0x{mt:02x}"
        print(f'[+] HandshakeResponse OK (len={ln})')

        # Phase 2: TunnelCreate (type=0x04)
        # Payload: capsFlags=0x3f(u32), fieldsPresent=0(u16), reserved=0(u16)
        tc = make_header(0x04, 8) + struct.pack('<IHH', 0x3f, 0, 0)
        await ws.send(tc)
        r = await ws.recv()
        mt, _, ln = parse_header(r)
        assert mt == 0x05, f"Expected TunnelResponse(0x05), got 0x{mt:02x}"
        print(f'[+] TunnelResponse OK (len={ln})')

        # Phase 3: TunnelAuth (type=0x06)
        # Payload: fieldsPresent=0(u16), clientNameLen(u16), clientName(utf16le+null)
        name_utf16 = 'test'.encode('utf-16-le') + b'\x00\x00'
        ta_payload = struct.pack('<HH', 0, len(name_utf16)) + name_utf16
        ta = make_header(0x06, len(ta_payload)) + ta_payload
        await ws.send(ta)
        r = await ws.recv()
        mt, _, ln = parse_header(r)
        assert mt == 0x07, f"Expected TunnelAuthResponse(0x07), got 0x{mt:02x}"
        print(f'[+] TunnelAuthResponse OK (len={ln})')

        # Phase 4: ChannelCreate (type=0x08)
        target = 'WIN-8QEC20TIHO4'
        t16 = target.encode('utf-16-le') + b'\x00\x00'
        # numResources(u8), numAltResources(u8), port(u16), protocol(i16), nameLen(u16), name(utf16)
        cc_payload = struct.pack('<BBHhH', 1, 0, 3389, 0, len(t16)) + t16
        cc = make_header(0x08, len(cc_payload)) + cc_payload
        await ws.send(cc)
        r = await ws.recv()
        mt, _, ln = parse_header(r)
        assert mt == 0x09, f"Expected ChannelResponse(0x09), got 0x{mt:02x}"
        print(f'[+] ChannelResponse OK (len={ln})')

        # Phase 5: Data relay - send RDP X.224 Connection Request
        rdp_req = bytes([
            0x03, 0x00, 0x00, 0x2f,  # TPKT: version=3, length=47
            0x2a, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,  # X.224 CR
            # Cookie: mstshash=WIN-8QEC2
            0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x3a, 0x20,
            0x6d, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68,
            0x3d, 0x57, 0x49, 0x4e, 0x2d, 0x38, 0x51, 0x45,
            0x43, 0x32, 0x0d, 0x0a,
            # RDP Neg Request: type=1, flags=0, len=8, protocols=0x0b (SSL|HYBRID|RDSTLS)
            0x01, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00
        ])

        # Wrap in TSG Data message: [header][cbDataLength:u16_le][rdp_data]
        data_payload = struct.pack('<H', len(rdp_req)) + rdp_req
        d = make_header(0x0A, len(data_payload)) + data_payload
        print(f'[*] Sending RDP Connection Request ({len(rdp_req)} bytes)...')
        await ws.send(d)

        # Wait for Connection Confirm from backend
        try:
            r = await asyncio.wait_for(ws.recv(), timeout=5.0)
            mt, _, length = parse_header(r)
            if mt == 0x0A:
                cb = struct.unpack_from('<H', r, 8)[0]
                rdp = r[10:10+cb]
                print(f'[+] Data response: cbDataLen={cb}, first bytes: {rdp[:20].hex()}')
                if rdp[0:1] == b'\x03':
                    tpkt_len = (rdp[2] << 8) | rdp[3]
                    x224_type = rdp[5] if len(rdp) > 5 else 0
                    print(f'[+] TPKT len={tpkt_len}, X.224 type=0x{x224_type:02x}', end='')
                    if x224_type == 0xd0:
                        print(' (Connection Confirm) - RELAY WORKS!')
                        # Parse negotiated protocol
                        if len(rdp) >= 15:
                            neg_proto = struct.unpack_from('<I', rdp, 15)[0]
                            print(f'[+] Negotiated protocol: {neg_proto} (1=SSL, 2=HYBRID, 8=RDSTLS)')

                        # Now test bidirectional: send TLS Client Hello and see if we get response
                        # Craft minimal TLS Client Hello
                        tls_hello = bytes([
                            0x16, 0x03, 0x01, 0x00, 0x05,  # TLS record: handshake, TLS 1.0, len=5
                            0x01, 0x00, 0x00, 0x01, 0x03,  # Client Hello (minimal/invalid but tests relay)
                        ])
                        d2_payload = struct.pack('<H', len(tls_hello)) + tls_hello
                        d2 = make_header(0x0A, len(d2_payload)) + d2_payload
                        print(f'[*] Sending fake TLS ClientHello ({len(tls_hello)} bytes)...')
                        await ws.send(d2)

                        try:
                            r2 = await asyncio.wait_for(ws.recv(), timeout=3.0)
                            mt2, _, ln2 = parse_header(r2)
                            if mt2 == 0x0A:
                                cb2 = struct.unpack_from('<H', r2, 8)[0]
                                print(f'[+] Got backend response: {cb2} bytes (relay bidirectional OK!)')
                                print(f'    First bytes: {r2[10:10+min(cb2,20)].hex()}')
                            else:
                                print(f'[!] Unexpected msg type 0x{mt2:02x}')
                        except asyncio.TimeoutError:
                            print('[!] No response to TLS hello (backend might have closed - expected for invalid TLS)')
                    else:
                        print(f' (unexpected type)')
            else:
                print(f'[!] Unexpected message type 0x{mt:02x}, len={length}')
                print(f'    Raw: {r[:min(len(r), 40)].hex()}')
        except asyncio.TimeoutError:
            print('[FAIL] TIMEOUT waiting for backend response - relay broken!')

asyncio.run(test())
