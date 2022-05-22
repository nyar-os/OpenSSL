//! Regression vectors for the TLS 1.3 primitives: RFC 8448 key schedule values
//! and ClientHello framing. These are the formal gates for the `tls` module's
//! cryptographic correctness; the handshake itself is covered by the loopback
//! interop tests.

#[test]
fn x25519_shared_secret_vector() {
    // RFC 8448 §4: client ephemeral private key and server public value.
    let client = [
        0x49, 0xaf, 0x42, 0xba, 0x7f, 0x79, 0x94, 0x85, 0x2d, 0x71, 0x3e, 0xf2, 0x78, 0x4b, 0xcb, 0xca, 0xa7, 0x91, 0x1d, 0xe2, 0x6a, 0xdc,
        0x56, 0x42, 0xcb, 0x63, 0x45, 0x40, 0xe7, 0xea, 0x50, 0x05,
    ];
    let server = [
        0xc9, 0x82, 0x88, 0x76, 0x11, 0x20, 0x95, 0xfe, 0x66, 0x76, 0x2b, 0xdb, 0xf7, 0xc6, 0x72, 0xe1, 0x56, 0xd6, 0xcc, 0x25, 0x3b, 0x83,
        0x3d, 0xf1, 0xdd, 0x69, 0xb1, 0xb0, 0x4e, 0x75, 0x1f, 0x0f,
    ];
    let expected = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";
    let got = open_ssl_core::tls::__test_shared_with(&client, &server);
    let hex = got.iter().map(|x| format!("{x:02x}")).collect::<String>();
    assert_eq!(hex, expected);
}

#[test]
fn key_schedule_matches_rfc_8448() {
    let shared = [
        0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63, 0xfd, 0xfb, 0xac, 0xf9, 0xf0, 0x4b, 0x9f, 0x0d, 0x35, 0xe6, 0xd6, 0x3f, 0x53, 0x75,
        0x63, 0xef, 0xd4, 0x62, 0x72, 0x90, 0x0f, 0x89, 0x49, 0x2d,
    ];
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let early = open_ssl_core::tls::__test_extract(&[0u8; 32], &[0u8; 32]);
    assert_eq!(hex(&early), "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
    let empty = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
        0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    ];
    let derived = open_ssl_core::tls::__test_derive_secret(&early, "derived", &empty);
    assert_eq!(hex(&derived), "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
    let hs = open_ssl_core::tls::__test_extract(&derived, &shared);
    assert_eq!(hex(&hs), "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
    let th = [
        0x86, 0x0c, 0x06, 0xed, 0xc0, 0x78, 0x58, 0xee, 0x8e, 0x78, 0xf0, 0xe7, 0x42, 0x8c, 0x58, 0xed, 0xd6, 0xb4, 0x3f, 0x2c, 0xa3, 0xe6,
        0xe9, 0x5f, 0x02, 0xed, 0x06, 0x3c, 0xf0, 0xe1, 0xca, 0xd8,
    ];
    let s_hs = open_ssl_core::tls::__test_derive_secret(&hs, "s hs traffic", &th);
    assert_eq!(hex(&s_hs), "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
    let key = open_ssl_core::tls::__test_expand_label(&s_hs, "key", &[], 16);
    assert_eq!(hex(&key), "3fce516009c21727d0f2e4e86ee403bc");
    let iv = open_ssl_core::tls::__test_expand_label(&s_hs, "iv", &[], 12);
    assert_eq!(hex(&iv), "5d313eb2671276ee13000b30");
}

#[test]
fn client_hello_extensions_frame_exactly() {
    let share = open_ssl_core::tls::__test_key_share();
    let hello = open_ssl_core::tls::__test_client_hello("example.com", &share, None);
    assert_eq!(hello[0], 1, "handshake type must be ClientHello");
    let declared = u32::from_be_bytes([0, hello[1], hello[2], hello[3]]) as usize;
    assert_eq!(declared, hello.len() - 4, "message length must match the body");
    let mut cursor = &hello[4 + 2 + 32 + 1 + 32..];
    let cs_len = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
    cursor = &cursor[2 + cs_len..];
    let comp_len = cursor[0] as usize;
    cursor = &cursor[1 + comp_len..];
    let ext_total = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
    cursor = &cursor[2..];
    assert_eq!(cursor.len(), ext_total, "extension data must end at the message");
    while !cursor.is_empty() {
        let length = u16::from_be_bytes([cursor[2], cursor[3]]) as usize;
        cursor = &cursor[4 + length..];
    }
}
