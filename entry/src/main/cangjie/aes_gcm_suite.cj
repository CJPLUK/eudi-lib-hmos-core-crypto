package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*

import eudi_lib_core_crypto.*

// ---------------------------------------------------------------------------
// AesGcm suite — AES-GCM AEAD, ciphertext layout ct || tag(16B).
// Covers public: AesGcm.seal, AesGcm.open. Includes a NIST GCM known-answer
// vector, round-trips for all 3 key sizes, and tamper/AAD rejection paths
// (open returns Option.None, never throws, never returns partial plaintext).
// ---------------------------------------------------------------------------

@Test
class AesGcmUT {
    private static let abc: Array<UInt8> = [0x61, 0x62, 0x63]

    // NIST GCM spec test case 14: AES-256-GCM(key=0*32, iv=0*12, P=0*16, AAD empty)
    // → C(16B) || T(16B)
    private static let gcm14CtTag: Array<UInt8> = [
        // ciphertext (16B)
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
        // tag (16B)
        0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19
    ]

    @TestCase
    func testSeal_nistCase14_exactBytes(): Unit {
        let k = Array<UInt8>(32, repeat: 0)
        let iv = Array<UInt8>(12, repeat: 0)
        let p = Array<UInt8>(16, repeat: 0)
        @Expect(ccEq(AesGcm.seal(k, iv, Array<UInt8>(), p), AesGcmUT.gcm14CtTag), true)
    }

    @TestCase
    func testSeal_outputLength_isPlaintextPlus16(): Unit {
        let k = Array<UInt8>(16, repeat: 0x11)
        let iv = Array<UInt8>(12, repeat: 0x22)
        let ct = AesGcm.seal(k, iv, Array<UInt8>(), AesGcmUT.abc)
        @Expect(ct.size, AesGcmUT.abc.size + 16)
    }

    @TestCase
    func testRoundTrip_aes128(): Unit {
        let k = Array<UInt8>(16, repeat: 0x33)
        let iv = Array<UInt8>(12, repeat: 0x44)
        let aad: Array<UInt8> = [0x01, 0x02]
        let ct = AesGcm.seal(k, iv, aad, AesGcmUT.abc)
        match (AesGcm.open(k, iv, aad, ct)) {
            case Some(pt) => @Expect(ccEq(pt, AesGcmUT.abc), true)
            case None => @Expect(false, true)
        }
    }

    @TestCase
    func testRoundTrip_aes192(): Unit {
        let k = Array<UInt8>(24, repeat: 0x55)
        let iv = Array<UInt8>(12, repeat: 0x66)
        let ct = AesGcm.seal(k, iv, Array<UInt8>(), AesGcmUT.abc)
        match (AesGcm.open(k, iv, Array<UInt8>(), ct)) {
            case Some(pt) => @Expect(ccEq(pt, AesGcmUT.abc), true)
            case None => @Expect(false, true)
        }
    }

    @TestCase
    func testRoundTrip_aes256(): Unit {
        let k = Array<UInt8>(32, repeat: 0x77)
        let iv = Array<UInt8>(12, repeat: 0x88)
        let ct = AesGcm.seal(k, iv, Array<UInt8>(), AesGcmUT.abc)
        match (AesGcm.open(k, iv, Array<UInt8>(), ct)) {
            case Some(pt) => @Expect(ccEq(pt, AesGcmUT.abc), true)
            case None => @Expect(false, true)
        }
    }

    @TestCase
    func testRoundTrip_emptyPlaintext(): Unit {
        let k = Array<UInt8>(16, repeat: 0x99)
        let iv = Array<UInt8>(12, repeat: 0xaa)
        let ct = AesGcm.seal(k, iv, Array<UInt8>(), Array<UInt8>())
        // empty plaintext → ciphertext is just the 16-byte tag
        @Expect(ct.size, 16)
        match (AesGcm.open(k, iv, Array<UInt8>(), ct)) {
            case Some(pt) => @Expect(pt.size, 0)
            case None => @Expect(false, true)
        }
    }

    @TestCase
    func testOpen_tamperedCiphertext_returnsNone(): Unit {
        let k = Array<UInt8>(32, repeat: 0x42)
        let iv = Array<UInt8>(12, repeat: 0x24)
        let aad: Array<UInt8> = [0x01]
        let ct = AesGcm.seal(k, iv, aad, AesGcmUT.abc)
        ct[0] = ct[0] ^ 0xff
        match (AesGcm.open(k, iv, aad, ct)) {
            case Some(_) => @Expect(false, true) // must not decrypt tampered ct
            case None => @Expect(true, true)
        }
    }

    @TestCase
    func testOpen_wrongAad_returnsNone(): Unit {
        let k = Array<UInt8>(32, repeat: 0x42)
        let iv = Array<UInt8>(12, repeat: 0x24)
        let ct = AesGcm.seal(k, iv, [0x01], AesGcmUT.abc)
        match (AesGcm.open(k, iv, [0x02], ct)) {
            case Some(_) => @Expect(false, true)
            case None => @Expect(true, true)
        }
    }

    @TestCase
    func testOpen_inputShorterThanTag_returnsNone(): Unit {
        let k = Array<UInt8>(16, repeat: 0x01)
        let iv = Array<UInt8>(12, repeat: 0x02)
        match (AesGcm.open(k, iv, Array<UInt8>(), Array<UInt8>(8, repeat: 0))) {
            case Some(_) => @Expect(false, true)
            case None => @Expect(true, true)
        }
    }
}
