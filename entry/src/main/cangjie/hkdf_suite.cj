package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*

import eudi_lib_core_crypto.*

// ---------------------------------------------------------------------------
// Hkdf suite — RFC 5869 HKDF-SHA256 (extract / expand / derive).
// Anchored on RFC 5869 Test Case 1. Covers public: Hkdf.extract,
// Hkdf.expand, Hkdf.derive, plus the CoreCryptoException error paths.
// ---------------------------------------------------------------------------

@Test
class HkdfUT {
    // RFC 5869 TC1 inputs
    private static let ikmTc1: Array<UInt8> = Array<UInt8>(22, repeat: 0x0b)

    // RFC 5869 TC1: PRK (output of extract)
    private static let prkTc1: Array<UInt8> = [
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
    ]
    // RFC 5869 TC1: OKM (42 bytes)
    private static let okmTc1: Array<UInt8> = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
    ]

    private static func saltTc1(): Array<UInt8> {
        let salt = Array<UInt8>(13, repeat: 0)
        for (i in 0..13) {
            salt[i] = UInt8(i)
        }
        return salt
    }

    private static func infoTc1(): Array<UInt8> {
        let info = Array<UInt8>(10, repeat: 0)
        for (i in 0..10) {
            info[i] = UInt8(0xf0 + i)
        }
        return info
    }

    @TestCase
    func testExtract_rfc5869_tc1_prk(): Unit {
        let prk = Hkdf.extract(HkdfUT.saltTc1(), HkdfUT.ikmTc1)
        @Expect(ccEq(prk, HkdfUT.prkTc1), true)
    }

    @TestCase
    func testExpand_rfc5869_tc1_okm(): Unit {
        let okm = Hkdf.expand(HkdfUT.prkTc1, HkdfUT.infoTc1(), 42)
        @Expect(ccEq(okm, HkdfUT.okmTc1), true)
    }

    @TestCase
    func testDerive_rfc5869_tc1_okm(): Unit {
        let okm = Hkdf.derive(HkdfUT.saltTc1(), HkdfUT.ikmTc1, HkdfUT.infoTc1(), 42)
        @Expect(ccEq(okm, HkdfUT.okmTc1), true)
    }

    @TestCase
    func testExtract_emptySalt_returns32Bytes(): Unit {
        // empty salt is replaced by HashLen zero bytes (RFC 5869 §2.2) → still 32B PRK
        @Expect(Hkdf.extract(Array<UInt8>(), HkdfUT.ikmTc1).size, 32)
    }

    @TestCase
    func testExpand_requestedLength_isHonored(): Unit {
        @Expect(Hkdf.expand(HkdfUT.prkTc1, Array<UInt8>(), 17).size, 17)
    }

    @TestCase
    func testExpand_zeroLength_throws(): Unit {
        var threw = false
        try {
            Hkdf.expand(HkdfUT.prkTc1, Array<UInt8>(), 0)
        } catch (e: CoreCryptoException) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func testExpand_lengthTooLarge_throws(): Unit {
        var threw = false
        try {
            // > 255 * 32 = 8160
            Hkdf.expand(HkdfUT.prkTc1, Array<UInt8>(), 8161)
        } catch (e: CoreCryptoException) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func testExpand_shortPrk_throws(): Unit {
        var threw = false
        try {
            Hkdf.expand(Array<UInt8>(8, repeat: 0x01), Array<UInt8>(), 16)
        } catch (e: CoreCryptoException) {
            threw = true
        }
        @Expect(threw, true)
    }
}
