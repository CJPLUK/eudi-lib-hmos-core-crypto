package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*

import eudi_lib_core_crypto.*

// ---------------------------------------------------------------------------
// Digest + Hmac suites — FIPS 180-2 SHA-2 KATs and RFC 4231 HMAC-SHA256 KATs.
// Covers public: Digest.sha256 / sha384 / sha512, Hmac.sha256, and the
// CoreCryptoException error path on an empty HMAC key.
// ---------------------------------------------------------------------------

func ccEq(a: Array<UInt8>, b: Array<UInt8>): Bool {
    if (a.size != b.size) {
        return false
    }
    var i = 0
    while (i < a.size) {
        if (a[i] != b[i]) {
            return false
        }
        i++
    }
    return true
}

@Test
class DigestUT {
    private static let abc: Array<UInt8> = [0x61, 0x62, 0x63]

    // FIPS 180-2: SHA-256("abc")
    private static let sha256Abc: Array<UInt8> = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    ]
    // SHA-256("")
    private static let sha256Empty: Array<UInt8> = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    ]
    // FIPS 180-2: SHA-384("abc")
    private static let sha384Abc: Array<UInt8> = [
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
        0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
        0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7
    ]
    // FIPS 180-2: SHA-512("abc")
    private static let sha512Abc: Array<UInt8> = [
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
    ]

    @TestCase
    func testSha256_abc_matchesFips180(): Unit {
        @Expect(ccEq(Digest.sha256(DigestUT.abc), DigestUT.sha256Abc), true)
    }

    @TestCase
    func testSha256_empty_matchesFips180(): Unit {
        @Expect(ccEq(Digest.sha256(Array<UInt8>()), DigestUT.sha256Empty), true)
    }

    @TestCase
    func testSha256_digestLength_is32(): Unit {
        @Expect(Digest.sha256(DigestUT.abc).size, 32)
    }

    @TestCase
    func testSha384_abc_matchesFips180(): Unit {
        @Expect(ccEq(Digest.sha384(DigestUT.abc), DigestUT.sha384Abc), true)
    }

    @TestCase
    func testSha384_digestLength_is48(): Unit {
        @Expect(Digest.sha384(DigestUT.abc).size, 48)
    }

    @TestCase
    func testSha512_abc_matchesFips180(): Unit {
        @Expect(ccEq(Digest.sha512(DigestUT.abc), DigestUT.sha512Abc), true)
    }

    @TestCase
    func testSha512_digestLength_is64(): Unit {
        @Expect(Digest.sha512(DigestUT.abc).size, 64)
    }

    @TestCase
    func testSha256_distinctInputs_distinctDigests(): Unit {
        let other: Array<UInt8> = [0x61, 0x62, 0x64]
        @Expect(ccEq(Digest.sha256(DigestUT.abc), Digest.sha256(other)), false)
    }
}

@Test
class HmacUT {
    // RFC 4231 Test Case 1: HMAC-SHA256(key=0x0b*20, "Hi There")
    private static let tc1: Array<UInt8> = [
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    ]

    @TestCase
    func testHmacSha256_rfc4231_tc1(): Unit {
        let key = Array<UInt8>(20, repeat: 0x0b)
        @Expect(ccEq(Hmac.sha256(key, "Hi There".toArray()), HmacUT.tc1), true)
    }

    @TestCase
    func testHmacSha256_macLength_is32(): Unit {
        let key = Array<UInt8>(4, repeat: 0x42)
        @Expect(Hmac.sha256(key, "x".toArray()).size, 32)
    }

    @TestCase
    func testHmacSha256_emptyData_isValid(): Unit {
        // RFC 4231-style: empty message is allowed, MAC is still 32 bytes.
        let key = Array<UInt8>(8, repeat: 0x0c)
        @Expect(Hmac.sha256(key, Array<UInt8>()).size, 32)
    }

    @TestCase
    func testHmacSha256_distinctKeys_distinctMacs(): Unit {
        let k1 = Array<UInt8>(16, repeat: 0x01)
        let k2 = Array<UInt8>(16, repeat: 0x02)
        let msg = "same message".toArray()
        @Expect(ccEq(Hmac.sha256(k1, msg), Hmac.sha256(k2, msg)), false)
    }

    @TestCase
    func testHmacSha256_emptyKey_throws(): Unit {
        var threw = false
        try {
            Hmac.sha256(Array<UInt8>(), "data".toArray())
        } catch (e: CoreCryptoException) {
            threw = true
        }
        @Expect(threw, true)
    }
}
