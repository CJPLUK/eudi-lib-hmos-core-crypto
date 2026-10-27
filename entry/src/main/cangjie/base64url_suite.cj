package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*

import eudi_lib_core_crypto.*

// ---------------------------------------------------------------------------
// Base64Url suite — RFC 4648 §5 url-safe base64, no padding.
// Covers public: Base64Url.encode, Base64Url.decode (incl. error path that
// raises CoreCryptoException on invalid length).
// ---------------------------------------------------------------------------

@Test
class Base64UrlUT {

    @TestCase
    func testEncode_emptyInput_returnsEmptyString(): Unit {
        @Expect(Base64Url.encode(Array<UInt8>()), "")
    }

    @TestCase
    func testDecode_emptyString_returnsEmptyArray(): Unit {
        @Expect(Base64Url.decode("").size, 0)
    }

    @TestCase
    func testEncode_urlSafeAlphabet_noPadding(): Unit {
        // 0xfb,0xff → standard b64 "+/8=", url-safe no-pad must be "-_8"
        @Expect(Base64Url.encode([0xfb, 0xff]), "-_8")
    }

    @TestCase
    func testEncode_knownVector_foobar(): Unit {
        // "foobar" → RFC 4648 base64 "Zm9vYmFy" (no +,/,= so url-safe is identical)
        @Expect(Base64Url.encode("foobar".toArray()), "Zm9vYmFy")
    }

    @TestCase
    func testEncode_singleByte_oneCharStrippedPadding(): Unit {
        // "f" → "Zg==" standard, "Zg" url-safe no-pad
        @Expect(Base64Url.encode("f".toArray()), "Zg")
    }

    @TestCase
    func testRoundTrip_arbitraryBytes(): Unit {
        let data: Array<UInt8> = [0x00, 0x01, 0x02, 0xfd, 0xfe, 0xff, 0x80, 0x7f, 0x10]
        @Expect(ccEq(Base64Url.decode(Base64Url.encode(data)), data), true)
    }

    @TestCase
    func testRoundTrip_allByteValues(): Unit {
        let data = Array<UInt8>(256, repeat: 0)
        for (i in 0..256) {
            data[i] = UInt8(i)
        }
        @Expect(ccEq(Base64Url.decode(Base64Url.encode(data)), data), true)
    }

    @TestCase
    func testDecode_withoutPadding_succeeds(): Unit {
        // "-_8" decodes back to [0xfb, 0xff]
        @Expect(ccEq(Base64Url.decode("-_8"), [0xfb, 0xff]), true)
    }

    @TestCase
    func testDecode_invalidLength_throws(): Unit {
        // length % 4 == 1 is structurally impossible base64 → CoreCryptoException
        var threw = false
        try {
            Base64Url.decode("A")
        } catch (e: CoreCryptoException) {
            threw = true
        }
        @Expect(threw, true)
    }
}
