package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*

import eudi_lib_core_crypto.*
import stdx.crypto.keys.*

// ---------------------------------------------------------------------------
// EcdsaP256 suite — ES256 (ECDSA P-256 / SHA-256), raw r||s (64B) signatures.
// Covers public: EcdsaP256.generate, publicKeyOf, sign, verify, derToRaw,
// rawToDer. Round-trip + tamper/wrong-key rejection + DER<->raw interconversion
// + malformed-DER error path (CoreCryptoException).
// ---------------------------------------------------------------------------

@Test
class EcdsaP256UT {
    private static let abc: Array<UInt8> = [0x61, 0x62, 0x63]

    @TestCase
    func testGenerate_andPublicKeyOf_succeed(): Unit {
        let priv = EcdsaP256.generate()
        let pub = EcdsaP256.publicKeyOf(priv)
        // sign with derived pub-keyed verify proves the pair is consistent
        let sig = EcdsaP256.sign(priv, EcdsaP256UT.abc)
        @Expect(EcdsaP256.verify(pub, EcdsaP256UT.abc, sig), true)
    }

    @TestCase
    func testSign_rawSignatureIs64Bytes(): Unit {
        let priv = EcdsaP256.generate()
        @Expect(EcdsaP256.sign(priv, EcdsaP256UT.abc).size, 64)
    }

    @TestCase
    func testSignVerify_roundTrip_returnsTrue(): Unit {
        let priv = EcdsaP256.generate()
        let pub = EcdsaP256.publicKeyOf(priv)
        let sig = EcdsaP256.sign(priv, EcdsaP256UT.abc)
        @Expect(EcdsaP256.verify(pub, EcdsaP256UT.abc, sig), true)
    }

    @TestCase
    func testVerify_tamperedMessage_returnsFalse(): Unit {
        let priv = EcdsaP256.generate()
        let pub = EcdsaP256.publicKeyOf(priv)
        let sig = EcdsaP256.sign(priv, EcdsaP256UT.abc)
        let other: Array<UInt8> = [0x61, 0x62, 0x64] // "abd"
        @Expect(EcdsaP256.verify(pub, other, sig), false)
    }

    @TestCase
    func testVerify_wrongPublicKey_returnsFalse(): Unit {
        let priv = EcdsaP256.generate()
        let otherPub = EcdsaP256.publicKeyOf(EcdsaP256.generate())
        let sig = EcdsaP256.sign(priv, EcdsaP256UT.abc)
        @Expect(EcdsaP256.verify(otherPub, EcdsaP256UT.abc, sig), false)
    }

    @TestCase
    func testVerify_wrongLengthSignature_returnsFalse(): Unit {
        let priv = EcdsaP256.generate()
        let pub = EcdsaP256.publicKeyOf(priv)
        // 63-byte signature is structurally invalid → false, no throw
        @Expect(EcdsaP256.verify(pub, EcdsaP256UT.abc, Array<UInt8>(63, repeat: 0)), false)
    }

    @TestCase
    func testDerRawRoundTrip_realSignature(): Unit {
        let priv = EcdsaP256.generate()
        let raw = EcdsaP256.sign(priv, EcdsaP256UT.abc)
        let der = EcdsaP256.rawToDer(raw)
        @Expect(ccEq(EcdsaP256.derToRaw(der), raw), true)
    }

    @TestCase
    func testRawToDer_producesSequenceTag(): Unit {
        let raw = Array<UInt8>(64, repeat: 0x01)
        let der = EcdsaP256.rawToDer(raw)
        @Expect(der[0], 0x30u8) // DER SEQUENCE tag
    }

    @TestCase
    func testRawToDer_leadingZeroComponent_roundTrips(): Unit {
        // r with high bit set in first non-zero byte exercises the 0x00 pad branch
        let raw = Array<UInt8>(64, repeat: 0)
        raw[0] = 0x80 // r top bit set → needs 0x00 prefix in DER
        raw[63] = 0x01 // small s
        @Expect(ccEq(EcdsaP256.derToRaw(EcdsaP256.rawToDer(raw)), raw), true)
    }

    @TestCase
    func testRawToDer_wrongLength_throws(): Unit {
        var threw = false
        try {
            EcdsaP256.rawToDer(Array<UInt8>(10, repeat: 0))
        } catch (e: CoreCryptoException) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func testDerToRaw_malformedInput_throws(): Unit {
        var threw = false
        try {
            // not a SEQUENCE, too short
            EcdsaP256.derToRaw([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
        } catch (e: CoreCryptoException) {
            threw = true
        }
        @Expect(threw, true)
    }
}
