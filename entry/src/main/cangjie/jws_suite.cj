package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*

import eudi_lib_core_crypto.*

// ---------------------------------------------------------------------------
// Jws suite — RFC 7515 JWS compact serialization with ES256.
// Covers public: Jws.signEs256, Jws.verifyEs256. Sign+verify round-trip,
// structural shape (3 dot-separated segments), tamper/wrong-key/malformed
// rejection (verify returns false, never throws).
// ---------------------------------------------------------------------------

@Test
class JwsUT {
    private static let headerJson: String = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}"
    private static let abc: Array<UInt8> = [0x61, 0x62, 0x63]

    private static func countDots(s: String): Int64 {
        let bytes = s.toArray()
        var n: Int64 = 0
        for (i in 0..bytes.size) {
            if (bytes[i] == b'.') {
                n += 1
            }
        }
        return n
    }

    @TestCase
    func testSignVerify_shortPayload_returnsTrue(): Unit {
        let priv = EcdsaP256.generate()
        let pub = EcdsaP256.publicKeyOf(priv)
        let compact = Jws.signEs256(JwsUT.headerJson, JwsUT.abc, priv)
        @Expect(Jws.verifyEs256(compact, pub), true)
    }

    @TestCase
    func testSign_compactHasThreeSegments(): Unit {
        let priv = EcdsaP256.generate()
        let compact = Jws.signEs256(JwsUT.headerJson, JwsUT.abc, priv)
        @Expect(JwsUT.countDots(compact), 2) // two dots → three segments
    }

    @TestCase
    func testSignVerify_emptyPayload_returnsTrue(): Unit {
        let priv = EcdsaP256.generate()
        let pub = EcdsaP256.publicKeyOf(priv)
        let compact = Jws.signEs256(JwsUT.headerJson, Array<UInt8>(), priv)
        @Expect(Jws.verifyEs256(compact, pub), true)
    }

    @TestCase
    func testSignVerify_multibyteUtf8Payload_returnsTrue(): Unit {
        let priv = EcdsaP256.generate()
        let pub = EcdsaP256.publicKeyOf(priv)
        // "EUDI Wallet €" (3-byte € = 0xE2 0x82 0xAC)
        let payload: Array<UInt8> = [
            0x45, 0x55, 0x44, 0x49, 0x20, 0x57, 0x61, 0x6c,
            0x6c, 0x65, 0x74, 0x20, 0xE2, 0x82, 0xAC
        ]
        let compact = Jws.signEs256(JwsUT.headerJson, payload, priv)
        @Expect(Jws.verifyEs256(compact, pub), true)
    }

    @TestCase
    func testVerify_wrongPublicKey_returnsFalse(): Unit {
        let priv = EcdsaP256.generate()
        let otherPub = EcdsaP256.publicKeyOf(EcdsaP256.generate())
        let compact = Jws.signEs256(JwsUT.headerJson, JwsUT.abc, priv)
        @Expect(Jws.verifyEs256(compact, otherPub), false)
    }

    @TestCase
    func testVerify_tamperedSignature_returnsFalse(): Unit {
        let priv = EcdsaP256.generate()
        let pub = EcdsaP256.publicKeyOf(priv)
        let compact = Jws.signEs256(JwsUT.headerJson, JwsUT.abc, priv)
        let bytes = compact.toArray()
        // flip a byte in the last (signature) segment
        var secondDot: Int64 = -1
        var dotCount: Int64 = 0
        for (i in 0..bytes.size) {
            if (bytes[i] == b'.') {
                dotCount += 1
                if (dotCount == 2) {
                    secondDot = i
                }
            }
        }
        let pos = secondDot + 1
        bytes[pos] = if (bytes[pos] == b'A') { b'B' } else { b'A' }
        @Expect(Jws.verifyEs256(String.fromUtf8(bytes), pub), false)
    }

    @TestCase
    func testVerify_malformedCompact_returnsFalse(): Unit {
        let pub = EcdsaP256.publicKeyOf(EcdsaP256.generate())
        // wrong segment count / undecodable signature
        @Expect(Jws.verifyEs256("aaa.bbb", pub), false)
    }

    @TestCase
    func testVerify_tooManySegments_returnsFalse(): Unit {
        let pub = EcdsaP256.publicKeyOf(EcdsaP256.generate())
        @Expect(Jws.verifyEs256("a.b.c.d", pub), false)
    }

    // Algorithm-confusion defense: a header claiming alg=none must be rejected
    // even when the token is genuinely ES256-signed over its own signing input.
    @TestCase
    func testVerify_algNoneHeader_rejected(): Unit {
        let priv = EcdsaP256.generate()
        let pub = EcdsaP256.publicKeyOf(priv)
        let noneCompact = Jws.signEs256("{\"alg\":\"none\"}", JwsUT.abc, priv)
        @Expect(Jws.verifyEs256(noneCompact, pub), false)
    }

    @TestCase
    func testVerify_wrongAlgHeader_rejected(): Unit {
        let priv = EcdsaP256.generate()
        let pub = EcdsaP256.publicKeyOf(priv)
        let hs = Jws.signEs256("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", JwsUT.abc, priv)
        @Expect(Jws.verifyEs256(hs, pub), false)
    }
}
