package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*

import eudi_lib_core_crypto.*

// ---------------------------------------------------------------------------
// EcdhP256 suite — P-256 ECDH via HUKS (kit.UniversalKeystoreKit).
// Device-runtime API: the key pair lives in the HUKS keystore under an alias.
// Covers public: EcdhP256.generateKey, hasKey, exportPublicKey, agree,
// deleteKey. The full two-party agreement round-trip asserts both peers derive
// the same shared secret; each test cleans up its aliases via deleteKey.
// ---------------------------------------------------------------------------

@Test
class EcdhP256UT {
    private static let aliasA: String = "eudi_cc_ecdh_test_a"
    private static let aliasB: String = "eudi_cc_ecdh_test_b"

    private static func cleanup(alias: String): Unit {
        // deleteKey is the public teardown path; ignore failures for absent keys.
        try {
            if (EcdhP256.hasKey(alias)) {
                EcdhP256.deleteKey(alias)
            }
        } catch (e: Exception) {
        }
    }

    @TestCase
    func testGenerateKey_thenHasKey_isTrue(): Unit {
        EcdhP256UT.cleanup(EcdhP256UT.aliasA)
        EcdhP256.generateKey(EcdhP256UT.aliasA)
        let present = EcdhP256.hasKey(EcdhP256UT.aliasA)
        EcdhP256UT.cleanup(EcdhP256UT.aliasA)
        @Expect(present, true)
    }

    @TestCase
    func testDeleteKey_thenHasKey_isFalse(): Unit {
        EcdhP256UT.cleanup(EcdhP256UT.aliasA)
        EcdhP256.generateKey(EcdhP256UT.aliasA)
        EcdhP256.deleteKey(EcdhP256UT.aliasA)
        @Expect(EcdhP256.hasKey(EcdhP256UT.aliasA), false)
    }

    @TestCase
    func testExportPublicKey_returnsNonEmpty(): Unit {
        EcdhP256UT.cleanup(EcdhP256UT.aliasA)
        EcdhP256.generateKey(EcdhP256UT.aliasA)
        let pub = EcdhP256.exportPublicKey(EcdhP256UT.aliasA)
        let nonEmpty = pub.size > 0
        EcdhP256UT.cleanup(EcdhP256UT.aliasA)
        @Expect(nonEmpty, true)
    }

    @TestCase
    func testAgree_twoParties_deriveSameSecret(): Unit {
        EcdhP256UT.cleanup(EcdhP256UT.aliasA)
        EcdhP256UT.cleanup(EcdhP256UT.aliasB)
        EcdhP256.generateKey(EcdhP256UT.aliasA)
        EcdhP256.generateKey(EcdhP256UT.aliasB)
        let pubA = EcdhP256.exportPublicKey(EcdhP256UT.aliasA)
        let pubB = EcdhP256.exportPublicKey(EcdhP256UT.aliasB)
        // A agrees with B's public; B agrees with A's public → identical secrets.
        let secretAB = EcdhP256.agree(EcdhP256UT.aliasA, pubB)
        let secretBA = EcdhP256.agree(EcdhP256UT.aliasB, pubA)
        EcdhP256UT.cleanup(EcdhP256UT.aliasA)
        EcdhP256UT.cleanup(EcdhP256UT.aliasB)
        @Expect(secretAB.size > 0 && ccEq(secretAB, secretBA), true)
    }

    @TestCase
    func testHasKey_unknownAlias_isFalse(): Unit {
        EcdhP256UT.cleanup("eudi_cc_ecdh_never_made")
        @Expect(EcdhP256.hasKey("eudi_cc_ecdh_never_made"), false)
    }
}
