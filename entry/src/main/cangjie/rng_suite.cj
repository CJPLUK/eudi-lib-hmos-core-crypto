package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*

import eudi_lib_core_crypto.*

// ---------------------------------------------------------------------------
// Rng suite — CSPRNG byte generation (stdx SecureRandom).
// Covers public: Rng.bytes. Length contract, non-repetition across draws,
// and CoreCryptoException error path on non-positive count.
// ---------------------------------------------------------------------------

@Test
class RngUT {

    @TestCase
    func testBytes_requestedLength_isHonored(): Unit {
        @Expect(Rng.bytes(32).size, 32)
    }

    @TestCase
    func testBytes_oneByte_returnsOneByte(): Unit {
        @Expect(Rng.bytes(1).size, 1)
    }

    @TestCase
    func testBytes_twoDraws_differ(): Unit {
        // Two 32-byte CSPRNG draws colliding has negligible probability.
        let a = Rng.bytes(32)
        let b = Rng.bytes(32)
        @Expect(ccEq(a, b), false)
    }

    @TestCase
    func testBytes_zeroCount_throws(): Unit {
        var threw = false
        try {
            Rng.bytes(0)
        } catch (e: CoreCryptoException) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func testBytes_negativeCount_throws(): Unit {
        var threw = false
        try {
            Rng.bytes(-5)
        } catch (e: CoreCryptoException) {
            threw = true
        }
        @Expect(threw, true)
    }
}
