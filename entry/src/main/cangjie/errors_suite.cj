package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*

import eudi_lib_core_crypto.*

// ---------------------------------------------------------------------------
// CoreCryptoException suite — the typed exception for the wrap layer.
// Covers public: CoreCryptoException.init(message) and its identity as an
// Exception subtype (catchable both as CoreCryptoException and as Exception).
// ---------------------------------------------------------------------------

@Test
class CoreCryptoExceptionUT {

    @TestCase
    func testInit_messageIsPreserved(): Unit {
        let e = CoreCryptoException("boom")
        @Expect(e.message, "boom")
    }

    @TestCase
    func testIsExceptionSubtype_catchableAsException(): Unit {
        var caught = false
        try {
            throw CoreCryptoException("subtype check")
        } catch (e: Exception) {
            caught = true
        }
        @Expect(caught, true)
    }

    @TestCase
    func testCatchableAsConcreteType(): Unit {
        var msg = ""
        try {
            throw CoreCryptoException("typed catch")
        } catch (e: CoreCryptoException) {
            msg = e.message
        }
        @Expect(msg, "typed catch")
    }
}
