/*
 * errors.cj — typed exception for the eudi_lib_core_crypto wrap layer.
 * Thrown on malformed input (DER/base64url/lengths) and on platform crypto failures
 * that callers must not silently swallow. AES-GCM tag mismatch is NOT reported via
 * this exception: AesGcm.open returns Option.None instead.
 */
package eudi_lib_core_crypto

public class CoreCryptoException <: Exception {
    public init(message: String) {
        super(message)
    }
}
