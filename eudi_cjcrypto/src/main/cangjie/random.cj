/*
 * random.cj — CSPRNG byte generation.
 * Thin wrap of stdx.crypto.crypto.SecureRandom (OpenSSL RAND_bytes-backed).
 */
package eudi_lib_core_crypto

import stdx.crypto.crypto.*

public class Rng {
    /* Generate `count` cryptographically strong random bytes (count must be positive). */
    public static func bytes(count: Int64): Array<UInt8> {
        if (count <= 0) {
            throw CoreCryptoException("random byte count must be positive, got ${count}")
        }
        if (count > 0x7FFF_FFFF) {
            throw CoreCryptoException("random byte count too large: ${count}")
        }
        let generator = SecureRandom()
        return generator.nextBytes(Int32(count))
    }
}
