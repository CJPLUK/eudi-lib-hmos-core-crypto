/*
 * digest.cj — SHA-2 digests and HMAC-SHA256 over byte arrays.
 * Thin wrap of stdx.crypto.digest (OpenSSL-backed). No hand-rolled hashing here:
 * this file only adapts the streaming stdx API to one-shot static helpers.
 */
package eudi_lib_core_crypto

import stdx.crypto.digest.*

public class Digest {
    public static func sha256(data: Array<UInt8>): Array<UInt8> {
        let hasher = SHA256()
        if (data.size > 0) {
            hasher.write(data)
        }
        return hasher.finish()
    }

    public static func sha384(data: Array<UInt8>): Array<UInt8> {
        let hasher = SHA384()
        if (data.size > 0) {
            hasher.write(data)
        }
        return hasher.finish()
    }

    public static func sha512(data: Array<UInt8>): Array<UInt8> {
        let hasher = SHA512()
        if (data.size > 0) {
            hasher.write(data)
        }
        return hasher.finish()
    }
}

public class Hmac {
    /*
     * HMAC-SHA256(key, data). The key must be non-empty (stdx HMAC rejects empty keys).
     * Empty data is valid: the write step is skipped and the MAC of the empty message
     * is returned, which RFC 4231 vectors rely on.
     */
    public static func sha256(key: Array<UInt8>, data: Array<UInt8>): Array<UInt8> {
        if (key.size == 0) {
            throw CoreCryptoException("HMAC key must not be empty")
        }
        let mac = HMAC(key, HashType.SHA256)
        if (data.size > 0) {
            mac.write(data)
        }
        return mac.finish()
    }
}
