/*
 * hkdf.cj — RFC 5869 HKDF-SHA256 (extract / expand / derive).
 * Pure Cangjie byte assembly over Hmac.sha256; the underlying HMAC primitive
 * is the stdx OpenSSL-backed implementation wrapped in digest.cj.
 */
package eudi_lib_core_crypto

public class Hkdf {
    private static let hashLen: Int64 = 32

    /*
     * HKDF-Extract(salt, IKM) -> PRK (32 bytes).
     * An empty salt is replaced by HashLen zero bytes per RFC 5869 §2.2.
     */
    public static func extract(salt: Array<UInt8>, ikm: Array<UInt8>): Array<UInt8> {
        let effectiveSalt = if (salt.size > 0) {
            salt
        } else {
            Array<UInt8>(hashLen, repeat: 0)
        }
        return Hmac.sha256(effectiveSalt, ikm)
    }

    /*
     * HKDF-Expand(PRK, info, L) -> OKM (L bytes), L in [1, 255*32].
     */
    public static func expand(prk: Array<UInt8>, info: Array<UInt8>, length: Int64): Array<UInt8> {
        if (length <= 0 || length > 255 * hashLen) {
            throw CoreCryptoException("HKDF expand length must be in [1, ${255 * hashLen}]")
        }
        if (prk.size < hashLen) {
            throw CoreCryptoException("HKDF PRK must be at least ${hashLen} bytes")
        }
        let okm = Array<UInt8>(length, repeat: 0)
        var previous = Array<UInt8>()
        var written: Int64 = 0
        var counter: Int64 = 1
        while (written < length) {
            // T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
            let block = Array<UInt8>(previous.size + info.size + 1, repeat: 0)
            for (i in 0..previous.size) {
                block[i] = previous[i]
            }
            for (i in 0..info.size) {
                block[previous.size + i] = info[i]
            }
            block[previous.size + info.size] = UInt8(counter)
            previous = Hmac.sha256(prk, block)
            var i: Int64 = 0
            while (i < previous.size && written < length) {
                okm[written] = previous[i]
                written += 1
                i += 1
            }
            counter += 1
        }
        return okm
    }

    /*
     * One-shot HKDF: derive(salt, ikm, info, length) = expand(extract(salt, ikm), info, length).
     */
    public static func derive(salt: Array<UInt8>, ikm: Array<UInt8>, info: Array<UInt8>,
        length: Int64): Array<UInt8> {
        return expand(extract(salt, ikm), info, length)
    }
}
