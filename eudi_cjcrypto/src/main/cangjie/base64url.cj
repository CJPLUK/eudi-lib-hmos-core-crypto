/*
 * base64url.cj — RFC 4648 §5 url-safe base64 without padding.
 * Wraps stdx.encoding.base64 (toBase64String/fromBase64String) and only performs the
 * alphabet translation (+/ <-> -_) and padding strip/restore. Codec, not cryptography.
 */
package eudi_lib_core_crypto

import stdx.encoding.base64.*

public class Base64Url {
    /* Encode bytes as url-safe base64 with no '=' padding. */
    public static func encode(data: Array<UInt8>): String {
        if (data.size == 0) {
            return ""
        }
        let standard = toBase64String(data).toArray()
        var outLen: Int64 = 0
        for (i in 0..standard.size) {
            if (standard[i] != b'=') {
                outLen += 1
            }
        }
        let out = Array<UInt8>(outLen, repeat: 0)
        var idx: Int64 = 0
        for (i in 0..standard.size) {
            let c = standard[i]
            if (c == b'=') {
                continue
            }
            if (c == b'+') {
                out[idx] = b'-'
            } else if (c == b'/') {
                out[idx] = b'_'
            } else {
                out[idx] = c
            }
            idx += 1
        }
        return String.fromUtf8(out)
    }

    /*
     * Decode url-safe base64 (padding optional/absent). Throws CoreCryptoException on
     * inputs that are not valid base64url.
     */
    public static func decode(text: String): Array<UInt8> {
        if (text.isEmpty()) {
            return Array<UInt8>()
        }
        let body = text.toArray()
        let remainder = body.size % 4
        if (remainder == 1) {
            throw CoreCryptoException("invalid base64url input length")
        }
        let padCount = if (remainder == 0) { 0 } else { 4 - remainder }
        let standard = Array<UInt8>(body.size + padCount, repeat: b'=')
        for (i in 0..body.size) {
            let c = body[i]
            if (c == b'-') {
                standard[i] = b'+'
            } else if (c == b'_') {
                standard[i] = b'/'
            } else {
                standard[i] = c
            }
        }
        match (fromBase64String(String.fromUtf8(standard))) {
            case Some(bytes) => return bytes
            case None => throw CoreCryptoException("invalid base64url input")
        }
    }
}
