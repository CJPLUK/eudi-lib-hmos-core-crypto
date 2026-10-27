/*
 * ecdsa.cj — ES256 (ECDSA over P-256 with SHA-256).
 * Wraps stdx.crypto.keys (OpenSSL-backed ECDSAPrivateKey/ECDSAPublicKey, Curve.P256).
 * stdx sign/verify use the ASN.1 DER signature wire format, so this file also carries
 * the pure-byte DER <-> raw(r||s, 64B) interconversion required by JWS/COSE callers.
 */
package eudi_lib_core_crypto

import stdx.crypto.keys.*

public class EcdsaP256 {
    private static let componentLen: Int64 = 32

    /* Generate a fresh P-256 private key (the public half is derived via publicKeyOf). */
    public static func generate(): ECDSAPrivateKey {
        return ECDSAPrivateKey(Curve.P256)
    }

    /* Derive the public key for a private key. */
    public static func publicKeyOf(priv: ECDSAPrivateKey): ECDSAPublicKey {
        return ECDSAPublicKey(priv)
    }

    /* Raw uncompressed P-256 public point 0x04||X(32)||Y(32) = 65 bytes (from the SPKI DER tail). */
    public static func publicKeyUncompressed(pub: ECDSAPublicKey): Array<UInt8> {
        let der = pub.encodeToDer().body
        if (der.size < 65) {
            throw CoreCryptoException("ECDSA public SPKI shorter than a 65-byte uncompressed point")
        }
        let start = der.size - 65
        if (der[start] != 0x04u8) {
            throw CoreCryptoException("ECDSA public SPKI does not end in an uncompressed (0x04) P-256 point")
        }
        let out = Array<UInt8>(65, repeat: 0)
        for (i in 0..65) {
            out[i] = der[start + i]
        }
        return out
    }

    /* Derive the public key from a private key and export its uncompressed point. */
    public static func publicKeyUncompressedOf(priv: ECDSAPrivateKey): Array<UInt8> {
        return publicKeyUncompressed(publicKeyOf(priv))
    }

    /*
     * ES256 sign: SHA-256 the message, sign the digest, return the raw r||s (64B) form.
     */
    public static func sign(priv: ECDSAPrivateKey, message: Array<UInt8>): Array<UInt8> {
        let derSignature = priv.sign(Digest.sha256(message))
        return derToRaw(derSignature)
    }

    /*
     * ES256 verify with a raw r||s (64B) signature. Malformed signatures yield false,
     * they never throw.
     */
    public static func verify(pub: ECDSAPublicKey, message: Array<UInt8>,
        rawSignature: Array<UInt8>): Bool {
        if (rawSignature.size != 2 * componentLen) {
            return false
        }
        var derSignature = Array<UInt8>()
        try {
            derSignature = rawToDer(rawSignature)
        } catch (e: Exception) {
            return false
        }
        return pub.verify(Digest.sha256(message), derSignature)
    }

    /*
     * Convert ASN.1 DER ECDSA-Sig-Value (SEQUENCE { INTEGER r, INTEGER s }) to raw r||s (64B).
     * Throws CoreCryptoException on malformed input or integers wider than 32 bytes.
     */
    public static func derToRaw(der: Array<UInt8>): Array<UInt8> {
        if (der.size < 8 || der[0] != 0x30) {
            throw CoreCryptoException("malformed DER ECDSA signature: missing SEQUENCE")
        }
        var pos: Int64 = 1
        var seqLen = Int64(der[pos])
        pos += 1
        if (seqLen == 0x81) {
            if (pos >= der.size) {
                throw CoreCryptoException("malformed DER ECDSA signature: truncated length")
            }
            seqLen = Int64(der[pos])
            pos += 1
        } else if (seqLen > 0x7F) {
            throw CoreCryptoException("malformed DER ECDSA signature: unsupported length form")
        }
        if (pos + seqLen != der.size) {
            throw CoreCryptoException("malformed DER ECDSA signature: length mismatch")
        }
        let raw = Array<UInt8>(2 * componentLen, repeat: 0)
        let afterR = copyDerInteger(der, pos, raw, 0)
        let afterS = copyDerInteger(der, afterR, raw, componentLen)
        if (afterS != der.size) {
            throw CoreCryptoException("malformed DER ECDSA signature: trailing bytes")
        }
        return raw
    }

    /*
     * Convert a raw r||s (64B) signature into ASN.1 DER ECDSA-Sig-Value form.
     */
    public static func rawToDer(raw: Array<UInt8>): Array<UInt8> {
        if (raw.size != 2 * componentLen) {
            throw CoreCryptoException("raw ECDSA signature must be ${2 * componentLen} bytes")
        }
        let r = minimalInteger(raw, 0)
        let s = minimalInteger(raw, componentLen)
        // Max body is 2+33+2+33 = 70 (< 128), so the short length form always suffices.
        let bodyLen = 2 + r.size + 2 + s.size
        let out = Array<UInt8>(2 + bodyLen, repeat: 0)
        out[0] = 0x30
        out[1] = UInt8(bodyLen)
        var pos: Int64 = 2
        out[pos] = 0x02
        out[pos + 1] = UInt8(r.size)
        pos += 2
        for (i in 0..r.size) {
            out[pos + i] = r[i]
        }
        pos += r.size
        out[pos] = 0x02
        out[pos + 1] = UInt8(s.size)
        pos += 2
        for (i in 0..s.size) {
            out[pos + i] = s[i]
        }
        return out
    }

    /*
     * Read one DER INTEGER starting at `position`, strip redundant leading zeros and
     * right-align its value into out[outOffset .. outOffset+32). Returns the position
     * just past the integer.
     */
    private static func copyDerInteger(der: Array<UInt8>, position: Int64, out: Array<UInt8>,
        outOffset: Int64): Int64 {
        var pos = position
        if (pos + 2 > der.size || der[pos] != 0x02) {
            throw CoreCryptoException("malformed DER ECDSA signature: missing INTEGER")
        }
        pos += 1
        var len = Int64(der[pos])
        pos += 1
        if (len == 0 || len > 0x7F || pos + len > der.size) {
            throw CoreCryptoException("malformed DER ECDSA signature: bad INTEGER length")
        }
        var start = pos
        while (len > 1 && der[start] == 0) {
            start += 1
            len -= 1
        }
        if (len > componentLen) {
            throw CoreCryptoException("DER INTEGER does not fit a P-256 component")
        }
        for (i in 0..len) {
            out[outOffset + componentLen - len + i] = der[start + i]
        }
        return pos + Int64(der[position + 1])
    }

    /*
     * Minimal positive DER INTEGER content bytes for one 32-byte big-endian component:
     * leading zeros stripped, a 0x00 prefix added when the top bit is set.
     */
    private static func minimalInteger(raw: Array<UInt8>, offset: Int64): Array<UInt8> {
        var start = offset
        let end = offset + componentLen
        while (start < end - 1 && raw[start] == 0) {
            start += 1
        }
        let needsPad = raw[start] >= 0x80
        let valueLen = end - start
        let outLen = valueLen + (if (needsPad) { 1 } else { 0 })
        let out = Array<UInt8>(outLen, repeat: 0)
        let base = if (needsPad) { 1 } else { 0 }
        for (i in 0..valueLen) {
            out[base + i] = raw[start + i]
        }
        return out
    }
}
