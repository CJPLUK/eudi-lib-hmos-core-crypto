/*
 * jws.cj — RFC 7515 JWS compact serialization with the ES256 algorithm.
 * Pure byte/string assembly over Base64Url + EcdsaP256: the signature is the raw
 * r||s (64B) form as JOSE requires (RFC 7518 §3.4), not DER.
 */
package eudi_lib_core_crypto

import stdx.crypto.keys.*

public class Jws {
    /*
     * Build the compact form: b64url(headerJson) "." b64url(payload) "." b64url(sig).
     * The caller provides the protected header JSON (must declare "alg":"ES256").
     */
    public static func signEs256(headerJson: String, payload: Array<UInt8>,
        priv: ECDSAPrivateKey): String {
        let signingInput = Base64Url.encode(headerJson.toArray()) + "." + Base64Url.encode(payload)
        let rawSignature = EcdsaP256.sign(priv, signingInput.toArray())
        return signingInput + "." + Base64Url.encode(rawSignature)
    }

    /*
     * Verify a compact JWS with ES256. Returns false (never throws) on structural
     * problems: wrong segment count, undecodable signature, or non-64-byte signature.
     */
    public static func verifyEs256(compact: String, pub: ECDSAPublicKey): Bool {
        let bytes = compact.toArray()
        var firstDot: Int64 = -1
        var secondDot: Int64 = -1
        for (i in 0..bytes.size) {
            if (bytes[i] == b'.') {
                if (firstDot < 0) {
                    firstDot = i
                } else if (secondDot < 0) {
                    secondDot = i
                } else {
                    return false
                }
            }
        }
        if (firstDot <= 0 || secondDot < 0 || secondDot >= bytes.size - 1) {
            return false
        }
        // Algorithm-confusion defense (RFC 7515/7518): the protected header MUST
        // declare alg=ES256. Without this, an attacker could swap the header to
        // "none" or another algorithm. Reject anything that is not ES256.
        let headerSeg = Array<UInt8>(firstDot, repeat: 0)
        for (i in 0..firstDot) {
            headerSeg[i] = bytes[i]
        }
        var headerJson = ""
        try {
            headerJson = String.fromUtf8(Base64Url.decode(String.fromUtf8(headerSeg)))
        } catch (e: Exception) {
            return false
        }
        let compactHeader = headerJson.replace(" ", "").replace("\n", "").replace("\t", "").replace("\r", "")
        if (!compactHeader.contains("\"alg\":\"ES256\"")) {
            return false
        }
        let signingInput = Array<UInt8>(secondDot, repeat: 0)
        for (i in 0..secondDot) {
            signingInput[i] = bytes[i]
        }
        let signaturePart = Array<UInt8>(bytes.size - secondDot - 1, repeat: 0)
        for (i in 0..signaturePart.size) {
            signaturePart[i] = bytes[secondDot + 1 + i]
        }
        var rawSignature = Array<UInt8>()
        try {
            rawSignature = Base64Url.decode(String.fromUtf8(signaturePart))
        } catch (e: Exception) {
            return false
        }
        if (rawSignature.size != 64) {
            return false
        }
        return EcdsaP256.verify(pub, signingInput, rawSignature)
    }
}
