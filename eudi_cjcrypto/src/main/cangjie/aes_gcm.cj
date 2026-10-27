/*
 * aes_gcm.cj — AES-GCM AEAD (128/192/256-bit keys), ciphertext layout ct || tag(16B).
 * Wraps kit.CryptoArchitectureKit (createCipher 'AESnnn|GCM|NoPadding', SymKeyGenerator
 * convertKey, GcmParamsSpec). Tag mismatch on open() returns Option.None, never crashes
 * and never returns partial plaintext.
 */
package eudi_lib_core_crypto

import kit.CryptoArchitectureKit.*

public class AesGcm {
    private static let tagLen: Int64 = 16

    /*
     * Encrypt: returns ciphertext with the 16-byte GCM auth tag appended.
     * key: 16/24/32 bytes; nonce: GCM IV (12 bytes recommended); aad may be empty.
     */
    public static func seal(key: Array<UInt8>, nonce: Array<UInt8>, aad: Array<UInt8>,
        plaintext: Array<UInt8>): Array<UInt8> {
        let symKey = importKey(key)
        let params = GcmParamsSpec("GcmParamsSpec", DataBlob(nonce), DataBlob(aad),
            DataBlob(Array<UInt8>()))
        let cipher = createCipher(transformationFor(key.size))
        cipher.initialize(CryptoMode.EncryptMode, symKey, params)
        var body = Array<UInt8>()
        if (plaintext.size > 0) {
            body = cipher.update(DataBlob(plaintext)).data
        }
        // In GCM encrypt mode doFinal(None) yields the auth tag (see CryptoArchitectureKit GCM sample).
        let tag = cipher.doFinal(Option<DataBlob>.None).data
        if (tag.size != tagLen) {
            throw CoreCryptoException("AES-GCM returned a ${tag.size}-byte auth tag, expected ${tagLen}")
        }
        let out = Array<UInt8>(body.size + tagLen, repeat: 0)
        for (i in 0..body.size) {
            out[i] = body[i]
        }
        for (i in 0..tagLen) {
            out[body.size + i] = tag[i]
        }
        return out
    }

    /*
     * Decrypt: input is ciphertext with the 16-byte auth tag appended (seal's output).
     * Returns Some(plaintext) on success; None on tag/aad mismatch or malformed input.
     */
    public static func open(key: Array<UInt8>, nonce: Array<UInt8>, aad: Array<UInt8>,
        ciphertextAndTag: Array<UInt8>): Option<Array<UInt8>> {
        if (ciphertextAndTag.size < tagLen) {
            return Option<Array<UInt8>>.None
        }
        let bodyLen = ciphertextAndTag.size - tagLen
        let body = Array<UInt8>(bodyLen, repeat: 0)
        for (i in 0..bodyLen) {
            body[i] = ciphertextAndTag[i]
        }
        let tag = Array<UInt8>(tagLen, repeat: 0)
        for (i in 0..tagLen) {
            tag[i] = ciphertextAndTag[bodyLen + i]
        }
        try {
            let symKey = importKey(key)
            let params = GcmParamsSpec("GcmParamsSpec", DataBlob(nonce), DataBlob(aad),
                DataBlob(tag))
            let decoder = createCipher(transformationFor(key.size))
            decoder.initialize(CryptoMode.DecryptMode, symKey, params)
            var plain = Array<UInt8>()
            if (bodyLen > 0) {
                plain = decoder.update(DataBlob(body)).data
            }
            // doFinal verifies the auth tag; it throws on mismatch (caught below -> None).
            let tail = decoder.doFinal(Option<DataBlob>.None).data
            if (tail.size == 0) {
                return Option<Array<UInt8>>.Some(plain)
            }
            let out = Array<UInt8>(plain.size + tail.size, repeat: 0)
            for (i in 0..plain.size) {
                out[i] = plain[i]
            }
            for (i in 0..tail.size) {
                out[plain.size + i] = tail[i]
            }
            return Option<Array<UInt8>>.Some(out)
        } catch (e: Exception) {
            return Option<Array<UInt8>>.None
        }
    }

    private static func transformationFor(keySize: Int64): String {
        if (keySize == 16) {
            return "AES128|GCM|NoPadding"
        }
        if (keySize == 24) {
            return "AES192|GCM|NoPadding"
        }
        if (keySize == 32) {
            return "AES256|GCM|NoPadding"
        }
        throw CoreCryptoException("AES-GCM key must be 16, 24 or 32 bytes, got ${keySize}")
    }

    private static func generatorFor(keySize: Int64): String {
        if (keySize == 16) {
            return "AES128"
        }
        if (keySize == 24) {
            return "AES192"
        }
        if (keySize == 32) {
            return "AES256"
        }
        throw CoreCryptoException("AES-GCM key must be 16, 24 or 32 bytes, got ${keySize}")
    }

    private static func importKey(key: Array<UInt8>): SymKey {
        let generator = createSymKeyGenerator(generatorFor(key.size))
        return generator.convertKey(DataBlob(key))
    }
}
