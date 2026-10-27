/*
 * ecdh.cj — P-256 ECDH shared-secret agreement via HUKS (kit.UniversalKeystoreKit).
 * Faithful to the HUKS key-agreement doc sample (cj-huks-key-agreement.md): the private
 * key lives in the HUKS keystore under an alias; agree() runs initSession/updateSession/
 * finishSession with HUKS_ALG_ECDH and exports the agreed secret to the caller.
 * Device-runtime API: off-device it surfaces a clear HUKS error; other primitives are unaffected.
 */
package eudi_lib_core_crypto

import kit.UniversalKeystoreKit.*

public class EcdhP256 {
    /*
     * Generate a P-256 key pair for agreement inside HUKS under `keyAlias`.
     */
    public static func generateKey(keyAlias: String): Unit {
        let properties: Array<HuksParam> = [
            HuksParam(
                HuksTag.HUKS_TAG_ALGORITHM,
                HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_ECC)
            ),
            HuksParam(
                HuksTag.HUKS_TAG_KEY_SIZE,
                HuksParamValue.Uint32Value(HuksKeySize.HUKS_ECC_KEY_SIZE_256)
            ),
            HuksParam(
                HuksTag.HUKS_TAG_PURPOSE,
                HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_AGREE)
            ),
            HuksParam(
                HuksTag.HUKS_TAG_DIGEST,
                HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_NONE)
            )
        ]
        generateKeyItem(keyAlias, HuksOptions(properties: properties, inData: Array<UInt8>()))
    }

    /*
     * Export the public key material of the HUKS-resident key pair (to hand to the peer).
     */
    public static func exportPublicKey(keyAlias: String): Array<UInt8> {
        return exportKeyItem(keyAlias, HuksOptions())
    }

    public static func hasKey(keyAlias: String): Bool {
        return hasKeyItem(keyAlias, HuksOptions())
    }

    public static func deleteKey(keyAlias: String): Unit {
        deleteKeyItem(keyAlias, HuksOptions())
    }

    /*
     * ECDH agree: own private key referenced by HUKS alias, peer public key as exported
     * HUKS key material. Returns the shared secret (export-allowed storage flag).
     */
    public static func agree(privateKeyAlias: String, peerPublicKey: Array<UInt8>): Array<UInt8> {
        let agreeProperties: Array<HuksParam> = [
            HuksParam(
                HuksTag.HUKS_TAG_ALGORITHM,
                HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_ECDH)
            ),
            HuksParam(
                HuksTag.HUKS_TAG_PURPOSE,
                HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_AGREE)
            ),
            HuksParam(
                HuksTag.HUKS_TAG_KEY_SIZE,
                HuksParamValue.Uint32Value(HuksKeySize.HUKS_ECC_KEY_SIZE_256)
            )
        ]
        let session = initSession(privateKeyAlias,
            HuksOptions(properties: agreeProperties, inData: Array<UInt8>()))
        let updateProperties: Array<HuksParam> = [
            HuksParam(
                HuksTag.HUKS_TAG_ALGORITHM,
                HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_ECDH)
            ),
            HuksParam(
                HuksTag.HUKS_TAG_PURPOSE,
                HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_AGREE)
            ),
            HuksParam(
                HuksTag.HUKS_TAG_DERIVED_AGREED_KEY_STORAGE_FLAG,
                HuksParamValue.Uint32Value(HuksKeyStorageType.HUKS_STORAGE_KEY_EXPORT_ALLOWED)
            )
        ]
        let _ = updateSession(session.handle,
            HuksOptions(properties: updateProperties, inData: peerPublicKey))
        let finishProperties: Array<HuksParam> = [
            HuksParam(
                HuksTag.HUKS_TAG_DERIVED_AGREED_KEY_STORAGE_FLAG,
                HuksParamValue.Uint32Value(HuksKeyStorageType.HUKS_STORAGE_KEY_EXPORT_ALLOWED)
            )
        ]
        let shared = finishSession(session.handle,
            HuksOptions(properties: finishProperties, inData: Array<UInt8>()))
        match (shared) {
            case Some(secret) => return secret
            case None => throw CoreCryptoException("HUKS ECDH agreement returned no shared secret")
        }
    }
}
