package com.glion.crypto_module

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher

/**
 * Project : CryptoModuleSample
 * File : RSAUtils
 * Created by glion on 2025-10-13
 *
 * Description:
 * - RSA 키 생성 암복호화 Utils
 *
 * Copyright @2025 Gangglion. All rights reserved
 */
class RSAUtils {
    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val RSA_ALIAS = "rsa_key"
        private const val KEY_SIZE = 2048
        private const val RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding"
    }

    private val keystore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    fun getOrCreateRSAKeyPair() : KeyPair {
        if(keystore.containsAlias(RSA_ALIAS)) {
            val entry = keystore.getEntry(RSA_ALIAS, null) as KeyStore.PrivateKeyEntry
            return KeyPair(entry.certificate.publicKey, entry.privateKey)
        } else {
            val keyGen = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA,
                ANDROID_KEYSTORE
            )
            val spec = KeyGenParameterSpec.Builder(
                RSA_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            ).apply {
                setKeySize(KEY_SIZE)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            }.build()

            keyGen.initialize(spec)
            return keyGen.generateKeyPair() // 생성과 동시에 KeyStore 에 저장됨
        }
    }

    /**
     * RSA 암호화
     * @param 암호화하고자 하는 ByteArray
     * @return 암호화된 값
     */
    fun encrypt(publicKey: PublicKey, origin: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return cipher.doFinal(origin)
    }

    /**
     * RSA 암호화
     * @param 암호화하고자 하는 문자열
     * @return 암호화된 값
     */
    fun encrypt(publicKey: PublicKey, origin: String): ByteArray {
        val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return cipher.doFinal(origin.toByteArray(Charsets.UTF_8))
    }

    /**
     * RSA 복호화
     * @param encryptedValue 암호화된 값
     * @return 복호화된 ByteArray
     */
    fun decryptByteArray(privateKey: PrivateKey, encryptedValue: ByteArray) : ByteArray {
        val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return cipher.doFinal(encryptedValue)
    }

    /**
     * RSA 복호화
     * @param encryptedValue 암호화된 값
     * @return 복호화된 문자열
     */
    fun decrypt(privateKey: PrivateKey, encryptedValue: ByteArray) : String {
        val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        val decryptValue = cipher.doFinal(encryptedValue)
        return String(decryptValue, Charsets.UTF_8)
    }
}