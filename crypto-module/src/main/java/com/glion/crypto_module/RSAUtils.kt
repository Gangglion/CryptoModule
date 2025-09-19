package com.glion.crypto_module

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import javax.crypto.Cipher

/**
 * Project : CryptoModule
 * File : RSAUtils
 * Created by glion on 2025-09-19
 *
 * Description:
 * - RSA 키 생성 암복호화 Utils
 *
 * Copyright @2025 Gangglion. All rights reserved
 */
object RSAUtils {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val RSA_ALIAS = "rsa_key"

    private const val RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding"
    private const val KEY_SIZE = 2048

    private val keystore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    var rsaKey: KeyPair? = null
        private set

    /**
     * RSA 키 가져와서 저장, 없으면 생성
     */
    fun getOrCreateRSAKeyPair() {
        if(keystore.containsAlias(RSA_ALIAS)) {
            val entry = keystore.getEntry(RSA_ALIAS, null) as KeyStore.PrivateKeyEntry
            rsaKey = KeyPair(entry.certificate.publicKey, entry.privateKey)
        } else {
            val keyGen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
            val spec = KeyGenParameterSpec.Builder(
                RSA_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            ).apply {
                setKeySize(KEY_SIZE)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            }.build()

            keyGen.initialize(spec)
            rsaKey = keyGen.generateKeyPair()
        }
    }

    /**
     * RSA 키의 공개키 리턴
     */
    fun getRsaPublicKey(): ByteArray {
        if(rsaKey == null) throw CryptoException("RSA 키가 생성되지 않았습니다.")

        return rsaKey!!.public.encoded
    }

    /**
     * RSA 암호화
     * @param 암호화하고자 하는 ByteArray
     * @return 암호화된 값
     */
    fun encrypt(origin: ByteArray): ByteArray {
        if(rsaKey == null) throw CryptoException("RSA 키가 생성되지 않았습니다.")

        val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, rsaKey!!.public)
        return cipher.doFinal(origin)
    }

    /**
     * RSA 암호화
     * @param 암호화하고자 하는 문자열
     * @return 암호화된 값
     */
    fun encrypt(origin: String): ByteArray {
        if(rsaKey == null) throw CryptoException("RSA 키가 생성되지 않았습니다.")

        val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, rsaKey!!.public)
        return cipher.doFinal(origin.toByteArray(Charsets.UTF_8))
    }

    /**
     * RSA 복호화
     * @param encryptedValue 암호화된 값
     * @return 복호화된 ByteArray
     */
    fun decryptByteArray(encryptedValue: ByteArray) : ByteArray {
        if(rsaKey == null) throw CryptoException("RSA 키가 생성되지 않았습니다.")

        val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, rsaKey!!.private)
        return cipher.doFinal(encryptedValue)
    }

    /**
     * RSA 복호화
     * @param encryptedValue 암호화된 값
     * @return 복호화된 문자열
     */
    fun decrypt(encryptedValue: ByteArray) : String {
        if(rsaKey == null) throw CryptoException("RSA 키가 생성되지 않았습니다.")

        val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, rsaKey!!.private)
        val decryptValue = cipher.doFinal(encryptedValue)
        return String(decryptValue, Charsets.UTF_8)
    }
}