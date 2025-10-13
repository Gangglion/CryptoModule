package com.glion.crypto_module

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Project : CryptoModuleSample
 * File : AESUtils
 * Created by glion on 2025-10-13
 *
 * Description:
 * - AES 키 생성 및 암복호화 Utils(키 생성은 keyStore 로 진행)
 *
 * Copyright @2025 Gangglion. All rights reserved
 */
class AESUtils {
    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val AES_ALIAS = "aes_key"
        private const val ALGORITHM = "AES"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val KEY_SIZE = 256
        private const val IV_SIZE = 12 // GCM 권장값
        private const val TAG_SIZE = 128
    }

    private val keystore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    /**
     * AES 키 생성 - KeyStore 에 저장
     */
    fun getOrCreateAESKey() : SecretKey {
        // 키스토어에 있는지 확인
        if(keystore.containsAlias(AES_ALIAS)) {
            val entry = keystore.getEntry(AES_ALIAS, null) as? KeyStore.SecretKeyEntry
            return entry!!.secretKey
        } else {
            // 없으면 생성 후 저장
            val keygen = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
            )
            val spec = KeyGenParameterSpec.Builder(AES_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true) // iv 자동생성
                .setKeySize(KEY_SIZE)
                .build()
            keygen.init(spec)
            return keygen.generateKey() // 생성과 동시에 KeyStore 에 저장됨
        }
    }

    private fun generateIv() : ByteArray = ByteArray(IV_SIZE).also { SecureRandom().nextBytes(it) }

    /**
     * KeyStore AES 키로 암호화
     * @param aesKey KeyStore 에서 생성한 AES 키
     * @param origin 암호화하고자 하는 값(ByteArray)
     * @return Pair(암호화된 값, iv)
     */
    fun encrypt(aesKey: SecretKey, origin: ByteArray): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, aesKey)
        // cipher 에서 자동 생성해준 iv 사용
        val iv = cipher.iv
        val encrypted = cipher.doFinal(origin)

        return encrypted to iv
    }

    /**
     * KeyStore AES 키로 암호화
     * @param aesKey KeyStore 에서 생성한 AES 키
     * @param origin 암호화하고자 하는 값(String)
     * @return Pair(암호화된 값, iv)
     */
    fun encrypt(aesKey: SecretKey, origin: String): Pair<ByteArray, ByteArray> {
        return encrypt(aesKey, origin.toByteArray(Charsets.UTF_8))
    }

    /**
     * 외부 AES 키로 암호화
     * @param aesKey 외부에서 받은 AES 키
     * @param origin 암호화하고자 하는 값(ByteArray)
     * @return Pair(암호화된 값, iv)
     */
    fun encrypt(aesKey: ByteArray, origin: ByteArray): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val secretKey = SecretKeySpec(aesKey, ALGORITHM)
        val iv = generateIv()
        val spec = GCMParameterSpec(TAG_SIZE, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)
        val encrypted = cipher.doFinal(origin)

        return encrypted to iv
    }

    /**
     * 외부 AES 키로 암호화
     * @param aesKey 외부에서 받은 AES 키
     * @param origin 암호화하고자 하는 값(String)
     * @return Pair(암호화된 값, iv)
     */
    fun encrypt(aesKey: ByteArray, origin: String): Pair<ByteArray, ByteArray> {
        return encrypt(aesKey, origin.toByteArray(Charsets.UTF_8))
    }

    /**
     * KeyStore AES 키로 복호화
     * @param aesKey KeyStore 에서 생성한 AES 키
     * @param encrypted 암호화된 값
     * @param iv 암호화 시 사용된 iv 값
     * @return 복호화된 ByteArray
     */
    fun decryptToByteArray(aesKey: SecretKey, encrypted: ByteArray, iv: ByteArray) : ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val spec = GCMParameterSpec(TAG_SIZE, iv)
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec)

        return cipher.doFinal(encrypted)
    }

    /**
     * KeyStore AES 키로 복호화
     * @param aesKey KeyStore 에서 생성한 AES 키
     * @param encrypted 암호화된 값
     * @param iv 암호화 시 사용된 iv 값
     * @return 복호화된 문자열
     */
    fun decryptToString(aesKey: SecretKey, encrypted: ByteArray, iv: ByteArray) : String {
        return String(decryptToByteArray(aesKey, encrypted, iv), Charsets.UTF_8)
    }

    /**
     * 외부 AES 키로 복호화
     * @param aesKey 외부에서 받은 AES 키
     * @param encrypted 암호화된 값
     * @param iv 암호화 시 사용된 iv 값
     * @return 복호화된 ByteArray
     */
    fun decryptToByteArray(aesKey: ByteArray, encrypted: ByteArray, iv: ByteArray) : ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val secretKey = SecretKeySpec(aesKey, ALGORITHM)
        val spec = GCMParameterSpec(TAG_SIZE, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

        return cipher.doFinal(encrypted)
    }

    /**
     * 외부 AES 키로 복호화
     * @param aesKey 외부에서 받은 AES 키
     * @param encrypted 암호화된 값
     * @param iv 암호화 시 사용된 iv 값
     * @return 복호화된 문자열
     */
    fun decryptToString(aesKey: ByteArray, encrypted: ByteArray, iv: ByteArray) : String {
        return String(decryptToByteArray(aesKey, encrypted, iv), Charsets.UTF_8)
    }
}