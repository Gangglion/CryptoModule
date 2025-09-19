package com.glion.crypto_module

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Project : CryptoModuleSample
 * File : AESUtils
 * Created by glion on 2025-09-19
 *
 * Description:
 * - AES 키 생성 및 암복호화 Utils(KeyStore 사용)
 *
 * Copyright @2025 Gangglion. All rights reserved
 */
object AESUtils {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val AES_ALIAS = "aes_key"

    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val KEY_SIZE = 256
    private const val IV_SIZE = 12 // GCM 권장값
    private const val TAG_SIZE = 128

    private val keystore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    // aes 키 값 - KeyStore 로 생성한 AES 키는 꺼낼 수 없음
    var aesKey: SecretKey? = null
        private set

    /**
     * AES 키 생성 - KeyStore 에 저장
     */
    fun getOrCreateAESKey() {
        // 키스토어에 있는지 확인
        if(keystore.containsAlias(AES_ALIAS)) {
            val entry = keystore.getEntry(AES_ALIAS, null) as? KeyStore.SecretKeyEntry
            aesKey = entry?.secretKey
        } else {
            // 없으면 생성 후 저장
            val keygen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            val spec = KeyGenParameterSpec.Builder(AES_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true) // iv 자동생성
                .setKeySize(KEY_SIZE)
                .build()
            keygen.init(spec)
            aesKey = keygen.generateKey()
        }
    }

    /**
     * 암호화
     * @param origin 암호화하고자 하는 값
     * @return Pair(암호화된 값, iv)
     */
    fun encrypt(origin: String): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, aesKey)
        val iv = cipher.iv // cipher 에서 자동 생성해준 iv 이용
        val encrypted = cipher.doFinal(origin.toByteArray(Charsets.UTF_8))

        return encrypted to iv
    }

    /**
     * 복호화
     * @param encrypted 암호화된 값
     * @param iv 암호화 시 사용된 iv 값
     * @return 복호화된 문자열
     */
    fun decrypt(encrypted: ByteArray, iv: ByteArray) : String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val spec = GCMParameterSpec(TAG_SIZE, iv)
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec)

        val decryptedValue = cipher.doFinal(encrypted)

        return String(decryptedValue, Charsets.UTF_8)
    }
}