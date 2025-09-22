package com.glion.crypto_module

import android.content.Context
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Project : CryptoModuleSample
 * File : ExternalAESUtils
 * Created by glion on 2025-09-19
 *
 * Description:
 * - 외부(서버) 에서 받은 AES 키를 사용하는 Utils
 *
 * Copyright @2025 Gangglion. All rights reserved
 */
object ExternalAESUtils {
    private const val ALGORITHM = "AES"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"

    private const val IV_SIZE = 12 // GCM 권장값
    private const val TAG_SIZE = 128

    private const val FILE_NAME = "aesKey"

    // aes 키 값
    private var aesKey: ByteArray? = null

    /**
     * 외부에서 AES key 값을 받아왔을때, 파일에 저장 - AES 키 값은 암호화된 형태
     * @param context Context 객체
     * @param encryptedAESKey 암호화된 AES 키 값
     */
    fun saveAESKey(context: Context, encryptedAESKey: ByteArray) {
        // 암호화된 상태 AES 키 값을 복호화하여 메모리에 저장 - 추후 사용하기 위함
        if(RSAUtils.rsaKey == null) throw CryptoException("AES 키 복호화를 위해 RSA 키 생성이 필요합니다.")
        aesKey = encryptedAESKey.decryptRSAByteArray()
        // 암호화된 상태 그대로 파일에 저장
        val file = File(context.filesDir, FILE_NAME)
        FileOutputStream(file).use { it.write(encryptedAESKey) }
    }

    /**
     * 파일에서 AES Key 값을 가져옴
     * @param context Context 객체
     */
    fun getAesKeyFromFile(context: Context) {
        val file = File(context.filesDir, FILE_NAME)
        if(!file.exists()) throw CryptoException("저장된 AES 키 파일이 없습니다")
        val encryptedAeyBytes = FileInputStream(file).use { it.readBytes() }
        if(RSAUtils.rsaKey == null) throw CryptoException("AES 키 복호화를 위해 RSA 키 생성이 필요합니다.")
        aesKey = encryptedAeyBytes.decryptRSAByteArray()
    }

    /**
     * 앱 내부저장소에 AES 키 파일 있는지 확인
     */
    fun isExistAESKeyFile(context: Context) = File(context.filesDir, FILE_NAME).exists()

    /**
     * IV 값 생성
     */
    private fun generateIv() : ByteArray = ByteArray(IV_SIZE).also { SecureRandom().nextBytes(it) }

    /**
     * 암호화
     * @param origin 암호화하고자 하는 값
     * @return Pair(암호화된 값, iv)
     */
    fun encrypt(origin: String): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val secretKey = SecretKeySpec(aesKey, ALGORITHM)
        val iv = generateIv()
        val spec = GCMParameterSpec(TAG_SIZE, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)
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
        val secretKey = SecretKeySpec(aesKey, ALGORITHM)
        val spec = GCMParameterSpec(TAG_SIZE, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

        val decryptedValue = cipher.doFinal(encrypted)

        return String(decryptedValue, Charsets.UTF_8)
    }
}