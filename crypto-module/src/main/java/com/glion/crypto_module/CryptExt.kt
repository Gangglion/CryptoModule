package com.glion.crypto_module

/**
 * Project : CryptoModuleSample
 * File : StringExt
 * Created by glion on 2025-09-19
 *
 * Description:
 * - 암복호화 편하게 사용하기 위한 확장함수
 *
 * Copyright @2025 Gangglion. All rights reserved
 */

/**
 * 문자열 -> RSA 암호화
 * @return 암호화된 바이트배열
 */
fun String.encryptRSA() : ByteArray = RSAUtils.encrypt(this)

/**
 * 바이트배열 -> RSA 암호화
 * @return 암호화된 바이트배열
 */
fun ByteArray.encryptRSA(): ByteArray = RSAUtils.encrypt(this)

/**
 * 바이트배열 -> RSA 복호화 -> 문자열
 * @return 복호화된 문자열
 */
fun ByteArray.decryptRSAStr(): String = RSAUtils.decrypt(this)

/**
 * 바이트배열 -> RSA 복호화 -> 바이트배열
 * @return 복호화된 바이트배열
 */
fun ByteArray.decryptRSAByteArray(): ByteArray = RSAUtils.decryptByteArray(this)

/**
 * 문자열 -> AES 암호화(키스토어 사용)
 * @return 암호화된 바이트배열, iv 바이트배열
 */
fun String.encryptKeyStoreAES(): Pair<ByteArray, ByteArray> = AESUtils.encrypt(this)

/**
 * (바이트배열, iv) -> AES 복호화(키스토어 사용)
 * @return 복호화된 문자열
 */
fun Pair<ByteArray, ByteArray>.decryptKeyStoreAES() : String = AESUtils.decrypt(this.first, this.second)

/**
 * 문자열 -> AES 암호화(외부 AES 키 사용)
 * @return 암호화된 바이트배열, iv 바이트배열
 */
fun String.encryptExternalAES(): Pair<ByteArray, ByteArray> = ExternalAESUtils.encrypt(this)

/**
 * (바이트배열, iv) -> AES 복호화(외부 AES 키 사용)
 * @return 복호화된 문자열
 */
fun Pair<ByteArray, ByteArray>.decryptExternalAES() : String = ExternalAESUtils.decrypt(this.first, this.second)

