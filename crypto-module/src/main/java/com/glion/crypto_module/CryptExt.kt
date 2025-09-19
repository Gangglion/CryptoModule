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

// RSA 관련
fun String.encryptRSA() : ByteArray = RSAUtils.encrypt(this)
fun ByteArray.encryptRSA(): ByteArray = RSAUtils.encrypt(this)
fun ByteArray.decryptRSA(): String = RSAUtils.decrypt(this)
fun ByteArray.decryptByteArray(): ByteArray = RSAUtils.decryptByteArray(this)

// AES 관련(KeyStore 생성)
fun String.encryptKeyStoreAES(): Pair<ByteArray, ByteArray> = AESUtils.encrypt(this)
fun Pair<ByteArray, ByteArray>.decryptKeyStoreAES() = AESUtils.decrypt(this.first, this.second)

// AES 관련(외부 AES 키 사용)
fun String.encryptExternalAES(): Pair<ByteArray, ByteArray> = ExternalAESUtils.encrypt(this)
fun Pair<ByteArray, ByteArray>.decryptExternalAES() = ExternalAESUtils.decrypt(this.first, this.second)

