package com.glion.cryptomodulesample

import android.app.Application
import com.glion.crypto_module.ExternalAESUtils

/**
 * Project : CryptoModuleSample
 * File : CryptoModuleSample
 * Created by shhan on 2025-09-23
 *
 * Description:
 * - 추후 기입
 *
 * Copyright @2025 UBIPLUS. All rights reserved
 */
class CryptoModuleSample : Application() {
    override fun onCreate() {
        super.onCreate()

        // 외부 AES 키 사용시 초기화 필수
        ExternalAESUtils.init(this)
    }
}