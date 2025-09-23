package com.glion.cryptomodulesample

import android.os.Bundle
import android.util.Log
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.glion.crypto_module.AESUtils
import com.glion.crypto_module.ExternalAESUtils
import com.glion.crypto_module.RSAUtils
import com.glion.crypto_module.decryptExternalAES
import com.glion.crypto_module.decryptKeyStoreAES
import com.glion.crypto_module.decryptRSAStr
import com.glion.crypto_module.encryptExternalAES
import com.glion.crypto_module.encryptKeyStoreAES
import com.glion.crypto_module.encryptRSA
import javax.crypto.KeyGenerator

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        // RSA 테스트
        Log.d("glion", "############### RSA 암복호화 테스트 시작 ###############")
        Log.d("glion", "##### RSA 키 생성 #####")
        RSAUtils.getOrCreateRSAKeyPair()
        Log.d("glion", "RSA Private Key : ${RSAUtils.rsaKey!!.private.encoded} // Public Key : ${RSAUtils.rsaKey!!.public.encoded}")
        val origin1 = "abcdefghijklmnopqrstuvwxxyz"
        Log.d("glion", "암호화 전 : $origin1")
        val encryptedOrigin1 = origin1.encryptRSA()
        Log.d("glion", "암호화 완료 : $encryptedOrigin1")
        val decrypted1 = encryptedOrigin1.decryptRSAStr()
        Log.d("glion", "복호화 완료 : $decrypted1")
        Log.d("glion", "############### RSA 암복호화 테스트 종료 ###############")

        // AES 테스트
        Log.d("glion", "############### AES 암복호화 테스트 시작 ###############")
        Log.d("glion", "##### AES 키 생성 #####")
        AESUtils.getOrCreateAESKey()
        Log.d("glion", "AES Key : ${AESUtils.aesKey}")
        val origin2 = "abcdefghijklmnopqrstuvwxxyz"
        Log.d("glion", "암호화 전 : $origin2")
        val encryptedOrigin2 = origin2.encryptKeyStoreAES()
        Log.d("glion", "암호화 완료 : ${encryptedOrigin2.first} // ${encryptedOrigin2.second}")
        val decrypted2 = encryptedOrigin2.decryptKeyStoreAES()
        Log.d("glion", "복호화 완료 : $decrypted2")
        Log.d("glion", "############### AES 암복호화 테스트 종료 ###############")

        // 서버에서 가져온 AES 키 값 저장 후 테스트
        Log.d("glion", "############### 외부에서 가져온 AES 키를 가지고 암복호화 테스트 시작 ###############")
        Log.d("glion", "##### 서버에서 AES 키 받음 #####")
        val tempKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey().encoded
        Log.d("glion", "AES Key : $tempKey")
        Log.d("glion", "##### 로컬에 AES 키 저장 #####")
        ExternalAESUtils.saveAESKey(tempKey.encryptRSA())
        Log.d("glion", "##### 로컬에 AES 키 저장되었는지 확인 #####")
        Log.d("glion", "결과 :: ${ExternalAESUtils.isExistAESKeyFile()}")
        val origin3 = "abcdefghijklmnopqrstuvwxxyz"
        Log.d("glion", "암호화 전 : $origin3")
        val encryptedOrigin3 = origin3.encryptExternalAES()
        Log.d("glion", "암호화 완료 : ${encryptedOrigin3.first} // ${encryptedOrigin3.second}")
        val decrypted3 = encryptedOrigin3.decryptExternalAES()
        Log.d("glion", "복호화 완료 : $decrypted3")
        Log.d("glion", "############### 외부에서 가져온 AES 키를 가지고 암복호화 테스트 종료 ###############")
    }
}