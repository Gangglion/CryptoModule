package com.glion.cryptomodulesample

import android.content.Context
import android.os.Bundle
import android.util.Log
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.glion.crypto_module.AESUtils
import com.glion.crypto_module.CryptoException
import com.glion.crypto_module.RSAUtils
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
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
        rsaTest()

        // AES 테스트
        aesTest()

        // 서버에서 가져온 AES 키 값 저장 후 테스트
        externalAesTest(this)
    }

    private fun rsaTest() {
        Log.d("glion", "############### RSA 암복호화 테스트 시작 ###############")
        Log.d("glion", "##### RSA 키 생성 #####")
        val rsaUtils = RSAUtils()
        val keyPair = rsaUtils.getOrCreateRSAKeyPair()
        Log.d("glion", "RSA Private Key(안보이는게 정상) : ${keyPair.private.encoded} // Public Key : ${keyPair.public.encoded}")
        val origin = "abcdefghijklmnopqrstuvwxxyz"
        Log.d("glion", "암호화 전 : $origin")
        val encryptedOrigin = rsaUtils.encrypt(keyPair.public, origin)
        Log.d("glion", "암호화 완료 : $encryptedOrigin")
        val decrypted = rsaUtils.decrypt(keyPair.private, encryptedOrigin)
        Log.d("glion", "복호화 완료 : $decrypted")
        Log.d("glion", "############### RSA 암복호화 테스트 종료 ###############")
    }

    private fun aesTest() {
        Log.d("glion", "############### AES 암복호화 테스트 시작 ###############")
        Log.d("glion", "##### AES 키 생성 #####")
        val aesUtils = AESUtils()
        val aesKey = aesUtils.getOrCreateAESKey()
        Log.d("glion", "AES Key : $aesKey")
        val origin = "abcdefghijklmnopqrstuvwxxyz"
        Log.d("glion", "암호화 전 : $origin")
        val encryptedOrigin = aesUtils.encrypt(aesKey, origin)
        Log.d("glion", "암호화 완료 : ${encryptedOrigin.first} // ${encryptedOrigin.second}")
        val decrypted = aesUtils.decryptToString(aesKey, encryptedOrigin.first, encryptedOrigin.second)
        Log.d("glion", "복호화 완료 : $decrypted")
        Log.d("glion", "############### AES 암복호화 테스트 종료 ###############")
    }

    private fun externalAesTest(context: Context) {
        val rsaUtils = RSAUtils()
        val keyPair = rsaUtils.getOrCreateRSAKeyPair()

        val aesUtils = AESUtils()

        Log.d("glion", "############### 외부에서 가져온 AES 키를 가지고 암복호화 테스트 시작 ###############")
        Log.d("glion", "##### 서버에서 AES 키 생성을 가정 #####")
        val tempKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey().encoded
        Log.d("glion", "AES Key : $tempKey")
        Log.d("glion", "##### 서버에서 RSA 로 암호화된 AES 키 받음 #####")
        val encryptedAesKey = rsaUtils.encrypt(keyPair.public, tempKey)
        Log.d("glion", "##### 로컬에 AES 키 저장 #####")
        saveAESKey(context, encryptedAesKey)
        Log.d("glion", "##### 로컬에 AES 키 저장되었는지 확인 #####")
        Log.d("glion", "결과 :: ${isExistAESKeyFile(context)}")
        val origin = "abcdefghijklmnopqrstuvwxxyz"
        Log.d("glion", "암호화 전 : $origin")
        val aesKey = getAesKeyFromFile(context, rsaUtils)
        val encryptedOrigin = aesUtils.encrypt(aesKey, origin)
        Log.d("glion", "암호화 완료 : ${encryptedOrigin.first} // ${encryptedOrigin.second}")
        val decrypted = aesUtils.decryptToString(aesKey, encryptedOrigin.first, encryptedOrigin.second)
        Log.d("glion", "복호화 완료 : $decrypted")
        Log.d("glion", "############### 외부에서 가져온 AES 키를 가지고 암복호화 테스트 종료 ###############")
    }


    // ############################################################################################ //
    // 키 값을 파일에 저장하고, 가져오는 책임은 crypto 모듈이 아닌 crypto 모듈을 사용하는 주체(:app) 에 있음
    // ############################################################################################ //

    private val FILE_NAME = "aesKey"
    /**
     * 외부에서 AES key 값을 받아왔을때, 파일에 저장 - AES 키 값은 암호화된 형태
     * @param context Context 객체
     * @param encryptedAESKey 암호화된 AES 키 값
     */
    private fun saveAESKey(context: Context, encryptedAESKey: ByteArray) {
        // 암호화된 상태 그대로 파일에 저장
        val file = File(context.filesDir, FILE_NAME)
        FileOutputStream(file).use { it.write(encryptedAESKey) }
    }

    /**
     * 파일에서 AES Key 값을 가져옴
     * @param context Context 객체
     */
    private fun getAesKeyFromFile(context: Context, rsaUtils: RSAUtils) : ByteArray {
        val file = File(context.filesDir, FILE_NAME)
        if(!isExistAESKeyFile(context)) throw CryptoException("저장된 AES 키 파일이 없습니다")
        val encryptedAeyBytes = FileInputStream(file).use { it.readBytes() }
        val privateKey = rsaUtils.getOrCreateRSAKeyPair().private
        return rsaUtils.decryptByteArray(privateKey, encryptedAeyBytes)
    }

    /**
     * 앱 내부저장소에 AES 키 파일 있는지 확인
     */
    private fun isExistAESKeyFile(context: Context) = File(context.filesDir, FILE_NAME).exists()
}