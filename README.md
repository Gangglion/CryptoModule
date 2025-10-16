# CryptoModule
RSA, AES 암복호화 Android Module

## 개요
```CryptoModule``` 은 Android 환경에서 RSA 및 AES 기반의 키를 생성하고 암호화/복호화를 간편하게 사용할 수 있도록 만든 모듈입니다.  
```AndroidKeyStore``` 를 이용한 RSA 키(PKCS1Padding 방식), AES(GCM 방식) 키 생성 및 관리, 암복호화 기능을 제공합니다.

## 주요 기능
* ```AndroidKeyStore``` 를 사용한 RSA/AES 키 생성/조회
* 외부에서 받은 바이너리 형태의 AES 키를 통한 암호화/복호화(GCM 방식으로 만들어진 256비트의 AES 키여야 합니다.)
* RSA 와 AES 키를 사용한 데이터 암호화/복호화

## API 예시
아래는 모듈이 제공하는 핵심 함수입니다. 실제 코드는 레포지토리 내 코드를 참고하세요.
### AESUtils.kt
| 함수                                                                                     | 설명                                                                                                                                    |
|----------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| `getOrCreateAESKey(): SecretKey`                                                       | 256비트 GCM 방식 AES 키를 생성하여 KeyStore에 저장 후 반환합니다. 이미 키가 존재하면 기존 키를 반환합니다.                                                                |
| `encrypt(aesKey: SecretKey, origin: ByteArray/String): Pair<ByteArray, ByteArray>`     | KeyStore에서 생성한 AES 키를 사용하여 데이터를 암호화합니다. 반환값은 `(암호화된 데이터, IV)` 입니다.                                                                    |
| `encrypt(aesKey: ByteArray, origin: ByteArray/String): Pair<ByteArray, ByteArray>`     | 외부에서 제공한 AES 키(ByteArray)를 사용하여 데이터를 암호화합니다. 반환값은 `(암호화된 데이터, IV)` 입니다.<br/>이때, 외부에서 제공되는 AES 키는 GCM/NoPadding 방식, 256비트 사이즈의 키여야 합니다 |
| `decryptToByteArray(aesKey: SecretKey/ByteArray, origin: ByteArray/String): ByteArray` | AES 키를 사용하여 데이터를 복호화하고 `ByteArray`로 반환합니다.                                                                                            |
| `decryptToString(aesKey: SecretKey/ByteArray, origin: ByteArray/String): String`       | AES 키를 사용하여 데이터를 복호화하고 `String`으로 반환합니다.                                                                                              |
### RSAUtils.kt
| 함수                                                                               | 설명                                                                               |
| -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `getOrCreateRSAKeyPair(): KeyPair`                                               | PKCS1Padding 방식의 2048비트 RSA 키를 생성하여 KeyStore에 저장 후 반환합니다. 기존 키가 있으면 해당 키를 반환합니다. |
| `encrypt(publicKey: PublicKey, origin: ByteArray/String): ByteArray`             | 주어진 PublicKey를 사용하여 데이터를 암호화합니다.                                                 |
| `decrypt(privateKey: PrivateKey, encryptedValue: ByteArray): String`             | 주어진 PrivateKey를 사용하여 데이터를 복호화하고 문자열로 반환합니다.                                      |
| `decryptByteArray(privateKey: PrivateKey, encryptedValue: ByteArray): ByteArray` | 주어진 PrivateKey를 사용하여 데이터를 복호화하고 `ByteArray`로 반환합니다.                              |

## 사용 방법
### 1) 모듈 추가
프로젝트 구조에 따라 crypto-module 을 서브 모듈로 포함하세요.
```kotlin
// settings.gradle.kts
include(":app", ":crypto-module")

// build.gradle.kts(:app)
dependencies {
    implementation(project(":crypto-module"))
}
```

### 2) RSA 키 생성/조회
```kotlin
val rsaUtils = RSAUtils()
val keyPair = rsaUtils.getOrCreateRSAKeyPair()
```
### 3) RSA 키 이용 암호화 / 복호화
```kotlin
val origin = "abcdefghijklmnopqrstuvwxxyz"
val encryptedOrigin = rsaUtils.encrypt(keyPair.public, origin) // 암호화
val decrypted = rsaUtils.decrypt(keyPair.private, encryptedOrigin) // 복호화
```  
### 4) AES 키 생성/조회
```kotlin
val aesUtils = AESUtils()
val aesKey = aesUtils.getOrCreateAESKey()
```
### 5) AES 키 이용 암호화 / 복호화
```kotlin
val origin = "abcdefghijklmnopqrstuvwxxyz"
val (cipherText, iv) = aesUtils.encrypt(aesKey, origin) // 암호화
val decrypted = aesUtils.decryptToString(aesKey, cipherText, iv) // 복호화
```

## 구성
```
crypto-module/
    ├─ AESUtils         // AES 키 생성 및 암호화/복호화
    ├─ RSAUtils         // RSA 키 생성 및 암호화/복호화
    └─ CryptoException  // 암복호화 도중 오류 발생시 리턴하는 커스텀 Exception
```

## 예시 앱
레포지토리의 app/ 폴더에 샘플 앱이 포함되어 있습니다. 샘플 코드를 빌드하고 Logcat 에서 동작을 확인하세요.