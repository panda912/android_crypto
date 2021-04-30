//
// Created by guobao.sun on 2021/4/28.
//
#include <jni.h>
#include <cstring>
#include <android/log.h>
#include <mbedtls/aes.h>
#include <mbedtls/des.h>
#include <mbedtls/platform.h>
#include "utils.h"

#define ZERO_PADDING 0
#define PKCS1_PADDING 1
#define PKCS7_PADDING 2
#define ISO10126_PADDING 3


#define LOG_TAG "crypto"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)


static u_char AES_KEY[16] = {0};
static u_char AES_IV[16] = {0};

static u_char DES_KEY[8] = {0};
static u_char DES_2KEY[8 * 2] = {0};
static u_char DES_3KEY[8 * 3] = {0};
static u_char DES_IV[8] = {0};

void init_aes_key(JNIEnv *env, jstring key_) {
  const char *key = env->GetStringUTFChars(key_, nullptr);
  memcpy(AES_KEY, key, 16);
  env->ReleaseStringUTFChars(key_, key);
}

void init_aes_key_iv(JNIEnv *env, jstring key_, jstring iv_) {
  init_aes_key(env, key_);
  const char *iv = env->GetStringUTFChars(iv_, nullptr);
  memcpy(AES_IV, iv, 16);
  env->ReleaseStringUTFChars(iv_, iv);
}

void init_des_key(JNIEnv *env, jstring key_) {
  const char *key = env->GetStringUTFChars(key_, nullptr);
  memcpy(DES_KEY, key, 8);
  env->ReleaseStringUTFChars(key_, key);
}

void init_des_iv(JNIEnv *env, jstring iv_) {
  const char *iv = env->GetStringUTFChars(iv_, nullptr);
  memcpy(DES_IV, iv, 8);
  env->ReleaseStringUTFChars(iv_, iv);
}

/**
 * aes ecb encrypt
 */
extern "C"
JNIEXPORT jbyteArray JNICALL
aes_ecb_encrypt(JNIEnv *env, jclass, jstring plain_text, jstring key) {
  init_aes_key(env, key);
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, AES_KEY, 128);

  const char *plain = env->GetStringUTFChars(plain_text, nullptr);
  jsize plain_len = env->GetStringUTFLength(plain_text);
  jsize len = 16 * (plain_len / 16 + 1);
  auto *input = static_cast<u_char *>(malloc(len));
//  if (padding == ZERO_PADDING) {
  memset(input, 0, len);
//  } else if (padding == PKCS7_PADDING) {
//    memset(input, len - plain_len, len);
//  } else if (padding == ISO10126_PADDING) {
//    memset(input, len - plain_len, len);
//    memset(input, 0, len - 1);
//  } else {
//    LOGE("unsupported padding: %d", padding);
//  }
  memcpy(input, plain, plain_len);

  int i, block = 0, length = len;
  u_char output[len], temp[16];
  while (length > 0) {
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, input, temp);

    for (i = 0; i < 16; i++) {
      output[block * 16 + i] = temp[i];
    }

    block++;
    input += 16;
    length -= 16;
  }

  mbedtls_aes_free(&ctx);
  env->ReleaseStringUTFChars(plain_text, plain);
  // reset input's point, if not, will be free error.
  input -= block * 16;
  free(input);

  jbyteArray bArr = env->NewByteArray(len);
  env->SetByteArrayRegion(bArr, 0, len, reinterpret_cast<const jbyte *>(output));
  return bArr;
}

/**
 * aes ecb decrypt
 */
extern "C"
JNIEXPORT jstring JNICALL
aes_ecb_decrypt(JNIEnv *env, jclass, jbyteArray bArr, jstring key) {
  init_aes_key(env, key);
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_dec(&ctx, AES_KEY, 128);

  jbyte *input = env->GetByteArrayElements(bArr, JNI_FALSE);
  jsize len = env->GetArrayLength(bArr);
  if (len <= 0) {
    return env->NewStringUTF("");
  }

  u_char output[len];
  int block = 0;
  while (len > 0) {
    u_char temp[16];
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, reinterpret_cast<const unsigned char *>(input), temp);

    for (int i = 0; i < 16; i++) {
      output[block * 16 + i] = temp[i];
    }

    block++;
    input += 16;
    len -= 16;
  }

  mbedtls_aes_free(&ctx);
  // reset input's point, if not, will be free error.
  input -= block * 16;
  env->ReleaseByteArrayElements(bArr, input, 0);

  return env->NewStringUTF(reinterpret_cast<const char *>(output));
}

/**
 * aes cbc encrypt
 */
extern "C"
JNIEXPORT jbyteArray JNICALL
aes_cbc_encrypt(JNIEnv *env, jclass, jstring plain_text, jstring key, jstring iv) {
  init_aes_key_iv(env, key, iv);
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, AES_KEY, 128);

  const char *plain = env->GetStringUTFChars(plain_text, nullptr);
  jsize plain_len = env->GetStringUTFLength(plain_text);
  jsize len = 16 * (plain_len / 16 + 1);
  auto *input = static_cast<u_char *>(malloc(len));
//  if (padding == ZERO_PADDING) {
  memset(input, 0, len);
//  } else if (padding == PKCS7_PADDING) {
//    memset(input, len - plain_len, len);
//  } else if (padding == ISO10126_PADDING) {
//    memset(input, len - plain_len, len);
//    memset(input, 0, len - 1);
//  } else {
//    LOGE("unsupported padding: %d", padding);
//  }
  memcpy(input, plain, plain_len);
  u_char output[len];

  mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, len, AES_IV, reinterpret_cast<const u_char *>(input), output);

  mbedtls_aes_free(&ctx);
  env->ReleaseStringUTFChars(plain_text, plain);
  free(input);

  jbyteArray bArr = env->NewByteArray(len);
  env->SetByteArrayRegion(bArr, 0, len, reinterpret_cast<const jbyte *>(output));
  return bArr;
}

/**
 * aes cbc decrypt
 */
extern "C"
JNIEXPORT jstring JNICALL
aes_cbc_decrypt(JNIEnv *env, jclass, jbyteArray cipher, jstring key, jstring iv) {
  init_aes_key_iv(env, key, iv);
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_dec(&ctx, AES_KEY, 128);

  jbyte *input = env->GetByteArrayElements(cipher, nullptr);
  jsize len = env->GetArrayLength(cipher);
  u_char output[len];

  mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, len, AES_IV, reinterpret_cast<const u_char *>(input), output);
  mbedtls_aes_free(&ctx);
  env->ReleaseByteArrayElements(cipher, input, 0);

  return env->NewStringUTF(reinterpret_cast<const char *>(output));
}

/**
 * des ecb encrypt
 */
extern "C"
JNIEXPORT jbyteArray JNICALL
des_ecb_encrypt(JNIEnv *env, jclass, jstring plain_text, jstring key) {
  init_des_key(env, key);
  mbedtls_des_context ctx;
  mbedtls_des_init(&ctx);
  mbedtls_des_setkey_enc(&ctx, DES_KEY);

  const char *plain = env->GetStringUTFChars(plain_text, nullptr);
  jsize plain_len = env->GetStringUTFLength(plain_text);
  jsize len = 8 * (plain_len / 8 + 1);
  auto *input = static_cast<u_char *>(malloc(len));
//  if (padding == ZERO_PADDING) {
  memset(input, 0, len);
//  } else if (padding == PKCS7_PADDING) {
//    memset(input, len - plain_len, len);
//  } else if (padding == ISO10126_PADDING) {
//    memset(input, len - plain_len, len);
//    memset(input, 0, len - 1);
//  } else {
//    LOGE("unsupported padding: %d", padding);
//  }
  memcpy(input, plain, plain_len);

  int i, block = 0, length = len;
  u_char output[len], temp[8];
  while (length > 0) {
    mbedtls_des_crypt_ecb(&ctx, input, temp);

    for (i = 0; i < 8; i++) {
      output[block * 8 + i] = temp[i];
    }

    block++;
    input += 8;
    length -= 8;
  }

  mbedtls_des_free(&ctx);
  env->ReleaseStringUTFChars(plain_text, plain);
  input -= block * 8;
  free(input);

  jbyteArray bArr = env->NewByteArray(len);
  env->SetByteArrayRegion(bArr, 0, len, reinterpret_cast<const jbyte *>(output));
  return bArr;
}

/**
 * des ecb decrypt
 */
extern "C"
JNIEXPORT jstring JNICALL
des_ecb_decrypt(JNIEnv *env, jclass, jbyteArray cipher, jstring key) {
  init_des_key(env, key);
  mbedtls_des_context ctx;
  mbedtls_des_init(&ctx);
  mbedtls_des_setkey_dec(&ctx, DES_KEY);

  jbyte *input = env->GetByteArrayElements(cipher, nullptr);
  jsize len = env->GetArrayLength(cipher);
  u_char output[len];

  int i, block = 0;
  u_char temp[8];
  while (len > 0) {
    mbedtls_des_crypt_ecb(&ctx, reinterpret_cast<const u_char *>(input), temp);

    for (i = 0; i < 8; i++) {
      output[block * 8 + i] = temp[i];
    }

    block++;
    input += 8;
    len -= 8;
  }

  mbedtls_des_free(&ctx);
  input -= block * 8;
  env->ReleaseByteArrayElements(cipher, input, 0);

  return env->NewStringUTF(reinterpret_cast<const char *>(output));
}

/**
 * des cbc encrypt
 */
extern "C"
JNIEXPORT jbyteArray JNICALL
des_cbc_encrypt(JNIEnv *env, jclass, jstring plain_text, jstring key, jstring iv) {
  init_des_key(env, key);
  init_des_iv(env, iv);
  mbedtls_des_context ctx;
  mbedtls_des_init(&ctx);
  mbedtls_des_setkey_enc(&ctx, DES_KEY);

  const char *plain = env->GetStringUTFChars(plain_text, nullptr);
  jsize plain_len = env->GetStringUTFLength(plain_text);
  jsize len = 8 * (plain_len / 8 + 1);
  auto *input = static_cast<u_char *>(malloc(len));
  memset(input, 0, len);
  memcpy(input, plain, plain_len);
  u_char output[len];

  mbedtls_des_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, len, DES_IV, reinterpret_cast<const u_char *>(input), output);

  mbedtls_des_free(&ctx);
  env->ReleaseStringUTFChars(plain_text, plain);
  free(input);

  jbyteArray bArr = env->NewByteArray(len);
  env->SetByteArrayRegion(bArr, 0, len, reinterpret_cast<const jbyte *>(output));
  return bArr;
}

/**
 * des cbc decrypt
 */
extern "C"
JNIEXPORT jstring JNICALL
des_cbc_decrypt(JNIEnv *env, jclass, jbyteArray cipher, jstring key, jstring iv) {
  init_des_key(env, key);
  init_des_iv(env, iv);
  mbedtls_des_context ctx;
  mbedtls_des_init(&ctx);
  mbedtls_des_setkey_dec(&ctx, DES_KEY);

  jbyte *input = env->GetByteArrayElements(cipher, nullptr);
  jsize len = env->GetArrayLength(cipher);
  u_char output[len];

  mbedtls_des_crypt_cbc(&ctx, MBEDTLS_DES_DECRYPT, len, DES_IV, reinterpret_cast<const u_char *>(input), output);
  mbedtls_des_free(&ctx);
  env->ReleaseByteArrayElements(cipher, input, 0);

  return env->NewStringUTF(reinterpret_cast<const char *>(output));
}


extern "C"
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
  JNIEnv *env;
  if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
    return JNI_ERR;
  }

  jclass cls = env->FindClass("com/panda912/crypto/mbedtls/Crypto");
  if (cls == nullptr) {
    return JNI_ERR;
  }

  static const JNINativeMethod methods[] = {
      {"aesEncrypt", "(Ljava/lang/String;Ljava/lang/String;)[B",                   reinterpret_cast<void *>(aes_ecb_encrypt)},
      {"aesDecrypt", "([BLjava/lang/String;)Ljava/lang/String;",                   reinterpret_cast<void *>(aes_ecb_decrypt)},
      {"aesEncrypt", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)[B", reinterpret_cast<void *>(aes_cbc_encrypt)},
      {"aesDecrypt", "([BLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;", reinterpret_cast<void *>(aes_cbc_decrypt)},
      {"desEncrypt", "(Ljava/lang/String;Ljava/lang/String;)[B",                   reinterpret_cast<void *>(des_ecb_encrypt)},
      {"desDecrypt", "([BLjava/lang/String;)Ljava/lang/String;",                   reinterpret_cast<void *>(des_ecb_decrypt)},
      {"desEncrypt", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)[B", reinterpret_cast<void *>(des_cbc_encrypt)},
      {"desDecrypt", "([BLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;", reinterpret_cast<void *>(des_cbc_decrypt)},
  };
  int rc = env->RegisterNatives(cls, methods, sizeof(methods) / sizeof(JNINativeMethod));
  if (rc != JNI_OK) {
    return rc;
  }

  return JNI_VERSION_1_6;
}