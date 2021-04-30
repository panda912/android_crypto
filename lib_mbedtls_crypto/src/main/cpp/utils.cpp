//
// Created by guobao.sun on 2021/4/30.
//

#include "utils.h"
#include <android/log.h>


unsigned char *jbyteArrayToChars(JNIEnv *env, jbyteArray arr) {
  unsigned char *result = nullptr;
  jbyte *bytes = env->GetByteArrayElements(arr, JNI_FALSE);
  jsize len = env->GetArrayLength(arr);
  __android_log_print(ANDROID_LOG_INFO, "utils", "len=%d", len);
  if (len > 0) {
    result = static_cast<unsigned char *>(malloc(len + 1));
    memcpy(result, bytes, len);
    result[len] = 0;
  }
  env->ReleaseByteArrayElements(arr, bytes, 0);
  return result;
}