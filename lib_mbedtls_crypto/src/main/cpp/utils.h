//
// Created by guobao.sun on 2021/4/30.
//

#ifndef ANDROID_CRYPTO_UTILS_H
#define ANDROID_CRYPTO_UTILS_H

#include <jni.h>
#include <malloc.h>
#include <string.h>

unsigned char *jbyteArrayToChars(JNIEnv *env, jbyteArray arr);

#endif //ANDROID_CRYPTO_UTILS_H
