/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_va_client_NativeClient */

#ifndef _Included_com_va_client_NativeClient
#define _Included_com_va_client_NativeClient
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_va_client_NativeClient
 * Method:    init
 * Signature: (IIII[II)V
 */
JNIEXPORT void JNICALL Java_com_va_client_NativeClient_init
  (JNIEnv *, jobject, jint, jint, jint, jint, jintArray, jint);

/*
 * Class:     com_va_client_NativeClient
 * Method:    exit
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_va_client_NativeClient_exit
  (JNIEnv *, jobject);

/*
 * Class:     com_va_client_NativeClient
 * Method:    clientAdvertiseKeys
 * Signature: (I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_va_client_NativeClient_clientAdvertiseKeys
  (JNIEnv *, jobject, jint);

/*
 * Class:     com_va_client_NativeClient
 * Method:    clientShareMetadata
 * Signature: (II[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_va_client_NativeClient_clientShareMetadata
  (JNIEnv *, jobject, jint, jint, jbyteArray);

/*
 * Class:     com_va_client_NativeClient
 * Method:    clientMaskedInputCollection
 * Signature: (II[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_va_client_NativeClient_clientMaskedInputCollection
  (JNIEnv *, jobject, jint, jint, jbyteArray);

/*
 * Class:     com_va_client_NativeClient
 * Method:    clientUnmasking
 * Signature: (II[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_va_client_NativeClient_clientUnmasking
  (JNIEnv *, jobject, jint, jint, jbyteArray);

/*
 * Class:     com_va_client_NativeClient
 * Method:    clientReceiveResult
 * Signature: (I[B)V
 */
JNIEXPORT void JNICALL Java_com_va_client_NativeClient_clientReceiveResult
  (JNIEnv *, jobject, jint, jbyteArray);

/*
 * Class:     com_va_client_NativeClient
 * Method:    clientDecommitting
 * Signature: (I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_va_client_NativeClient_clientDecommitting
  (JNIEnv *, jobject, jint);

/*
 * Class:     com_va_client_NativeClient
 * Method:    clientDroppedDecommitting
 * Signature: (II[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_va_client_NativeClient_clientDroppedDecommitting
  (JNIEnv *, jobject, jint, jint, jbyteArray);

/*
 * Class:     com_va_client_NativeClient
 * Method:    clientBatchChecking
 * Signature: (I[B)Z
 */
JNIEXPORT jboolean JNICALL Java_com_va_client_NativeClient_clientBatchChecking
  (JNIEnv *, jobject, jint, jbyteArray);

/*
 * Class:     com_va_client_NativeClient
 * Method:    testHomHash
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_va_client_NativeClient_testHomHash
  (JNIEnv *, jobject);

/*
 * Class:     com_va_client_NativeClient
 * Method:    testCommitment
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_va_client_NativeClient_testCommitment
  (JNIEnv *, jobject);

/*
 * Class:     com_va_client_NativeClient
 * Method:    testSecretShare
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_va_client_NativeClient_testSecretShare
  (JNIEnv *, jobject);

/*
 * Class:     com_va_client_NativeClient
 * Method:    testKeyAgreement
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_va_client_NativeClient_testKeyAgreement
  (JNIEnv *, jobject);

/*
 * Class:     com_va_client_NativeClient
 * Method:    testCipher
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_va_client_NativeClient_testCipher
  (JNIEnv *, jobject);

/*
 * Class:     com_va_client_NativeClient
 * Method:    testMultipliedInput
 * Signature: (II)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_va_client_NativeClient_testMultipliedInput
  (JNIEnv *, jobject, jint, jint);

#ifdef __cplusplus
}
#endif
#endif
