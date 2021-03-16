#include "com_va_server_NativeServer.h"

#include "ServerContext.h"
extern "C" {
	static ServerContext *sctx;
}

void Java_com_va_server_NativeServer_init(JNIEnv *env, jobject obj,
	jint logR, jint d, jint t, jint N, jint batch)
{
	sctx = new ServerContext(logR, d, t, N, batch);
}

void Java_com_va_server_NativeServer_exit(JNIEnv *env, jobject obj)
{
	delete sctx;
}

/*
 *	Protocol interfaces
 */

void Java_com_va_server_NativeServer_serverUpdateKeys(JNIEnv *env, jobject obj,
	jbyteArray message)
{
	jsize len = env->GetArrayLength(message);
	unsigned char *message_buffer = new unsigned char[len];
	env->GetByteArrayRegion(message, 0, len, (jbyte *)message_buffer);

	// Unpack message
	MaskKey my_maskKey(sctx->mask.curve, message_buffer);

	// Proceed with received message
	sctx->UpdateKeys(my_maskKey);
}

void Java_com_va_server_NativeServer_serverUpdateU2(JNIEnv *env, jobject obj,
	jint pid)
{
	// Proceed with received pid
	sctx->UpdateU2(pid);
}

void Java_com_va_server_NativeServer_serverUpdateInput(JNIEnv *env, jobject obj,
	jbyteArray message)
{
	jsize len = env->GetArrayLength(message);
	unsigned char *message_buffer = new unsigned char[len];
	env->GetByteArrayRegion(message, 0, len, (jbyte *)message_buffer);

	// Unpack message
	MaskedInput my_maskedInput(sctx->d, sctx->n_bytes_agg_bound,
		message_buffer);

	// Proceed with received message
	sctx->UpdateInput(my_maskedInput);
}

void Java_com_va_server_NativeServer_serverUpdateMaskShares(JNIEnv *env, jobject obj,
	jbyteArray message)
{
	jsize len = env->GetArrayLength(message);
	unsigned char *message_buffer = new unsigned char[len];
	env->GetByteArrayRegion(message, 0, len, (jbyte *)message_buffer);

	// Unpack message
	MaskShares my_maskShares(sctx->U2_size[sctx->curr_epoch] - 1,
		sctx->U3_size[sctx->curr_epoch] - 1,
		message_buffer);

	// Proceed with received message
	sctx->UpdateMaskShares(my_maskShares);
}

jbyteArray Java_com_va_server_NativeServer_serverFinalResult(JNIEnv *env, jobject obj)
{
	// Get final result
	unsigned char buffer[_ULTRA_BUFFER_SIZE];
	int ret_len = sctx->FinalResult(buffer);

	// Prepare return value
	jbyteArray ret = env->NewByteArray(ret_len);
	env->SetByteArrayRegion(ret, 0, ret_len, (jbyte *)buffer);

	return ret;
}

void Java_com_va_server_NativeServer_serverUpdateV1(JNIEnv *env, jobject obj,
	jint pid)
{
	// Proceed with received pid
	sctx->UpdateV1(pid);
}

void Java_com_va_server_NativeServer_serverUpdateDecomStrShares(JNIEnv *env, jobject obj,
	jbyteArray message)
{
	jsize len = env->GetArrayLength(message);
	unsigned char *message_buffer = new unsigned char[len];
	env->GetByteArrayRegion(message, 0, len, (jbyte *)message_buffer);

	// Unpack message
	int dropped_size = 0;
	for (int i = 0; i < sctx->batch; ++i)
		dropped_size += (sctx->U3_size[i] - sctx->V1.size());

	DecomStrShares my_decomStrShares(dropped_size,
		message_buffer);

	// Proceed with received message
	sctx->UpdateDecomStrShares(my_decomStrShares);
}

jbyteArray Java_com_va_server_NativeServer_serverFinalDecomStr(JNIEnv *env, jobject obj)
{
	// Get final result
	unsigned char buffer[_ULTRA_BUFFER_SIZE];
	int ret_len = sctx->FinalDecomStr(buffer);

	// Prepare return value
	jbyteArray ret = env->NewByteArray(ret_len);
	env->SetByteArrayRegion(ret, 0, ret_len, (jbyte *)buffer);

	return ret;
}