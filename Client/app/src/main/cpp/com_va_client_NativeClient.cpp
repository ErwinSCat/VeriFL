#include "com_va_client_NativeClient.h"

#include <vector>
using namespace std;

#include "Context.h"
extern "C" {
	static int ctx_number;
	static vector<Context *> ctx_arr;
}

void Java_com_va_client_NativeClient_init(JNIEnv *env, jobject obj,
	jint logR, jint d, jint t, jint N, jintArray pids, jint batch)
{
	ctx_number = env->GetArrayLength(pids);
	jint *cpids = env->GetIntArrayElements(pids, JNI_FALSE);

	ctx_arr.resize(ctx_number);
	for (int i = 0; i < ctx_number; ++i)
		ctx_arr[i] = new Context(logR, d, t, N, cpids[i], batch);

	env->ReleaseIntArrayElements(pids, cpids, 0);
}

void Java_com_va_client_NativeClient_exit(JNIEnv *env, jobject obj)
{
	for (int i = 0; i < ctx_number; ++i)
		delete ctx_arr[i];
}

/*
 *	Protocol interfaces
 */

jbyteArray Java_com_va_client_NativeClient_clientAdvertiseKeys(JNIEnv *env, jobject obj,
	jint pid)
{
	// Generate two key pairs
	unsigned char buffer[_MAX_BUFFER_SIZE];
	int ret_len = ctx_arr[pid - 1]->AdvertiseKeys(buffer);

	// Prepare return value
	jbyteArray ret = env->NewByteArray(ret_len);
	env->SetByteArrayRegion(ret, 0, ret_len, (jbyte *)buffer);

	return ret;
}

jbyteArray Java_com_va_client_NativeClient_clientShareMetadata(JNIEnv *env, jobject obj,
	jint pid, jint exclusive_U1_size, jbyteArray message)
{
	jsize len = env->GetArrayLength(message);
	unsigned char *message_buffer = new unsigned char[len];
	env->GetByteArrayRegion(message, 0, len, (jbyte *)message_buffer);

	// Unpack message
	Round_1_Msg round_1_msg(ctx_arr[pid - 1]->pid,
		exclusive_U1_size,
		ctx_arr[pid - 1]->enc.curve, ctx_arr[pid - 1]->mask.curve,
		message_buffer);

	// Simulate random input
	ctx_arr[pid - 1]->_rand_input();

	// Compute my metadata
	unsigned char buffer[_ULTRA_BUFFER_SIZE];
	int ret_len = ctx_arr[pid - 1]->ShareMetadata(buffer, round_1_msg);

	// Cleanup memory
	delete[] message_buffer;

	// Prepare return value
	jbyteArray ret = env->NewByteArray(ret_len);
	env->SetByteArrayRegion(ret, 0, ret_len, (jbyte *)buffer);

	return ret;
}

jbyteArray Java_com_va_client_NativeClient_clientMaskedInputCollection(JNIEnv *env, jobject obj,
	jint pid, jint exclusive_U2_size, jbyteArray message)
{
	jsize len = env->GetArrayLength(message);
	unsigned char *message_buffer = new unsigned char[len];
	env->GetByteArrayRegion(message, 0, len, (jbyte *)message_buffer);

	// Unpack message
	Round_2_Msg round_2_msg(exclusive_U2_size,
		message_buffer);

	// Compute my masked input
	unsigned char buffer[_ULTRA_BUFFER_SIZE];
	int ret_len = ctx_arr[pid - 1]->MaskedInputCollection(buffer, round_2_msg);

	// Cleanup memory
	delete[] message_buffer;

	// Prepare return value
	jbyteArray ret = env->NewByteArray(ret_len);
	env->SetByteArrayRegion(ret, 0, ret_len, (jbyte *)buffer);

	return ret;
}

jbyteArray Java_com_va_client_NativeClient_clientUnmasking(JNIEnv *env, jobject obj,
	jint pid, jint exclusive_U3_size, jbyteArray message)
{
	jsize len = env->GetArrayLength(message);
	unsigned char *message_buffer = new unsigned char[len];
	env->GetByteArrayRegion(message, 0, len, (jbyte *)message_buffer);

	// Unpack message
	Round_3_Msg round_3_msg(ctx_arr[pid - 1]->pid,
		exclusive_U3_size,
		message_buffer);

	// Compute my masked input
	unsigned char buffer[_ULTRA_BUFFER_SIZE];
	int ret_len = ctx_arr[pid - 1]->Unmasking(buffer, round_3_msg);

	// Cleanup memory
	delete[] message_buffer;

	// Prepare return value
	jbyteArray ret = env->NewByteArray(ret_len);
	env->SetByteArrayRegion(ret, 0, ret_len, (jbyte *)buffer);

	return ret;
}

void Java_com_va_client_NativeClient_clientReceiveResult(JNIEnv *env, jobject obj,
	jint pid, jbyteArray message)
{
	jsize len = env->GetArrayLength(message);
	unsigned char *message_buffer = new unsigned char[len];
	env->GetByteArrayRegion(message, 0, len, (jbyte *)message_buffer);

	// Unpack message
	Epoch_Result_Msg epoch_result_msg(ctx_arr[pid - 1]->d,
		ctx_arr[pid - 1]->n_bytes_agg_bound,
		message_buffer);

	// Proceed with this aggregated result
	ctx_arr[pid - 1]->ReceiveResult(epoch_result_msg);
}

jbyteArray Java_com_va_client_NativeClient_clientDecommitting(JNIEnv *env, jobject obj,
	jint pid)
{
	// Get my opening strings of different epochs
	unsigned char buffer[_ULTRA_BUFFER_SIZE];
	int ret_len = ctx_arr[pid - 1]->Decommitting(buffer);

	// Prepare return value
	jbyteArray ret = env->NewByteArray(ret_len);
	env->SetByteArrayRegion(ret, 0, ret_len, (jbyte *)buffer);

	return ret;
}

jbyteArray Java_com_va_client_NativeClient_clientDroppedDecommitting(JNIEnv *env, jobject obj,
	jint pid, jint exclusive_V1_size, jbyteArray message)
{
	jsize len = env->GetArrayLength(message);
	unsigned char *message_buffer = new unsigned char[len];
	env->GetByteArrayRegion(message, 0, len, (jbyte *)message_buffer);

	// Unpack message
	Ver_Round_1_Msg ver_round_1_msg(ctx_arr[pid - 1]->pid,
		exclusive_V1_size,
		ctx_arr[pid - 1]->batch,
		message_buffer);

	// Get my shares of other parties' opening strings
	unsigned char buffer[_ULTRA_BUFFER_SIZE];
	int ret_len = ctx_arr[pid - 1]->DroppedDecommitting(buffer, ver_round_1_msg);

	// Cleanup memory
	delete[] message_buffer;

	// Prepare return value
	jbyteArray ret = env->NewByteArray(ret_len);
	env->SetByteArrayRegion(ret, 0, ret_len, (jbyte *)buffer);

	return ret;
}

jboolean Java_com_va_client_NativeClient_clientBatchChecking(JNIEnv *env, jobject obj,
	jint pid, jbyteArray message)
{
	jsize len = env->GetArrayLength(message);
	unsigned char *message_buffer = new unsigned char[len];
	env->GetByteArrayRegion(message, 0, len, (jbyte *)message_buffer);

	// Unpack message
	int dropped_size = 0;
	for (int i = 0; i < ctx_arr[pid - 1]->batch; ++i)
		dropped_size += (ctx_arr[pid - 1]->exclusive_U3_size[i] - ctx_arr[pid - 1]->V1.size());

	Ver_Round_2_Msg ver_round_2_msg(dropped_size,
		message_buffer);

	// Do batch verification
	jboolean flag = ctx_arr[pid - 1]->BatchChecking(ver_round_2_msg);

	// Cleanup memory
	delete[] message_buffer;

	return flag;
}

/*
 *	Debug interfaces
 */
void Java_com_va_client_NativeClient_testHomHash(JNIEnv *env, jobject obj)
{
	_test_HomHash();
}

void Java_com_va_client_NativeClient_testCommitment(JNIEnv *env, jobject obj)
{
	_test_Commitment();
}

void Java_com_va_client_NativeClient_testSecretShare(JNIEnv *env, jobject obj)
{
	_test_SecretShare();
}

void Java_com_va_client_NativeClient_testKeyAgreement(JNIEnv *env, jobject obj)
{
	_test_KeyAgreement();
}

void Java_com_va_client_NativeClient_testCipher(JNIEnv *env, jobject obj)
{
	_test_Cipher();
}

jbyteArray Java_com_va_client_NativeClient_testMultipliedInput(JNIEnv *env, jobject obj,
	jint pid, jint scalar)
{
	unsigned char *buffer
		= new unsigned char[(ctx_arr[pid - 1]->d)*(int)(ceil((ctx_arr[pid - 1]->logR + _AGG_BOUND_SLACK_SIZE)/8.0))];
	int len = ctx_arr[pid - 1]->_compute_multiplied_input(buffer, scalar);

	jbyteArray ret = env->NewByteArray(len);
	env->SetByteArrayRegion(ret, 0, len, (jbyte *)buffer);

	delete[] buffer;
	return ret;
}