package com.va.client;

public class NativeClient {

    // Used to load the 'native-client' library on application startup.
    static {
        System.loadLibrary("native-client");
    }

    // Invoke c++ constructor and destructor
    public native void      init(int logR, int d, int t, int N,
                                 int[] pids, int batch);
    public native void      exit();

    // Protocol interfaces
    public native byte[]    clientAdvertiseKeys(int pid);
    public native byte[]    clientShareMetadata(int pid, int exclusive_U1_size, byte[] Round_1_Msg);
    public native byte[]    clientMaskedInputCollection(int pid, int exclusive_U2_size, byte[] Round_2_Msg);
    public native byte[]    clientUnmasking(int pid, int exclusive_U3_size, byte[] Round_3_Msg);
    public native void      clientReceiveResult(int pid, byte[] Epoch_Result_Msg);

    public native byte[]    clientDecommitting(int pid);
    public native byte[]    clientDroppedDecommitting(int pid, int exclusive_V1_size, byte[] Ver_Round_1_Msg);
    public native boolean   clientBatchChecking(int pid, byte[] Ver_Round_2_Msg);

    // Debug interfaces
    public native void      testHomHash();
    public native void      testCommitment();
    public native void      testSecretShare();
    public native void      testKeyAgreement();
    public native void      testCipher();

    public native byte[]    testMultipliedInput(int pid, int scalar);
}
