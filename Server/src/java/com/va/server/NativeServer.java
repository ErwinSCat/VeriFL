package com.va.server;

import java.lang.reflect.Field;

public class NativeServer {

    // Used to load the 'native-server' library on application startup.
    static {
        try {
            System.setProperty("java.library.path",
                System.getProperty("java.library.path") +
                ":" + System.getProperty("user.dir") + "/src/cpp/build");

            Field fieldSysPath = ClassLoader.class.getDeclaredField("sys_paths");
            fieldSysPath.setAccessible(true);
            fieldSysPath.set(null, null);
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.loadLibrary("native-server");
    }

    // Invoke c++ constructor and destructor
    public native void      init(int logR, int d, int t, int N, int batch);
    public native void      exit();

    // Protocol interfaces
    public native void      serverUpdateKeys(byte[] keys);
    public native void      serverUpdateU2(int pid);
    public native void      serverUpdateInput(byte[] maskedInput);
    public native void      serverUpdateMaskShares(byte[] shares);
    public native byte[]    serverFinalResult();

    public native void      serverUpdateV1(int pid);
    public native void      serverUpdateDecomStrShares(byte[] shares);
    public native byte[]    serverFinalDecomStr();
}
