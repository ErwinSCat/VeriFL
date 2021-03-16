package com.va.server;

public class DropoutStructure {

    // Dropout types
    public static final int nEpochDropoutTypes = 1;
    public static final int _IN_MASKEDINPUTCOLLECTION = 0;

    public static final int nVeriDropoutTypes = 1;
    public static final int _IN_DECOMMITTING = 0;

    private int[][] nEpochDrop_arr;
    private int[] nVeriDrop_arr;

    DropoutStructure(int batch) {
        nEpochDrop_arr = new int[batch][nEpochDropoutTypes];
        for (int i = 0; i < batch; i++) {
            for (int j = 0; j < nEpochDropoutTypes; j++) {
                nEpochDrop_arr[i][j] = 0;
            }
        }
        nVeriDrop_arr = new int[nVeriDropoutTypes];
        for (int i = 0; i < nVeriDropoutTypes; i++) {
            nVeriDrop_arr[i] = 0;
        }
    }

    void SetEpochDropout(int epoch, int when, int nDropout) {
        nEpochDrop_arr[epoch][when] = nDropout;
    }

    int GetEpochDropout(int epoch, int when) {
        return nEpochDrop_arr[epoch][when];
    }

    void SetVeriDropout(int when, int nDropout) {
        nVeriDrop_arr[when] = nDropout;
    }

    int GetVeriDropout(int when) {
        return nVeriDrop_arr[when];
    }
}
