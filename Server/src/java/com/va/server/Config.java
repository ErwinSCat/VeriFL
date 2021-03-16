package com.va.server;

public class Config {
    // Pre-defined data length
    public static final int _PID_BYTE_SIZE = 2;

    private static final int _ECC_POINT_SIZE = 33;
    public static final int _ROUND_1_MSGITEMLEN
            = _PID_BYTE_SIZE + _ECC_POINT_SIZE*2;

    public static final int _COMMITMENT_SIZE = 32;
    private static final int _SHARE_FIELD_SIZE = (_ECC_POINT_SIZE + 1);
    public static final int _SYM_CIPHERTEXT_SIZE = (_SHARE_FIELD_SIZE*4);
    public static final int _ROUND_2_MSGITEMLEN
            = _PID_BYTE_SIZE + _COMMITMENT_SIZE + _SYM_CIPHERTEXT_SIZE;

    public static final int _DECOM_STRING_SIZE
            = _ECC_POINT_SIZE*2;

}
