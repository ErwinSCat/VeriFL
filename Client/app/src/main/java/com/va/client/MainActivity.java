package com.va.client;

import android.os.Handler;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

public class MainActivity extends AppCompatActivity {

    private ArrayList<String> logs = new ArrayList<String>();
    private ArrayAdapter<String> adapter;
    private Thread th;
    private Date date = new Date();
    private static final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public Handler handler = new Handler() {
        @Override
        public void handleMessage(Message message) {
            switch (message.what) {
                case Config._SYS_INIT:
                    date.getTime();
                    logs.add(format.format(date) + ": logR: " + ((long [])message.obj)[0] +
                            ", d: " + ((long [])message.obj)[1] +
                            ", t: " + ((long [])message.obj)[2] +
                            ", N: " + ((long [])message.obj)[3] +
                            ", pid: " + ((long [])message.obj)[4] +
                            ", batch: " + ((long [])message.obj)[5]);
                    logs.add(format.format(date) + ": Setup: " + ((long [])message.obj)[6] + " ms");
                    adapter.notifyDataSetChanged();
                    break;
                case Config._ADVERTISE_KEYS:
                    date.getTime();
                    logs.add(format.format(date) + ": Epoch " + ((long [])message.obj)[0]);
                    logs.add(format.format(date) + ": AdvertiseKeys: " + ((long [])message.obj)[1] + " ms");
                    adapter.notifyDataSetChanged();
                    break;
                case Config._SHARE_METADATA:
                    date.getTime();
                    logs.add(format.format(date) + ": ShareMetadata: " + ((long [])message.obj)[0] + " ms");
                    adapter.notifyDataSetChanged();
                    break;
                case Config._MASKED_INPUT:
                    date.getTime();
                    logs.add(format.format(date) + ": MaskedInputCollection: " + ((long [])message.obj)[0] + " ms");
                    adapter.notifyDataSetChanged();
                    break;
                case Config._UNMASKING:
                    date.getTime();
                    logs.add(format.format(date) + ": Unmasking: " + ((long [])message.obj)[0] + " ms");
                    adapter.notifyDataSetChanged();
                    break;
                case Config._RECEIVE:
                    date.getTime();
                    logs.add(format.format(date) + ": ReceiveResult: " + ((long [])message.obj)[0] + " ms");
                    adapter.notifyDataSetChanged();
                    break;
                case Config._DECOM:
                    date.getTime();
                    logs.add(format.format(date) + ": Decommitting: " + ((long [])message.obj)[0] + " ms");
                    adapter.notifyDataSetChanged();
                    break;
                case Config._DROPPED_DECOM:
                    date.getTime();
                    logs.add(format.format(date) + ": DroppedDecommitting: " + ((long [])message.obj)[0] + " ms");
                    adapter.notifyDataSetChanged();
                    break;
                case Config._BATCH_CHECK:
                    date.getTime();
                    logs.add(format.format(date) + ": BatchChecking: " + ((long [])message.obj)[0] + " ms");
                    logs.add(format.format(date) + ((((long [])message.obj)[1] == 1) ? ": True" : ": False"));
                    adapter.notifyDataSetChanged();
                    break;
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        adapter = new ArrayAdapter<String>(
                MainActivity.this, android.R.layout.simple_list_item_1, logs);
        ((ListView) findViewById(R.id.logs)).setAdapter(adapter);

        clientBenchmark();
    }

    public void onClickConnect(View view) {
        // Setup my connection to the aggregation server
        String server_host = ((EditText)findViewById(R.id.txt_ip)).getText().toString();
        th = new Thread(new ClientSocket(this, server_host));
        th.start();

        // Disable elements
        ((EditText)findViewById(R.id.txt_ip)).setEnabled(false);
        ((Button)findViewById(R.id.btn_connect)).setEnabled(false);

        // Print log
        date.getTime();
        logs.add(format.format(date) + ": Client app ready");
        adapter.notifyDataSetChanged();
    }

    public void clientBenchmark() {
        long start, end;
        int logR = 24;
        int d = 100000;
        int t = 100;
        int N = 500;
        int pid = 1;
        int batch = 10;

        int[] pids = { pid };

        /*
         *  Constants defined in Config.h
         */
        final int _ECC_POINT_SIZE = 33;
        final int _SHARE_FIELD_SIZE = (_ECC_POINT_SIZE + 1);
        final int _COMMITMENT_SIZE = 32;
        final int _SYM_KEY_SIZE = 32;
        final int _IV_SIZE = 16;
        final int _AGREED_KEY_SIZE = (_SYM_KEY_SIZE + _IV_SIZE);
        final int _PID_BYTE_SIZE = 2;
        final int _SYM_CIPHERTEXT_SIZE = (_SHARE_FIELD_SIZE*4);

        final int _ROUND_1_MSGITEMLEN
                = _PID_BYTE_SIZE + _ECC_POINT_SIZE*2;
        final int _ROUND_2_MSGITEMLEN
                = _PID_BYTE_SIZE + _COMMITMENT_SIZE + _SYM_CIPHERTEXT_SIZE;
        final int _ROUND_3_MSGITEMLEN
                = _PID_BYTE_SIZE;

        final int _VER_ROUND_1_MSGITEMLEN
                = _PID_BYTE_SIZE + batch*_ECC_POINT_SIZE*2;

        /*
         *  Client context initialization
         */
        start = System.nanoTime();
        NativeClient nc = new NativeClient();
        nc.init(logR, d, t, N, pids, batch);
        end = System.nanoTime();
        long initTime = (end - start) / 1000000;
        System.out.println("Setup: " + initTime);

        for (int epoch = 0; epoch < batch; epoch++) {
            System.out.println(">> Epoch " + epoch);

            /*
             *  Round 0 (AdvertiseKeys)
             */
            // Client
            start = System.nanoTime();
            byte[] keys = nc.clientAdvertiseKeys(pid);
            end = System.nanoTime();
            long advertiseTime = (end - start) / 1000000;
            System.out.println("AdvertiseKeys: " + advertiseTime);

            // Simulate server
            byte[] server_keys = new byte[N*_ROUND_1_MSGITEMLEN];
            for (int other_pid = 1; other_pid <= N; other_pid++) {
                System.arraycopy(keys, 0,
                        server_keys, (other_pid - 1)*_ROUND_1_MSGITEMLEN,
                        _ROUND_1_MSGITEMLEN);
                // Change pid
                server_keys[(other_pid - 1)*_ROUND_1_MSGITEMLEN]
                        = (byte) (other_pid&0xff);
                server_keys[(other_pid - 1)*_ROUND_1_MSGITEMLEN + 1]
                        = (byte) ((other_pid >> 8)&0xff);
            }

            /*
             *  Round 1 (ShareMetadata)
             */
            // Client
            start = System.nanoTime();
            byte[] metadata = nc.clientShareMetadata(pid, N - 1, server_keys);
            end = System.nanoTime();
            long metadataTime = (end - start) / 1000000;
            System.out.println("ShareMetadata: " + metadataTime);

            // Simulate server
            byte[] simulated_agg_result = nc.testMultipliedInput(pid, N);
            byte[] server_metadata = new byte[(N - 1)*_ROUND_2_MSGITEMLEN];
            for (int other_pid = 2; other_pid <= N; other_pid++) {
                // Change pid
                server_metadata[(other_pid - 2)*_ROUND_2_MSGITEMLEN]
                        = (byte) (other_pid&0xff);
                server_metadata[(other_pid - 2)*_ROUND_2_MSGITEMLEN + 1]
                        = (byte) ((other_pid >> 8)&0xff);

                System.arraycopy(metadata,
                        _PID_BYTE_SIZE,
                        server_metadata,
                        (other_pid - 2)*_ROUND_2_MSGITEMLEN + _PID_BYTE_SIZE,
                        _COMMITMENT_SIZE);
                System.arraycopy(metadata,
                        _PID_BYTE_SIZE + _COMMITMENT_SIZE + _PID_BYTE_SIZE,
                        server_metadata,
                        (other_pid - 2)*_ROUND_2_MSGITEMLEN + _PID_BYTE_SIZE + _COMMITMENT_SIZE,
                        _SYM_CIPHERTEXT_SIZE);
            }

            /*
             *  Round 2 (MaskedInputCollection)
             */
            // Client
            start = System.nanoTime();
            byte[] maskedinput = nc.clientMaskedInputCollection(pid, N - 1, server_metadata);
            end = System.nanoTime();
            long inputTime = (end - start) / 1000000;
            System.out.println("MaskedInputCollection: " + inputTime);

            // Simulate server
            byte[] server_input = new byte[N*_ROUND_3_MSGITEMLEN];
            for (int other_pid = 1; other_pid <= N; other_pid++) {
                // Change pid
                server_input[(other_pid - 1)*_ROUND_3_MSGITEMLEN]
                        = (byte) (other_pid&0xff);
                server_input[(other_pid - 1)*_ROUND_3_MSGITEMLEN + 1]
                        = (byte) ((other_pid >> 8)&0xff);
            }

            /*
             *  Round 3 (Unmasking)
             */
            // Client
            start = System.nanoTime();
            byte[] unmasking = nc.clientUnmasking(pid, N - 1, server_input);
            end = System.nanoTime();
            long unmaskTime = (end - start) / 1000000;
            System.out.println("Unmasking: " + unmaskTime);

            // Simulate server
            // simulated_agg_result was computed above

            /*
             *  Round 4 (ReceiveResult)
             */
            // Client
            start = System.nanoTime();
            nc.clientReceiveResult(pid, simulated_agg_result);
            end = System.nanoTime();
            long receiveTime = (end - start) / 1000000;
            System.out.println("ReceiveResult: " + receiveTime);
        }

        /*
         *  Verification Round 0 (Decommitting)
         */
        // Client
        start = System.nanoTime();
        byte[] decom = nc.clientDecommitting(pid);
        end = System.nanoTime();
        long decomTime = (end - start) / 1000000;
        System.out.println("Decommitting: " + decomTime);

        // Simulate server
        byte[] server_decom = new byte[N*_VER_ROUND_1_MSGITEMLEN];
        for (int other_pid = 1; other_pid <= N; other_pid++) {
            System.arraycopy(decom, 0,
                    server_decom, (other_pid - 1)*_VER_ROUND_1_MSGITEMLEN,
                    _VER_ROUND_1_MSGITEMLEN);
            // Change pid
            server_decom[(other_pid - 1)*_VER_ROUND_1_MSGITEMLEN]
                    = (byte) (other_pid&0xff);
            server_decom[(other_pid - 1)*_VER_ROUND_1_MSGITEMLEN + 1]
                    = (byte) ((other_pid >> 8)&0xff);
        }

        /*
         *  Verification Round 1 (DroppedDecommitting)
         */
        // Client
        start = System.nanoTime();
        byte[] drop = nc.clientDroppedDecommitting(pid, N - 1, server_decom);
        end = System.nanoTime();
        long dropTime = (end - start) / 1000000;
        System.out.println("DroppedDecommitting: " + dropTime);

        // Simulate server
        // Nobody drops

        /*
         *  Verification Round 2 (BatchChecking)
         */
        // Client
        byte[] dummy = new byte[1];
        start = System.nanoTime();
        boolean flag = nc.clientBatchChecking(pid, dummy);
        end = System.nanoTime();
        long checkTime = (end - start) / 1000000;
        System.out.println("BatchChecking: " + checkTime);
        System.out.println(flag);

        /*
         *  Cleanup memory
         */
        nc.exit();
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for(int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if(hex.length() < 2){
                sb.append(0);
            }
            sb.append(hex);
        }
        return sb.toString();
    }
}
