package com.va.client;

import android.os.Message;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

public class ClientSocket implements Runnable {
    private MainActivity context;
    private String server_host;
    private final int server_port = 17999;

    public ClientSocket(MainActivity context,
                        String server_host) {
        this.context = context;
        this.server_host = server_host;
    }

    public void run() {
        long start, end, used;
        NativeClient nc = new NativeClient();

        try {
            Socket socket = new Socket(server_host, server_port);

            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            /*
             *  Setup phase
             */
            int logR = in.readInt();
            int d = in.readInt();
            int t = in.readInt();
            int N = in.readInt();
            int pid = in.readInt();
            int batch = in.readInt();

            int[] pids = { pid };

            start = System.nanoTime();
            nc.init(logR, d, t, N, pids, batch);
            end = System.nanoTime();
            used = (end - start) / 1000000;

            // Update log
            Message message = new Message();
            message.obj = new long[7];
            ((long [])message.obj)[0] = logR;
            ((long [])message.obj)[1] = d;
            ((long [])message.obj)[2] = t;
            ((long [])message.obj)[3] = N;
            ((long [])message.obj)[4] = pid;
            ((long [])message.obj)[5] = batch;
            ((long [])message.obj)[6] = used;
            message.what = Config._SYS_INIT;
            context.handler.sendMessage(message);

            for (int curr_epoch = 1; curr_epoch <= batch; curr_epoch++) {
                /*
                 *  Round 0 (AdvertiseKeys)
                 */
                start = System.nanoTime();
                byte[] my_keys = nc.clientAdvertiseKeys(pid);
                end = System.nanoTime();
                used = (end - start) / 1000000;

                out.writeInt(my_keys.length);
                out.write(my_keys, 0, my_keys.length);

                // Update log
                Message log_advertiseKeys = new Message();
                log_advertiseKeys.obj = new long[2];
                ((long [])log_advertiseKeys.obj)[0] = curr_epoch;
                ((long [])log_advertiseKeys.obj)[1] = used;
                log_advertiseKeys.what = Config._ADVERTISE_KEYS;
                context.handler.sendMessage(log_advertiseKeys);

                /*
                 *  Round 1 (ShareMetadata)
                 */
                int U1_size = in.readInt();
                int U1_keys_length = in.readInt();
                byte[] U1_keys = new byte[U1_keys_length];
                in.read(U1_keys, 0, U1_keys_length);

                start = System.nanoTime();
                byte[] my_metadata
                        = nc.clientShareMetadata(pid, U1_size - 1, U1_keys);
                end = System.nanoTime();
                used = (end - start) / 1000000;

                out.writeInt(my_metadata.length);
                out.write(my_metadata, 0, my_metadata.length);

                // Update log
                Message log_shareMetadata = new Message();
                log_shareMetadata.obj = new long[1];
                ((long [])log_shareMetadata.obj)[0] = used;
                log_shareMetadata.what = Config._SHARE_METADATA;
                context.handler.sendMessage(log_shareMetadata);

                /*
                 *  Round 2 (MaskedInputCollection)
                 */
                int U2_size = in.readInt();
                int U2_metadata_length = in.readInt();
                byte[] U2_metadata = new byte[U2_metadata_length];
                in.read(U2_metadata, 0, U2_metadata_length);

                start = System.nanoTime();
                byte[] my_maskedInput
                        = nc.clientMaskedInputCollection(pid, U2_size - 1, U2_metadata);
                end = System.nanoTime();
                used = (end - start) / 1000000;

                out.writeInt(my_maskedInput.length);
                out.write(my_maskedInput, 0, my_maskedInput.length);

                // Update log
                Message log_maskedInput = new Message();
                log_maskedInput.obj = new long[1];
                ((long [])log_maskedInput.obj)[0] = used;
                log_maskedInput.what = Config._MASKED_INPUT;
                context.handler.sendMessage(log_maskedInput);

                /*
                 *  Round 3 (Unmasking)
                 */
                int U3_size = in.readInt();
                byte[] U3_set = new byte[U3_size*Config._PID_BYTE_SIZE];
                in.read(U3_set, 0, U3_size*Config._PID_BYTE_SIZE);

                start = System.nanoTime();
                byte[] my_shares
                        = nc.clientUnmasking(pid, U3_size - 1, U3_set);
                end = System.nanoTime();
                used = (end - start) / 1000000;

                out.writeInt(my_shares.length);
                out.write(my_shares, 0, my_shares.length);

                // Update log
                Message log_unmasking = new Message();
                log_unmasking.obj = new long[1];
                ((long [])log_unmasking.obj)[0] = used;
                log_unmasking.what = Config._UNMASKING;
                context.handler.sendMessage(log_unmasking);

                /*
                 *  Receive result from aggregation server
                 */
                int length = in.readInt();
                byte[] agg_result = new byte[length];
                in.read(agg_result, 0, length);

                start = System.nanoTime();
                nc.clientReceiveResult(pid, agg_result);
                end = System.nanoTime();
                used = (end - start) / 1000000;

                // Update log
                Message log_receive = new Message();
                log_receive.obj = new long[1];
                ((long [])log_receive.obj)[0] = used;
                log_receive.what = Config._RECEIVE;
                context.handler.sendMessage(log_receive);
            }

            /*
             *  Verification Round 0 (Decommitting)
             */
            start = System.nanoTime();
            byte[] my_decom_str = nc.clientDecommitting(pid);
            end = System.nanoTime();
            used = (end - start) / 1000000;

            out.writeInt(my_decom_str.length);
            out.write(my_decom_str, 0, my_decom_str.length);

            // Update log
            Message log_decom = new Message();
            log_decom.obj = new long[1];
            ((long [])log_decom.obj)[0] = used;
            log_decom.what = Config._DECOM;
            context.handler.sendMessage(log_decom);

            /*
             *  Verification Round 1 (DroppedDecommitting)
             */
            int V1_size = in.readInt();
            int V1_decom_str_length = in.readInt();
            byte[] V1_decom_str = new byte[V1_decom_str_length];
            in.read(V1_decom_str, 0, V1_decom_str_length);

            start = System.nanoTime();
            byte[] my_decom_str_shares
                    = nc.clientDroppedDecommitting(pid, V1_size - 1, V1_decom_str);
            end = System.nanoTime();
            used = (end - start) / 1000000;

            out.writeInt(my_decom_str_shares.length);
            out.write(my_decom_str_shares, 0, my_decom_str_shares.length);

            // Update log
            Message log_droppedDecom = new Message();
            log_droppedDecom.obj = new long[1];
            ((long [])log_droppedDecom.obj)[0] = used;
            log_droppedDecom.what = Config._DROPPED_DECOM;
            context.handler.sendMessage(log_droppedDecom);

            /*
             *  Verification Round 2 (BatchChecking)
             */
            int recons_decom_str_length = in.readInt();
            byte[] recons_decom_str = new byte[recons_decom_str_length];
            in.read(recons_decom_str, 0, recons_decom_str_length);

            start = System.nanoTime();
            boolean flag = nc.clientBatchChecking(pid, recons_decom_str);
            end = System.nanoTime();
            used = (end - start) / 1000000;

            // Update log
            Message log_batchChecking = new Message();
            log_batchChecking.obj = new long[2];
            ((long [])log_batchChecking.obj)[0] = used;
            ((long [])log_batchChecking.obj)[1] = (flag == true) ? 1 : 0;
                    log_batchChecking.what = Config._BATCH_CHECK;
            context.handler.sendMessage(log_batchChecking);

            /*
             *  Cleanup memory
             */
            nc.exit();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
