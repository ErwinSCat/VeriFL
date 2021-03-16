package com.va.server;

import java.util.*;

import static com.va.server.DropoutStructure.*;

public class SimAggregationServer {

    private NativeServer ns = new NativeServer();
    public com.va.client.NativeClient nc = new com.va.client.NativeClient();

    private int logR;
    private int d;
    private int t;
    private int N;
    private int batch;

    private DropoutStructure ds;

    public SimAggregationServer(int logR, int d, int t, int N, int batch, DropoutStructure ds) {
        this.logR = logR;
        this.d = d;
        this.t = t;
        this.N = N;
        this.batch = batch;

        this.ds = ds;
    }

    public void run_sim_server() {
        int[] pids = new int[N];
        for (int i = 0; i < N; i++) {
            pids[i] = i + 1;
        }

        System.out.println("-------------------- Parameters --------------------");
        System.out.println("logR: " + logR);
        System.out.println("d: " + d);
        System.out.println("t: " + t);
        System.out.println("N: " + N);
        System.out.println("batch: " + batch);
        System.out.println("dropout:");

        int num = 0;
        boolean out = false;

        for (int i = 0; i < batch; i++) {
            num = ds.GetEpochDropout(i, _IN_MASKEDINPUTCOLLECTION);
            if (num > 0) {
                System.out.println("    " + num + " dropouts in the " + i + "-th aggregation phase");
                out |= true;
            }
        }
        num = ds.GetVeriDropout(_IN_DECOMMITTING);
        if (num > 0) {
            System.out.println("    " + num + " dropouts in the verification phase");
            out |= true;
        }
        if (!out) System.out.println("    null");

        ns.init(logR, d, t, N, batch);
        nc.init(logR, d, t, N, pids, batch);

        Set<Integer> U1 = new TreeSet<>();
        Set<Integer> U2 = new TreeSet<>();
        Set<Integer> U3 = new TreeSet<>();
        Set<Integer> U4 = new TreeSet<>();

        long start, end;

        long avg_client_round_0_time = 0;
        long client_round_0_cnt = 0;
        long avg_server_round_0_time = 0;

        long avg_client_round_1_time = 0;
        long client_round_1_cnt = 0;
        long avg_server_round_1_time = 0;

        long avg_client_round_2_time = 0;
        long client_round_2_cnt = 0;
        long avg_server_round_2_time = 0;

        long avg_client_round_3_time = 0;
        long client_round_3_cnt = 0;
        long avg_server_round_3_time = 0;

        long avg_client_receive_result_time = 0;
        long client_receive_result_cnt = 0;

        long avg_client_ver_round_0_time = 0;
        long avg_server_ver_round_0_time = 0;

        long avg_client_ver_round_1_time = 0;
        long avg_server_ver_round_1_time = 0;

        long avg_client_ver_round_2_time = 0;

        double client_round_0_send = -1;

        double client_round_1_recv = -1;
        double client_round_1_send = -1;

        double client_round_2_recv = -1;
        double client_round_2_send = -1;

        double client_round_3_recv = -1;
        double client_round_3_send = -1;

        double client_epoch_result_recv = -1;

        double client_ver_round_0_send = -1;

        double client_ver_round_1_recv = -1;
        double client_ver_round_1_send = -1;

        double client_ver_round_2_recv = -1;

        for (int pid = 1; pid <= N; pid++) {
            U4.add(pid);
        }

        System.out.println("-------------------- Aggregation phase --------------------");
        for (int epoch = 0; epoch < batch; epoch++) {

            System.out.println("[Epoch " + epoch + "]: Start");

            /*
             *  Round 0 (AdvertiseKeys)
             */
            U1.clear();
            byte[] keys = new byte[N*Config._ROUND_1_MSGITEMLEN];
            int keys_offset = 0;

            for (Integer pid: U4) {
                start = System.nanoTime();
                byte[] my_keys = nc.clientAdvertiseKeys(pid);
                end = System.nanoTime();
                avg_client_round_0_time += (end - start)/1000000;
                client_round_0_cnt++;
                client_round_0_send = my_keys.length;

                start = System.nanoTime();
                U1.add(pid);
                System.arraycopy(my_keys, 0,
                        keys, keys_offset,
                        Config._ROUND_1_MSGITEMLEN);
                keys_offset += Config._ROUND_1_MSGITEMLEN;

                ns.serverUpdateKeys(my_keys);
                end = System.nanoTime();
                avg_server_round_0_time += (end - start)/1000000;
                client_round_1_recv = keys_offset;
            }

            System.out.println("[Epoch " + epoch + "]: Round 0 done");

            /*
             *  Round 1 (ShareMetadata)
             */
            U2.clear();
            byte[][] metadata = new byte[N][(U1.size() - 1)*Config._ROUND_2_MSGITEMLEN];
            int[] metadata_offset = new int[N];

            for (Integer pid: U1) {
                start = System.nanoTime();
                byte[] my_metadata = nc.clientShareMetadata(pid, U1.size() - 1, keys);
                end = System.nanoTime();
                avg_client_round_1_time += (end - start)/1000000;
                client_round_1_cnt++;
                client_round_1_send = my_metadata.length;

                start = System.nanoTime();
                U2.add(pid);
                int dest_pid;
                for (int offset = Config._PID_BYTE_SIZE + Config._COMMITMENT_SIZE;
                     offset < my_metadata.length;
                     offset += (Config._PID_BYTE_SIZE + Config._SYM_CIPHERTEXT_SIZE)) {

                    dest_pid = decodePid(my_metadata, offset);

                    System.arraycopy(my_metadata, 0,
                            metadata[dest_pid - 1], metadata_offset[dest_pid - 1],
                            Config._PID_BYTE_SIZE + Config._COMMITMENT_SIZE);
                    metadata_offset[dest_pid - 1] += Config._PID_BYTE_SIZE + Config._COMMITMENT_SIZE;

                    System.arraycopy(my_metadata, offset + Config._PID_BYTE_SIZE,
                            metadata[dest_pid - 1], metadata_offset[dest_pid - 1],
                            Config._SYM_CIPHERTEXT_SIZE);
                    metadata_offset[dest_pid - 1] += Config._SYM_CIPHERTEXT_SIZE;
                }

                ns.serverUpdateU2(pid);
                end = System.nanoTime();
                avg_server_round_1_time += (end - start)/1000000;
                client_round_2_recv = metadata_offset[0];
            }

            System.out.println("[Epoch " + epoch + "]: Round 1 done");

            // Simulate dropout
            System.out.println("    - U2 size: " + U2.size());
            Set<Integer> surviving_U2 = new TreeSet<>();
            Random rand = new Random();
            while (surviving_U2.size() != U2.size() - ds.GetEpochDropout(epoch, _IN_MASKEDINPUTCOLLECTION)) {
                int pid = rand.nextInt(N) + 1;
                if (U2.contains(pid))
                    surviving_U2.add(pid);
            }

            /*
             *  Round 2 (MaskedInputCollection)
             */
            U3.clear();
            for (Integer pid: U2) {
                start = System.nanoTime();
                byte[] my_maskedInput = nc.clientMaskedInputCollection(pid, U2.size() - 1,
                        metadata[pid - 1]);
                end = System.nanoTime();
                avg_client_round_2_time += (end - start)/1000000;
                client_round_2_cnt++;
                client_round_2_send = my_maskedInput.length;

                // Simulate dropout
                if (surviving_U2.contains(pid)) {
                    start = System.nanoTime();
                    U3.add(pid);
                    ns.serverUpdateInput(my_maskedInput);
                    end = System.nanoTime();
                    avg_server_round_2_time += (end - start)/1000000;
                }
            }

            System.out.println("[Epoch " + epoch + "]: Round 2 done");
            System.out.println("    - U3 size: " + U3.size());

            /*
             *  Round 3 (Unmasking)
             */
            U4.clear();
            start = System.nanoTime();
            byte[] U3_set = new byte[U3.size()*Config._PID_BYTE_SIZE];
            int U3_set_offset = 0;
            for (Integer pid: U3) {
                encodePid(U3_set, U3_set_offset, pid);
                U3_set_offset += Config._PID_BYTE_SIZE;
            }
            end = System.nanoTime();
            avg_server_round_3_time += (end - start)/1000000;
            client_round_3_recv = U3_set_offset;

            for (Integer pid: U3) {
                start = System.nanoTime();
                byte[] my_maskShares = nc.clientUnmasking(pid, U3.size() - 1, U3_set);
                end = System.nanoTime();
                avg_client_round_3_time += (end - start)/1000000;
                client_round_3_cnt++;
                client_round_3_send = my_maskShares.length;

                start = System.nanoTime();
                U4.add(pid);
                ns.serverUpdateMaskShares(my_maskShares);
                end = System.nanoTime();
                avg_server_round_3_time += (end - start)/1000000;
            }

            start = System.nanoTime();
            byte[] epoch_result = ns.serverFinalResult();
            end = System.nanoTime();
            avg_server_round_3_time += (end - start)/1000000;
            client_epoch_result_recv = epoch_result.length;

            System.out.println("[Epoch " + epoch + "]: Round 3 done");

            /*
             *  Send result to each party in U4
             */
            start = System.nanoTime();
            for (Integer pid: U4) {
                nc.clientReceiveResult(pid, epoch_result);
            }
            end = System.nanoTime();
            avg_client_receive_result_time += (end - start)/1000000;
            client_receive_result_cnt += U4.size();

            System.out.println("[Epoch " + epoch + "]: Result done");


            /*
             *  Print computation overhead
             */
            System.out.println();
            System.out.println("-------------------- Computation Overhead in Epoch " + epoch + " --------------------");
            System.out.println("Client timer:");
            // Aggregation phase
            System.out.println("    - Average round 0 (AdvertiseKeys): " + avg_client_round_0_time/client_round_0_cnt + " ms");
            System.out.println("    - Average round 1 (ShareMetadata): " + avg_client_round_1_time/client_round_1_cnt + " ms");
            System.out.println("    - Average round 2 (MaskedInputCollection): " + avg_client_round_2_time/client_round_2_cnt + " ms");
            System.out.println("    - Average round 3 (Unmasking): " + avg_client_round_3_time/client_round_3_cnt + " ms");
            System.out.println("    - Average receive result: " + avg_client_receive_result_time/client_receive_result_cnt + " ms");

            System.out.println("Server timer:");
            // Aggregation phase
            System.out.println("    - Average round 0 (AdvertiseKeys): " + avg_server_round_0_time + " ms");
            System.out.println("    - Average round 1 (ShareMetadata): " + avg_server_round_1_time + " ms");
            System.out.println("    - Average round 2 (MaskedInputCollection): " + avg_server_round_2_time + " ms");
            System.out.println("    - Average round 3 (Unmasking): " + avg_server_round_3_time + " ms");

            /*
             *  Print communication overhead
             */
            System.out.println();
            System.out.println("-------------------- Communication Overhead in Epoch " + epoch + " --------------------");
            System.out.println("Client side:");
            // Aggregation phase
            System.out.println("    - Message sent in round 0 (AdvertiseKeys): " + client_round_0_send/1024.0 + " KBytes");

            System.out.println("    - Message received in round 1 (ShareMetadata): " + client_round_1_recv/1024.0 + " KBytes");
            System.out.println("    - Message sent in round 1 (ShareMetadata): " + client_round_1_send/1024.0 + " KBytes");

            System.out.println("    - Message received in round 2 (MaskedInputCollection): " + client_round_2_recv/1024.0 + " KBytes");
            System.out.println("    - Message sent in round 2 (MaskedInputCollection): " + client_round_2_send/1024.0 + " KBytes");

            System.out.println("    - Message received in round 3 (Unmasking): " + client_round_3_recv/1024.0 + " KBytes");
            System.out.println("    - Message sent in round 3 (Unmasking): " + client_round_3_send/1024.0 + " KBytes");

            System.out.println("    - Epoch result received: " + client_epoch_result_recv/1024.0 + " KBytes");

            System.out.println("    - Total: " +
                    (client_round_0_send +
                            client_round_1_recv + client_round_1_send +
                            client_round_2_recv + client_round_2_send +
                            client_round_3_recv + client_round_3_send +
                            client_epoch_result_recv)/1024.0 +
                    " KBytes");
            System.out.println();

            /*
             *  Reset measurement
             */
            avg_client_round_0_time = 0;
            client_round_0_cnt = 0;
            avg_client_round_1_time = 0;
            client_round_1_cnt = 0;
            avg_client_round_2_time = 0;
            client_round_2_cnt = 0;
            avg_client_round_3_time = 0;
            client_round_3_cnt = 0;
            avg_client_receive_result_time = 0;
            client_receive_result_cnt = 0;

            avg_server_round_0_time = 0;
            avg_server_round_1_time = 0;
            avg_server_round_2_time = 0;
            avg_server_round_3_time = 0;
        }

        System.out.println("-------------------- Verification phase --------------------");

        /*
         *  Verification Round 0 (Decommitting)
         */
        Set<Integer> V1 = new TreeSet<>();
        byte[] decom_str = new byte[U4.size()*(Config._PID_BYTE_SIZE + batch*Config._DECOM_STRING_SIZE)];
        int decom_str_offset = 0;

        // Simulate dropout
        System.out.println("    - U4 size in last epoch: " + U4.size());

        Set<Integer> surviving_V1 = new TreeSet<>();
        Random rand = new Random();
        while (surviving_V1.size() != U4.size() - ds.GetVeriDropout(_IN_DECOMMITTING)) {
            int pid = rand.nextInt(N) + 1;
            if (U4.contains(pid))
                surviving_V1.add(pid);
        }

        for (Integer pid: U4) {
            start = System.nanoTime();
            byte[] my_decom_str = nc.clientDecommitting(pid);
            end = System.nanoTime();
            avg_client_ver_round_0_time += (end - start)/1000000;
            client_ver_round_0_send = my_decom_str.length;

            if (surviving_V1.contains(pid)) {
                start = System.nanoTime();
                V1.add(pid);
                System.arraycopy(my_decom_str, 0,
                        decom_str, decom_str_offset,
                        Config._PID_BYTE_SIZE + batch*Config._DECOM_STRING_SIZE);
                decom_str_offset += (Config._PID_BYTE_SIZE + batch*Config._DECOM_STRING_SIZE);

                ns.serverUpdateV1(pid);
                end = System.nanoTime();
                avg_server_ver_round_0_time += (end - start)/1000000;
                client_ver_round_1_recv = decom_str_offset;
            }
        }

        System.out.println("Verification Round 0 done");
        System.out.println("    - V1 size: " + V1.size());

        Set<Integer> set = new TreeSet<>();
        for (Integer pid: U4) {
            if (!V1.contains(pid))
                set.add(pid);
        }

        System.out.println("    - U4\\V1: " + set);
        System.out.println("    - U4\\V1 size: " + set.size());

        /*
         *  Verification Round 1 (DroppedDecommitting)
         */
        Set<Integer> V2 = new TreeSet<>();

        for (Integer pid: V1) {
            start = System.nanoTime();
            byte[] my_decom_str_shares = nc.clientDroppedDecommitting(pid, V1.size() - 1,
                    decom_str);
            end = System.nanoTime();
            avg_client_ver_round_1_time += (end - start)/1000000;
            client_ver_round_1_send = my_decom_str_shares.length;

            start = System.nanoTime();
            V2.add(pid);
            ns.serverUpdateDecomStrShares(my_decom_str_shares);
            end = System.nanoTime();
            avg_server_ver_round_1_time += (end - start)/1000000;
        }

        start = System.nanoTime();
        byte[] recons_decom_str = ns.serverFinalDecomStr();
        end = System.nanoTime();
        avg_server_ver_round_1_time += (end - start)/1000000;
        client_ver_round_2_recv = recons_decom_str.length;

        System.out.println("Verification Round 1 done");
        System.out.println("    - V2 size: " + V2.size());
        System.out.println("    - recons_decom_str length: " + recons_decom_str.length + " bytes");

        /*
         *  Verification Round 2 (BatchChecking)
         */
        boolean pass = true;
        start = System.nanoTime();
        for (Integer pid: V2) {
            boolean flag = nc.clientBatchChecking(pid, recons_decom_str);
            pass = pass && flag;
            //System.out.println("    Client " + pid + ": " + flag);
        }
        end = System.nanoTime();
        avg_client_ver_round_2_time += (end - start)/1000000;

        System.out.println("Verification Round 2 done");
        System.out.println("    - Verification passed: " + pass);


        /*
         *  Print computation overhead
         */
        System.out.println();
        System.out.println("-------------------- Computation Overhead in Verification Phase --------------------");
        System.out.println("Client timer:");
        // Verification phase
        System.out.println("    - Average verification round 0 (Decommitting): " + avg_client_ver_round_0_time/U4.size() + " ms");
        System.out.println("    - Average verification round 1 (DroppedDecommitting): " + avg_client_ver_round_1_time/V1.size() + " ms");
        System.out.println("    - Average verification round 2 (BatchChecking): " + avg_client_ver_round_2_time/V2.size() + " ms");
        System.out.println("    - Amortized verification time: " +
                (avg_client_ver_round_0_time/U4.size() +
                        avg_client_ver_round_1_time/V1.size() +
                        avg_client_ver_round_2_time/V2.size())/batch +
                " ms");

        System.out.println("Server timer:");
        // Verification phase
        System.out.println("    - Average verification round 0 (Decommitting): " + avg_server_ver_round_0_time + " ms");
        System.out.println("    - Average verification round 1 (DroppedDecommitting): " + avg_server_ver_round_1_time + " ms");
        System.out.println("    - Amortized verification time: " +
                (avg_server_ver_round_0_time + avg_server_ver_round_1_time)/batch + " ms");

        /*
         *  Print communication overhead
         */
        System.out.println();
        System.out.println("-------------------- Communication Overhead in Verification Phase --------------------");
        System.out.println("Client side:");
        // Aggregation phase
        System.out.println("    - Message sent in verification round 0 (Decommitting): " + client_ver_round_0_send/1024.0 + " KBytes");

        System.out.println("    - Message received in verification round 1 (DroppedDecommitting): " + client_ver_round_1_recv/1024.0 + " KBytes");
        System.out.println("    - Message sent in verification round 1 (DroppedDecommitting): " + client_ver_round_1_send/1024.0 + " KBytes");

        System.out.println("    - Message received in verification round 2 (BatchChecking): " + client_ver_round_2_recv/1024.0 + " KBytes");

        System.out.println("    - Total: " +
                (client_ver_round_0_send +
                        client_ver_round_1_recv + client_ver_round_1_send +
                        client_ver_round_2_recv)/1024.0 +
                " KBytes");

        ns.exit();
        nc.exit();
    }

    private void encodePid(byte[] buffer, int offset, int pid) {
        buffer[offset] = (byte)(pid&0xff);
        buffer[offset + 1] = (byte)((pid >> 8)&0xff);
    }

    private int decodePid(byte[] buffer, int offset) {
        return ((buffer[offset + 1]&0xff) << 8) + (buffer[offset]&0xff);
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
