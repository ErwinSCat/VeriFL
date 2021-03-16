package com.va.server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;

public class AggregationServer {
    private int logR;
    private int d;
    private int t;
    private int N;
    private int batch;

    private String my_host;
    private int my_port = 17999;
    private int timeout;

    // Round 0
    private Set<Integer> U1 = new TreeSet<>();
    private Semaphore U1_lock = new Semaphore(1, true);
    private byte[] U1_buffer;
    private int U1_buffer_offset = 0;
    private Semaphore U1_sync_read;

    // Round 1
    private Set<Integer> U2 = new TreeSet<>();
    private Semaphore U2_lock = new Semaphore(1, true);
    private byte[][] U2_buffer;
    private int[] U2_buffer_offset;
    private Semaphore U2_sync_read;

    // Round 2
    private Set<Integer> U3 = new TreeSet<>();
    private Semaphore U3_lock = new Semaphore(1, true);
    private Semaphore U3_sync_read;

    // Round 3
    private NativeServer ns = new NativeServer();
    private Semaphore native_lock = new Semaphore(1, true);
    private Semaphore epoch_result_sync_read;

    // Aggregated result
    private byte[] epoch_result;

    // Semaphore for epoch end
    private Semaphore epoch_end;

    // Verification Round 0
    private Set<Integer> V1 = new TreeSet<>();
    private Semaphore V1_lock = new Semaphore(1, true);
    private byte[] V1_buffer;
    private int V1_buffer_offset = 0;
    private Semaphore V1_sync_read;

    // Decommitment strings
    private Semaphore recons_decom_str_sync_read;
    private byte[] recons_decom_str;


    public AggregationServer(int logR, int d, int t, int N, int batch,
                             int timeout, String my_host) {
        this.logR = logR;
        this.d = d;
        this.t = t;
        this.N = N;
        this.batch = batch;

        this.timeout = timeout;
        this.my_host = my_host;

        this.U1_buffer = new byte[N*Config._ROUND_1_MSGITEMLEN];
        this.U1_sync_read = new Semaphore(N, true);

        this.U2_buffer_offset = new int[N];
        this.U2_sync_read = new Semaphore(N, true);

        this.U3_sync_read = new Semaphore(N, true);

        this.ns.init(logR, d, t, N, batch);
        this.epoch_result_sync_read = new Semaphore(N, true);

        this.epoch_end = new Semaphore(N, true);

        this.V1_buffer = new byte[N*(Config._PID_BYTE_SIZE + batch*Config._DECOM_STRING_SIZE)];
        this.V1_sync_read = new Semaphore(N, true);

        this.recons_decom_str_sync_read = new Semaphore(N, true);
    }

    public void run_server() {

        int pid_counter = 0;
        Date date = new Date();
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        try {
            ServerSocket ss = new ServerSocket(my_port, N, InetAddress.getByName(my_host));
            date.getTime();
            System.out.println(format.format(date) + ": Server is running on "
                    + ss.getInetAddress() + ":" + my_port);

            date.getTime();
            System.out.println(format.format(date) + ": Wait for " + N + " clients");

            // Get locks
            U1_sync_read.acquire(N);
            U2_sync_read.acquire(N);
            U3_sync_read.acquire(N);
            epoch_result_sync_read.acquire(N);

            // Setup sockets
            while (pid_counter < N) {
                Socket socket = ss.accept();
                pid_counter++;

                date.getTime();
                System.out.println(format.format(date) +
                        ": Client " + pid_counter + " connected");

                new Thread(new ServerThread(socket, pid_counter)).start();
            }

            for (int curr_epoch = 1; curr_epoch < batch; curr_epoch++) {
                // Wait for timeout and lock U1
                Thread.sleep(timeout);
                U1_lock.acquire();

                date.getTime();
                System.out.println(format.format(date) + ": U1_lock acquire");

                U2_buffer = new byte[N][(U1.size() - 1)*Config._ROUND_2_MSGITEMLEN];
                U1_sync_read.release(N);

                date.getTime();
                System.out.println(format.format(date) + ": U1_sync_read unlock");

                // Wait for timeout and lock U2
                Thread.sleep(timeout);
                U2_lock.acquire();
                U2_sync_read.release(N);

                // Wait for timeout and lock U3
                Thread.sleep(timeout);
                U3_lock.acquire();
                U3_sync_read.release(N);

                // Wait for timeout and prepare aggregated result
                Thread.sleep(timeout);
                native_lock.acquire();
                epoch_result = ns.serverFinalResult();
                if (epoch_result == null) throw new Exception("Aggregation failed");
                epoch_result_sync_read.release(N);

                // Reset status
                epoch_end.acquire(N);
                U1.clear();
                U2.clear();
                U3.clear();
                U1_sync_read.acquire(N);
                U2_sync_read.acquire(N);
                U3_sync_read.acquire(N);
                epoch_result_sync_read.acquire(N);
                U1_lock.release();
                U2_lock.release();
                U3_lock.release();
                native_lock.release();
                epoch_end.release(N);
            }
            // Wait for timeout and lock V1
            Thread.sleep(timeout);
            V1_lock.acquire();
            V1_sync_read.release(N);

            // Wait for timeout and prepare decommitment strings
            Thread.sleep(timeout);
            native_lock.acquire();
            recons_decom_str = ns.serverFinalDecomStr();
            recons_decom_str_sync_read.release(N);

            ns.exit();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    class ServerThread implements Runnable {
        private Socket socket;
        private int my_pid;

        public ServerThread(Socket socket, int my_pid) {
            this.socket = socket;
            this.my_pid = my_pid;
        }

        @Override
        public void run() {
            try {
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());

                /*
                 *  Setup phase
                 */
                out.writeInt(logR);
                out.writeInt(d);
                out.writeInt(t);
                out.writeInt(N);
                out.writeInt(my_pid);
                out.writeInt(batch);

                int length;
                Date date = new Date();
                SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

                for (int curr_epoch = 1; curr_epoch <= batch; curr_epoch++) {
                    epoch_end.acquire();
                    date.getTime();
                    System.out.println(format.format(date) + " [Client " + my_pid + "]: Entering epoch " + curr_epoch);

                    /*
                     *  Round 0 (AdvertiseKeys)
                     */
                    length = in.readInt();
                    byte[] my_keys = new byte[length];
                    in.read(my_keys, 0, length);

                    date.getTime();
                    System.out.println(format.format(date) + " [Client " + my_pid + "]: Read keys of length " + length);

                    U1_lock.acquire();
                    U1.add(my_pid);

                    System.out.println("  [java] U1 add");

                    System.arraycopy(my_keys, 0,
                            U1_buffer, U1_buffer_offset,
                            length);

                    System.out.println("  [java] array copy");

                    ns.serverUpdateKeys(my_keys);

                    System.out.println("  [java] native call");

                    U1_buffer_offset += length;
                    U1_lock.release();

                    date.getTime();
                    System.out.println(format.format(date) + " [Client " + my_pid + "]: Stored keys in context");

                    U1_sync_read.acquire();

                    System.out.println("  Check point 1 in client " + my_pid);

                    out.writeInt(U1.size());
                    out.writeInt(U1_buffer_offset);
                    out.write(U1_buffer, 0, U1_buffer_offset);
                    U1_sync_read.release();

                    /*
                     *  Round 1 (ShareMetadata)
                     */
                    length = in.readInt();
                    byte[] my_metadata = new byte[length];
                    in.read(my_metadata, 0, length);
                    U2_lock.acquire();

                    System.out.println("  Check point 2 in client " + my_pid);

                    U2.add(my_pid);
                    ns.serverUpdateU2(my_pid);
                    int dest_pid;
                    for (int offset = Config._PID_BYTE_SIZE + Config._COMMITMENT_SIZE;
                        offset < length; offset += (Config._PID_BYTE_SIZE + Config._SYM_CIPHERTEXT_SIZE)) {
                        dest_pid = decodePid(my_metadata, offset);

                        System.arraycopy(my_metadata, 0,
                                U2_buffer[dest_pid - 1], U2_buffer_offset[dest_pid - 1],
                                Config._PID_BYTE_SIZE + Config._COMMITMENT_SIZE);
                        U2_buffer_offset[dest_pid - 1] += (Config._PID_BYTE_SIZE + Config._COMMITMENT_SIZE);

                        System.arraycopy(my_metadata, offset + Config._PID_BYTE_SIZE,
                                U2_buffer[dest_pid - 1], U2_buffer_offset[dest_pid - 1],
                                Config._SYM_CIPHERTEXT_SIZE);
                        U2_buffer_offset[dest_pid - 1] += Config._SYM_CIPHERTEXT_SIZE;
                    }
                    U2_lock.release();

                    date.getTime();
                    System.out.println(format.format(date) + ": Get metadata from client " + my_pid);

                    U2_sync_read.acquire();
                    out.writeInt(U2.size());
                    out.writeInt(U2_buffer[my_pid - 1].length);
                    out.write(U2_buffer[my_pid - 1], 0, U2_buffer[my_pid - 1].length);
                    U2_sync_read.release();

                    /*
                     *  Round 2 (MaskedInputCollection)
                     */
                    length = in.readInt();
                    byte[] my_maskedInput = new byte[length];
                    in.read(my_maskedInput, 0, length);
                    U3_lock.acquire();
                    U3.add(my_pid);
                    ns.serverUpdateInput(my_maskedInput);
                    U3_lock.release();

                    date.getTime();
                    System.out.println(format.format(date) + ": Get masked input from client " + my_pid);

                    U3_sync_read.acquire();
                    byte[] U3_set = new byte[U3.size()*Config._PID_BYTE_SIZE];
                    int U3_offset = 0;
                    for (Integer pid: U3) {
                        encodePid(U3_set, U3_offset, pid);
                        U3_offset += Config._PID_BYTE_SIZE;
                    }
                    out.writeInt(U3.size());
                    out.write(U3_set, 0, U3.size()*Config._PID_BYTE_SIZE);
                    U3_sync_read.release();

                    /*
                     *  Round 3 (Unmasking)
                     */
                    length = in.readInt();
                    byte[] my_shares = new byte[length];
                    in.read(my_shares, 0, length);
                    native_lock.acquire();
                    ns.serverUpdateMaskShares(my_shares);
                    native_lock.release();

                    date.getTime();
                    System.out.println(format.format(date) + ": Get shares from client " + my_pid);

                    epoch_result_sync_read.acquire();
                    out.writeInt(epoch_result.length);
                    out.write(epoch_result, 0, epoch_result.length);
                    epoch_result_sync_read.release();

                    epoch_end.release();
                }

                /*
                 *  Verification Round 0 (Decommitting)
                 */
                length = in.readInt();
                byte[] my_decom_str = new byte[length];
                in.read(my_decom_str, 0, length);
                V1_lock.acquire();
                V1.add(my_pid);
                ns.serverUpdateV1(my_pid);
                System.arraycopy(my_decom_str, 0,
                        V1_buffer, V1_buffer_offset,
                        length);
                V1_buffer_offset += length;
                V1_lock.release();

                date.getTime();
                System.out.println(format.format(date) + ": Get decommitment string from client " + my_pid);

                V1_sync_read.acquire();
                out.writeInt(V1.size());
                out.writeInt(V1_buffer_offset);
                out.write(V1_buffer, 0, V1_buffer_offset);
                V1_sync_read.release();

                /*
                 *  Verification Round 1 (DroppedDecommitting)
                 */
                length = in.readInt();
                byte[] my_decom_str_shares = new byte[length];
                in.read(my_decom_str_shares, 0, length);
                native_lock.acquire();
                ns.serverUpdateDecomStrShares(my_decom_str_shares);
                native_lock.release();

                date.getTime();
                System.out.println(format.format(date) + ": Get shares of decommitment strings from client " + my_pid);

                recons_decom_str_sync_read.acquire();
                out.writeInt(recons_decom_str.length);
                out.write(recons_decom_str, 0, recons_decom_str.length);
                recons_decom_str_sync_read.release();

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void encodePid(byte[] buffer, int offset, int pid) {
        buffer[offset] = (byte)(pid&0xff);
        buffer[offset + 1] = (byte)((pid >> 8)&0xff);
    }

    private int decodePid(byte[] buffer, int offset) {
        return ((buffer[offset + 1]&0xff) << 8) + (buffer[offset]&0xff);
    }
}

