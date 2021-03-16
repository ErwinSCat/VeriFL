package com.va.server;

import static com.va.server.DropoutStructure.*;
import org.apache.commons.cli.*;

public class Main {

    public static void main(String[] args) {

        Options options = new Options();
        options.addOption("logR", true,
                "Set the bit length of the modulus R for the quotient ring Z_R");
        options.addOption("d", true,
                "Set the dimension of gradient vectors");
        options.addOption("N", true,
                "Set the number of clients");
        options.addOption("t", true,
                "Set the threshold of secret sharing");
        options.addOption("batch", true,
                "Set the batch size in amortization verification");

        options.addOption("maskedColl", true,
                "Set dropouts in the MaskedInputCollection round");
        options.addOption("decom", true,
                "Set the number of clients that drop out in the Decommitting round");

        // Parse args
        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = null;
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException ex) {
            System.out.println("Error in parsing args");
            return;
        }

        int logR = 0, d = 0, N = 0, t = 0, batch = 0;
        DropoutStructure ds = null;

        try {
            logR = Integer.parseInt(cmd.getOptionValue("logR"));
            d = Integer.parseInt(cmd.getOptionValue("d"));
            N = Integer.parseInt(cmd.getOptionValue("N"));
            t = Integer.parseInt(cmd.getOptionValue("t"));
            batch = Integer.parseInt(cmd.getOptionValue("batch"));

            ds = new DropoutStructure(batch);

            String[] maskedColl = cmd.getOptionValue("maskedColl").split(",");
            for (int i = 0; i < maskedColl.length; i += 2) {
                ds.SetEpochDropout(Integer.parseInt(maskedColl[i]),
                        _IN_MASKEDINPUTCOLLECTION,
                        Integer.parseInt(maskedColl[i + 1]));
            }

            ds.SetVeriDropout(_IN_DECOMMITTING,
                    Integer.parseInt(cmd.getOptionValue("decom")));

        } catch (Exception ex) {
            System.out.println("Invalid parameters!");

            System.out.println(logR);
            System.out.println(d);
            System.out.println(N);
            System.out.println(t);
            System.out.println(batch);

            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("Options", options);
            return;
        }

        SimAggregationServer server
                = new SimAggregationServer(logR, d, t, N, batch, ds);
        server.run_sim_server();
    }
}

