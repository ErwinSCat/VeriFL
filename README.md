# VeriFL

## Preface

This repository provides two [IntelliJ IDEA](https://www.jetbrains.com/idea/download/) projects for VeriFL. The project **Client** involves the Android benchmark for clients participating in VeriFL protocol. The project **Server** involves the benchmark of the whole VeriFL protocol (see `Server/src/java/com/va/server/Main.java` and `Server/src/java/com/va/server/SimAggregationServer.java` for detail).


## Requirements
- OS: Ubuntu 16.04 LTS
- IDE: IntelliJ IDEA Community Edition 2019.1.3
- GCC, G++: version 7.4.0
- JAVA: 1.8.0_211
- Cmake: version 3.15.3

## To Benchmark VeriFL

To run the VeriFL benchmark program in **Server** folder, download this repository and run the following commands in shell.
```bash
cd Server/src/cpp/build
cmake .. && make
cd ../../..
```
The parameters required to run the benchmark are listed as follows.

| Parameters  | Description
| ---------   | -------- 
| -logR       | Set the bit length of the modulus R for the quotient ring Z_R
| -d          | Set the dimension of gradient vectors
| -N          | Set the number of clients
| -t          | Set the threshold of secret sharing
| -batch      | Set the batch size in amortization verification
| -maskedColl | Set dropouts in the MaskedInputCollection round (e.g., 0,10,2,30 represents there are 10 dropouts in the 0-th epoch and 30 dropouts in the 2-th epoch)
| -decom      | Set the number of clients that drop out in the Decommitting round
 
For example, in `Server/` directory, run
```bash
java -Xmx8192m -Xms8192m -Xss8192m -jar Server.jar -logR 24 -d 10000 -N 100 -t 25 -batch 1 -maskedColl 0,0 -decom 0
```
Note that our simulation requires a large amount of memory and the heap size should be large enough.
