# VeriFL

## Important Note on Security

On May 20, 2022, we found that there is a flaw in the security proof of [VeriFL](https://ieeexplore.ieee.org/document/9285303). We thank [@Jinhyun So](https://jinhyun-so.github.io/) for helping us spot this issue and plan to present a detailed patched version of VeriFL protocol in a few months. We sincerely apologize for any inconvenience caused by our work.

(Updated Aug 22, 2022, **security patch**) The patched protocol secure against any standard **malicious** adversary can be found at [https://eprint.iacr.org/2022/1073](https://eprint.iacr.org/2022/1073).
Fortunately, the same dropout model in our original work can be preserved in the patched protocol.

~(Updated May 26, 2022) Due to the requirement that there is no dropout between several rounds, we think that our patched VeriFL is limited to the FL settings without dropout.~ 

### The issue

We discuss this flaw as follows. In brief, **the published homomorphic hashes in the verification phase may help the adversary guess the input vector of an honest client if this vector itself does not have sufficient entropy (i.e., has only a few possible values)**.

In VeriFL, we consider a "weakened" malicious adversary such that the corrupted parties must use their original inputs (this frees us from extracting the actually used inputs as in standard malicious security, making the communication-independent feature possible). To show that input privacy holds for the inputs of honest parties, we need to construct a simulator that is only given the aggregate results but can "simulate" the messages to be received by the corrupted parties without knowing the individual input of each honest party. The term "simulate" refers to that the distribution of these simulated messages should be identically/statistically/computationally indistinguishable from that of the messages in the real protocol. If such a simulator does not exist, there must be some information leakage in the real protocol beyond what can be obtained from the aggregate results.

Note that a linearly homomorphic hash is a **deterministic** function of a input vector. This means that the simulator without knowning the actual inputs of honest parties cannot simulate some hash values such that their distribution is exactly that in the real protocol. Even if secret sharing and commitment help us hide the distribution of simulated hashes in the **aggregation phase**, these hashes still need to be revealed in the **verification phase**. Therefore, the distinguisher can distinguish between the real case and the simulated case, failing the security proof.

### A high-level description about the patched VeriFL
Please refer to Section 3.1 in our linked paper.

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
