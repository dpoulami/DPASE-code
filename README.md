DPaSE
paper link: https://eprint.iacr.org/2020/1443.pdf

Overview of Code:
The code in this repository is a proof of concept implementation of our DPaSE protocol for a password-authenticated encryption service.
It is run between a client and n servers

Usage:
The code has been written in Java 1.8 and uses Maven, so make sure you use that compiler and have Maven installed. 
To run the tests go to the root of the project and run 'mvn initialize' followed by 'mvn clean install package'.
To run the Benchmarks, go to DPASE\src\test\java\benchmark and run Benchmark.java

License:
The source code of the DPaSE project is licensed under the Apache License, Version 2.0.
