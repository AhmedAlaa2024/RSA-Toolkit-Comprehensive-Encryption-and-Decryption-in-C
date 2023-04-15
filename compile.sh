#!/bin/sh

gcc PerformanceAnalysis/Encryption_Decryption_Analysis.c RSAToolkit/RSA_toolkit.c -o PerformanceAnalysis/Encryption_Decryption_Analysis -lm -lgmp
gcc PerformanceAnalysis/BruteforceAttack_PrimeFactorization_Analysis.c RSAToolkit/RSA_toolkit.c -o PerformanceAnalysis/BruteforceAttack_PrimeFactorization_Analysis -lm -lgmp
gcc ChattingRoom/Server.c RSAToolkit/RSA_toolkit.c -o ChattingRoom/Server -lm -lgmp
gcc ChattingRoom/Client.c RSAToolkit/RSA_toolkit.c -o ChattingRoom/Client -lm -lgmp
