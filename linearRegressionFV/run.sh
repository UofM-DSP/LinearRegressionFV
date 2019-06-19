#!/usr/bin/env bash
g++ testFV.cpp -o testFV.o testFV.out   -I./include/ -I./include/nfl/ -I./include/nfl/prng/ -I./lib/prng/ -I./lib/params/ -I./include/nfl/opt/arch/ -std=c++11 -lgmpxx -lgmp  -lmpfr -m64 -DNTT_AVX -DNTT_SSE && ./testFV.o

#g++ cloud.cpp -o cloud.o a.out   -I./include/ -I./include/nfl/ -I./include/nfl/prng/ -I./lib/prng/ -I./lib/params/ -I./include/nfl/opt/arch/ -std=c++11 -lgmpxx -lgmp  -lmpfr -m64 -DNTT_AVX -DNTT_SSE -fopenmp && ./cloud.o

#g++ decrypt.cpp -o decrypt.o a.out   -I./include/ -I./include/nfl/ -I./include/nfl/prng/ -I./lib/prng/ -I./lib/params/ -I./include/nfl/opt/arch/ -std=c++11 -lgmpxx -lgmp  -lmpfr -m64 -DNTT_AVX -DNTT_SSE && ./decrypt.o