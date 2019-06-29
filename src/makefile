#Makefile 
TARGET = main
DEBUG = debug

CC = gcc -O3
# -lgmp for gmp 
CFLAGS = -lm -lgmp #-Wall -lcrypto -Wextra
DEBUG_FLAG = DEBUG


main:
	$(CC) -c -g $(CFLAGS) main.c 
	$(CC) -g -o main main.o $(CFLAGS) 

rc4Lib: textConverter
	$(CC) -c -g $(CFLAGS) rc4Lib.c 

rsa: rng
	$(CC) -c -g $(CFLAGS) rsa.c 

textConverter:
	$(CC) -c -g $(CFLAGS) textConverter.c 

rng: rc4Lib
	$(CC) -c -g $(CFLAGS) randomNumberGenerator.c



############ final platforms
rc4: rc4Lib
	$(CC) -c -g $(CFLAGS) rc4.c
	$(CC) -g -o rc4 rc4.o rc4Lib.o textConverter.o $(CFLAGS) 

rsaencrypt: rsa
	$(CC) -c -g $(CFLAGS) rsaencrypt.c
	$(CC) -g -o rsaencrypt rsaencrypt.o rsa.o randomNumberGenerator.o rc4Lib.o textConverter.o $(CFLAGS) 

rsadecrypt: rsa
	$(CC) -c -g $(CFLAGS) rsadecrypt.c
	$(CC) -g -o rsadecrypt rsadecrypt.o rsa.o randomNumberGenerator.o rc4Lib.o textConverter.o $(CFLAGS) 

rsakeygen: rsa
	$(CC) -c -g $(CFLAGS) rsakeygen.c
	$(CC) -g -o rsakeygen rsakeygen.o rsa.o randomNumberGenerator.o rc4Lib.o textConverter.o $(CFLAGS) 

######### testers
rc4LibTester: rc4Lib
	$(CC) -c -g $(CFLAGS) rc4LibTester.c
	$(CC) -g -o rc4LibTester rc4LibTester.o rc4Lib.o textConverter.o $(CFLAGS) 

rngTester: rng
	$(CC) -c -g $(CFLAGS) rngTester.c
	$(CC) -g -o rngTester rngTester.o randomNumberGenerator.o rc4Lib.o textConverter.o $(CFLAGS) 

rsaTester: rsa
	$(CC) -c -g $(CFLAGS) rsaTester.c
	$(CC) -g -o rsaTester rsaTester.o rsa.o randomNumberGenerator.o rc4Lib.o textConverter.o $(CFLAGS) 
################### runs
run-main: clean main
	./main

run-rc4LibTester: clean rc4LibTester
	./rc4LibTester

run-rc4: clean rc4
	./rc4

run-rngTester: clean rngTester
	./rngTester

run-rsaTester: clean rsaTester
	./rsaTester

clean:
	rm -f *.o *.exe *.out main rc4 rc4LibTester rngTester rsaTester rsakeygen rsadecrypt rsaencrypt

