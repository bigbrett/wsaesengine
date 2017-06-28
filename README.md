[![experimental](http://badges.github.io/stability-badges/dist/experimental.svg)](http://github.com/badges/stability-badges)
# wsaesengine
A minimal openSSL engine for offloading aescbc functions to a hardware accelerator in FPGA logic

## Prerequisites
1. You are running linux on the Xilinx ZYNQ-7000 development board, with the necessary design instantiated in PL [link to final design goes here]
2. Ensure you have openSSL using the command `$ openssl version`. If you have lower than version 1.0.2, you must upgrade to this version.
3. Check out the repository using git `$ git clone https://github.com/bigbrett/wsaesengine.git` 

## Building the engine

    $ cd wsaesengine
    $ make

You can verify that the engine can be loaded using: 

    $ openssl engine -t -c `pwd`/bin/libwsaesengine.so
    (/home/brett/wsaesengine/bin/libwsaesengine.so) A test engine for the ws aescbc hardware encryption module, on the Xilinx ZYNQ7000
    Loaded: (wsaesengine) A test engine for the ws aescbc hardware encryption module, on the Xilinx ZYNQ7000
        [ available ]

## Testing the engine
### Quck test
A quick and easy test goes like this, where the output of the decryption should match the input: 

    $ msg="OpenSSL has poor documentation!"; key="01234567890123456789012345678901"; iv="01234567890123456"
    $ epath=/path/to/libwsaesengine.so; encfile=/tmp/enc.bin
    $ echo $msg | openssl enc -e -aes-256-cbc -K $key -iv $iv -engine $epath -out $encfile
        engine "wsaescbc" set.
    $ openssl enc -d -aes-256-cbc -K $key -iv $iv -engine $epath -in $encfile
        OpenSSL has poor documentation!
      

### Custom Test
A more advanced test, using a c test program, can be conducted like this (see test/wsaesengine_test.c for implementation): 
    
    $ make test
    $ source test/runtest.sh

NOTE: the runtest.sh script must remain in the test directory, but should be able to be called from anywhere
    
### OpenSSL speed test
The speed of the engine's digest computation can be tested using the built-in openSSL speed command (making sure to explicitly specify using the EVP API for the message digest)

    $ openssl speed -evp aes-256-cbc -engine /path/to/libwsaesengine.so


