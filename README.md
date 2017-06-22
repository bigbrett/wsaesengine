[![experimental](http://badges.github.io/stability-badges/dist/experimental.svg)](http://github.com/badges/stability-badges)
# wsaescbcengine
A minimal openSSL engine for offloading aescbc functions to a hardware accelerator in FPGA logic

## Prerequisites
1. You are running linux on the Xilinx ZYNQ-7000 development board, with the necessary design instantiated in PL [link to final design goes here]
2. Ensure you have openSSL using the command `$ openssl version`. If you have lower than version 1.0.2, you must upgrade to this version.
3. Check out the repository using git `$ git clone https://github.com/bigbrett/wsaescbcengine.git` 

## Building the engine

    $ cd wsaescbcengine
    $ make

You can verify that the engine can be loaded using: 

    $ openssl engine -t -c `pwd`/bin/libwsaescbcengine.so
    (/home/brett/wsaescbcengine/bin/libwsaescbcengine.so) A test engine for the ws aescbc hardware encryption module, on the Xilinx ZYNQ7000
    Loaded: (wsaescbcengine) A test engine for the ws aescbc hardware encryption module, on the Xilinx ZYNQ7000
        [ available ]

**Note** You may get an error complaining that `ERROR: Digest is empty! (NID = 0)`. I'm investigating the cause of this, however the engine still loads properly and it does not seem to affect the functionality of the test program 

## Testing the engine
### Quck test
A quick and easy test goes like this, where the resultant digest values should be identical: 

    $ teststr="Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec vel nulla malesuada, dictum diam ut, semper sapien. Etiam faucibus porttitor tristique. Vestibulum id magna sed velit ornare varius vitae nec erat. Mauris dui arcu, pulvinar eu pretium posuere."
    
    $ echo $teststr | openssl dgst -engine /full/path/to/libwsaescbcengine.so -aescbc
      (stdin)= 28ed684090a0df4a70fd2ac9249a5cb13ddda6f34055148b739cd3b668445cf9
    
    $ echo $teststr | openssl dgst -aescbc
      (stdin)= 28ed684090a0df4a70fd2ac9249a5cb13ddda6f34055148b739cd3b668445cf9

### Custom Test
A more advanced test, using a c test program, can be conducted like this (see test/wsaescbcengine_test.c for implementation): 
    
    $ make test
    $ source test/runtest.sh

NOTE: the runtest.sh script must remain in the test directory, but should be able to be called from anywhere
    
### OpenSSL speed test
The speed of the engine's digest computation can be tested using the built-in openSSL speed command (making sure to explicitly specify using the EVP API for the message digest)

    $ openssl speed -evp aescbc -engine /path/to/libwsaescbcengine.so


