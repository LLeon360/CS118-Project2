# CS 118 Winter 25 Project 2

Anthony Yu
Joshua Zhu
Leon Liu

## Description of Work

We noticed the set up of the interfacing between the transport and the security layer was such that the security layer's `input_sec` and `output_sec` functions were configured such that they interfaced with the transport layer listen loop. This added the constraint that the function's had to inplement the same interface that `input_io` and `output_io` did which is to simply provide a buffer to receive or pass in data and the length for this data. But the security layer has different phases and state necessary to implement the logic of client and server handshakes.

Thus to solve this problem, we used global variables to track this state and had conditional behavior for these input output functions such that they would generate the appropriate handshake or parse the handshake or perform general encryption and decryption once the handshake was completed. Also because the input and output were decoupled, we had to be careful that we put certain secret derivations steps in the right function such that that the necessary information/keys are contained in the state before executing these operations. 

Besides this, we ran into minor issues with handling lengths correctly for certain fields, reading the certificate in properly (deserializing it), and generally working back and forth between tlvs and byte buffers. These were fixed with some debugging.