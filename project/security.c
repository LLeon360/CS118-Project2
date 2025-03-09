#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void init_sec(int type, char *host) {
    init_io();
}


ssize_t input_sec(uint8_t *buf, size_t max_length) { 
    ssize_t input_len = input_io(buf, max_length);

    return input_len;
}

void output_sec(uint8_t *buf, size_t length) { 
    // decrypt first
    output_io(buf, length); 
}

// Generate a client hello TLV and return it
// Returns serialized buffer on success, NULL on failure
// *out_length will contain the total length of the resulting buffer
tlv* generate_client_hello(size_t *out_length) {
    // Create CLIENT_HELLO container
    tlv* client_hello_tlv = create_tlv(CLIENT_HELLO);
    
    // Create and add NONCE
    tlv* nonce_tlv = create_tlv(NONCE);
    uint8_t nonce[NONCE_SIZE];
    generate_nonce(nonce, NONCE_SIZE);
    add_val(nonce_tlv, nonce, NONCE_SIZE);
    add_tlv(client_hello_tlv, nonce_tlv);
    
    // Generate keys and add PUBLIC_KEY
    generate_private_key();
    derive_public_key();

    tlv* public_key_tlv = create_tlv(PUBLIC_KEY);
    add_val(public_key_tlv, public_key, pub_key_size);
    add_tlv(client_hello_tlv, public_key_tlv);
    
    return client_hello_tlv;
}

//  Generate a server hello tlv and return it
// Returns NULL on error, caller must free the returned buffer
tlv* generate_server_hello(size_t *out_length, const uint8_t *client_hello_data, size_t client_hello_length) {
    tlv* server_hello_tlv = create_tlv(SERVER_HELLO);

    // Create and add NONCE
    tlv* nonce_tlv = create_tlv(NONCE);
    uint8_t nonce[NONCE_SIZE];
    generate_nonce(nonce, NONCE_SIZE);
    add_val(nonce_tlv, nonce, NONCE_SIZE);
    add_tlv(server_hello_tlv, nonce_tlv);

    // generate a server (emphemeral) public key, note: this is different from the public key in the certificate
    generate_private_key();
    derive_public_key();

    // Pack public key into TLV
    tlv* public_key_tlv = create_tlv(PUBLIC_KEY);
    add_val(public_key_tlv, public_key, pub_key_size);
    add_tlv(server_hello_tlv, public_key_tlv);

    load_certificate("server_cert.bin");

    uint8_t *signed_client_hello[72];
    size_t signed_client_hello_length = sign(signed_client_hello, client_hello_data, client_hello_length);

    // Pack signed client hello into TLV
    tlv* signed_client_hello_tlv = create_tlv(SIGNATURE);
    add_val(signed_client_hello_tlv, signed_client_hello, signed_client_hello_length);
    add_tlv(server_hello_tlv, signed_client_hello_tlv);
    
    return server_hello_tlv;
}