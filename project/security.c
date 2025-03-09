#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int __type; 
char *__host;
int phase = 0; // 0 = client hello, 1 = server hello, 2 = finished, 3 = data

uint8_t *client_hello_data;
uint8_t *server_hello_data;

size_t client_hello_data_length;
size_t server_hello_data_length;

void init_sec(int type, char *host) {
    init_io();

    __type = type;
    __host = host;

    phase = 0;
}

ssize_t input_sec(uint8_t *buf, size_t max_length) { 
    if (__type == CLIENT && phase == 0) {
        // If client, and client hello
        tlv* client_hello_tlv = generate_client_hello();
        
        // serialize to buffer
        ssize_t client_hello_data_length = serialize_tlv(client_hello_data, client_hello_tlv);

        free_tlv(client_hello_tlv);

        memcpy(buf, client_hello_data, client_hello_data_length);

        return client_hello_data_length;
    }
    else if (__type == SERVER && phase == 1) {
        // If server, and server hello
        tlv* server_hello_tlv = generate_server_hello();
        
        // serialize to buffer
        ssize_t server_hello_data_length = serialize_tlv(server_hello_data, server_hello_tlv);

        free_tlv(server_hello_tlv);

        memcpy(buf, server_hello_data, server_hello_data_length);
        
        return server_hello_data_length;
    }
    else if (__type == CLIENT && phase == 2) {
        // If client, and finished
        tlv* finished_tlv = generate_finished(client_hello_data, client_hello_data_length, server_hello_data, server_hello_data_length);
        
        // serialize to buffer
        ssize_t data_len = serialize_tlv(buf, finished_tlv);

        free_tlv(finished_tlv);

        return data_len;
    }
    else if (phase == 3) {
        // If data read from stdin 
        // Encrypt data

        ssize_t input_len = input_io(buf, max_length);

        return input_len;
    }
    
    return 0;
}

void output_sec(uint8_t *buf, size_t length) { 
    // decrypt first
    output_io(buf, length);
}

// Generate a client hello TLV and return it
tlv* generate_client_hello() {
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
tlv* generate_server_hello(const uint8_t *client_hello_data, size_t client_hello_length) {
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

tlv* generated_finished(const uint8_t *client_hello_data, size_t client_hello_data, const uint8_t *server_hello_data, size_t server_hello_data) {
    tlv* finished_tlv = create_tlv(FINISHED);

    uint8_t client_server_hello_combined[client_hello_data_length + server_hello_data_length];
    memcpy(client_server_hello_combined, client_hello_data, client_hello_data_length);
    memcpy(client_server_hello_combined + client_hello_data_length, server_hello_data, server_hello_data_length);

    uint8_t transcript[MAC_SIZE];

    hmac(transcript, client_server_hello_combined, client_hello_data_length + server_hello_data_length);

    tlv* transcript_tlv = create_tlv(TRANSCRIPT);
    add_val(transcript_tlv, transcript, MAC_SIZE);

    add_tlv(finished_tlv, transcript_tlv);

    return finished_tlv;
}
