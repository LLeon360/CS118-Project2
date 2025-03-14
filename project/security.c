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

    // Allocate buffers
    client_hello_data = malloc(1024); // Note: larger than max payload to be safe
    if (!client_hello_data) {
        exit(EXIT_FAILURE); // Memory allocation failure
    }
    
    server_hello_data = malloc(1024);
    if (!server_hello_data) {
        free(client_hello_data);
        exit(EXIT_FAILURE); // Memory allocation failure
    }

    phase = 0;
}

// Forward declarations of helper functions
tlv *generate_client_hello();
tlv *generate_server_hello();
tlv *generate_finished();

ssize_t input_sec(uint8_t *buf, size_t max_length) {
    if (__type == CLIENT && phase == 0) {
        // If client, and in client hello phase
        tlv *client_hello_tlv = generate_client_hello();
        if (!client_hello_tlv) {
            exit(EXIT_FAILURE); // Failed to create client hello
        }

        // serialize to buffer
        client_hello_data_length = serialize_tlv(client_hello_data, client_hello_tlv);

        free_tlv(client_hello_tlv);

        memcpy(buf, client_hello_data, client_hello_data_length);

        // Move to server hello phase
        phase = 1;

        return client_hello_data_length;
    }
    else if (__type == SERVER && phase == 1) {
        // If server, and in server hello phase
        tlv *server_hello_tlv = generate_server_hello();
        if (!server_hello_tlv) {
            exit(EXIT_FAILURE); // Failed to create server hello
        }

        // serialize to buffer
        server_hello_data_length = serialize_tlv(server_hello_data, server_hello_tlv);

        // derived shared secret here, peer public key should have been loaded (in output_sec client
        // hello phase) and private key generated (in generate_server_hello)
        derive_secret();

        // derive encryption and MAC keys
        uint8_t *combined_hello = malloc(client_hello_data_length + server_hello_data_length);
        if (!combined_hello) {
            free_tlv(server_hello_tlv);
            exit(EXIT_FAILURE);
        }
        
        memcpy(combined_hello, client_hello_data, client_hello_data_length);
        memcpy(combined_hello + client_hello_data_length, server_hello_data, server_hello_data_length);

        derive_keys(combined_hello, client_hello_data_length + server_hello_data_length);        

        free(combined_hello);
        free_tlv(server_hello_tlv);

        memcpy(buf, server_hello_data, server_hello_data_length);

        // Move to finished phase
        phase = 2;

        return server_hello_data_length;
    }
    else if (__type == CLIENT && phase == 2) {
        // If client, and in finished phase
        tlv *finished_tlv = generate_finished();
        if (!finished_tlv) {
            exit(EXIT_FAILURE); // Failed to create finished
        }

        // serialize to buffer
        ssize_t data_len = serialize_tlv(buf, finished_tlv);

        free_tlv(finished_tlv);

        // Move to data phase
        phase = 3;

        return data_len;
    }
    else if (phase == 3) {
        // If data read from stdin
        // Encrypt data
        ssize_t input_len = input_io(buf, max_length);

        // TODO: Implement data encryption
        // For now, just return the input data length
        return input_len;
    }

    return 0;
}


void output_sec(uint8_t *buf, size_t length) {
    if (__type == SERVER && phase == 0) {
        // If server, and in client hello phase
        tlv *client_hello_tlv = deserialize_tlv(buf, length);
        if (!client_hello_tlv) {
            exit(6); // Unexpected message
        }

        // save client hello data
        memcpy(client_hello_data, buf, length);
        client_hello_data_length = length;

        // Get client's public key
        tlv *public_key_tlv = get_tlv(client_hello_tlv, PUBLIC_KEY);
        if (!public_key_tlv) {
            free_tlv(client_hello_tlv);
            exit(6); // Unexpected message
        }
        
        load_peer_public_key(public_key_tlv->val, public_key_tlv->length);

        free_tlv(client_hello_tlv);

        // Move to server hello phase
        phase = 1;
    }
    else if (__type == CLIENT && phase == 1) {
        // If client, and in server hello phase
        tlv *server_hello_tlv = deserialize_tlv(buf, length);
        if (!server_hello_tlv) {
            exit(6); // Unexpected message
        }

        // Save server hello data for later verification
        server_hello_data_length = length;
        memcpy(server_hello_data, buf, server_hello_data_length);

        // Get the certificate from the server hello
        tlv *certificate_tlv = get_tlv(server_hello_tlv, CERTIFICATE);
        if (!certificate_tlv) {
            free_tlv(server_hello_tlv);
            exit(6); // Unexpected message
        }

        // Extract DNS name and public key from certificate
        tlv *dns_name_tlv = get_tlv(certificate_tlv, DNS_NAME);
        tlv *cert_pubkey_tlv = get_tlv(certificate_tlv, PUBLIC_KEY);
        tlv *cert_sig_tlv = get_tlv(certificate_tlv, SIGNATURE);

        if (!dns_name_tlv || !cert_pubkey_tlv || !cert_sig_tlv) {
            free_tlv(server_hello_tlv);
            exit(6); // Unexpected message
        }

        // Load CA public key
        load_ca_public_key("ca_public_key.bin");

        // Verify the certificate's signature
        // The data to verify is the DNS name and public key concatenated
        // Allocate sufficient buffer for the data
        uint8_t *cert_data = malloc(dns_name_tlv->length + cert_pubkey_tlv->length + 16);
        if (!cert_data) {
            free_tlv(server_hello_tlv);
            exit(EXIT_FAILURE); // Memory allocation failure
        }

        // Copy the actual values 
        memcpy(cert_data, dns_name_tlv->val, dns_name_tlv->length);
        memcpy(cert_data + dns_name_tlv->length, cert_pubkey_tlv->val, cert_pubkey_tlv->length);

        size_t cert_data_len = dns_name_tlv->length + cert_pubkey_tlv->length;

        if (!verify(cert_sig_tlv->val, cert_sig_tlv->length, cert_data, cert_data_len,
                    ec_ca_public_key)) {
            free(cert_data);
            free_tlv(server_hello_tlv);
            exit(1); // Bad certificate
        }
        free(cert_data);

        // Verify DNS name matches expected host
        if (dns_name_tlv->length != strlen(__host) ||
            memcmp(dns_name_tlv->val, __host, dns_name_tlv->length) != 0) {
            free_tlv(server_hello_tlv);
            exit(2); // Bad DNS name
        }

        // Get server's handshake signature
        tlv *handshake_sig_tlv = get_tlv(server_hello_tlv, HANDSHAKE_SIGNATURE);
        if (!handshake_sig_tlv) {
            free_tlv(server_hello_tlv);
            exit(6); // Unexpected message
        }

        // Load server's public key from certificate to verify handshake signature
        load_peer_public_key(cert_pubkey_tlv->val, cert_pubkey_tlv->length);

        // Create data to verify signature: Client Hello + Server Hello components
        // Get the server nonce and ephemeral public key
        tlv *server_nonce_tlv = get_tlv(server_hello_tlv, NONCE);
        tlv *server_ephemeral_key_tlv = get_tlv(server_hello_tlv, PUBLIC_KEY);

        if (!server_nonce_tlv || !server_ephemeral_key_tlv) {
            free_tlv(server_hello_tlv);
            exit(6); // Unexpected message
        }

        // Allocate buffer for the handshake signature verification data
        // Estimate size based on known components
        size_t sig_data_len = client_hello_data_length + server_nonce_tlv->length +
                              certificate_tlv->length + server_ephemeral_key_tlv->length +
                              32; // Extra space for TLV headers
        uint8_t *sig_data = malloc(sig_data_len);
        if (!sig_data) {
            free_tlv(server_hello_tlv);
            exit(EXIT_FAILURE);
        }

        // Combine all data for signature verification
        // Copy client hello data
        memcpy(sig_data, client_hello_data, client_hello_data_length);
        size_t offset = client_hello_data_length;

        // Copy nonce value
        memcpy(sig_data + offset, server_nonce_tlv->val, server_nonce_tlv->length);
        offset += server_nonce_tlv->length;

        // Copy certificate value
        memcpy(sig_data + offset, certificate_tlv->val, certificate_tlv->length);
        offset += certificate_tlv->length;

        // Copy ephemeral public key value
        memcpy(sig_data + offset, server_ephemeral_key_tlv->val, server_ephemeral_key_tlv->length);
        offset += server_ephemeral_key_tlv->length;

        // Actual length of combined data
        sig_data_len = offset;

        // Verify handshake signature
        if (!verify(handshake_sig_tlv->val, handshake_sig_tlv->length, sig_data, sig_data_len,
                    ec_peer_public_key)) {
            free(sig_data);
            free_tlv(server_hello_tlv);
            exit(3); // Bad signature
        }
        free(sig_data);

        // Save server's ephemeral public key and derive shared secret
        load_peer_public_key(server_ephemeral_key_tlv->val, server_ephemeral_key_tlv->length);
        derive_secret();

        // Save data needed for key derivation
        uint8_t *combined_hello = malloc(client_hello_data_length + server_hello_data_length);
        if (!combined_hello) {
            free_tlv(server_hello_tlv);
            exit(EXIT_FAILURE);
        }
        memcpy(combined_hello, client_hello_data, client_hello_data_length);
        memcpy(combined_hello + client_hello_data_length, server_hello_data, server_hello_data_length);

        // Derive encryption and MAC keys
        derive_keys(combined_hello, client_hello_data_length + server_hello_data_length);

        free(combined_hello);
        free_tlv(server_hello_tlv);

        // Move to finished phase
        phase = 2;
    }
    else if (__type == SERVER && phase == 2) {
        // If server, and in finished phase
        tlv *finished_tlv = deserialize_tlv(buf, length);
        if (!finished_tlv) {
            exit(6); // Unexpected message
        }

        // Generate own HMAC digest
        uint8_t *combined_hello = malloc(client_hello_data_length + server_hello_data_length);
        if (!combined_hello) {
            free_tlv(finished_tlv);
            exit(EXIT_FAILURE);
        }
        memcpy(combined_hello, client_hello_data, client_hello_data_length);
        memcpy(combined_hello + client_hello_data_length, server_hello_data, server_hello_data_length);

        uint8_t transcript[MAC_SIZE];
        hmac(transcript, combined_hello, client_hello_data_length + server_hello_data_length);

        // Verify the received HMAC digest
        tlv *transcript_tlv = get_tlv(finished_tlv, TRANSCRIPT);
        if (!transcript_tlv) {
            free(combined_hello);
            free_tlv(finished_tlv);
            exit(6); // Unexpected message
        }

        if (transcript_tlv->length != MAC_SIZE || 
            memcmp(transcript_tlv->val, transcript, MAC_SIZE) != 0) {
            free(combined_hello);
            free_tlv(finished_tlv);
            exit(4); // Bad HMAC
        }
        
        // Cleanup memory
        free(combined_hello);
        free_tlv(finished_tlv);

        // Move to data phase
        phase = 3;
    }
    else if (phase == 3) {
        // TODO: Implement data decryption
        // For now, just output the raw data
    }

    // decrypt first
    output_io(buf, length);
}

// Generate a client hello TLV and return it
tlv *generate_client_hello() {
    // Create CLIENT_HELLO container
    tlv *client_hello_tlv = create_tlv(CLIENT_HELLO);

    // Create and add NONCE
    tlv *nonce_tlv = create_tlv(NONCE);
    uint8_t nonce[NONCE_SIZE];
    generate_nonce(nonce, NONCE_SIZE);
    add_val(nonce_tlv, nonce, NONCE_SIZE);
    add_tlv(client_hello_tlv, nonce_tlv);

    // Generate keys and add PUBLIC_KEY
    generate_private_key();
    derive_public_key();

    tlv *public_key_tlv = create_tlv(PUBLIC_KEY);
    add_val(public_key_tlv, public_key, pub_key_size);
    add_tlv(client_hello_tlv, public_key_tlv);

    return client_hello_tlv;
}

//  Generate a server hello tlv and return it
tlv *generate_server_hello() {
    tlv *server_hello_tlv = create_tlv(SERVER_HELLO);

    // Create and add NONCE
    tlv *nonce_tlv = create_tlv(NONCE);
    uint8_t nonce[NONCE_SIZE];
    generate_nonce(nonce, NONCE_SIZE);
    add_val(nonce_tlv, nonce, NONCE_SIZE);
    add_tlv(server_hello_tlv, nonce_tlv);

    // Add the certificate
    load_certificate("server_cert.bin");
    tlv *certificate_tlv = create_tlv(CERTIFICATE);
    add_val(certificate_tlv, certificate, cert_size);
    add_tlv(server_hello_tlv, certificate_tlv);

    // Generate a server (emphemeral) public key, note: this is different from the public key in the
    // certificate
    generate_private_key();
    EVP_PKEY *server_ephemeral_public_key = get_private_key();
    derive_public_key();

    // Pack public key into TLV
    tlv *public_key_tlv = create_tlv(PUBLIC_KEY);
    add_val(public_key_tlv, public_key, pub_key_size);
    add_tlv(server_hello_tlv, public_key_tlv);

    // Sign over the client hello data, Nonce, certificate, and (ephemeral) public key data
    load_private_key("server_key.bin");

    // Create signature
    uint8_t *handshake_signature_data =
        (uint8_t *) malloc(client_hello_data_length + NONCE_SIZE + cert_size + pub_key_size);
    
    memcpy(handshake_signature_data, client_hello_data, client_hello_data_length);
    memcpy(handshake_signature_data + client_hello_data_length, nonce, NONCE_SIZE);
    memcpy(handshake_signature_data + client_hello_data_length + NONCE_SIZE, certificate, cert_size);
    memcpy(handshake_signature_data + client_hello_data_length + NONCE_SIZE + cert_size, public_key,
           pub_key_size);

    uint8_t handshake_signature[SIGNATURE_MAX_SIZE];
    size_t signature_size = sign(handshake_signature, handshake_signature_data,
         client_hello_data_length + NONCE_SIZE + cert_size + pub_key_size);

    tlv *handshake_signature_tlv = create_tlv(HANDSHAKE_SIGNATURE);
    add_val(handshake_signature_tlv, handshake_signature, signature_size);
    add_tlv(server_hello_tlv, handshake_signature_tlv);

    // restore the ephemeral key
    set_private_key(server_ephemeral_public_key);

    free(handshake_signature_data);

    return server_hello_tlv;
}

tlv *generate_finished() {
    tlv *finished_tlv = create_tlv(FINISHED);

    uint8_t client_server_hello_combined[client_hello_data_length + server_hello_data_length];
    memcpy(client_server_hello_combined, client_hello_data, client_hello_data_length);
    memcpy(client_server_hello_combined + client_hello_data_length, server_hello_data,
           server_hello_data_length);

    uint8_t transcript[MAC_SIZE];

    hmac(transcript, client_server_hello_combined,
         client_hello_data_length + server_hello_data_length);

    tlv *transcript_tlv = create_tlv(TRANSCRIPT);
    add_val(transcript_tlv, transcript, MAC_SIZE);

    add_tlv(finished_tlv, transcript_tlv);

    return finished_tlv;
}

