#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include "security.h"
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


        uint8_t *input_buf = malloc(max_length);

        const ssize_t MAX_PLAINTEXT_LENGTH = ((max_length - 60) / 16) * 16 - 1;
        // let's just assume it's -60, and we aren't transmitting a ciphertext so small that the length fits in 1 byte instead of 2

        ssize_t input_len = input_io(input_buf, MAX_PLAINTEXT_LENGTH);


        uint8_t* iv_buf = malloc(IV_SIZE);
        uint8_t* ciphertext_buf = malloc(max_length); // idk what size this should be. 1024?

        ssize_t ciphertext_len = encrypt_data(iv_buf, ciphertext_buf, input_buf, input_len);

        // Create IV TLV
        tlv* IV_tlv = create_tlv(IV);
        add_val(IV_tlv, iv_buf, IV_SIZE);

        // Create Ciphertext TLV
        tlv* ciphertext_tlv = create_tlv(CIPHERTEXT);
        add_val(ciphertext_tlv, ciphertext_buf, ciphertext_len);

        uint8_t* hmac_digest = malloc(MAC_SIZE);

        hmac_iv_ciphertext(hmac_digest, IV_tlv, ciphertext_tlv);

        // Create HMAC TLV
        tlv* MAC_tlv = create_tlv(MAC);
        add_val(MAC_tlv, hmac_digest, MAC_SIZE);

        // Create Data TLV
        tlv* data_tlv = create_tlv(DATA);
        add_tlv(data_tlv, IV_tlv);
        add_tlv(data_tlv, ciphertext_tlv);
        add_tlv(data_tlv, MAC_tlv);



        // Copy Data TLV to output
        uint8_t* data_tlv_buf = malloc(max_length);
        size_t data_length = serialize_tlv(data_tlv, data_tlv_buf);
        memcpy(buf, data_tlv_buf, data_length);


        free(input_buf);
        free(iv_buf);
        free(ciphertext_buf);

        free(hmac_digest);
        free(data_tlv_buf);
        

        return data_length;
    }

    return 0;
}


void output_sec(uint8_t *buf, size_t length) {
    if (__type == SERVER && phase == 0) {
        // If server, and in client hello phase
        tlv *client_hello_tlv = deserialize_tlv(buf, length);
        if (!client_hello_tlv) {
            exit(UNEXPECTED_MESSAGE);
        }

        // Save client hello data
        memcpy(client_hello_data, buf, length);
        client_hello_data_length = length;

        // Get client's public key
        tlv *public_key_tlv = get_tlv(client_hello_tlv, PUBLIC_KEY);
        if (!public_key_tlv) {
            free_tlv(client_hello_tlv);
            exit(UNEXPECTED_MESSAGE);
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
            fprintf(stderr, "Error: no server hello");
            exit(UNEXPECTED_MESSAGE);
        }

        // Save server hello data for later verification
        server_hello_data_length = length;
        memcpy(server_hello_data, buf, server_hello_data_length);

        // Get the certificate from the server hello
        tlv *certificate_tlv = get_tlv(server_hello_tlv, CERTIFICATE);
        if (!certificate_tlv) {
            free_tlv(server_hello_tlv);
            fprintf(stderr, "Error: no certificate");
            exit(UNEXPECTED_MESSAGE);
        }

        // Extract DNS name and public key from certificate
        tlv *dns_name_tlv = get_tlv(certificate_tlv, DNS_NAME);
        tlv *cert_pubkey_tlv = get_tlv(certificate_tlv, PUBLIC_KEY);
        tlv *cert_sig_tlv = get_tlv(certificate_tlv, SIGNATURE);

        if (!dns_name_tlv || !cert_pubkey_tlv || !cert_sig_tlv) {
            free_tlv(server_hello_tlv);
            fprintf(stderr, "Error: certificate missing field");
            exit(UNEXPECTED_MESSAGE);
        }

        // Load CA public key
        load_ca_public_key("ca_public_key.bin");

        // Verify the certificate's signature
        // The data to verify is the DNS name and public key concatenated
        // Allocate sufficient buffer for the data
        uint8_t *cert_data = malloc(dns_name_tlv->length + cert_pubkey_tlv->length + (2*4));
        if (!cert_data) {
            free_tlv(server_hello_tlv);
            exit(EXIT_FAILURE); // Memory allocation failure
        }

        // Copy the actual values 
        int cert_data_len = 0;
        cert_data_len += serialize_tlv(cert_data, dns_name_tlv);
        cert_data_len += serialize_tlv(cert_data + cert_data_len, cert_pubkey_tlv);

        if (!verify(cert_sig_tlv->val, cert_sig_tlv->length, cert_data, cert_data_len,
                    ec_ca_public_key)) {
            free(cert_data);
            free_tlv(server_hello_tlv);
            fprintf(stderr, "Error: certificate verification failed");
            exit(BAD_CERTIFICATE);
        }
        free(cert_data);

        // Verify DNS name matches expected host
        // The tlv length counts the null byte in the name
        if (dns_name_tlv->length != (strlen(__host) + 1) ||
            strcmp(dns_name_tlv->val, __host) != 0) {
            free_tlv(server_hello_tlv);
            fprintf(stderr, "Error: dns did not match");
            exit(BAD_DNS);
        }

        // Get server's handshake signature
        tlv *handshake_sig_tlv = get_tlv(server_hello_tlv, HANDSHAKE_SIGNATURE);
        if (!handshake_sig_tlv) {
            free_tlv(server_hello_tlv);
            fprintf(stderr, "Error: no signature on server hello");
            exit(UNEXPECTED_MESSAGE);
        }

        // Load server's public key from certificate to verify handshake signature
        load_peer_public_key(cert_pubkey_tlv->val, cert_pubkey_tlv->length);

        // Create data to verify signature: Client Hello + Server Hello components
        // Get the server nonce and ephemeral public key
        tlv *server_nonce_tlv = get_tlv(server_hello_tlv, NONCE);
        tlv *server_ephemeral_key_tlv = get_tlv(server_hello_tlv, PUBLIC_KEY);

        if (!server_nonce_tlv || !server_ephemeral_key_tlv) {
            free_tlv(server_hello_tlv);
            fprintf(stderr, "Error: server hello missing fields");
            exit(UNEXPECTED_MESSAGE);
        }

        // Allocate buffer for the handshake signature verification data
        size_t sig_data_len = 0;
        uint8_t *sig_data = malloc(client_hello_data_length + server_hello_data_length);
        if (!sig_data) {
            free_tlv(server_hello_tlv);
            exit(EXIT_FAILURE);
        }

        // Combine all data for signature verification
        // Copy client hello data
        memcpy(sig_data, client_hello_data, client_hello_data_length);
        sig_data_len += client_hello_data_length;

        // Copy nonce value
        sig_data_len += serialize_tlv(sig_data + sig_data_len, server_nonce_tlv);

        // Copy certificate value
        sig_data_len += serialize_tlv(sig_data + sig_data_len, certificate_tlv);

        // Copy ephemeral public key value
        sig_data_len += serialize_tlv(sig_data + sig_data_len, server_ephemeral_key_tlv);

        // Verify handshake signature
        if (!verify(handshake_sig_tlv->val, handshake_sig_tlv->length, sig_data, sig_data_len,
                    ec_peer_public_key)) {
            free(sig_data);
            free_tlv(server_hello_tlv);
            fprintf(stderr, "Error: invalid signature on server hello");
            exit(BAD_SIGNATURE);
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
            exit(UNEXPECTED_MESSAGE); // Unexpected message
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
            exit(UNEXPECTED_MESSAGE);
        }

        if (transcript_tlv->length != MAC_SIZE || 
            memcmp(transcript_tlv->val, transcript, MAC_SIZE) != 0) {
            free(combined_hello);
            free_tlv(finished_tlv);
            exit(BAD_MAC);
        }
        
        // Cleanup memory
        free(combined_hello);
        free_tlv(finished_tlv);

        // Move to data phase
        phase = 3;
    }
    else if (phase == 3) {
        
        tlv* data_tlv = deserialize_tlv(buf, length);
        tlv* IV_tlv = get_tlv(data_tlv, IV);
        tlv* ciphertext_tlv = get_tlv(data_tlv, CIPHERTEXT);
        tlv* MAC_tlv = get_tlv(data_tlv, MAC);

        // TODO: check if tlvs are NULL, then exit with proper status code

        uint8_t* calculated_hmac_digest = malloc(MAC_SIZE);
        hmac_iv_ciphertext(calculated_hmac_digest, IV_tlv, ciphertext_tlv);

        if (MAC_tlv->length != MAC_SIZE ||
            memcmp(MAC_tlv->val, calculated_hmac_digest, MAC_SIZE) != 0) {
            
            free(calculated_hmac_digest);
            free_tlv(data_tlv);
            exit(BAD_MAC);
        }

        decrypt_cipher(buf, ciphertext_tlv -> val, ciphertext_tlv->length, IV_tlv->val);


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
    tlv *certificate_tlv = deserialize_tlv(certificate, cert_size);
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
    // Each TLV header adds at most 4 bytes (type is 1, length is either 1 or 3)
    uint8_t *handshake_signature_data =
        (uint8_t *) malloc(client_hello_data_length + NONCE_SIZE + cert_size + pub_key_size + (4*4));
    
    int pos = 0;
    tlv* client_hello_tlv_tmp = deserialize_tlv(client_hello_data, client_hello_data_length);

    pos += serialize_tlv(handshake_signature_data, client_hello_tlv_tmp);
    pos += serialize_tlv(handshake_signature_data + pos, nonce_tlv);
    pos += serialize_tlv(handshake_signature_data + pos, certificate_tlv);
    pos += serialize_tlv(handshake_signature_data + pos, public_key_tlv);

    free_tlv(client_hello_tlv_tmp);

    uint8_t handshake_signature[SIGNATURE_MAX_SIZE];
    size_t signature_size = sign(handshake_signature, handshake_signature_data, pos);

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

// calculates hmac from IV_tlv and ciphertext_tlv, returns it into hmac_digest
void hmac_iv_ciphertext(uint8_t* hmac_digest, tlv* IV_tlv, tlv* ciphertext_tlv) {
    // Smoosh IV + Ciphertext together to calculate HMAC
    uint8_t* IV_tlv_serialized = malloc(IV_SIZE + 2);
    uint8_t* ciphertext_tlv_serialized = malloc(1024); // TODO: fix this hard coding

    size_t IV_tlv_serial_length = serialize_tlv(IV_tlv_serialized, IV_tlv);
    size_t ciphertext_tlv_serial_length = serialize_tlv(ciphertext_tlv_serialized, ciphertext_tlv);
    size_t IV_ciphertext_length = IV_tlv_serial_length + ciphertext_tlv_serial_length;

    uint8_t* IV_plus_ciphertext = malloc(IV_ciphertext_length);
    memcpy(IV_plus_ciphertext, IV_tlv_serialized, IV_tlv_serial_length);
    memcpy(IV_plus_ciphertext + IV_tlv_serial_length, ciphertext_tlv_serialized, ciphertext_tlv_serial_length);

    // Calculate HMAC from IV + Ciphertext (serialized versions)
    hmac(hmac_digest, IV_plus_ciphertext, IV_ciphertext_length);

    free(IV_tlv_serialized);
    free(ciphertext_tlv_serialized);
    free(IV_plus_ciphertext);
}