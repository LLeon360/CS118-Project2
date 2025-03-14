#pragma once

#include <stdint.h>
#include <unistd.h>

// Error statuses
#define BAD_CERTIFICATE 1
#define BAD_DNS 2
#define BAD_SIGNATURE 3
#define BAD_TRANSCRIPT 4
#define BAD_MAC 5
#define UNEXPECTED_MESSAGE 6

// Initialize security layer
void init_sec(int type, char* host);

// Get input from security layer
ssize_t input_sec(uint8_t* buf, size_t max_length);

// Output to security layer
void output_sec(uint8_t* buf, size_t length);
