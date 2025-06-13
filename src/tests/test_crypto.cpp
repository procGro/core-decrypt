#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <cstring> // For std::memcpy, std::memcmp
#include <iomanip> // For std::hex, std::setw, std::setfill

#include "../core-decrypt.h"
#include "../util.h"

// Helper to print byte arrays for debugging
void print_hex_ulong_array(const char* label, const ulong* data, size_t num_ulongs) {
    std::cout << label << ": ";
    for (size_t i = 0; i < num_ulongs; ++i) {
        std::cout << std::hex << std::setw(16) << std::setfill('0') << data[i] << " ";
    }
    std::cout << std::dec << std::endl;
}

void test_password_kdf() {
    std::cout << "Running test_password_kdf..." << std::endl;
    const char* password = "test_password";
    unsigned char salt[8];
    for(int i=0; i<8; ++i) salt[i] = (unsigned char)i;
    unsigned int iterations = 10;

    unsigned int derived_key[8];

    password_kdf(password, strlen(password), iterations, salt, derived_key);

    bool key_is_nonzero = false;
    for(int i=0; i<8; ++i) {
        if (derived_key[i] != 0) {
            key_is_nonzero = true;
            break;
        }
    }
    assert(key_is_nonzero);

    unsigned int derived_key2[8];
    password_kdf(password, strlen(password), iterations, salt, derived_key2);
    assert(std::memcmp(derived_key, derived_key2, sizeof(derived_key)) == 0);

    std::cout << "test_password_kdf PASSED (non-zero and determinism check)" << std::endl;
}

void test_aes_decrypt() {
    std::cout << "Running test_aes_decrypt..." << std::endl;
    unsigned int key[8];
    unsigned int iv[4];

    for(int i=0; i<8; ++i) key[i] = 0x01020304 + i*0x01010101;
    for(int i=0; i<4; ++i) iv[i]  = 0x05060708 + i*0x01010101;

    unsigned int ciphertext[4] = { 0xAABBCCDD, 0xEEFF0011, 0x22334455, 0x66778899 };
    unsigned int decrypted_pt1[4];
    unsigned int decrypted_pt2[4];

    aes256_cbc_decrypt(key, iv, ciphertext, decrypted_pt1);
    aes256_cbc_decrypt(key, iv, ciphertext, decrypted_pt2);

    assert(std::memcmp(decrypted_pt1, decrypted_pt2, sizeof(decrypted_pt1)) == 0);

    std::cout << "test_aes_decrypt PASSED (basic determinism check)" << std::endl;
}

void test_sha512_iterations() {
    std::cout << "Running test_sha512_iterations..." << std::endl;

    // Initial message block (needs to be 16 ulongs for sha512_iterations's first internal sha512(w) call)
    // Let's use a simple message "abc", correctly padded.
    // "abc" = 0x616263. Length is 3 bytes = 24 bits.
    // Padded message: 0x6162638000000000...0000000000000018 (length in bits at the end)
    ulong initial_msg_block[16] = {0};
    initial_msg_block[0] = 0x6162638000000000ULL; // "abc" + padding byte
    // ... rest are 0 until the length ...
    initial_msg_block[15] = 24; // length in bits

    const unsigned int N_ITERATIONS = 3;

    ulong state_path1_final[8]; // Will hold H^N(M)
    ulong state_path2_step1[8]; // Will hold H(M)
    ulong state_path2_final[8]; // Will hold H^(N-1) (H(M))

    // Path 1: N_ITERATIONS iterations directly
    // sha512_iterations expects msg to be a 16-element ulong array.
    sha512_iterations(initial_msg_block, state_path1_final, N_ITERATIONS);

    // Path 2: 1 iteration, then N_ITERATIONS - 1 iterations
    sha512_iterations(initial_msg_block, state_path2_step1, 1);

    // Now, prepare the output of the first iteration (state_path2_step1, which is 8 ulongs)
    // as a new 16-ulong message block for the next call to sha512_iterations.
    // This new message is the 512-bit hash, so it needs padding.
    ulong intermediate_hash_as_msg_block[16] = {0};
    memcpy(intermediate_hash_as_msg_block, state_path2_step1, 8 * sizeof(uint64_t)); // Copy the 8 ulongs hash
    intermediate_hash_as_msg_block[8] = 0x8000000000000000ULL; // Padding byte (message is 8*8=64 bytes = 512 bits)
    intermediate_hash_as_msg_block[15] = 512; // Length of the message (the hash) is 512 bits

    if (N_ITERATIONS > 1) {
        sha512_iterations(intermediate_hash_as_msg_block, state_path2_final, N_ITERATIONS - 1);
    } else { // If N_ITERATIONS was 1, then state_path2_final is just state_path2_step1
        memcpy(state_path2_final, state_path2_step1, sizeof(state_path2_step1));
    }

    if (std::memcmp(state_path1_final, state_path2_final, sizeof(state_path1_final)) != 0) {
        std::cout << "SHA512 Iteration Test FAILED:" << std::endl;
        print_hex_ulong_array("Initial Msg Block (Padded 'abc')", initial_msg_block, 16);
        print_hex_ulong_array("Path1 Final (Iter N)", state_path1_final, 8);
        print_hex_ulong_array("Path2 Step1 (Iter 1)", state_path2_step1, 8);
        print_hex_ulong_array("Path2 Intermediate Msg Block (Padded H(M))", intermediate_hash_as_msg_block, 16);
        print_hex_ulong_array("Path2 Final (Iter N-1 on H(M))", state_path2_final, 8);
    }
    assert(std::memcmp(state_path1_final, state_path2_final, sizeof(state_path1_final)) == 0);

    std::cout << "test_sha512_iterations PASSED" << std::endl;
}


int main() {
    test_password_kdf();
    test_aes_decrypt();
    test_sha512_iterations();

    std::cout << "\nAll crypto tests PASSED!" << std::endl;
    return 0;
}
