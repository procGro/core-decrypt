#include <stdio.h>
#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <cmath>
#include <algorithm>

#include "core-decrypt.h"

const unsigned int MAIN_ALPHABET_SIZE = 26;


std::vector<unsigned int> parse_words(std::string s)
{
    if(s.length() % 8 != 0) {
        int count = 8 - s.length() % 8;
        for(int i = 0; i < count; i++) {
            s = "0" + s;
        }
    }
    std::vector<unsigned int> words;
    for(size_t i = 0; i < s.length(); i+=8) { // Use size_t
        unsigned int word = 0;
        sscanf(s.substr(i, 8).c_str(), "%8x", &word);
        words.push_back(word);
    }
    return words;
}

std::vector<unsigned char> parse_bytes(std::string s)
{
    if(s.length() % 2 != 0) {
        s = "0" + s;
    }
    std::vector<unsigned char> bytes;
    for(size_t i = 0; i < s.length(); i += 2) { // Use size_t
        unsigned int byte_val = 0;
        sscanf(s.substr(i, 2).c_str(), "%2x", &byte_val);
        bytes.push_back((unsigned char)byte_val);
    }
    return bytes;
}

bool is_hex(const std::string &s)
{
    for(size_t i = 0; i < s.length(); i++) {
        char c = s[i];
        if(!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F')) {
            return false;
        }
    }
    return true;
}

bool parse_encrypted_key(const std::string &s, unsigned int iv[4], unsigned int ct[4], unsigned char salt[8], unsigned int *iterations)
{
    if(s.length() != 88 || !is_hex(s)) {
        std::cerr << "Invalid encrypted key: expected 88 hex characters" << std::endl;
        return false;
    }
    std::vector<unsigned int> words_iv = parse_words(s.substr(0, 32));
    std::memcpy(iv, words_iv.data(), 16);
    std::vector<unsigned int> words_ct = parse_words(s.substr(32, 32));
    std::memcpy(ct, words_ct.data(), 16);
    std::vector<unsigned char> bytes_salt = parse_bytes(s.substr(64, 16));
    std::memcpy(salt, bytes_salt.data(), 8);
    std::vector<unsigned int> words_iter = parse_words(s.substr(80, 8));
    *iterations = words_iter[0];
    return true;
}

void list_device(const struct device_info &device)
{
    std::cout << "ID:         " << device.logical_id << std::endl;
    std::cout << "Name:       " << device.name << std::endl;
    std::cout << "Memory:     " << (device.memory / (1024 * 1024)) << "MB" << std::endl;
    std::cout << "Processors: " << device.cores << std::endl;
    std::cout << "Clock:      " << device.clock_frequency << "MHz" << std::endl;
}

void list_devices(const std::vector<struct device_info> &devices)
{
    for(size_t i = 0; i < devices.size(); i++) {
        list_device(devices[i]);
        if(i < devices.size() - 1) {
            std::cout << std::endl;
        }
    }
}

bool parse_int(const std::string &s, int *x)
{
    if (s.empty()) return false;
    for (char c : s) {
        if (!isdigit(c) && !(c == '-' && &c == &s[0])) return false;
    }
    if(sscanf(s.c_str(), "%d", x) != 1) {
        return false;
    }
    return true;
}

bool parse_uint64(const std::string &s, uint64_t *x)
{
    if (s.empty()) return false;
    for (char c : s) {
        if (!isdigit(c)) return false;
    }
    if(sscanf(s.c_str(), "%llu", x) != 1) {
        return false;
    }
    return true;
}

void parse_dictionaries(const std::vector<std::string> &input_files, std::vector<std::string> &files, std::vector<int> &format)
{
    files.clear();
    format.clear();
    for(size_t i = 0; i < input_files.size(); i++) {
        bool exists = false;
        for(size_t j = 0; j < files.size(); j++) {
            if(files[j] == input_files[i]) {
                exists = true;
                break;
            }
        }
        if(!exists) {
            files.push_back(input_files[i]);
        }
    }
    for(size_t i = 0; i < input_files.size(); i++) {
        for(size_t j = 0; j < files.size(); j++) {
            if(input_files[i] == files[j]) {
                format.push_back(j);
                break;
            }
        }
    }
}

void usage()
{
    std::cout << "Usage: btcdecrypt [OPTIONS] ENCRYPTED_KEY [MODE_ARGS]" << std::endl;
    std::cout << std::endl;
    std::cout << "Global Options:" << std::endl;
    std::cout << "  --list-devices          List available OpenCL devices and exit." << std::endl;
    std::cout << "  --device DEVICE_ID      Specify OpenCL device ID to use (default: 0)." << std::endl;
    std::cout << "                          (Note: For brute-force mode, device selection might be limited by implementation)." << std::endl;
    std::cout << "  --start START_INDEX     Specify global start index for search space (default: 0)." << std::endl;
    std::cout << "  --mode MODE             Attack mode: 'dictionary' or 'bruteforce' (default: dictionary)." << std::endl;
    std::cout << std::endl;
    std::cout << "Dictionary Mode (--mode dictionary):" << std::endl;
    std::cout << "  ENCRYPTED_KEY WORDLIST1 [WORDLIST2 ...]" << std::endl;
    std::cout << "  At least one WORDLIST is required." << std::endl;
    std::cout << std::endl;
    std::cout << "Brute-Force Mode (--mode bruteforce):" << std::endl;
    std::cout << "  ENCRYPTED_KEY --length PASS_LENGTH" << std::endl;
    std::cout << "  --length PASS_LENGTH    Specify password length for brute-force (e.g., 1-12)." << std::endl;
    std::cout << std::endl;
}

enum class AttackMode {
    DICTIONARY,
    BRUTEFORCE
};

int main(int argc, char **argv)
{
    std::vector<std::string> args;
    for(int i = 1; i < argc; i++) {
        args.push_back(std::string(argv[i]));
    }

    int selected_device_idx = 0;
    unsigned char salt[8];
    unsigned int ct[4];
    unsigned int iv[4];
    unsigned int iterations = 0;
    uint64_t cli_start_index = 0;

    AttackMode attack_mode = AttackMode::DICTIONARY;
    int bruteforce_password_len = 0;

    std::vector<struct device_info> devices = get_devices();
    if(devices.empty()) {
        std::cerr << "No OpenCL devices found. Exiting." << std::endl;
        return 1;
    }

    for(size_t i = 0; i < args.size(); ++i) {
        if(args[i] == "--list-devices") {
            list_devices(devices);
            return 0;
        }
    }

    std::vector<std::string> positional_operands;
    for(size_t i = 0; i < args.size(); ++i) {
        std::string arg = args[i];
        std::string prefix = arg + ": ";

        if(arg == "--device") {
            if(args.size() <= i + 1 || !parse_int(args[i + 1], &selected_device_idx) || selected_device_idx < 0 || (size_t)selected_device_idx >= devices.size()) {
                std::cerr << prefix << "invalid or missing DEVICE_ID." << std::endl;
                usage(); return 1;
            }
            i++;
        } else if(arg == "--start") {
            if(args.size() <= i + 1 || !parse_uint64(args[i + 1], &cli_start_index)) {
                std::cerr << prefix << "invalid or missing START_INDEX." << std::endl;
                usage(); return 1;
            }
            i++;
        } else if(arg == "--mode") {
            if(args.size() <= i + 1) { std::cerr << prefix << "argument required (dictionary or bruteforce)." << std::endl; usage(); return 1; }
            std::string mode_str = args[++i];
            if(mode_str == "dictionary") attack_mode = AttackMode::DICTIONARY;
            else if(mode_str == "bruteforce") attack_mode = AttackMode::BRUTEFORCE;
            else { std::cerr << prefix << "invalid mode '" << mode_str << "'. Use 'dictionary' or 'bruteforce'." << std::endl; usage(); return 1; }
        } else if(arg == "--length") {
            if(args.size() <= i + 1 || !parse_int(args[i + 1], &bruteforce_password_len)) {
                std::cerr << prefix << "invalid or missing PASS_LENGTH for brute-force mode." << std::endl;
                usage(); return 1;
            }
            i++;
        } else {
            positional_operands.push_back(arg);
        }
    }

    if(positional_operands.empty()) {
        std::cerr << "Error: Encrypted key is required." << std::endl;
        usage(); return 1;
    }

    if(!parse_encrypted_key(positional_operands[0], iv, ct, salt, &iterations)) {
        return 1;
    }

    std::cout << "KDF Iterations: " << iterations << std::endl;
    if (cli_start_index > 0) {
        std::cout << "Starting search from index: " << cli_start_index << std::endl;
    }

    if (attack_mode == AttackMode::DICTIONARY) {
        std::cout << "Mode: Dictionary Attack" << std::endl;
        std::cout << "Using device ID " << selected_device_idx << ": " << devices[selected_device_idx].name << std::endl;
        if(positional_operands.size() < 2) {
            std::cerr << "Error: Dictionary files required for dictionary mode." << std::endl;
            usage(); return 1;
        }
        std::vector<std::string> dictionary_files_unique;
        std::vector<int> dictionary_format_indices;
        std::vector<std::string> dict_files_from_cli(positional_operands.begin() + 1, positional_operands.end());
        parse_dictionaries(dict_files_from_cli, dictionary_files_unique, dictionary_format_indices);

        std::cout << "Loading dictionary... ";
        try {
            PasswordDictionary dict_obj(dictionary_files_unique, dictionary_format_indices);
            std::cout << "Done." << std::endl;
            std::cout << "Dictionary contains " << dict_obj.get_size() << " combinations." << std::endl;
            dictionary_cl(devices[selected_device_idx], dict_obj, ct, iv, salt, iterations, cli_start_index, 1, 1000);
        } catch(const std::string& err_msg) {
            std::cerr << "Error initializing dictionary: " << err_msg << std::endl;
            return 1;
        } catch(const std::exception& e) {
             std::cerr << "Standard exception during dictionary processing: " << e.what() << std::endl;
            return 1;
        }

    } else if (attack_mode == AttackMode::BRUTEFORCE) {
        std::cout << "Mode: Brute-Force Attack" << std::endl;
        // Note: brute_force_cl will internally select a device (likely device 0) due to header constraint workaround.
        // The selected_device_idx from command line is effectively ignored for brute-force.
        if (bruteforce_password_len <= 0) {
            std::cerr << "Error: Password length (--length) must be a positive integer for brute-force mode." << std::endl;
            usage(); return 1;
        }
        if (bruteforce_password_len > 12) {
            std::cerr << "Warning: Password length " << bruteforce_password_len << " might be too large for practical brute-force." << std::endl;
        }
        if (positional_operands.size() > 1) {
            std::cerr << "Warning: Extra positional arguments found for brute-force mode (expected only encrypted key)." << std::endl;
        }

        std::cout << "Password length for brute-force: " << bruteforce_password_len << std::endl;

        uint64_t bf_search_space_end = 1;
        if (MAIN_ALPHABET_SIZE > 0) {
            for(int k=0; k<bruteforce_password_len; ++k) {
                 if (UINT64_MAX / MAIN_ALPHABET_SIZE < bf_search_space_end) {
                    bf_search_space_end = UINT64_MAX; break;
                }
                bf_search_space_end *= MAIN_ALPHABET_SIZE;
            }
        } else if (bruteforce_password_len > 0) {
             std::cerr << "Error: Cannot perform brute-force with empty alphabet and positive length." << std::endl;
             return 1;
        }

        uint64_t bf_stride = 1;

        // Call brute_force_cl with its original signature (matching core-decrypt.h)
        // The device selection happens inside brute_force_cl (hardcoded to device 0 as a workaround)
        brute_force_cl(bruteforce_password_len, ct, iv, salt, iterations, cli_start_index, bf_search_space_end, bf_stride);

    } else {
        std::cerr << "Error: Unknown attack mode selected." << std::endl;
        return 1;
    }

    return 0;
}
