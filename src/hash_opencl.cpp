#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <stdint.h>
#include <stdio.h>
#include <algorithm> // For std::min/max
#include <cmath>     // For pow
#include <CL/cl.h>

#include "cl_util.h"
#include "util.h"

#include "core-decrypt.h"

// Defined in core-decrypt_cl.cpp
extern char _core_decrypt_cl[];

std::string _kernelSource;

const std::string _alphabet = "abcdefghijklmnopqrstuvwxyz";
unsigned int _alphabet_size = (unsigned int)_alphabet.length();

// Forward declaration for do_brute_force (keeps its enhanced signature)
static void do_brute_force(struct device_info &device, int password_len, unsigned int encrypted_block[4], unsigned int iv[4], unsigned char salt[8], unsigned int iterations, uint64_t start_param, uint64_t end_param, uint64_t stride_param);

namespace { // Anonymous namespace for helper not part of a class
    std::string gen_password_from_index(uint64_t idx, int len, const std::string& alphabet_str) {
        if (alphabet_str.empty()) {
            if (len == 0 && idx == 0) return "";
            return "Error: Empty Alphabet";
        }
        if (len == 0) {
            return (idx == 0) ? "" : "Error: Index out of bounds for 0-length password";
        }

        std::string pass_str(len, ' ');
        uint64_t current_val = idx;
        unsigned int alphabet_len = alphabet_str.length();

        uint64_t max_idx_check = 1;
        bool overflow = false;
        for(int k=0; k<len; ++k) {
            if (alphabet_len == 0) {
                 overflow = true; break;
            }
            if (k > 0 && (UINT64_MAX / alphabet_len < max_idx_check)) {
                overflow = true;
                break;
            }
            max_idx_check *= alphabet_len;
        }
        if (max_idx_check == 0 && len > 0) overflow = true;

        if (!overflow && idx >= max_idx_check) {
             return "Error: Index out of bounds for password length";
        }
         if (overflow && idx > 0) {
            if (alphabet_len > 1) return "Error: Index potentially out of bounds due to large alphabet/length";
            if (alphabet_len == 1 && idx != 0) return "Error: Index out of bounds for single-character alphabet";
        }

        for (int i = len - 1; i >= 0; --i) {
            pass_str[i] = alphabet_str[current_val % alphabet_len];
            current_val /= alphabet_len;
        }
        if (current_val > 0 && idx !=0) {
            return "Error: Index too large for password length (remainder check)";
        }
        return pass_str;
    }
} // end anonymous namespace


std::string format(const char *formatStr, double value)
{
    char buf[100] = { 0 };
    sprintf(buf, formatStr, value);
    return std::string(buf);
}

void text_to_file(std::string file_name, std::string text)
{
    std::ofstream f;
    f.open(file_name.c_str());
    f << text;
    f.close();
}

std::string formatSeconds(unsigned int seconds)
{
    char s[128] = { 0 };
    unsigned int days = seconds / 86400;
    unsigned int hours = (seconds % 86400) / 3600;
    unsigned int minutes = (seconds % 3600) / 60;
    unsigned int sec = seconds % 60;

    if(days > 0) {
        sprintf(s, "%d:%02d:%02d:%02d", days, hours, minutes, sec);
    } else {
        sprintf(s, "%02d:%02d:%02d", hours, minutes, sec);
    }
    return std::string(s);
}

void clCall(cl_int err)
{
    if(err != CL_SUCCESS) {
        std::cerr << "OpenCL runtime error: " << getErrorString(err) << std::endl;
        exit(1);
    }
}

void load_kernel_source()
{
    if (_kernelSource.empty()) {
        _kernelSource = std::string(_core_decrypt_cl);
    }
}

std::vector<struct device_info> get_devices()
{
    cl_int err = 0;
    unsigned int num_platforms = 0;
    cl_platform_id platform_ids[10];
    std::vector<struct device_info> devices;

    err = clGetPlatformIDs(0, NULL, &num_platforms);
    if (err != CL_SUCCESS || num_platforms == 0) {
        std::cerr << "No OpenCL platforms found or error getting platform IDs." << std::endl;
        return devices;
    }
    num_platforms = std::min(num_platforms, (unsigned int)10);

    clGetPlatformIDs(num_platforms, platform_ids, NULL);

    for(unsigned int i = 0; i < num_platforms; i++) {
        unsigned int num_platform_devices = 0;
        cl_device_id platform_device_ids[10];

        clGetDeviceIDs(platform_ids[i], CL_DEVICE_TYPE_ALL, 0, NULL, &num_platform_devices);
        if (num_platform_devices == 0) {
            continue;
        }
        num_platform_devices = std::min(num_platform_devices, (unsigned int)10);

        clGetDeviceIDs(platform_ids[i], CL_DEVICE_TYPE_ALL, num_platform_devices, platform_device_ids, NULL);

        for(unsigned int j = 0; j < num_platform_devices; j++) {
            struct device_info d;
            d.logical_id = (int)devices.size();
            d.id = platform_device_ids[j];

            char buf[256] = { 0 };
            size_t name_size;
            clGetDeviceInfo(d.id, CL_DEVICE_NAME, sizeof(buf), buf, &name_size);
            d.name = std::string(buf, name_size > 0 ? name_size -1 : 0);

            clGetDeviceInfo(d.id, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(d.cores), &d.cores, NULL);
            clGetDeviceInfo(d.id, CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(d.clock_frequency), &d.clock_frequency, NULL);
            clGetDeviceInfo(d.id, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(d.memory), &d.memory, NULL);

            devices.push_back(d);
        }
    }
    return devices;
}


void initialize_device_dictionaries(cl_context ctx, cl_command_queue cmd, cl_mem *dev_words, cl_mem *dev_index, cl_mem *dev_offsets, int *password_len, PasswordDictionary &dictionary)
{
    cl_int err;
    std::string& words = dictionary.get_words();
    std::vector<unsigned int>& index = dictionary.get_index();
    std::vector<struct password_offset> offsets = dictionary.get_offsets();

    *dev_words = clCreateBuffer(ctx, CL_MEM_READ_ONLY, words.length(), NULL, &err);
    clCall(err);
    *dev_index = clCreateBuffer(ctx, CL_MEM_READ_ONLY, index.size() * sizeof(unsigned int), NULL, &err);
    clCall(err);
    *dev_offsets = clCreateBuffer(ctx, CL_MEM_READ_ONLY, offsets.size() * sizeof(struct password_offset), NULL, &err);
    clCall(err);
    *password_len = (int)offsets.size();

    clCall(clEnqueueWriteBuffer(cmd, *dev_words, CL_TRUE, 0, words.length(), words.c_str(), 0, NULL, NULL));
    clCall(clEnqueueWriteBuffer(cmd, *dev_index, CL_TRUE, 0, index.size() * sizeof(unsigned int), index.data(), 0, NULL, NULL));
    clCall(clEnqueueWriteBuffer(cmd, *dev_offsets, CL_TRUE, 0, offsets.size() * sizeof(struct password_offset), offsets.data(), 0, NULL, NULL));
}

static void find_best_parameters(const struct device_info &device, cl_context ctx, cl_command_queue cmd, cl_kernel kernel, size_t &global, size_t &local)
{
    unsigned int test_iterations_for_find_best = 2000;
    size_t max_wg_size = 0;
    cl_int err_info = clGetDeviceInfo(device.id, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(size_t), &max_wg_size, NULL);
    if(err_info != CL_SUCCESS || max_wg_size == 0) max_wg_size = 256;

    std::vector<size_t> local_sizes_to_test;
    for(size_t ls_val = 32; ls_val <= max_wg_size && ls_val <= 1024; ls_val *= 2) {
        local_sizes_to_test.push_back(ls_val);
    }
    if (local_sizes_to_test.empty()){
        local_sizes_to_test.push_back(std::min((size_t)64, max_wg_size > 0 ? max_wg_size : (size_t)64));
    }

    unsigned int highest_speed = 0;
    size_t best_local_size = local_sizes_to_test[0];

    std::cout << "Finding optimal kernel parameters for " << device.name
              << " (Device Cores: " << device.cores << ", Max WG Size: " << max_wg_size << ")" << std::endl;

    for(size_t current_local_size_test : local_sizes_to_test) {
        size_t current_global_size_test = current_local_size_test * std::max(1u, device.cores);
        if (current_global_size_test == 0) continue;

        cl_int err_test = 0;
        cl_mem dev_hashes_test_buf = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(uint64_t) * 8 * current_global_size_test, NULL, &err_test);
        if(err_test != CL_SUCCESS) {
            std::cerr << "find_best_parameters: Failed to create test buffer for local size " << current_local_size_test << ", Error: " << getErrorString(err_test) << std::endl;
            continue;
        }

        uint64_t time_start_test = getSystemTime();

        err_test = clSetKernelArg(kernel, 0, sizeof(cl_mem), &dev_hashes_test_buf);
        if (err_test != CL_SUCCESS) { clReleaseMemObject(dev_hashes_test_buf); std::cerr << "find_best_parameters: clSetKernelArg 0 failed. Error: " << getErrorString(err_test) << std::endl; continue; }

        err_test = clSetKernelArg(kernel, 1, sizeof(unsigned int), &test_iterations_for_find_best);
        if (err_test != CL_SUCCESS) { clReleaseMemObject(dev_hashes_test_buf); std::cerr << "find_best_parameters: clSetKernelArg 1 failed. Error: " << getErrorString(err_test) << std::endl; continue; }

        err_test = clEnqueueNDRangeKernel(cmd, kernel, 1, NULL, &current_global_size_test, &current_local_size_test, 0, NULL, NULL);
        if (err_test != CL_SUCCESS) { clReleaseMemObject(dev_hashes_test_buf); std::cerr << "find_best_parameters: clEnqueueNDRangeKernel failed. Error: " << getErrorString(err_test) << std::endl; continue; }

        err_test = clFinish(cmd);
        if (err_test != CL_SUCCESS) { clReleaseMemObject(dev_hashes_test_buf); std::cerr << "find_best_parameters: clFinish failed. Error: " << getErrorString(err_test) << std::endl; continue; }

        uint64_t time_end_test = getSystemTime() - time_start_test;
        clReleaseMemObject(dev_hashes_test_buf);

        if (time_end_test == 0) time_end_test = 1;

        unsigned int speed_calc = (unsigned int)(((double)current_global_size_test * test_iterations_for_find_best) / ((double)time_end_test / 1000.0));

        if(speed_calc > highest_speed) {
            highest_speed = speed_calc;
            best_local_size = current_local_size_test;
        }
    }

    local = best_local_size;
    global = local * std::max(1u, device.cores);
    if (global == 0) {
       local = 64; global = local * std::max(1u, device.cores); if (global==0) global=local;
       std::cerr << "Warning: find_best_parameters resulted in 0 global/local size. Using default heuristic." << std::endl;
    }
    std::cout << "Selected optimal params - Global: " << global << ", Local: " << local << ", Highest Speed: " << highest_speed << " H/s" << std::endl;
}

static void do_dictionary(struct device_info &device, PasswordDictionary &dictionary, unsigned int encrypted_block[4], unsigned int iv[4], unsigned char salt[8], unsigned int iterations, uint64_t start, int stride, unsigned int intensity)
{
    cl_mem dev_index = 0, dev_words = 0, dev_offsets = 0, dev_hashes = 0;
    cl_mem dev_encrypted_block = 0, dev_iv = 0, dev_salt = 0, dev_result = 0;
    cl_context ctx = 0; cl_command_queue cmd = 0; cl_program prog = 0;
    cl_kernel start_kernel = 0, middle_kernel = 0, end_kernel = 0;
    cl_int err = 0;

    uint64_t dictionary_size = dictionary.get_size();

    ctx = clCreateContext(0, 1, &device.id, NULL, NULL, &err); clCall(err);
    cmd = clCreateCommandQueue(ctx, device.id, 0, &err); clCall(err);

    load_kernel_source();
    size_t kernel_source_len = _kernelSource.length();
    const char *kernel_source_ptr = _kernelSource.c_str();
    prog = clCreateProgramWithSource(ctx, 1, &kernel_source_ptr, &kernel_source_len, &err); clCall(err);

    err = clBuildProgram(prog, 1, &device.id, NULL, NULL, NULL);
    if(err != CL_SUCCESS) {
        char *buffer = NULL; size_t log_len = 0;
        std::cerr << "Error: Failed to build dictionary program! error code " << err << std::endl;
        clGetProgramBuildInfo(prog, device.id, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_len);
        buffer = new char[log_len + 1]; buffer[log_len] = '\0';
        clGetProgramBuildInfo(prog, device.id, CL_PROGRAM_BUILD_LOG, log_len, buffer, NULL);
        std::cerr << "Build Log:\n" << buffer << std::endl;
        delete[] buffer; clCall(err);
    }
    std::cout << "Dictionary kernel program built." << std::endl;

    start_kernel = clCreateKernel(prog, "dictionary_attack", &err); clCall(err);
    middle_kernel = clCreateKernel(prog, "hash_middle", &err); clCall(err);
    end_kernel = clCreateKernel(prog, "hash_end", &err); clCall(err);

    size_t global_ws, local_ws;
    find_best_parameters(device, ctx, cmd, middle_kernel, global_ws, local_ws);

    int num_words_in_dict_segment = 0;
    initialize_device_dictionaries(ctx, cmd, &dev_words, &dev_index, &dev_offsets, &num_words_in_dict_segment, dictionary);

    dev_encrypted_block = clCreateBuffer(ctx, CL_MEM_READ_ONLY, sizeof(unsigned int) * 4, NULL, &err); clCall(err);
    dev_iv = clCreateBuffer(ctx, CL_MEM_READ_ONLY, sizeof(unsigned int) * 4, NULL, &err); clCall(err);
    dev_salt = clCreateBuffer(ctx, CL_MEM_READ_ONLY, 8, NULL, &err); clCall(err);
    dev_hashes = clCreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(uint64_t) * 8 * global_ws, NULL, &err); clCall(err);
    dev_result = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(int), NULL, &err); clCall(err);

    int result_val = -1;
    clCall(clEnqueueWriteBuffer(cmd, dev_encrypted_block, CL_TRUE, 0, sizeof(unsigned int) * 4, encrypted_block, 0, NULL, NULL));
    clCall(clEnqueueWriteBuffer(cmd, dev_iv, CL_TRUE, 0, sizeof(unsigned int) * 4, iv, 0, NULL, NULL));
    clCall(clEnqueueWriteBuffer(cmd, dev_salt, CL_TRUE, 0, 8, salt, 0, NULL, NULL));
    clCall(clEnqueueWriteBuffer(cmd, dev_result, CL_TRUE, 0, sizeof(int), &result_val, 0, NULL, NULL));

    unsigned int s_iter = 1, m_iter = 0, e_iter = 0;
    if (iterations > 1) {
        m_iter = std::min(intensity, iterations -1);
        if (m_iter == 0 && iterations > 1) m_iter = iterations -1;
    }
    unsigned int m_calls = 0;
    if (m_iter > 0) m_calls = (iterations - 1) / m_iter;
    if (iterations > 1) e_iter = (iterations - 1) - (m_calls * m_iter);
    else s_iter = iterations;

    uint64_t time_main_loop_start = getSystemTime();
    uint64_t time_progress_report = getSystemTime();
    uint64_t passwords_done_total = 0;
    uint64_t passwords_done_since_report = 0;

    std::cout << "Running dictionary attack..." << std::endl;

    for(uint64_t current_offset = start; current_offset < dictionary_size; ) {
        clCall(clSetKernelArg(start_kernel, 0, sizeof(cl_mem), &dev_words));
        clCall(clSetKernelArg(start_kernel, 1, sizeof(cl_mem), &dev_index));
        clCall(clSetKernelArg(start_kernel, 2, sizeof(cl_mem), &dev_offsets));
        clCall(clSetKernelArg(start_kernel, 3, sizeof(unsigned int), &num_words_in_dict_segment));
        clCall(clSetKernelArg(start_kernel, 4, sizeof(uint64_t), &dictionary_size));
        clCall(clSetKernelArg(start_kernel, 5, sizeof(unsigned int), &s_iter));
        clCall(clSetKernelArg(start_kernel, 6, sizeof(cl_mem), &dev_salt));
        clCall(clSetKernelArg(start_kernel, 7, sizeof(uint64_t), &current_offset));
        clCall(clSetKernelArg(start_kernel, 8, sizeof(int), &stride));
        clCall(clSetKernelArg(start_kernel, 9, sizeof(cl_mem), &dev_hashes));
        clCall(clEnqueueNDRangeKernel(cmd, start_kernel, 1, NULL, &global_ws, &local_ws, 0, NULL, NULL));
        clCall(clFinish(cmd));

        if (m_calls > 0 && m_iter > 0) {
            for(unsigned int j = 0; j < m_calls; j++) {
                clCall(clSetKernelArg(middle_kernel, 0, sizeof(cl_mem), &dev_hashes));
                clCall(clSetKernelArg(middle_kernel, 1, sizeof(unsigned int), &m_iter));
                clCall(clEnqueueNDRangeKernel(cmd, middle_kernel, 1, NULL, &global_ws, &local_ws, 0, NULL, NULL));
                clCall(clFinish(cmd));
            }
        }
        if (e_iter > 0) {
            clCall(clSetKernelArg(middle_kernel, 0, sizeof(cl_mem), &dev_hashes));
            clCall(clSetKernelArg(middle_kernel, 1, sizeof(unsigned int), &e_iter));
            clCall(clEnqueueNDRangeKernel(cmd, middle_kernel, 1, NULL, &global_ws, &local_ws, 0, NULL, NULL));
            clCall(clFinish(cmd));
        }

        clCall(clSetKernelArg(end_kernel, 0, sizeof(cl_mem), &dev_encrypted_block));
        clCall(clSetKernelArg(end_kernel, 1, sizeof(cl_mem), &dev_iv));
        clCall(clSetKernelArg(end_kernel, 2, sizeof(cl_mem), &dev_hashes));
        clCall(clSetKernelArg(end_kernel, 3, sizeof(unsigned int), &e_iter));
        clCall(clSetKernelArg(end_kernel, 4, sizeof(cl_mem), &dev_result));
        clCall(clEnqueueNDRangeKernel(cmd, end_kernel, 1, NULL, &global_ws, &local_ws, 0, NULL, NULL));
        clCall(clEnqueueReadBuffer(cmd, dev_result, CL_TRUE, 0, sizeof(int), &result_val, 0, NULL, NULL));
        clCall(clFinish(cmd));

        uint64_t num_in_batch = global_ws * stride;
        passwords_done_total += num_in_batch;
        passwords_done_since_report += num_in_batch;

        if(result_val >= 0) {
            uint64_t found_idx_base = current_offset + (uint64_t)result_val * stride;
            std::string password_str = dictionary.get_password(found_idx_base);
            std::cout << "\n======== Password found ========" << std::endl;
            std::cout << "Password: " << password_str << " (Index: " << found_idx_base << ")" << std::endl;
            std::cout << "================================" << std::endl;
            text_to_file("password_" + std::to_string(getSystemTime()) + ".txt", password_str);
            current_offset = dictionary_size;
            break;
        }

        uint64_t time_since_report = getSystemTime() - time_progress_report;
        if (time_since_report >= 1800 || (current_offset + num_in_batch) >= dictionary_size) {
            double current_speed = (time_since_report > 0) ? (double)passwords_done_since_report / (time_since_report / 1000.0) : 0;
            std::cout << device.name.substr(0,16) << "| "
                      << formatSeconds((unsigned int)((getSystemTime() - time_main_loop_start)/1000)) << " "
                      << (unsigned int)current_speed << "/sec "
                      << passwords_done_total << "/" << dictionary_size
                      << " (" << format("%.3f", std::min(((double)passwords_done_total/dictionary_size) * 100.0, 100.0)) << "%)"
                      << std::endl;
            time_progress_report = getSystemTime();
            passwords_done_since_report = 0;
        }
        current_offset += num_in_batch;
    }

    clReleaseMemObject(dev_words); clReleaseMemObject(dev_offsets); clReleaseMemObject(dev_index);
    clReleaseMemObject(dev_encrypted_block); clReleaseMemObject(dev_iv); clReleaseMemObject(dev_salt);
    clReleaseMemObject(dev_hashes); clReleaseMemObject(dev_result);
    clReleaseKernel(start_kernel); clReleaseKernel(middle_kernel); clReleaseKernel(end_kernel);
    clReleaseProgram(prog); clReleaseCommandQueue(cmd); clReleaseContext(ctx);
}


static void do_brute_force(struct device_info &device, int password_len, unsigned int encrypted_block[4], unsigned int iv[4], unsigned char salt[8], unsigned int iterations, uint64_t start_param, uint64_t end_param, uint64_t stride_param)
{
    cl_mem dev_alphabet = 0, dev_hashes = 0, dev_encrypted_block = 0, dev_iv = 0, dev_salt = 0, dev_result = 0;
    cl_context ctx = 0; cl_command_queue cmd = 0; cl_program prog = 0;
    cl_kernel start_kernel = 0, middle_kernel = 0, end_kernel = 0;
    cl_int err = 0;

    ctx = clCreateContext(0, 1, &device.id, NULL, NULL, &err); clCall(err);
    cmd = clCreateCommandQueue(ctx, device.id, 0, &err); clCall(err);

    load_kernel_source();
    size_t kernel_source_len_val = _kernelSource.length();
    const char *kernel_source_ptr_val = _kernelSource.c_str();
    prog = clCreateProgramWithSource(ctx, 1, &kernel_source_ptr_val, &kernel_source_len_val, &err); clCall(err);

    uint64_t actual_kernel_stride = stride_param;
    if (actual_kernel_stride == 0) {
        std::cout << "Warning: stride_param is 0 for brute_force. Defaulting BRUTE_FORCE_STRIDE to 1." << std::endl;
        actual_kernel_stride = 1;
    }
    std::string build_options = "-DBRUTE_FORCE_STRIDE=" + std::to_string(actual_kernel_stride);
    std::cout << "Building brute_force kernels with options: " << build_options << " ... ";
    err = clBuildProgram(prog, 1, &device.id, build_options.c_str(), NULL, NULL);
    if(err != CL_SUCCESS) {
        char *buffer = NULL; size_t log_len = 0;
        std::cerr << "Error: Failed to build brute_force program! Error code " << err << std::endl;
        clGetProgramBuildInfo(prog, device.id, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_len);
        buffer = new char[log_len + 1]; buffer[log_len] = '\0';
        clGetProgramBuildInfo(prog, device.id, CL_PROGRAM_BUILD_LOG, log_len, buffer, NULL);
        std::cerr << "Build Log:\n" << buffer << std::endl;
        delete[] buffer; clCall(err);
    }
    std::cout << "Done." << std::endl;

    start_kernel = clCreateKernel(prog, "brute_force_alphabet", &err); clCall(err);
    middle_kernel = clCreateKernel(prog, "hash_middle", &err); clCall(err);
    end_kernel = clCreateKernel(prog, "hash_end", &err); clCall(err);

    size_t global_ws, local_ws;
    find_best_parameters(device, ctx, cmd, middle_kernel, global_ws, local_ws);

    dev_alphabet = clCreateBuffer(ctx, CL_MEM_READ_ONLY, _alphabet_size, NULL, &err); clCall(err);
    dev_encrypted_block = clCreateBuffer(ctx, CL_MEM_READ_ONLY, sizeof(unsigned int) * 4, NULL, &err); clCall(err);
    dev_iv = clCreateBuffer(ctx, CL_MEM_READ_ONLY, sizeof(unsigned int) * 4, NULL, &err); clCall(err);
    dev_salt = clCreateBuffer(ctx, CL_MEM_READ_ONLY, 8, NULL, &err); clCall(err);
    dev_hashes = clCreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(uint64_t) * 8 * global_ws, NULL, &err); clCall(err);
    dev_result = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(int), NULL, &err); clCall(err);

    int result_val = -1;
    clCall(clEnqueueWriteBuffer(cmd, dev_alphabet, CL_TRUE, 0, _alphabet_size, _alphabet.c_str(), 0, NULL, NULL));
    clCall(clEnqueueWriteBuffer(cmd, dev_encrypted_block, CL_TRUE, 0, sizeof(unsigned int) * 4, encrypted_block, 0, NULL, NULL));
    clCall(clEnqueueWriteBuffer(cmd, dev_iv, CL_TRUE, 0, sizeof(unsigned int) * 4, iv, 0, NULL, NULL));
    clCall(clEnqueueWriteBuffer(cmd, dev_salt, CL_TRUE, 0, 8, salt, 0, NULL, NULL));
    clCall(clEnqueueWriteBuffer(cmd, dev_result, CL_TRUE, 0, sizeof(int), &result_val, 0, NULL, NULL));

    unsigned int s_iter = 1, m_iter = 0, e_iter = 0;
    if (iterations > 1) {
        unsigned int middle_chunk_kdf = 1000;
        if (iterations -1 < middle_chunk_kdf) middle_chunk_kdf = iterations -1;
        if (middle_chunk_kdf == 0 && iterations > 1) middle_chunk_kdf = iterations -1;
        m_iter = middle_chunk_kdf;
    }
    unsigned int m_calls = 0;
    if (m_iter > 0) m_calls = (iterations - 1) / m_iter;
    if (iterations > 1) e_iter = (iterations - 1) - (m_calls * m_iter);
    else s_iter = iterations;

    uint64_t total_passwords_in_space = 0;
    if (password_len > 0 && _alphabet_size > 0) {
        total_passwords_in_space = 1;
        for(int k=0; k<password_len; ++k) {
            if (UINT64_MAX / _alphabet_size < total_passwords_in_space) {
                total_passwords_in_space = UINT64_MAX;
                break;
            }
            total_passwords_in_space *= _alphabet_size;
        }
    } else if (password_len == 0) {
        total_passwords_in_space = 1;
    }

    uint64_t actual_end_param = std::min(end_param, total_passwords_in_space);
    if (start_param >= actual_end_param && !(password_len == 0 && start_param == 0 && actual_end_param == 1) ) {
        std::cout << "Start index ("<<start_param<<") is beyond or at end index ("<<actual_end_param<<"). Nothing to do." << std::endl;
        clReleaseMemObject(dev_alphabet); clReleaseMemObject(dev_encrypted_block); clReleaseMemObject(dev_iv);
        clReleaseMemObject(dev_salt); clReleaseMemObject(dev_hashes); clReleaseMemObject(dev_result);
        clReleaseKernel(start_kernel); clReleaseKernel(middle_kernel); clReleaseKernel(end_kernel);
        clReleaseProgram(prog); clReleaseCommandQueue(cmd); clReleaseContext(ctx);
        return;
    }

    uint64_t time_main_loop_start = getSystemTime();
    uint64_t time_progress_report = getSystemTime();
    uint64_t passwords_done_total = 0;
    uint64_t passwords_done_since_report = 0;

    std::cout << "Running brute-force attack for passwords of length " << password_len
              << " with alphabet size " << _alphabet_size << std::endl;
    std::cout << "Total search space to check: " << (actual_end_param - start_param)
              << " (from " << start_param << " to " << actual_end_param-1 << ")" <<std::endl;

    for (uint64_t current_batch_start_idx = start_param; current_batch_start_idx < actual_end_param; ) {
        clCall(clSetKernelArg(start_kernel, 0, sizeof(cl_mem), &dev_alphabet));
        clCall(clSetKernelArg(start_kernel, 1, sizeof(unsigned int), &_alphabet_size));
        clCall(clSetKernelArg(start_kernel, 2, sizeof(unsigned int), &password_len));
        clCall(clSetKernelArg(start_kernel, 3, sizeof(unsigned int), &s_iter));
        clCall(clSetKernelArg(start_kernel, 4, sizeof(cl_mem), &dev_salt));
        clCall(clSetKernelArg(start_kernel, 5, sizeof(uint64_t), &current_batch_start_idx));
        clCall(clSetKernelArg(start_kernel, 6, sizeof(cl_mem), &dev_hashes));

        size_t current_global_dispatch_size = global_ws;
        uint64_t num_candidates_in_batch = current_global_dispatch_size * actual_kernel_stride;

        clCall(clEnqueueNDRangeKernel(cmd, start_kernel, 1, NULL, &current_global_dispatch_size, &local_ws, 0, NULL, NULL));
        clCall(clFinish(cmd));

        if (iterations > 1) {
            if (m_calls > 0 && m_iter > 0) {
                for(unsigned int j = 0; j < m_calls; j++) {
                    clCall(clSetKernelArg(middle_kernel, 0, sizeof(cl_mem), &dev_hashes));
                    clCall(clSetKernelArg(middle_kernel, 1, sizeof(unsigned int), &m_iter));
                    clCall(clEnqueueNDRangeKernel(cmd, middle_kernel, 1, NULL, &current_global_dispatch_size, &local_ws, 0, NULL, NULL));
                    clCall(clFinish(cmd));
                }
            }
            if (e_iter > 0) {
                clCall(clSetKernelArg(middle_kernel, 0, sizeof(cl_mem), &dev_hashes));
                clCall(clSetKernelArg(middle_kernel, 1, sizeof(unsigned int), &e_iter));
                clCall(clEnqueueNDRangeKernel(cmd, middle_kernel, 1, NULL, &current_global_dispatch_size, &local_ws, 0, NULL, NULL));
                clCall(clFinish(cmd));
            }
        }

        clCall(clSetKernelArg(end_kernel, 0, sizeof(cl_mem), &dev_encrypted_block));
        clCall(clSetKernelArg(end_kernel, 1, sizeof(cl_mem), &dev_iv));
        clCall(clSetKernelArg(end_kernel, 2, sizeof(cl_mem), &dev_hashes));
        clCall(clSetKernelArg(end_kernel, 3, sizeof(unsigned int), &e_iter));
        clCall(clSetKernelArg(end_kernel, 4, sizeof(cl_mem), &dev_result));
        clCall(clEnqueueNDRangeKernel(cmd, end_kernel, 1, NULL, &current_global_dispatch_size, &local_ws, 0, NULL, NULL));
        clCall(clEnqueueReadBuffer(cmd, dev_result, CL_TRUE, 0, sizeof(int), &result_val, 0, NULL, NULL));
        clCall(clFinish(cmd));

        passwords_done_total += num_candidates_in_batch;
        passwords_done_since_report += num_candidates_in_batch;

        if(result_val >= 0) {
            uint64_t found_block_start_candidate_idx = current_batch_start_idx + (uint64_t)result_val * actual_kernel_stride;
            std::string found_password_str = "Error: Could not determine password";

            std::cout << "\n======== Password found ========" << std::endl;
            if (found_block_start_candidate_idx < actual_end_param) {
                 found_password_str = gen_password_from_index(found_block_start_candidate_idx, password_len, _alphabet);
                 std::cout << "Password candidate: " << found_password_str << " (Index: " << found_block_start_candidate_idx << ")" << std::endl;
                 if (actual_kernel_stride > 1) {
                    std::cout << "Note: This is the first of " << actual_kernel_stride << " candidates in the block checked by the successful work-item." << std::endl;
                    std::cout << "The actual password is between index " << found_block_start_candidate_idx << " and " << found_block_start_candidate_idx + actual_kernel_stride - 1 << "." << std::endl;
                 }
            } else {
                 std::cout << "Error: Result index " << found_block_start_candidate_idx << " is out of bounds." << std::endl;
            }
            std::cout << "================================" << std::endl;
            text_to_file("password_" + std::to_string(getSystemTime()) + ".txt", found_password_str);
            current_batch_start_idx = actual_end_param;
            break;
        }

        uint64_t time_since_report = getSystemTime() - time_progress_report;
        if (time_since_report >= 3000 || (current_batch_start_idx + num_candidates_in_batch) >= actual_end_param ) {
            double current_speed = (time_since_report > 0) ? (double)passwords_done_since_report / (time_since_report / 1000.0) : 0;
            double percent_done = (actual_end_param > 0) ? ((double)passwords_done_total / actual_end_param) * 100.0 : 0.0;
            percent_done = std::min(percent_done, 100.0);

            std::cout << device.name.substr(0,16) << "| "
                      << formatSeconds((unsigned int)((getSystemTime() - time_main_loop_start)/1000)) << " "
                      << (unsigned int)current_speed << " cand/sec "
                      << passwords_done_total << "/" << actual_end_param
                      << " (" << format("%.3f", percent_done) << "%)"
                      << std::endl;
            time_progress_report = getSystemTime();
            passwords_done_since_report = 0;
        }
        current_batch_start_idx += num_candidates_in_batch;
    }

    clReleaseMemObject(dev_alphabet); clReleaseMemObject(dev_encrypted_block); clReleaseMemObject(dev_iv);
    clReleaseMemObject(dev_salt); clReleaseMemObject(dev_hashes); clReleaseMemObject(dev_result);
    clReleaseKernel(start_kernel); clReleaseKernel(middle_kernel); clReleaseKernel(end_kernel);
    clReleaseProgram(prog); clReleaseCommandQueue(cmd); clReleaseContext(ctx);
}

// Reverted signature to match core-decrypt.h for compilation workaround
bool brute_force_cl(int password_len, unsigned int encrypted_block[4], unsigned int iv[4], unsigned char salt[8], unsigned int iterations, uint64_t start, uint64_t end, uint64_t stride)
{
    std::vector<struct device_info> devices = get_devices();
    if (devices.empty()) {
        std::cerr << "brute_force_cl: No OpenCL devices found." << std::endl;
        return false;
    }
    // Workaround: Use device 0 by default, as the header doesn't allow passing device_info directly.
    // The --device option from main will be ignored for brute-force mode due to this.
    struct device_info &selected_device = devices[0];
    std::cout << "brute_force_cl: Using device 0: " << selected_device.name
              << " (ID: " << selected_device.logical_id
              << ", Cores: " << selected_device.cores
              << ", Clock: " << selected_device.clock_frequency << "MHz)" << std::endl;
    std::cout << "Note: --device option from command line is ignored for brute-force mode due to header constraints." << std::endl;


    load_kernel_source();

    do_brute_force(selected_device, password_len, encrypted_block, iv, salt, iterations, start, end, stride);
    return true;
}

bool dictionary_cl(struct device_info &device, PasswordDictionary &dictionary, unsigned int encrypted_block[4], unsigned int iv[4], unsigned char salt[8], unsigned int iterations, uint64_t start, int stride, unsigned int intensity)
{
    load_kernel_source();
    do_dictionary(device, dictionary, encrypted_block, iv, salt, iterations, start, stride, intensity);
    return true;
}
