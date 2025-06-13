#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cassert>
#include <numeric> // For std::iota if needed, not strictly for this one

// Assuming core-decrypt.h is the main header that pulls in PasswordDictionary
// Adjust include path based on actual location from src/tests/
#include "../core-decrypt.h"
#include "../util.h" // For removeNewline, though PasswordDictionary handles it internally

// Helper to create a temporary dictionary file
void create_temp_dict_file(const std::string& filename, const std::vector<std::string>& lines) {
    std::ofstream outfile(filename.c_str());
    for (size_t i = 0; i < lines.size(); ++i) {
        outfile << lines[i] << (i == lines.size() - 1 ? "" : "\n");
    }
    outfile.close();
}

void test_load_single_dictionary() {
    std::cout << "Running test_load_single_dictionary..." << std::endl;
    const char* filename = "test_dict1.txt";
    std::vector<std::string> lines;
    lines.push_back("pass1");
    lines.push_back("word2");
    lines.push_back("secret3");
    create_temp_dict_file(filename, lines);

    std::vector<std::string> files;
    files.push_back(filename);
    std::vector<int> format;
    format.push_back(0);

    PasswordDictionary pd(files, format);
    assert(pd.get_size() == 3);
    assert(pd.get_password(0) == "pass1");
    assert(pd.get_password(1) == "word2");
    assert(pd.get_password(2) == "secret3");

    remove(filename); // Clean up
    std::cout << "test_load_single_dictionary PASSED" << std::endl;
}

void test_load_multiple_dictionaries() {
    std::cout << "Running test_load_multiple_dictionaries..." << std::endl;
    const char* f1 = "multi_dict1.txt";
    const char* f2 = "multi_dict2.txt";
    std::vector<std::string> l1;
    l1.push_back("apple");
    l1.push_back("banana");
    create_temp_dict_file(f1, l1);

    std::vector<std::string> l2;
    l2.push_back("cat");
    l2.push_back("dog");
    create_temp_dict_file(f2, l2);

    std::vector<std::string> files;
    files.push_back(f1);
    files.push_back(f2);

    std::vector<int> format; // format for "word_from_dict1" + "word_from_dict2"
    format.push_back(0); // Use dict1.txt
    format.push_back(1); // Use dict2.txt

    PasswordDictionary pd(files, format);
    // Expected size = size(dict1) * size(dict2) = 2 * 2 = 4
    assert(pd.get_size() == 4);

    // Test password combinations
    // idx 0: apple + cat
    // idx 1: banana + cat
    // idx 2: apple + dog
    // idx 3: banana + dog
    assert(pd.get_password(0) == "applecat");
    assert(pd.get_password(1) == "bananacat");
    assert(pd.get_password(2) == "appledog");
    assert(pd.get_password(3) == "bananadog");

    remove(f1);
    remove(f2);
    std::cout << "test_load_multiple_dictionaries PASSED" << std::endl;
}

void test_empty_dictionary() {
    std::cout << "Running test_empty_dictionary..." << std::endl;
    const char* filename = "empty_dict.txt";
    std::vector<std::string> lines; // Empty lines
    create_temp_dict_file(filename, lines);

    std::vector<std::string> files;
    files.push_back(filename);
    std::vector<int> format;
    format.push_back(0);

    PasswordDictionary pd(files, format);
    assert(pd.get_size() == 0); // Or 1 if it's treated as one empty word? The logic implies 0 count for empty file.

    // Test with another non-empty dictionary to ensure format with empty still works
    const char* f_nonempty = "nonempty_dict.txt";
    std::vector<std::string> l_nonempty;
    l_nonempty.push_back("test");
    create_temp_dict_file(f_nonempty, l_nonempty);

    files.push_back(f_nonempty); // files = {"empty_dict.txt", "nonempty_dict.txt"}

    std::vector<int> format2; // word_from_empty + word_from_nonempty
    format2.push_back(0); // empty_dict.txt (count = 0)
    format2.push_back(1); // nonempty_dict.txt (count = 1)

    // Size should be 0 because one of the components in format has 0 words
    PasswordDictionary pd2(files, format2);
    assert(pd2.get_size() == 0);


    std::vector<int> format3; // word_from_nonempty + word_from_empty
    format3.push_back(1);
    format3.push_back(0);
    PasswordDictionary pd3(files, format3);
    assert(pd3.get_size() == 0);


    remove(filename);
    remove(f_nonempty);
    std::cout << "test_empty_dictionary PASSED" << std::endl;
}


int main() {
    test_load_single_dictionary();
    test_load_multiple_dictionaries();
    test_empty_dictionary();
    // Add more tests as needed

    std::cout << "All PasswordDictionary tests PASSED!" << std::endl;
    return 0;
}
