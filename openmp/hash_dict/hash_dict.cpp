#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <omp.h>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/md5.h>

enum HashAlgorithm {
    HASH_SHA256,
    HASH_MD5
};

std::string hash_word(const std::string& word, HashAlgorithm algorithm = HASH_SHA256) {
    std::stringstream ss;
    switch (algorithm) {
        case HASH_SHA256: {
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, word.c_str(), word.size());
            SHA256_Final(hash, &sha256);
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
            }
            break;
        }
        case HASH_MD5: {
            unsigned char hash[MD5_DIGEST_LENGTH];
            MD5_CTX md5;
            MD5_Init(&md5);
            MD5_Update(&md5, word.c_str(), word.size());
            MD5_Final(hash, &md5);
            for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
            }
            break;
        }
        default:
            return hash_word(word, HASH_SHA256);
    }
    return ss.str();
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <input_file> <output_file> <hash_algorithm>" << std::endl;
        return 1;
    }

    std::string input_file = argv[1];
    std::string output_file = argv[2];
    HashAlgorithm algorithm;

    if (std::string(argv[3]) == "SHA256") {
        algorithm = HASH_SHA256;
    } else if (std::string(argv[3]) == "MD5") {
        algorithm = HASH_MD5;
    } else {
        std::cerr << "Invalid hash algorithm. Supported algorithms: SHA256, MD5" << std::endl;
        return 1;
    }

    std::ifstream infile(input_file);
    if (!infile) {
        std::cerr << "Error opening input file: " << input_file << std::endl;
        return 1;
    }

    std::ofstream outfile(output_file);
    if (!outfile) {
        std::cerr << "Error opening output file: " << output_file << std::endl;
        return 1;
    }

    std::vector<std::string> words;
    std::string word;
    while (std::getline(infile, word)) {
        words.push_back(word);
    }

    infile.close();

    std::vector<std::string> results(words.size());

    #pragma omp parallel for
    for (size_t i = 0; i < words.size(); ++i) {
        std::string hashed_word = hash_word(words[i], algorithm);
        results[i] = hashed_word + ":" + words[i];
    }

    for (const auto& result : results) {
        outfile << result << std::endl;
    }

    outfile.close();

    return 0;
}
