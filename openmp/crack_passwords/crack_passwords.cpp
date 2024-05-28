#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <omp.h>

std::string crackMD5(const std::string& hash, const std::string& salt, const std::vector<std::string>& dictionary) {
    std::string result;
    bool found = false;
    #pragma omp parallel for shared(found)
    for (int i = 0; i < dictionary.size(); ++i) {
        if (found)
            continue;
        std::string word = dictionary[i];
        word.append(salt);
        unsigned char digest[MD5_DIGEST_LENGTH];
        MD5((unsigned char*)word.c_str(), word.length(), digest);

        char md5_hash[MD5_DIGEST_LENGTH * 2 + 1];
        for (int j = 0; j < MD5_DIGEST_LENGTH; j++)
            sprintf(&md5_hash[j * 2], "%02x", (unsigned int)digest[j]);

        if (hash == md5_hash) {
            #pragma omp critical
            {
                if (!found) {
                    result = dictionary[i];
                    found = true;
                }
            }
        }
    }
    return result;
}

std::string crackSHA256(const std::string& hash, const std::string& salt, const std::vector<std::string>& dictionary) {
    std::string result;
    bool found = false;
    #pragma omp parallel for shared(found)
    for (int i = 0; i < dictionary.size(); ++i) {
        if (found)
            continue;
        std::string word = dictionary[i];
        word.append(salt);
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)word.c_str(), word.length(), digest);

        char sha256_hash[SHA256_DIGEST_LENGTH * 2 + 1];
        for (int j = 0; j < SHA256_DIGEST_LENGTH; j++)
            sprintf(&sha256_hash[j * 2], "%02x", (unsigned int)digest[j]);

        if (hash == sha256_hash) {
            #pragma omp critical
            {
                if (!found) {
                    result = dictionary[i];  // save only the original word
                    found = true;
                }
            }
        }
    }
    return result;
}

std::string extractHash(const std::string& input) {
    size_t firstDollarPos = input.find('$');
    if (firstDollarPos != std::string::npos) {
        size_t secondDollarPos = input.find('$', firstDollarPos + 1);
        if (secondDollarPos != std::string::npos) {
            size_t thirdDollarPos = input.find('$', secondDollarPos + 1);
            if (thirdDollarPos != std::string::npos) {
                return input.substr(thirdDollarPos + 1);
            }
        }
    }
    return "";
}

int main(int argc, char* argv[]) {
    if (argc != 4 && argc != 6) {
        std::cerr << "Usage: " << argv[0] << " <hash_file> <dictionary_file> <output_file> [<hash_lines> <dict_lines>]\n";
        return 1;
    }

	int login_lines;
	int dict_lines;
	if (argc == 6){
		login_lines = std::atoi(argv[4]);
		dict_lines = std::atoi(argv[5]);
	}

    std::ifstream hashFile(argv[1]);
    if (!hashFile.is_open()) {
        std::cerr << "Error: Couldn't open hash file.\n";
        return 1;
    }

    std::ifstream dictionaryFile(argv[2]);
    if (!dictionaryFile.is_open()) {
        std::cerr << "Error: Couldn't open dictionary file.\n";
        return 1;
    }

    std::ofstream outputFile(argv[3]);
    if (!outputFile.is_open()) {
        std::cerr << "Error: Couldn't create output file.\n";
        return 1;
    }

    std::unordered_map<std::string, std::string> loginToHash;
    std::vector<std::string> dictionary;

    std::string line;
    int i = 0;
    while (std::getline(hashFile, line)) {
        size_t pos = line.find(':');
        if (pos != std::string::npos) {
            std::string login = line.substr(0, pos);
            std::string hash = line.substr(pos + 1);
            loginToHash[login] = hash;
        }	

		if (argc == 6 && i>login_lines) break;
		i++;
    }

    i = 0;
    while (std::getline(dictionaryFile, line)) {
        dictionary.push_back(line);

		if (argc == 6 && i>dict_lines) break;
		i++;
    }

    std::vector<std::string> results;

    #pragma omp parallel
    {
        std::vector<std::string> local_results;
        #pragma omp for nowait
        for (int i = 0; i < loginToHash.size(); ++i) {
            auto pair = std::next(std::begin(loginToHash), i);
            std::string password;
            std::string whole_hash = pair->second;
            std::string login = pair->first;
            std::string algorithm = whole_hash.substr(whole_hash.find('$') + 1, whole_hash.find('$', whole_hash.find('$') + 1) - whole_hash.find('$') - 1);
            std::string salt = whole_hash.substr(whole_hash.find('$', whole_hash.find('$') + 1) + 1, whole_hash.find('$', whole_hash.find('$', whole_hash.find('$') + 1) + 1) - whole_hash.find('$', whole_hash.find('$') + 1) - 1);
            std::string hash = extractHash(whole_hash);

            if (algorithm == "MD5")
                password = crackMD5(hash, salt, dictionary);
            else if (algorithm == "SHA256")
                password = crackSHA256(hash, salt, dictionary);

            if (!password.empty()) {
                local_results.push_back(login + ":" + password);
            } else {
                #pragma omp critical
                {
                    std::cout << "Password for " << login << " wasn't cracked" << std::endl;
                }
            }
        }

        #pragma omp critical
        {
            results.insert(results.end(), local_results.begin(), local_results.end());
        }
    }

    for (const auto& result : results) {
        outputFile << result << "\n";
    }

    hashFile.close();
    dictionaryFile.close();
    outputFile.close();

    return 0;
}
