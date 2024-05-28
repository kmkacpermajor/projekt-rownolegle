#include <iostream>
#include <fstream>
#include <unordered_map>
#include <string>
#include <vector>
#include <omp.h>

std::unordered_map<std::string, std::string> loadDictionary(const std::string& filename) {
    std::unordered_map<std::string, std::string> dictionary;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Nie udało się otworzyć pliku słownika.\n";
        return dictionary;
    }

    std::string line;
    while (std::getline(file, line)) {
        size_t delimiter_pos = line.find(':');
        if (delimiter_pos != std::string::npos) {
            std::string hash = line.substr(0, delimiter_pos);
            std::string password = line.substr(delimiter_pos + 1);
            dictionary[hash] = password;
        }
    }

    file.close();
    return dictionary;
}

std::vector<std::pair<std::string, std::string>> loadLogins(const std::string& filename) {
    std::vector<std::pair<std::string, std::string>> logins;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Nie udało się otworzyć pliku z loginami.\n";
        return logins;
    }

    std::string line;
    while (std::getline(file, line)) {
        size_t delimiter_pos = line.find(':');
        if (delimiter_pos != std::string::npos) {
            std::string login = line.substr(0, delimiter_pos);
            std::string hash = line.substr(delimiter_pos + 1);
            logins.emplace_back(login, hash);
        }
    }

    file.close();
    return logins;
}

void processPasswords(const std::vector<std::pair<std::string, std::string>>& logins,
                      const std::unordered_map<std::string, std::string>& dictionary,
                      const std::string& outputFilename) {
    std::ofstream outfile(outputFilename);
    if (!outfile.is_open()) {
        std::cerr << "Nie udało się otworzyć pliku wyjściowego.\n";
        return;
    }

    #pragma omp parallel for
    for (size_t i = 0; i < logins.size(); ++i) {
        const auto& [login, hash] = logins[i];
        auto it = dictionary.find(hash);
        if (it != dictionary.end()) {
            #pragma omp critical
            outfile << login << ':' << it->second << '\n';
        } else {
            #pragma omp critical
            std::cout << "Nie udało się złamać hasła dla " << login << '\n';
        }
    }

    outfile.close();
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Użycie: " << argv[0] << " <plik słownika> <plik z loginami> <plik wyjściowy>\n";
        return 1;
    }

    std::string dictionaryFilename = argv[1];
    std::string inputFilename = argv[2];
    std::string outputFilename = argv[3];

    std::unordered_map<std::string, std::string> dictionary = loadDictionary(dictionaryFilename);
    std::vector<std::pair<std::string, std::string>> logins = loadLogins(inputFilename);

    processPasswords(logins, dictionary, outputFilename);

    return 0;
}
