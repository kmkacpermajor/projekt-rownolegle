#include <iostream>
#include <fstream>
#include <unordered_map>
#include <string>
#include <vector>
#include <cuda_runtime.h>

// Własna implementacja strcmp na GPU
__device__ int strcmp_gpu(const char* str1, const char* str2) {
	while (*str1 && (*str1 == *str2)) {
		str1++;
		str2++;
	}
	return *(unsigned char*)str1 - *(unsigned char*)str2;
}

// Własna implementacja strcpy na GPU
__device__ char* strcpy_gpu(char* dest, const char* src) {
	char* d = dest;
	const char* s = src;
	while ((*d++ = *s++));
	return dest;
}

__global__ void crackPasswordsKernel(const char* d_logins, const char* d_hashes, const char* d_dict_hashes, const char* d_dict_passwords, char* d_results, int num_logins, int num_dict_entries, int max_password_length) {
	int idx = blockIdx.x * blockDim.x + threadIdx.x;
	if (idx < num_logins) {
		const char* hash = &d_hashes[idx * (max_password_length + 1)];
		bool found = false;

		for (int j = 0; j < num_dict_entries; ++j) {
			const char* dict_hash = &d_dict_hashes[j * (max_password_length + 1)];
			const char* dict_password = &d_dict_passwords[j * (max_password_length + 1)];

			if (strcmp_gpu(hash, dict_hash) == 0) {
				strcpy_gpu(&d_results[idx * (max_password_length + 1)], dict_password);
				found = true;
				break;
			}
		}

		if (!found) {
			strcpy_gpu(&d_results[idx * (max_password_length + 1)], "NOT_FOUND");
		}
	}
}

std::unordered_map<std::string, std::string> loadDictionary(const std::string& filename, int& max_length) {
	std::unordered_map<std::string, std::string> dictionary;
	std::ifstream file(filename);
	if (!file.is_open()) {
		std::cerr << "Nie udało się otworzyć pliku słownika.\n";
		return dictionary;
	}

	std::string line;
	max_length = 0;
	while (std::getline(file, line)) {
		size_t delimiter_pos = line.find(':');
		if (delimiter_pos != std::string::npos) {
			std::string hash = line.substr(0, delimiter_pos);
			std::string password = line.substr(delimiter_pos + 1);
			dictionary[hash] = password;
			max_length = std::max(max_length, (int)std::max(hash.size(), password.size()));
		}
	}

	file.close();
	return dictionary;
}

std::vector<std::pair<std::string, std::string>> loadLogins(const std::string& filename, int& max_length) {
	std::vector<std::pair<std::string, std::string>> logins;
	std::ifstream file(filename);
	if (!file.is_open()) {
		std::cerr << "Nie udało się otworzyć pliku z loginami.\n";
		return logins;
	}

	std::string line;
	max_length = 0;
	while (std::getline(file, line)) {
		size_t delimiter_pos = line.find(':');
		if (delimiter_pos != std::string::npos) {
			std::string login = line.substr(0, delimiter_pos);
			std::string hash = line.substr(delimiter_pos + 1);
			logins.emplace_back(login, hash);
			max_length = std::max(max_length, (int)std::max(login.size(), hash.size()));
		}
	}

	file.close();
	return logins;
}

void processPasswords(const std::vector<std::pair<std::string, std::string>>& logins,
					  const std::unordered_map<std::string, std::string>& dictionary,
					  const std::string& outputFilename,
					  int max_password_length) {
	int num_logins = logins.size();
	int num_dict_entries = dictionary.size();

	std::vector<char> logins_flat((max_password_length + 1) * num_logins);
	std::vector<char> hashes_flat((max_password_length + 1) * num_logins);
	std::vector<char> dict_hashes_flat((max_password_length + 1) * num_dict_entries);
	std::vector<char> dict_passwords_flat((max_password_length + 1) * num_dict_entries);
	std::vector<char> results_flat((max_password_length + 1) * num_logins, '\0');

	int i = 0;
	for (const auto& login_hash_pair : logins) {
		strcpy(&logins_flat[i * (max_password_length + 1)], login_hash_pair.first.c_str());
		strcpy(&hashes_flat[i * (max_password_length + 1)], login_hash_pair.second.c_str());
		++i;
	}

	i = 0;
	for (const auto& dict_entry : dictionary) {
		strcpy(&dict_hashes_flat[i * (max_password_length + 1)], dict_entry.first.c_str());
		strcpy(&dict_passwords_flat[i * (max_password_length + 1)], dict_entry.second.c_str());
		++i;
	}

	char* d_logins, * d_hashes, * d_dict_hashes, * d_dict_passwords, * d_results;
	cudaMalloc(&d_logins, logins_flat.size());
	cudaMalloc(&d_hashes, hashes_flat.size());
	cudaMalloc(&d_dict_hashes, dict_hashes_flat.size());
	cudaMalloc(&d_dict_passwords, dict_passwords_flat.size());
	cudaMalloc(&d_results, results_flat.size());

	cudaMemcpy(d_logins, logins_flat.data(), logins_flat.size(), cudaMemcpyHostToDevice);
	cudaMemcpy(d_hashes, hashes_flat.data(), hashes_flat.size(), cudaMemcpyHostToDevice);
	cudaMemcpy(d_dict_hashes, dict_hashes_flat.data(), dict_hashes_flat.size(), cudaMemcpyHostToDevice);
	cudaMemcpy(d_dict_passwords, dict_passwords_flat.data(), dict_passwords_flat.size(), cudaMemcpyHostToDevice);

	int threads_per_block = 256;
	int blocks_per_grid = (num_logins + threads_per_block - 1) / threads_per_block;

	crackPasswordsKernel<<<blocks_per_grid, threads_per_block>>>(d_logins, d_hashes, d_dict_hashes, d_dict_passwords, d_results, num_logins, num_dict_entries, max_password_length);

	cudaMemcpy(results_flat.data(), d_results, results_flat.size(), cudaMemcpyDeviceToHost);

	cudaFree(d_logins);
	cudaFree(d_hashes);
	cudaFree(d_dict_hashes);
	cudaFree(d_dict_passwords);
	cudaFree(d_results);

	std::ofstream outfile(outputFilename);
	if (!outfile.is_open()) {
		std::cerr << "Nie udało się otworzyć pliku wyjściowego.\n";
		return;
	}

	for (int i = 0; i < num_logins; ++i) {
		std::string result(&results_flat[i * (max_password_length + 1)]);
		if (result == "NOT_FOUND") {
			std::cout << "Nie udało się złamać hasła dla " << logins[i].first << '\n';
		} else {
			outfile << logins[i].first << ':' << result << '\n';
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

	int max_dict_length = 0;
	std::unordered_map<std::string, std::string> dictionary = loadDictionary(dictionaryFilename, max_dict_length);

	int max_login_length = 0;
	std::vector<std::pair<std::string, std::string>> logins = loadLogins(inputFilename, max_login_length);

	int max_length = std::max(max_dict_length, max_login_length);

	processPasswords(logins, dictionary, outputFilename, max_length);

	return 0;
}
