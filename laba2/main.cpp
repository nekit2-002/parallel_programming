#include <algorithm>
#include <atomic>
#include <iomanip>
#include <iostream>
#include <openssl/md5.h>
#include <optional>
#include <pthread.h>
#include <sstream>
#include <vector>

#define ERROR_CREATE_THREAD -11
#define ERROR_JOIN_THREAD -12
#define SUCCESS 0
std::atomic<bool> found(false);

std::string md5(const std::string &pswd) {
  unsigned char hash[MD5_DIGEST_LENGTH];

  MD5_CTX md5;
  MD5_Init(&md5);
  MD5_Update(&md5, pswd.c_str(), pswd.size());
  MD5_Final(hash, &md5);

  std::stringstream ss;

  for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
    ss << std::hex << std::setw(2) << std::setfill('0')
       << static_cast<int>(hash[i]);
  }
  return ss.str();
}

std::optional<std::string> iter_bytes(std::string pswd, std::string hash,
                                      std::string stop_word) {
  int i = 5;
  while (pswd != stop_word && !found.load()) {
    if (hash == md5(pswd)) {
      found.store(true);
      return std::optional<std::string>{pswd};
    }

    if (pswd.substr(i, 6 - i) != stop_word.substr(i, 6 - i)) {
      pswd[i] += 1;
      if (pswd[i] == ':') {
        pswd[i] += 39;
      }

      i = 5;
      continue;
    }

    int c = 0;
    for (int idx = 5; idx >= 0; idx--) {
      if (pswd[idx] != 'z') {
        break;
      }

      c += 1;
    }

    i -= c;

    for (int i2 = i + 1; i2 < 6; i2++) {
      pswd[i2] = '0';
    }
  }

  if (hash == md5(pswd)) {
    found.store(true);
    return pswd;
  }

  return std::nullopt;
}

void find_password(std::string args) {
  std::stringstream ss(args);
  std::string word;
  std::vector<std::string> hash_start_stop;
  while (getline(ss, word, ' ')) {
    hash_start_stop.push_back(word);
  }

  auto res =
      iter_bytes(hash_start_stop[1], hash_start_stop[0], hash_start_stop[2]);
  if (res != std::nullopt) {
    std::cout << "Found password, the password is: " << *res << std::endl;
  }
}

std::optional<std::string> check_len(std::string line, std::size_t n) {
  auto l = line.length();
  if (l > n) {
    std::cout << "The input is too long, so it was cut to the appropriate size!"
              << std::endl;
    line.resize(n + 1);
    std::cout << "Now the input is " << line << std::endl;
  } else if (l < n) {
    std::cout << "The input is too short!" << std::endl;
    return std::nullopt;
  }

  return std::optional<std::string>{line};
}

std::optional<std::string> check_line(std::string line, char sem) {
  std::cout << "Input is " << line << std::endl;
  line.erase(std::remove_if(line.begin(), line.end(), isspace), line.end());
  for (auto c : line) {
    if (!isalnum(c)) {
      return std::nullopt;
    }

    if (sem == 'h' && c > 'f') {
      return std::nullopt;
    }
    std::tolower(c);
  }

  switch (sem) {
  case 'p': {
    return check_len(line, 6);
  }

  case 'h': {
    return check_len(line, 32);
  }

  default: {
    return std::nullopt;
  }
  }
}

int main() {
  std::cout << "Following options are avaluable:" << std::endl;
  std::cout << "1 -- quit" << std::endl;
  std::cout << "2 -- input password" << std::endl;
  std::cout << "3 -- run single thread search of the password" << std::endl;

  char option;
  std::cout << ">> ";
  std::cin >> option;
  while (option != '1') {
    switch (option) {
    case '2': {
      std::cout
          << "Input 6 bytes of password. Symbols a-z and 0-9 are permitted."
          << std::endl;
      std::cout << ">> ";
      std::string pswd;
      std::cin >> pswd;
      auto res = check_line(pswd, 'p');
      if (!res) {
        std::cout << "Invalid password!" << std::endl;
        break;
      }

      std::cout << "Hash for the password is: " << md5(pswd) << std::endl;
      break;
    }

    case '3': {
      std::cout
          << "Input 32 symbols of hash-sum. Symbols a-f and 0-9 are permitted."
          << std::endl;
      std::cout << ">> ";
      std::string hash;
      std::cin >> hash;

      auto res = check_line(hash, 'h');
      if (!res) {
        std::cout << "Invalid hash!" << std::endl;
        break;
      }

      auto args = (*res + " " + "000000 " + "zzzzzz");
      find_password(args);
      break;
    }

    default: {
      std::cout << "Invalid option!" << std::endl;
      break;
    }
    }
    std::cout << ">> ";
    std::cin >> option;
  }

  return 0;
}