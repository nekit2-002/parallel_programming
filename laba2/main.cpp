#include <algorithm>
#include <atomic>
#include <iomanip>
#include <iostream>
#include <openssl/md5.h>
#include <optional>
#include <sstream>
#include <string.h>
#include <unistd.h>
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
    return std::optional<std::string>{pswd};
  }

  return std::nullopt;
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
  std::cout << "4 -- run parallel search via double fork()" << std::endl;

  char option;
  std::cout << ">> ";
  std::cin >> option;
  switch (option) {
  case '2': {
    std::cout << "Input 6 bytes of password. Symbols a-z and 0-9 are permitted."
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

    res = iter_bytes("000000", *res, "zzzzzz");
    if (!res) {
      std::cout << "Failed to find password!" << std::endl;
      break;
    }

    std::cout << "Found password is: " << *res << std::endl;
    break;
  }

  case '4': {
    std::cout
        << "Input 32 symbols of hash-sum. Symbols a-f and 0-9 are permitted."
        << std::endl;
    std::cout << ">> ";
    std::string hash;
    std::cin >> hash;

    auto res = check_line(hash, 'h');
    if (!res) {
      std::cout << "Invalid hash!" << std::endl;
      exit(1);
    }

    int fds[2];
    if (pipe(fds) != 0) {
      std::cout << "Error while creating pipes!" << std::endl;
      exit(1);
    }

    int pid1 = fork();
    if (pid1 < 0) {
      std::cout << "Error while creating child process!" << std::endl;
      exit(1);
    }
    // main process
    else if (pid1 > 0) {
      close(fds[1]);
      int fds1[2];
      if (pipe(fds1) != 0) {
        std::cout << "Error while creating pipes!" << std::endl;
        exit(1);
      }

      int pid = fork();
      if (pid < 0) {
        std::cout << "Error while splitting the child!" << std::endl;
        exit(1);
      }

      else if (pid > 0) { // main
        res = iter_bytes("000000", hash, "8zzzzz");
        if (res) {
          std::cout << "Found password: " << *res << std::endl;
          return 0;
        }

        char pswd[6];
        read(fds[0], pswd, 6);
        close(fds[0]);
        auto r = std::string{pswd};
        if (!r.empty()) {
          std::cout << "Found password is: " << r << std::endl;
        } else {
          read(fds1[0], pswd, 6);
          close(fds1[0]);
          r = std::string{pswd};
          if (!r.empty()) {
            std::cout << "Found password is: " << r << std::endl;
          }
        }

        break;
      } else { // another child of main
        close(fds[0]);
        close(fds[1]);
        close(fds1[0]);
        res = iter_bytes("i00000", hash, "qzzzzz");
        if (res) {
          write(fds1[1], (*res).c_str(), 6);
        }

        close(fds1[1]);
      }

    } else { // child process
      int fds1[2];
      std::cout << "Run child process" << std::endl;
      int pid = fork();
      if (pid < 0) {
        std::cout << "Error while splitting the child!" << std::endl;
        exit(1);
      }

      else if (pid > 0) { // same child process
        close(fds[0]);
        res = iter_bytes("900000", hash, "hzzzzz");
        if (res) {
          std::cout << "Password found: " << *res << std::endl;
          write(fds[1], (*res).c_str(), 6);
          exit(0);
        }

        char pswd[6];
        read(fds1[0], pswd, 6); // check if fds1 contains our password
        auto r = std::string{pswd};
        if (!r.empty()) {
          write(fds[1], pswd, 6);
        }

        close(fds1[1]);
      }

      else { // child of the child
        close(fds[0]);
        close(fds[1]);
        res = iter_bytes("r00000", hash, "zzzzzz");
        if (res) {
          write(fds1[1], (*res).c_str(), 6);
        }

        close(fds1[1]);
      }
    }
    break;
  }

  default: {
    std::cout << "Invalid option!" << std::endl;
    break;
  }
  }

  return 0;
}