#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <mpi.h>
#include <openssl/md5.h>
#include <optional>
#include <signal.h>
#include <sstream>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

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

// single thread overload
std::optional<std::string> iter_bytes(std::string pswd, std::string hash,
                                      std::string stop_word) {
  int i = 5;
  while (pswd != stop_word) {
    if (hash == md5(pswd)) {
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
    return std::optional<std::string>{pswd};
  }

  return std::nullopt;
}

int main(int argc, char *argv[]) {
  MPI_Init(&argc, &argv);
  std::string starts[4] = {"000000", "900000", "i00000", "r00000"};
  std::string ends[4] = {"8zzzzz", "hzzzzz", "qzzzzz", "zzzzzz"};
  auto pswd = std::string{argv[1]};
  auto hash = md5(pswd);
  int rank;
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  for (int i = 0; i < 4; i++) {
    if (rank == i) {
      auto res = iter_bytes(starts[i], hash, ends[i]);
      if (res) {
        std::cout << "Password found: " << *res << std::endl;
        MPI_Finalize();
        exit(0);
      }
    }
  }

  return 0;
}