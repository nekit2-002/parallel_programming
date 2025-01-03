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

// argv[1] is assumed to be the password
int main(int argc, char *argv[]) {
  std::vector<int> pids(4);
  MPI_Init(&argc, &argv);
  std::string starts[4] = {"000000", "900000", "i00000", "r00000"};
  std::string ends[4] = {"8zzzzz", "hzzzzz", "qzzzzz", "zzzzzz"};

  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <password>" << std::endl;
    MPI_Finalize();
    return 1;
  }

  auto pswd = std::string{argv[1]};
  auto hash = md5(pswd);

  int rank;
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  int pid = getpid();

  MPI_Allgather(&pid, 1, MPI_INT, pids.data(), 1, MPI_INT, MPI_COMM_WORLD);
  auto res = iter_bytes(starts[rank], hash, ends[rank]);
  if (res.has_value()) {
    std::cout << "Rank " << rank << " found password: " << *res << std::endl;
  }

  for (int i = 0; i < 4; i++) {
    if (pids[i] != pid) {
      kill(pids[i], SIGTERM);
    }
  }

  MPI_Finalize();
  return 0;
}