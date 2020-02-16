#include <simpleopenssl/simpleopenssl.h>

#include <gtest/gtest.h>

#include <sstream>

#include "utils.h"

namespace so { namespace ut { namespace hash {

namespace hash = ::so::hash;

struct HashFileTestInput
{
  std::string shortDesc;
  std::string fileName;
  std::string expectedHexString;
  std::function<::so::Result<::so::Bytes>(const std::string&)> hasher;
};

inline std::ostream& operator<<(std::ostream &s, const HashFileTestInput &i)
{
  return s << i.shortDesc;
}

class HashFileUT: public ::testing::TestWithParam<HashFileTestInput>
{};

TEST_P(HashFileUT, hash)
{
  // GIVEN
  const auto input { GetParam() };

  // WHEN
  const auto btHash = input.hasher(input.fileName);

  // THEN
  ASSERT_TRUE(btHash);
  EXPECT_EQ(input.expectedHexString, utils::bin2Hex(*btHash));
}

const auto testCases = ::testing::Values(
    
  HashFileTestInput{
      "md4",
      "./data/random_20kB.data",
      "bcf3132f2dc6d4dd3538dec6782790b4",
      [](const std::string &path) -> ::so::Result<::so::Bytes> {return ::so::hash::fileMD4(path);},
    },

  HashFileTestInput{
      "md4 200kB",
      "./data/random_200kB.data",
      "7dfe81476bba354faee82131ae29b2b5",
      [](const std::string &path) -> ::so::Result<::so::Bytes> {return ::so::hash::fileMD4(path);},
    },

  HashFileTestInput{
      "md5",
      "./data/random_20kB.data",
      "3a230011272f3d219e3999833b8df77a",
      [](const std::string &path) -> ::so::Result<::so::Bytes> {return ::so::hash::fileMD5(path);},
    },

  HashFileTestInput{
      "md5 200kB",
      "./data/random_200kB.data",
      "34bc845260c5c7584d27c006fe05fd5d",
      [](const std::string &path) -> ::so::Result<::so::Bytes> {return ::so::hash::fileMD5(path);},
    },

  HashFileTestInput{
      "sha1",
      "./data/random_20kB.data",
      "7da2e0276dacd60dd9208d8c0c56cfc7560c9140",
      [](const std::string &path) -> ::so::Result<::so::Bytes> {return ::so::hash::fileSHA1(path);},
    },

  HashFileTestInput{
      "sha1 200kB",
      "./data/random_200kB.data",
      "2b24d9c2fa88103153a4023f6766dffbb9d272b8",
      [](const std::string &path) -> ::so::Result<::so::Bytes> {return ::so::hash::fileSHA1(path);},
    },

  HashFileTestInput{
      "sha224",
      "./data/random_20kB.data",
      "32823f3099a7610848cc3db940f5b477523e42f35b7db280e749cde2",
      [](const std::string &path) -> ::so::Result<::so::Bytes> {return ::so::hash::fileSHA224(path);},
    },

  HashFileTestInput{
      "sha224 200kB",
      "./data/random_200kB.data",
      "69edbe9f700eef273d1222b5e2c94d5caea6a7b77724bdc8030d9d9e",
      [](const std::string &path) -> ::so::Result<::so::Bytes> {return ::so::hash::fileSHA224(path);},
    },

  HashFileTestInput{
      "sha256",
      "./data/random_20kB.data",
      "c839f5a0a75ddf9191ed73cc1ad30eae966ebde2bc3e27ca8a446a271e47141d",
      [](const std::string &path) -> ::so::Result<::so::Bytes> {return ::so::hash::fileSHA256(path);},
    },

  HashFileTestInput{
      "sha256 200kB",
      "./data/random_200kB.data",
      "bfc175b14fd473e5faf2155da20b48bd807813756626b9a9fcbccd5f36c96438",
      [](const std::string &path) -> ::so::Result<::so::Bytes> {return ::so::hash::fileSHA256(path);},
    },

  HashFileTestInput{
      "sha384",
      "./data/random_20kB.data",
      "50855909d9c6b2c73ebb4f60ca9a66a26bcef06c03777aaa6326e66a606f97c6f3694bae339d57203444435e9fd0a2bb",
      [](const std::string &path) -> ::so::Result<::so::Bytes> {return ::so::hash::fileSHA384(path);},
    },

  HashFileTestInput{
      "sha384 200kB",
      "./data/random_200kB.data",
      "f4e62032ac0599de4da88013db1a6bbda9aa1cb3bd285cd91b0dc95724328ed1e0b9b866aa08371804783228feecaeb9",
      [](const std::string &path) -> ::so::Result<::so::Bytes> {return ::so::hash::fileSHA384(path);},
    },

  HashFileTestInput{
      "sha512",
      "./data/random_20kB.data",
      "db866b9b1c7b8c2f3419a0a1f3b1f44413480d9ee2b9472fdcf1e6a78ac0a0a71a3a7d742711bfffc30bf015e10f5b551f8d3c22277405d464ab5d50295554d5",
      [](const std::string &path) -> ::so::Result<::so::Bytes> {return ::so::hash::fileSHA512(path);},
    },

    HashFileTestInput{
      "sha512 200kB",
      "./data/random_200kB.data",
      "25cd6cd66a06e082be9ab2836605877b5d2f93177b8076dd13c6ad7f5a75ccf79835f41bde54386de862a385146fb4bc58c2d339e260fd3089c23d1de1fd4dc9",
      [](const std::string &path) -> ::so::Result<::so::Bytes> {return ::so::hash::fileSHA512(path);},
    }
);


INSTANTIATE_TEST_CASE_P(
    Hash,
    HashFileUT,
    testCases 
);

}}}
