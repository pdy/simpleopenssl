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
  std::function<::so::Expected<::so::Bytes>(const std::string&)> hasher;
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
      [](const std::string &path) -> ::so::Expected<::so::Bytes> {return ::so::hash::fileMD4(path);},
    },

  HashFileTestInput{
      "md5",
      "./data/random_20kB.data",
      "3a230011272f3d219e3999833b8df77a",
      [](const std::string &path) -> ::so::Expected<::so::Bytes> {return ::so::hash::fileMD5(path);},
    },

  HashFileTestInput{
      "sha1",
      "./data/random_20kB.data",
      "7da2e0276dacd60dd9208d8c0c56cfc7560c9140",
      [](const std::string &path) -> ::so::Expected<::so::Bytes> {return ::so::hash::fileSHA1(path);},
    },

  HashFileTestInput{
      "sha224",
      "./data/random_20kB.data",
      "32823f3099a7610848cc3db940f5b477523e42f35b7db280e749cde2",
      [](const std::string &path) -> ::so::Expected<::so::Bytes> {return ::so::hash::fileSHA224(path);},
    },

  HashFileTestInput{
      "sha256",
      "./data/random_20kB.data",
      "c839f5a0a75ddf9191ed73cc1ad30eae966ebde2bc3e27ca8a446a271e47141d",
      [](const std::string &path) -> ::so::Expected<::so::Bytes> {return ::so::hash::fileSHA256(path);},
    },

  HashFileTestInput{
      "sha384",
      "./data/random_20kB.data",
      "50855909d9c6b2c73ebb4f60ca9a66a26bcef06c03777aaa6326e66a606f97c6f3694bae339d57203444435e9fd0a2bb",
      [](const std::string &path) -> ::so::Expected<::so::Bytes> {return ::so::hash::fileSHA384(path);},
    },

  HashFileTestInput{
      "sha512",
      "./data/random_20kB.data",
      "db866b9b1c7b8c2f3419a0a1f3b1f44413480d9ee2b9472fdcf1e6a78ac0a0a71a3a7d742711bfffc30bf015e10f5b551f8d3c22277405d464ab5d50295554d5",
      [](const std::string &path) -> ::so::Expected<::so::Bytes> {return ::so::hash::fileSHA512(path);},
    }
);

INSTANTIATE_TEST_CASE_P(
    Hash,
    HashFileUT,
    testCases 
);

}}}
