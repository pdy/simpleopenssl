#include <simpleopenssl/simpleopenssl.h>

#include <gtest/gtest.h>

#include <sstream>

#include "utils.h"

namespace so { namespace ut { namespace hash {

namespace hash = ::so::hash;

struct HashTestInput
{
  std::string shortDesc;
  std::string plaintext;
  std::string expectedHexString;
  std::function<::so::Result<::so::Bytes>(const ::so::Bytes&)> hasher;
  std::function<::so::Result<::so::Bytes>(const ::std::string&)> strHasher;
};

inline std::ostream& operator<<(std::ostream &s, const HashTestInput &i)
{
  return s << i.shortDesc;
}

class HashUT: public ::testing::TestWithParam<HashTestInput>
{};

TEST_P(HashUT, hash)
{
  // GIVEN
  const auto input { GetParam() };  
  const auto data = utils::toBytes(input.plaintext);

  // WHEN
  const auto btHash = input.hasher(data);
  const auto strHash = input.strHasher(input.plaintext);

  // THEN
  ASSERT_TRUE(btHash);
  ASSERT_TRUE(strHash);
  EXPECT_EQ(input.expectedHexString, utils::bin2Hex(*btHash));
  EXPECT_EQ(input.expectedHexString, utils::bin2Hex(*strHash));
}

const auto testCases = ::testing::Values(

    HashTestInput{
      "md4",
      "test_test_foobar",
      "e0e7ea8d8da4cd38dea5c40951292dae",
      [](const ::so::Bytes &bytes) -> ::so::Result<::so::Bytes> {return ::so::hash::md4(bytes);},
      [](const ::std::string &str) -> ::so::Result<::so::Bytes> {return ::so::hash::md4(str);}
    },

  HashTestInput{
      "md5",
      "test_test_foobar",
      "506c5777af0c699d27f0e1214343e90a",
      [](const ::so::Bytes &bytes) -> ::so::Result<::so::Bytes> {return ::so::hash::md5(bytes);},
      [](const ::std::string &str) -> ::so::Result<::so::Bytes> {return ::so::hash::md5(str);}
    },

  HashTestInput{
      "sha1",
      "test_test_foobar",
      "42316b3d7b91ddb03e3980173e66d59522ceafb0",
      [](const ::so::Bytes &bytes) -> ::so::Result<::so::Bytes> {return ::so::hash::sha1(bytes);},
      [](const ::std::string &str) -> ::so::Result<::so::Bytes> {return ::so::hash::sha1(str);}
    },

  HashTestInput{
      "sha224",
      "test_test_foobar",
      "42388802eda260242eabb109f3959dca377cc326a4fe6ef0b6cf7b25",
      [](const ::so::Bytes &bytes) -> ::so::Result<::so::Bytes> {return ::so::hash::sha224(bytes);},
      [](const ::std::string &str) -> ::so::Result<::so::Bytes> {return ::so::hash::sha224(str);}
    },

  HashTestInput{
      "sha256",
      "test_test_foobar",
      "bc454e8c3505ee0315b34389de085393a08e0eb7f5d600222207bbe3498c53a6",
      [](const ::so::Bytes &bytes) -> ::so::Result<::so::Bytes> {return ::so::hash::sha256(bytes);},
      [](const ::std::string &str) -> ::so::Result<::so::Bytes> {return ::so::hash::sha256(str);}
    },

  HashTestInput{
      "sha384",
      "test_test_foobar",
      "9962cbe6aae7259c26a50f1892bcfab6b287ad0609a484739a2ac6d0f3e800533b369b663fd6ddc0bd7d3dee62801d4b",
      [](const ::so::Bytes &bytes) -> ::so::Result<::so::Bytes> {return ::so::hash::sha384(bytes);},
      [](const ::std::string &str) -> ::so::Result<::so::Bytes> {return ::so::hash::sha384(str);}
    },

  HashTestInput{
      "sha512",
      "test_test_foobar",
      "781a5cfc1fb0cb51b550696fad366c37486000a69f70510701106db7e8081a381c0790f245e14cfbbb1eaee59c1e8811dc05d82cf75f50b7eabc1ff7923b0a08",
      [](const ::so::Bytes &bytes) -> ::so::Result<::so::Bytes> {return ::so::hash::sha512(bytes);},
      [](const ::std::string &str) -> ::so::Result<::so::Bytes> {return ::so::hash::sha512(str);}
    }
);

INSTANTIATE_TEST_CASE_P(
    Hash,
    HashUT,
    testCases 
);
}}}
