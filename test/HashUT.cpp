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
  std::function<::so::Expected<::so::Bytes>(const ::so::Bytes&)> hasher;
};

std::ostream& operator<<(std::ostream &s, const HashTestInput &i)
{
  return s << i.shortDesc;
}

class HashUT: public ::testing::TestWithParam<HashTestInput>
{};

TEST_P(HashUT, hash)
{
  const HashTestInput input { GetParam() };
  
  ::so::Bytes data(input.plaintext.size());
  std::transform(input.plaintext.begin(), input.plaintext.end(), data.begin(), [](char chr){return static_cast<uint8_t>(chr);});

  // WHEN
  const auto hash = input.hasher(data);

  // THEN
  ASSERT_TRUE(hash);
  EXPECT_EQ(input.expectedHexString, utils::bin2Hex(*hash));
}

const auto testCases = ::testing::Values(

    HashTestInput{
      "md4",
      "test_test_foobar",
      "e0e7ea8d8da4cd38dea5c40951292dae",
      ::so::hash::md4
    },

  HashTestInput{
      "md5",
      "test_test_foobar",
      "506c5777af0c699d27f0e1214343e90a",
      ::so::hash::md5
    },

  HashTestInput{
      "sha1",
      "test_test_foobar",
      "42316b3d7b91ddb03e3980173e66d59522ceafb0",
      ::so::hash::sha1
    },

  HashTestInput{
      "sha224",
      "test_test_foobar",
      "42388802eda260242eabb109f3959dca377cc326a4fe6ef0b6cf7b25",
      ::so::hash::sha224
    },

  HashTestInput{
      "sha256",
      "test_test_foobar",
      "bc454e8c3505ee0315b34389de085393a08e0eb7f5d600222207bbe3498c53a6",
      ::so::hash::sha256
    },

  HashTestInput{
      "sha384",
      "test_test_foobar",
      "9962cbe6aae7259c26a50f1892bcfab6b287ad0609a484739a2ac6d0f3e800533b369b663fd6ddc0bd7d3dee62801d4b",
      ::so::hash::sha384
    },

  HashTestInput{
      "sha512",
      "test_test_foobar",
      "781a5cfc1fb0cb51b550696fad366c37486000a69f70510701106db7e8081a381c0790f245e14cfbbb1eaee59c1e8811dc05d82cf75f50b7eabc1ff7923b0a08",
      ::so::hash::sha512
    }
);

INSTANTIATE_TEST_CASE_P(
    Hash,
    HashUT,
    testCases 
);
}}}
