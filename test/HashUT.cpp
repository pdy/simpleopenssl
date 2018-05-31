#include <simpleopenssl/simpleopenssl.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sstream>

#include "utils.h"

namespace so { namespace ut { namespace hash {

namespace hash = ::so::hash;

TEST(Hash, md4)
{
  // GIVEN
  // generated using 'openssl md4' on debian
  const std::string str = "test_test_foobar";
  const std::string expectedHexString = "e0e7ea8d8da4cd38dea5c40951292dae";
  ::so::Bytes data(str.size());
  std::transform(str.begin(), str.end(), data.begin(), [](char chr){return static_cast<uint8_t>(chr);});

  // WHEN
  const auto hash = hash::md4(data);

  // THEN
  ASSERT_TRUE(hash);
  EXPECT_EQ(expectedHexString, utils::bin2Hex(*hash));
}

TEST(Hash, md5)
{
  // GIVEN
  // generated using debian's builtin md5sum
  const std::string str = "test_test_foobar";
  const std::string expectedHexString = "506c5777af0c699d27f0e1214343e90a";
  ::so::Bytes data(str.size());
  std::transform(str.begin(), str.end(), data.begin(), [](char chr){return static_cast<uint8_t>(chr);});

  // WHEN
  const auto hash = hash::md5(data);

  // THEN
  ASSERT_TRUE(hash);
  EXPECT_EQ(expectedHexString, utils::bin2Hex(*hash));
}

TEST(Hash, sha1)
{
  // GIVEN
  // generated using debian's builtin sha1sum
  const std::string str = "test_test_foobar";
  const std::string expectedHexString = "42316b3d7b91ddb03e3980173e66d59522ceafb0";
  ::so::Bytes data(str.size());
  std::transform(str.begin(), str.end(), data.begin(), [](char chr){return static_cast<uint8_t>(chr);});

  // WHEN
  const auto hash = hash::sha1(data);

  // THEN
  ASSERT_TRUE(hash);
  EXPECT_EQ(expectedHexString, utils::bin2Hex(*hash));
}

TEST(Hash, sha224)
{
  // GIVEN
  // generated using debian's builtin sha224sum
  const std::string str = "test_test_foobar";
  const std::string expectedHexString = "42388802eda260242eabb109f3959dca377cc326a4fe6ef0b6cf7b25";
  ::so::Bytes data(str.size());
  std::transform(str.begin(), str.end(), data.begin(), [](char chr){return static_cast<uint8_t>(chr);});

  // WHEN
  const auto hash = hash::sha224(data);

  // THEN
  ASSERT_TRUE(hash);
  EXPECT_EQ(expectedHexString, utils::bin2Hex(*hash));
}

TEST(Hash, sha256)
{
  // GIVEN
  // generated using debian's builtin sha256sum
  const std::string str = "test_test_foobar";
  const std::string expectedHexString = "bc454e8c3505ee0315b34389de085393a08e0eb7f5d600222207bbe3498c53a6";
  ::so::Bytes data(str.size());
  std::transform(str.begin(), str.end(), data.begin(), [](char chr){return static_cast<uint8_t>(chr);});

  // WHEN
  const auto hash = hash::sha256(data);

  // THEN
  ASSERT_TRUE(hash);
  EXPECT_EQ(expectedHexString, utils::bin2Hex(*hash));
}

TEST(Hash, sha384)
{
  // GIVEN
  // generated using debian's builtin sha384sum
  const std::string str = "test_test_foobar";
  const std::string expectedHexString = "9962cbe6aae7259c26a50f1892bcfab6b287ad0609a484739a2ac6d0f3e800533b369b663fd6ddc0bd7d3dee62801d4b";
  ::so::Bytes data(str.size());
  std::transform(str.begin(), str.end(), data.begin(), [](char chr){return static_cast<uint8_t>(chr);});

  // WHEN
  const auto hash = hash::sha384(data);

  // THEN
  ASSERT_TRUE(hash);
  EXPECT_EQ(expectedHexString, utils::bin2Hex(*hash));
}

TEST(Hash, sha512)
{
  // GIVEN
  // generated using debian's builtin sha512sum
  const std::string str = "test_test_foobar";
  const std::string expectedHexString = "781a5cfc1fb0cb51b550696fad366c37486000a69f70510701106db7e8081a381c0790f245e14cfbbb1eaee59c1e8811dc05d82cf75f50b7eabc1ff7923b0a08";
  ::so::Bytes data(str.size());
  std::transform(str.begin(), str.end(), data.begin(), [](char chr){return static_cast<uint8_t>(chr);});

  // WHEN
  const auto hash = hash::sha512(data);

  // THEN
  ASSERT_TRUE(hash);
  EXPECT_EQ(expectedHexString, utils::bin2Hex(*hash));
} 

}}} // namespace so { namespace ut { namepsace hash
