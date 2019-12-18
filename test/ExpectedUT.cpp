#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.h>
#include "utils.h"

namespace so { namespace ut { namespace expected {

//template<typename T>
//using Expected = ::so::Expected<T>;

TEST(ExpectedUT, okUsageWithBytes)
{
  // WHEN
  const auto expected = ::so::internal::ok(::so::Bytes{0x00, 0x01});

  // THEN
  EXPECT_TRUE(expected);
  EXPECT_TRUE(expected.hasValue());
  EXPECT_FALSE(expected.hasError());
  EXPECT_EQ(static_cast<unsigned long>(0), expected.errorCode());
  EXPECT_EQ("ok", expected.msg());
  EXPECT_EQ((::so::Bytes{0x00, 0x01}), *expected);
  EXPECT_EQ((::so::Bytes{0x00, 0x01}), expected.value());
}

TEST(ExpectedUT, errUsageWithBytes)
{
  // WHEN
  const auto expected = ::so::internal::err<::so::Bytes>(5);

  // THEN
  EXPECT_FALSE(expected);
  EXPECT_FALSE(expected.hasValue());
  EXPECT_TRUE(expected.hasError());
  EXPECT_EQ(static_cast<unsigned long>(5), expected.errorCode());
  EXPECT_EQ((::so::Bytes{}), *expected);
  EXPECT_EQ((::so::Bytes{}), expected.value());
}

TEST(ExpectedUT, okUsageWithUptrs)
{
  // WHEN
  const auto expected = ::so::internal::ok(::so::make_unique<BIGNUM>(nullptr));

  // THEN
  EXPECT_TRUE(expected);
  EXPECT_TRUE(expected.hasValue());
  EXPECT_FALSE(expected.hasError());
  EXPECT_EQ(static_cast<unsigned long>(0), expected.errorCode());
  EXPECT_EQ("ok", expected.msg());
}

TEST(ExpectedUT, errUsageWithUptrs)
{
  // WHEN 
  const auto expected = ::so::internal::err<::so::BIGNUM_uptr>(5);

  // THEN
  EXPECT_FALSE(expected);
  EXPECT_FALSE(expected.hasValue());
  EXPECT_TRUE(expected.hasError());
  EXPECT_EQ(static_cast<unsigned long>(5), expected.errorCode());
}

}}} // namespace so { namespace ut { namespace bignum {
