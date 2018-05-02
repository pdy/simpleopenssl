#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <simpleopenssl/simpleopenssl.h>
#include <chrono>

namespace so { namespace ut { namespace asn1 {

namespace asn1 = ::so::asn1;

TEST(Asn1UT, asn1TimeToStdTimeSuccess)
{
  // GIVEN
  auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  so::ASN1_TIME_uptr time;
  ASN1_TIME_set(time.get(), now);

  // WHEN
  auto actual = asn1::time2StdTime(*time);

  // THEN
  ASSERT_TRUE(actual);
  EXPECT_EQ(now, *actual);
}

}}} // namespace so { namespace ut { namespace asn1 {
