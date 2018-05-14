#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <simpleopenssl/simpleopenssl.h>
#include <chrono>

namespace so { namespace ut { namespace asn1 {

namespace asn1 = ::so::asn1;

TEST(Asn1UT, asn1TimeToStdTimeOK)
{
  // GIVEN
  auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  so::ASN1_TIME_uptr time;
  ASN1_TIME_set(time.get(), now);

  // WHEN
  auto actual = asn1::timeToStdTime(*time);

  // THEN
  ASSERT_TRUE(actual);
  EXPECT_EQ(now, *actual);
}

TEST(Asn1UT, asn1ApiTimeConvertersIntegrityOK)
{
  // GIVEN
  auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

  // WHEN
  auto maybeAsn1Time = asn1::stdTimeToTime(now);
  ASSERT_TRUE(maybeAsn1Time);
  auto asn1Time = maybeAsn1Time.moveValue();
  const auto stdTime = asn1::timeToStdTime(*asn1Time);
  ASSERT_TRUE(stdTime);

  // THEN
  EXPECT_EQ(now, *stdTime);
}

}}} // namespace so { namespace ut { namespace asn1 {
