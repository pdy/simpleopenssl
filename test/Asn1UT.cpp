#include <gtest/gtest.h>
//#include <gmock/gmock.h>

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
  auto actual = asn1::convertToStdTime(*time);

  // THEN
  ASSERT_TRUE(actual);
  EXPECT_EQ(now, *actual);
}

TEST(Asn1UT, asn1ApiTimeConvertersIntegrityOK)
{
  // GIVEN
  auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

  // WHEN
  auto maybeAsn1Time = asn1::convertToAsn1Time(now);
  ASSERT_TRUE(maybeAsn1Time);
  auto asn1Time = maybeAsn1Time.moveValue();
  const auto stdTime = asn1::convertToStdTime(*asn1Time);
  ASSERT_TRUE(stdTime);

  // THEN
  EXPECT_EQ(now, *stdTime);
}

class Asn1ObjectEncodeUT : public testing::TestWithParam<std::string>
{};

TEST_P(Asn1ObjectEncodeUT, encodeDecodeApiIntegrity)
{
  // GIVEN
  const std::string input { GetParam() };

  // WHEN
  auto maybeEncoded = asn1::encodeObject(input);
  ASSERT_TRUE(maybeEncoded);
  auto encoded = maybeEncoded.moveValue();
  auto actual = asn1::convertObjToStr(*encoded);
  
  // THEN
  ASSERT_TRUE(actual);
  EXPECT_EQ(input, *actual);
}

INSTANTIATE_TEST_CASE_P(
    Asn1UT,
    Asn1ObjectEncodeUT,
    ::testing::Values(
      std::string{"name"},
      std::string{"1.3.6.1.4.1.343"},
      std::string{"2.1.5.3.6.1.243"},
      std::string{"serialNumber"},
      std::string{"md5WithRSAEncryption"},
      std::string{"userPassword"}
  )
);

}}} // namespace so { namespace ut { namespace asn1 {
