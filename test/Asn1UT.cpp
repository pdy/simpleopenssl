/*
* Copyright (c) 2018 Pawel Drzycimski
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*
*/

#include <gtest/gtest.h>

#include <simpleopenssl/simpleopenssl.h>
#include <chrono>

namespace so { namespace ut { namespace asn1 {

namespace asn1 = ::so::asn1;

TEST(Asn1UT, asn1TimeToStdTimeOK)
{
  // GIVEN
  auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  so::ASN1_TIME_uptr time = so::make_unique(ASN1_TIME_set(nullptr, now));

  // WHEN
  auto actual = asn1::convertToStdTime(*time);

  // THEN
  ASSERT_TRUE(actual);
  EXPECT_EQ(now, actual.value);
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
  EXPECT_EQ(now, stdTime.value);
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
  EXPECT_EQ(input, actual.value);
}

INSTANTIATE_TEST_SUITE_P(
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
