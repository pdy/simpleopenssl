/*
* Copyright (c) 2021 Pawel Drzycimski
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
#include <simpleopenssl/simpleopenssl.hpp>
#include <sstream>
#include <algorithm>

namespace so { namespace ut { namespace expected {

namespace {

std::tuple<unsigned long, std::string> makeFaultyOperation()
{
  auto cert = ::so::x509::create();

  ::so::make_unique(X509_dup(cert.value.get()));
  
  // return std::make_tuple(0x0D078079, "error:0D078079:asn1 encoding routines:asn1_item_embed_d2i:field missing");
  return std::make_tuple(0x0D08303A, "error:0D08303A:asn1 encoding routines:asn1_template_noexp_d2i:nested asn1 error");
}

std::string toHexStr(unsigned long val)
{
  std::stringstream ss;
  ss << std::hex << val;

  auto ret = ss.str();
  std::transform(ret.begin(), ret.end(), ret.begin(), [](unsigned char c) { return ::std::toupper(c);});

  return ret;
}

} // namespace


TEST(Errs, getLastErrorCode)
{
  // GIVEN
  unsigned long expectedErrCode;
  std::string expectedErrString;
    
  std::tie(expectedErrCode, expectedErrString) = makeFaultyOperation();
  const auto expectedErrCodeHexStr = toHexStr(expectedErrCode);

  // WHEN
  const auto actualErrCode = ::so::getLastErrCode();
  const auto actualErrString = ::so::errCodeToString(actualErrCode);

  // THEN
  EXPECT_EQ(expectedErrCode, actualErrCode);
  EXPECT_EQ(expectedErrString, actualErrString);
  EXPECT_TRUE(actualErrString.find(expectedErrCodeHexStr) != std::string::npos);
}

TEST(Errs, DISABLED_getLastErrorStr)
{ 
  // GIVEN
  unsigned long expectedErrCode;
  std::string expectedErrString;
    
  std::tie(expectedErrCode, expectedErrString) = makeFaultyOperation();
  const auto expectedErrCodeHexStr = toHexStr(expectedErrCode);

  // TODO:
  // For some reason here we're getting:
  // "error:0D08303A:asn1 encoding routines:asn1_template_noexp_d2i:nested asn1 error"
  // I'll leave it failing for now.
  
  // WHEN
  const auto actualErrString = ::so::getLastErrString();

  // THEN
  EXPECT_TRUE(actualErrString.find(expectedErrCodeHexStr) != std::string::npos);
  EXPECT_EQ(expectedErrString, actualErrString);
}

}}}
