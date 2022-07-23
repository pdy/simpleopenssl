/*
* Copyright (c) 2021 - 2022 Pawel Drzycimski
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
#include "../precalculated.h"
#include "../utils.h"
#include "../platform.h"

namespace so { namespace ut { namespace x509 {

namespace x509 = ::so::x509;

TEST(X509DERUT, certToDerFile)
{
  const std::string TMP_OUT_FILENAME = "data/tmp_der_cert.der";

  const unsigned char *it = data::validDerCert.get();
  auto cert = ::so::make_unique(d2i_X509(nullptr, &it, static_cast<long>(data::validDerCert.size())));
  ASSERT_TRUE(cert);

  auto scope = ::makeScopeGuard([&] { ::removeFile(TMP_OUT_FILENAME); });

  // WHEN
  const auto result = x509::convertX509ToDerFile(*cert, TMP_OUT_FILENAME.c_str(), TMP_OUT_FILENAME.size());

  // THEN
  ASSERT_TRUE(result);
  EXPECT_TRUE(utils::filesEqual("data/validdercert.der", TMP_OUT_FILENAME));
}

TEST(X509DERUT, certToDerFile_TooLongFileName)
{
  const std::string TMP_OUT_FILENAME = "data/tmp_der_cert.der";
  const std::string LONG_FILENAME = TMP_OUT_FILENAME + std::string(1024, '-');

  const unsigned char *it = data::validDerCert.get();
  auto cert = ::so::make_unique(d2i_X509(nullptr, &it, static_cast<long>(data::validDerCert.size())));
  ASSERT_TRUE(cert);

  auto scope = ::makeScopeGuard([&] { ::removeFile(TMP_OUT_FILENAME); });

  // WHEN
  const auto result = x509::convertX509ToDerFile(*cert, LONG_FILENAME.c_str(), TMP_OUT_FILENAME.size());

  // THEN
  ASSERT_TRUE(result);
  EXPECT_TRUE(utils::filesEqual("data/validdercert.der", TMP_OUT_FILENAME));
}

TEST(X509DERUT, certToDerFileNullTermString)
{
  const std::string TMP_OUT_FILENAME = "data/tmp_der_cert.der";

  const unsigned char *it = data::validDerCert.get();
  auto cert = ::so::make_unique(d2i_X509(nullptr, &it, static_cast<long>(data::validDerCert.size())));
  ASSERT_TRUE(cert);

  auto scope = ::makeScopeGuard([&] { ::removeFile(TMP_OUT_FILENAME); });

  // WHEN
  const auto result = x509::convertX509ToDerFile(*cert, TMP_OUT_FILENAME.c_str());

  // THEN
  ASSERT_TRUE(result);
  EXPECT_TRUE(utils::filesEqual("data/validdercert.der", TMP_OUT_FILENAME));
}

TEST(X509DERUT, derFileToCert)
{
  // WHEN
  const std::string filePath = "data/validdercert.der";
  auto cert = x509::convertDerFileToX509(filePath.c_str(), filePath.size());

  // THEN
  ASSERT_TRUE(cert);

  unsigned char *der = nullptr;
  const int len = i2d_X509(cert.value.get(), &der);
  ASSERT_TRUE(len >= 0); 
  EXPECT_TRUE(utils::equals(der, static_cast<size_t>(len), data::validDerCert));
  OPENSSL_free(der);
}

TEST(X509DERUT, derFileToCertNullTermStr)
{
  // WHEN
  const std::string filePath = "data/validdercert.der";
  auto cert = x509::convertDerFileToX509(filePath.c_str());

  // THEN
  ASSERT_TRUE(cert);

  unsigned char *der = nullptr;
  const int len = i2d_X509(cert.value.get(), &der);
  ASSERT_TRUE(len >= 0); 
  EXPECT_TRUE(utils::equals(der, static_cast<size_t>(len), data::validDerCert));
  OPENSSL_free(der);
}

}}}
