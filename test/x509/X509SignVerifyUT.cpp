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

#include <numeric>
#include <simpleopenssl/simpleopenssl.h>

#include "../precalculated.h"
#include "../utils.h"

namespace so { namespace ut { namespace x509 {

namespace x509 = ::so::x509;

class X509SignVerifyUT : public ::testing::Test
{
protected:
  so::EVP_PKEY_uptr m_key;
  so::X509_uptr m_cert;
  so::ecdsa::Curve m_curve = so::ecdsa::Curve::SECP384R1;

  void SetUp() override
  {
    x509::Subject name;
    name.commonName = "CommonName";
    name.organizationName = "simpleopenssl";
    m_cert = ::so::make_unique(X509_new());
    ASSERT_TRUE(x509::setSubject(*m_cert, name));
    ASSERT_TRUE(x509::setIssuer(*m_cert, name));
    auto maybeEcKey = ::so::ecdsa::create(m_curve);
    ASSERT_TRUE(maybeEcKey);
    auto maybeKey = ::so::ecdsa::convertToEvp(*maybeEcKey.moveValue());
    ASSERT_TRUE(maybeKey);
    m_key = maybeKey.moveValue();
  }
};

TEST_F(X509SignVerifyUT, certSignSha1VerifyAPIIntegrity)
{
  // WHEN
  const auto signResult = x509::signSha1(*m_cert, *m_key);
  const auto verResult = x509::verifySignature(*m_cert, *m_key);

  // THEN
  ASSERT_TRUE(signResult);
  ASSERT_TRUE(verResult);
  EXPECT_TRUE(verResult.value);  
}

TEST_F(X509SignVerifyUT, certSignSha256VerifyAPIIntegrity)
{
  // WHEN
  const auto signResult = x509::signSha256(*m_cert, *m_key);
  const auto verResult = x509::verifySignature(*m_cert, *m_key);

  // THEN
  ASSERT_TRUE(signResult);
  ASSERT_TRUE(verResult);
  EXPECT_TRUE(verResult.value);  
}

TEST_F(X509SignVerifyUT, certSignSha384VerifyAPIIntegrity)
{
  // WHEN
  const auto signResult = x509::signSha384(*m_cert, *m_key);
  const auto verResult = x509::verifySignature(*m_cert, *m_key);

  // THEN
  ASSERT_TRUE(signResult);
  ASSERT_TRUE(verResult);
  EXPECT_TRUE(verResult.value);  
}

TEST_F(X509SignVerifyUT, certSignSha512VerifyAPIIntegrity)
{
  // WHEN
  const auto signResult = x509::signSha512(*m_cert, *m_key);
  const auto verResult = x509::verifySignature(*m_cert, *m_key);

  // THEN
  ASSERT_TRUE(signResult);
  ASSERT_TRUE(verResult);
  EXPECT_TRUE(verResult.value);  
}

}}} // namespace so ut x509
