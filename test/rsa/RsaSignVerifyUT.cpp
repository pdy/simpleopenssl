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

#include <vector>
#include <algorithm>
#include <numeric>
#include <functional>
#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.h>

#include "../precalculated.h"


namespace so { namespace ut { namespace rsa {

namespace rsa = ::so::rsa;
namespace evp = ::so::evp;

struct SignVerifyInput
{
  std::string shortDesc;
  std::string privKeyPem;
  std::string pubKeyPem;
  ::so::Bytes privKeyDer;
  ::so::Bytes pubKeyDer;
  ::so::Bytes signedData;
  ::so::Bytes signature;
  std::function<::so::Result<::so::Bytes>(const ::so::Bytes&, RSA&)> signer;
  std::function<::so::Result<bool>(const ::so::Bytes&,const ::so::Bytes&, RSA&)> verifier;
  std::function<::so::Result<bool>(const ::so::Bytes&,const ::so::Bytes&, EVP_PKEY&)> evpVerifier;
};

std::ostream& operator<<(std::ostream &oss, const SignVerifyInput &input)
{
  return oss << input.shortDesc;
}

class RsaSignVerifyUT : public ::testing::TestWithParam<SignVerifyInput>
{};

TEST_P(RsaSignVerifyUT, verify_AgainstPrecalculatedSignature)
{
  // GIVEN
  const SignVerifyInput input { GetParam() };
  auto maybePemKey = rsa::convertPemToPubKey(input.pubKeyPem);
  ASSERT_TRUE(maybePemKey);
  auto keyPem = maybePemKey.moveValue();

  auto maybeDerKey = rsa::convertDerToPubKey(input.pubKeyDer);
  ASSERT_TRUE(maybeDerKey);
  auto keyDer = maybeDerKey.moveValue();

  // WHEN
  const auto verifiedPem = input.verifier(input.signature, input.signedData, *keyPem); 
  const auto verifiedDer = input.verifier(input.signature, input.signedData, *keyDer); 

  // THEN
  ASSERT_TRUE(verifiedPem);
  EXPECT_TRUE(verifiedPem.value);
  ASSERT_TRUE(verifiedDer);
  EXPECT_TRUE(verifiedDer.value);
}

TEST_P(RsaSignVerifyUT, signVerify_PemDerConversionsAgainstPrecalculatedKey)
{
  // GIVEN
  const SignVerifyInput input { GetParam() };
  auto maybePemKey = rsa::convertPemToPrivKey(input.privKeyPem);
  ASSERT_TRUE(maybePemKey);
  auto pemKey = maybePemKey.moveValue();
  
  auto maybeDerKey = rsa::convertDerToPrivKey(input.privKeyDer);
  ASSERT_TRUE(maybeDerKey);
  auto derKey = maybeDerKey.moveValue();

  // WHEN
  const auto sigPem = input.signer(input.signedData, *pemKey); 
  ASSERT_TRUE(sigPem);
  const auto pemVerified = input.verifier(sigPem.value, input.signedData, *pemKey);
  ASSERT_TRUE(pemVerified);

  const auto sigDer = input.signer(input.signedData, *derKey); 
  ASSERT_TRUE(sigDer);
  const auto derVerified = input.verifier(sigDer.value, input.signedData, *derKey);
  ASSERT_TRUE(derVerified);

  // THEN
  EXPECT_TRUE(pemVerified.value);
  EXPECT_TRUE(derVerified.value);
}


TEST_P(RsaSignVerifyUT, signVerify_ApiIntegrity)
{
  // GIVEN
  const SignVerifyInput input { GetParam() };
  std::vector<uint8_t> data(256);
  std::iota(data.begin(), data.end(), 0); 
  auto key = rsa::create(rsa::KeyBits::_2048_);
  ASSERT_TRUE(key);

  auto keyUptr = key.moveValue();
  
  // WHEN
  const auto sig = input.signer(data, *keyUptr);
  const auto verResult = input.verifier(sig.value, data, *keyUptr);

  // THEN
  ASSERT_TRUE(verResult);
  ASSERT_TRUE(verResult.value);
}

TEST_P(RsaSignVerifyUT, signVerify_IntegrityWithEvp)
{
  // GIVEN
  const SignVerifyInput input { GetParam() };
  std::vector<uint8_t> data(256);
  std::iota(data.begin(), data.end(), 0); 
  auto key = rsa::create(rsa::KeyBits::_2048_);
  ASSERT_TRUE(key);

  auto keyUptr = key.moveValue();
  
  const auto sig = input.signer(data, *keyUptr);
  const auto verResult = input.verifier(sig.value, data, *keyUptr);

  // WHEN
  auto evpKey = rsa::convertToEvp(*keyUptr);
  const auto evpVerResult = input.evpVerifier(sig.value, data, *evpKey.moveValue());
  
  // THEN
  ASSERT_TRUE(verResult);
  EXPECT_TRUE(verResult.value);
  ASSERT_TRUE(evpVerResult);
  EXPECT_TRUE(evpVerResult.value);
}

const auto testCases = ::testing::Values(
  SignVerifyInput {
    "Sign/Verify with SHA1",
    data::rsa3072PrivKeyPem,
    data::rsa3072PubKeyPem,
    data::rsa3072PrivKeyDer,
    data::rsa3072PubKeyDer,
    data::signedTextBytes,
    data::signature_rsa_sha1,
    &::so::rsa::signSha1,
    &::so::rsa::verifySha1Signature,
    &::so::evp::verifySha1Signature
  },

  SignVerifyInput {
    "Sign/Verify with SHA224",
    data::rsa3072PrivKeyPem,
    data::rsa3072PubKeyPem,
    data::rsa3072PrivKeyDer,
    data::rsa3072PubKeyDer,
    data::signedTextBytes,
    data::signature_rsa_sha224,
    &::so::rsa::signSha224,
    &::so::rsa::verifySha224Signature,
    &::so::evp::verifySha224Signature
  },

  SignVerifyInput {
    "Sign/Verify with SHA256",
    data::rsa3072PrivKeyPem,
    data::rsa3072PubKeyPem,
    data::rsa3072PrivKeyDer,
    data::rsa3072PubKeyDer,
    data::signedTextBytes,
    data::signature_rsa_sha256,
    &::so::rsa::signSha256,
    &::so::rsa::verifySha256Signature,
    &::so::evp::verifySha256Signature
  },

  SignVerifyInput {
    "Sign/Verify with SHA384",
    data::rsa3072PrivKeyPem,
    data::rsa3072PubKeyPem,
    data::rsa3072PrivKeyDer,
    data::rsa3072PubKeyDer,
    data::signedTextBytes,
    data::signature_rsa_sha384,
    &::so::rsa::signSha384,
    &::so::rsa::verifySha384Signature,
    &::so::evp::verifySha384Signature
  },

  SignVerifyInput {
    "Sign/Verify with SHA512",
    data::rsa3072PrivKeyPem,
    data::rsa3072PubKeyPem,
    data::rsa3072PrivKeyDer,
    data::rsa3072PubKeyDer,
    data::signedTextBytes,
    data::signature_rsa_sha512,
    &::so::rsa::signSha512,
    &::so::rsa::verifySha512Signature,
    &::so::evp::verifySha512Signature
  }

);
INSTANTIATE_TEST_SUITE_P(
    Rsa,
    RsaSignVerifyUT,
    testCases 
);

}}}
