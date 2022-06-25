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
#include <numeric>
#include <functional>
#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.hpp>

#include "../precalculated.h"


namespace so { namespace ut { namespace ecdsa {

namespace ecdsa = ::so::ecdsa;
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
  std::function<::so::Result<::so::Bytes>(const ::so::Bytes&, EC_KEY&)> signer;
  std::function<::so::Result<bool>(const ::so::Bytes&,const ::so::Bytes&, EC_KEY&)> verifier;
  std::function<::so::Result<bool>(const ::so::Bytes&,const ::so::Bytes&, EVP_PKEY&)> evpVerifier;
};

// so that gtest failure log would be more descriptive
std::ostream& operator<<(std::ostream &s, const SignVerifyInput &input)
{
  return s << input.shortDesc;
}

class EcdsaSignVerifyUT : public ::testing::TestWithParam<SignVerifyInput>
{};

TEST_P(EcdsaSignVerifyUT, verify_AgainstPrecalculatedSignature)
{
  // GIVEN
  const SignVerifyInput input { GetParam() };
  auto maybeKeyDer = ecdsa::convertPemToPubKey(input.pubKeyPem);
  ASSERT_TRUE(maybeKeyDer);
  auto keyPem = maybeKeyDer.moveValue();

  auto maybeDerKey = ecdsa::convertDerToPubKey(input.pubKeyDer);
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

TEST_P(EcdsaSignVerifyUT, signVerify_AgainstPrecalculatedKey)
{
  // GIVEN
  const SignVerifyInput input { GetParam() };
  auto maybeKeyPem = ecdsa::convertPemToPrivKey(input.privKeyPem);
  ASSERT_TRUE(maybeKeyPem);
  auto keyPem = maybeKeyPem.moveValue();

  auto maybeKeyDer = ecdsa::convertDerToPrivKey(input.privKeyDer);
  ASSERT_TRUE(maybeKeyPem);
  auto keyDer = maybeKeyDer.moveValue();

  // WHEN
  const auto sigPem = input.signer(input.signedData, *keyPem); 
  ASSERT_TRUE(sigPem);
  const auto verifiedPem = input.verifier(sigPem.value, input.signedData, *keyPem);
  ASSERT_TRUE(verifiedPem);

  const auto sigDer = input.signer(input.signedData, *keyDer); 
  ASSERT_TRUE(sigPem);
  const auto verifiedDer = input.verifier(sigDer.value, input.signedData, *keyDer);
  ASSERT_TRUE(verifiedDer);

  // THEN
  EXPECT_TRUE(verifiedPem.value);
  EXPECT_TRUE(verifiedDer.value);
}

TEST_P(EcdsaSignVerifyUT, signVerify_ApiIntegrity)
{
  // GIVEN
  const SignVerifyInput input { GetParam() };
  std::vector<uint8_t> data(256);
  std::iota(data.begin(), data.end(), 0); 
  auto key = ecdsa::create(ecdsa::Curve::SECP224R1);
  ASSERT_TRUE(key);

  auto keyUptr = key.moveValue();
  
  // WHEN
  const auto sig = input.signer(data, *keyUptr);
  const auto verResult = input.verifier(sig.value, data, *keyUptr);

  // THEN
  ASSERT_TRUE(verResult);
  ASSERT_TRUE(verResult.value);
}

TEST_P(EcdsaSignVerifyUT, signVerify_IntegrityWithEvp)
{
  // GIVEN
  const SignVerifyInput input { GetParam() };
  std::vector<uint8_t> data(256);
  std::iota(data.begin(), data.end(), 0); 
  auto key = ecdsa::create(ecdsa::Curve::SECT233K1);
  ASSERT_TRUE(key);

  auto keyUptr = key.moveValue();
  
  const auto sig = input.signer(data, *keyUptr);
  const auto verResult = input.verifier(sig.value, data, *keyUptr);

  // WHEN
  auto evpKey = ecdsa::convertToEvp(*keyUptr);
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
    data::secp256k1PrivKeyPem,
    data::secp256PubKeyPem,
    data::secp256k1PrivKeyDer,
    data::secp256PubKeyDer,
    data::signedTextBytes,
    data::signature_sha1,
    &::so::ecdsa::signSha1,
    &::so::ecdsa::verifySha1Signature,
    &::so::evp::verifySha1Signature   
  },
  
  SignVerifyInput {
    "Sign/Verify with SHA224",
    data::secp256k1PrivKeyPem,
    data::secp256PubKeyPem,
    data::secp256k1PrivKeyDer,
    data::secp256PubKeyDer,
    data::signedTextBytes,
    data::signature_sha224,
    &::so::ecdsa::signSha224,
    &::so::ecdsa::verifySha224Signature,
    &::so::evp::verifySha224Signature   
  },

  SignVerifyInput {
    "Sign/Verify with SHA256",
    data::secp256k1PrivKeyPem,
    data::secp256PubKeyPem,
    data::secp256k1PrivKeyDer,
    data::secp256PubKeyDer,
    data::signedTextBytes,
    data::signature_sha256,
    &::so::ecdsa::signSha256,
    &::so::ecdsa::verifySha256Signature,
    &::so::evp::verifySha256Signature   
  },

  SignVerifyInput {
    "Sign/Verify with SHA384",
    data::secp256k1PrivKeyPem,
    data::secp256PubKeyPem,
    data::secp256k1PrivKeyDer,
    data::secp256PubKeyDer,
    data::signedTextBytes,
    data::signature_sha384,
    &::so::ecdsa::signSha384,
    &::so::ecdsa::verifySha384Signature,
    &::so::evp::verifySha384Signature   
  },
  
  SignVerifyInput {
    "Sign/Verify with SHA512",
    data::secp256k1PrivKeyPem,
    data::secp256PubKeyPem,
    data::secp256k1PrivKeyDer,
    data::secp256PubKeyDer,
    data::signedTextBytes,
    data::signature_sha512,
    &::so::ecdsa::signSha512,
    &::so::ecdsa::verifySha512Signature,
    &::so::evp::verifySha512Signature   
  }
  
);

INSTANTIATE_TEST_SUITE_P(
    Ecdsa,
    EcdsaSignVerifyUT,
    testCases 
);

}}} //namespace so { namespace ut { namespace ecdsa {
