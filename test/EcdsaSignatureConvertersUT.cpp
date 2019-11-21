#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.h>

#include "precalculated.h"

namespace so { namespace ut { namespace ecdsa {

namespace ecdsa = ::so::ecdsa;

TEST(ecdsa, derSignatureBytesToSignatureStruct)
{
  // GIVEN
  const ecdsa::Signature expected { data::signature_sha256_R, data::signature_sha256_S };

  // WHEN
  auto maybeSig = ecdsa::convertToSignature(data::signature_sha256);
  ASSERT_TRUE(maybeSig);
  
  auto sig = maybeSig.moveValue();

  // THEN
  EXPECT_EQ(expected, sig); 
}

TEST(ecdsa, signatureStructToDerBytes)
{
  // GIVEN
  const so::Bytes expected { data::signature_sha256 };
  const ecdsa::Signature sig { data::signature_sha256_R, data::signature_sha256_S };

  // WHEN
  auto maybeDer = ecdsa::convertToDer(sig);
  ASSERT_TRUE(maybeDer);

  auto der = maybeDer.moveValue();

  // THEN
  ASSERT_EQ(expected.size(), der.size());
  EXPECT_TRUE(std::equal(expected.begin(), expected.end(), der.begin()));
}

}}} // namespace so { namespace ut { namespace ecdsa {
