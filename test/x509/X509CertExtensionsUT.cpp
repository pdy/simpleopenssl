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

#include <numeric>
#include <simpleopenssl/simpleopenssl.h>

#include "../precalculated.h"
#include "../utils.h"

namespace so { namespace ut { namespace x509 {

namespace x509 = ::so::x509;


namespace {

  inline std::ostream& operator<<(std::ostream &oss, const x509::CertExtension &ext)
  {
    oss << "Name [" << ext.name << "] oid [" << ext.oidNumerical << "] Data [";
    std::copy(ext.data.begin(), ext.data.end(), std::ostream_iterator<char>(oss, ""));
    return oss << "] " << "critical [" << ext.critical << "]\n";
  }
 
} // anonymous namespace 


TEST(X509CertExtensionsUT, getExtensionCountShouldEqualToZero)
{
  // GIVEN
  auto cert = so::make_unique(X509_new());

  // WHEN
  const auto extCount = x509::getExtensionsCount(*cert);

  // THEN
  const size_t expected = 0;  
  EXPECT_TRUE(extCount);
  EXPECT_EQ(expected, extCount.value);
}

TEST(X509CertExtensionsUT, getExtensionsCountShouldEqualToThree)
{
  // GIVEN
  auto maybeCert = x509::convertPemToX509(data::selfSignedCAPemCert);
  ASSERT_TRUE(maybeCert);
  auto cert = maybeCert.moveValue();

  // WHEN
  const auto extCount = x509::getExtensionsCount(*cert);
  
  // THEN
  ASSERT_TRUE(extCount);
  EXPECT_EQ(3, extCount.value);
}

TEST(X509CertExtensionsUT, getExtensions)
{
  // GIVEN
  const std::vector<x509::CertExtension> expected {
    {
      x509::CertExtensionId::SUBJECT_KEY_IDENTIFIER,
      false,
      "X509v3 Subject Key Identifier",
      "2.5.29.14",
      internal::bytes::fromString("75:71:A7:19:48:19:BC:9D:9D:EA:41:47:DF:94:C4:48:77:99:D3:79")
    },
    {
      x509::CertExtensionId::KEY_USAGE,
      true,
      "X509v3 Key Usage",
      "2.5.29.15",
      internal::bytes::fromString("Certificate Sign, CRL Sign")
    },
    {
      x509::CertExtensionId::BASIC_CONSTRAINTS,
      true,
      "X509v3 Basic Constraints",
      "2.5.29.19",
      internal::bytes::fromString("CA:TRUE")
    } 
  };
  
  auto maybeCert = x509::convertPemToX509(data::selfSignedCAPemCert);
  ASSERT_TRUE(maybeCert);
  auto cert = maybeCert.moveValue();

  // WHEN
  const auto extCount = x509::getExtensionsCount(*cert);
  const auto extensions = x509::getExtensions(*cert);
  

  // THEN
  ASSERT_TRUE(extCount);
  ASSERT_TRUE(extensions);
  ASSERT_EQ(extCount.value, (extensions.value).size());
  ASSERT_EQ(expected.size(), (extensions.value).size());
  ASSERT_EQ(expected, (extensions.value));
}

TEST(X509CertExtensionsUT, getExtensionKeyUsage)
{
  // GIVEN
  const x509::CertExtension expected {
    x509::CertExtensionId::KEY_USAGE,
    true,
    "X509v3 Key Usage",
    "2.5.29.15",
    internal::bytes::fromString("Certificate Sign, CRL Sign")
  };

  auto maybeCert = x509::convertPemToX509(data::selfSignedCAPemCert);
  ASSERT_TRUE(maybeCert);
  auto cert = maybeCert.moveValue();

  // WHEN
  const auto extension = x509::getExtension(*cert, x509::CertExtensionId::KEY_USAGE);
  
  // THEN
  ASSERT_TRUE(extension);
  EXPECT_EQ(expected, extension.value);
}

TEST(X509CertExtensionsUT, getExtensionKeyUsageByOidNumerical)
{
  // GIVEN
  const std::string oidToFind = "2.5.29.15";
  const x509::CertExtension expected {
    x509::CertExtensionId::KEY_USAGE,
    true,
    "X509v3 Key Usage",
    oidToFind,
    internal::bytes::fromString("Certificate Sign, CRL Sign")
  };

  auto maybeCert = x509::convertPemToX509(data::selfSignedCAPemCert);
  ASSERT_TRUE(maybeCert);
  auto cert = maybeCert.moveValue();

  // WHEN
  const auto extension = x509::getExtension(*cert, oidToFind);
  
  // THEN
  ASSERT_TRUE(extension);
  EXPECT_EQ(expected, extension.value);
}

TEST(X509CertExtensionsUT, getExtensionShouldReturnErrorWhenExtensionDoesNotExists)
{
  // GIVEN 
  auto maybeCert = x509::convertPemToX509(data::selfSignedCAPemCert);
  ASSERT_TRUE(maybeCert);
  auto cert = maybeCert.moveValue();

  // WHEN
  const auto extension = x509::getExtension(*cert, x509::CertExtensionId::TLS_FEATURE);
  
  // THEN
  ASSERT_FALSE(extension);
}

TEST(X509CertExtensionsUT, addCustomExtensionAPIIntegrity)
{
  // GIVEN
  const x509::CertExtension expected {
    x509::CertExtensionId::UNDEF,
    false,
    "",
    // intel net adapter found at http://oid-info.com
    "1.3.6.1.4.1.343.2.7.2",
    {0xaa, 0xbb}
  }; 
  auto cert = so::make_unique(X509_new());
  ASSERT_TRUE(cert);
  auto maybeData = so::asn1::encodeOctet(expected.data);
  ASSERT_TRUE(maybeData);
  auto data = maybeData.moveValue();

  // WHEN
  const auto addResult = x509::setCustomExtension(*cert, expected.oidNumerical, *data);
  auto getResult = x509::getExtensions(*cert);

  // THEN
  ASSERT_TRUE(addResult);
  ASSERT_TRUE(getResult);
  ASSERT_EQ(1, (getResult.value).size());
  EXPECT_EQ(expected, (getResult.value).at(0));
}

TEST(X509CertExtensionsUT, addCustomExtensionUsingLibraryStructure)
{
  // GIVEN
  const x509::CertExtension expected {
    x509::CertExtensionId::UNDEF,
    false,
    "",
    // intel net adapter found at http://oid-info.com
    "1.3.6.1.4.1.343.2.7.2",
    {0xaa, 0xbb}
  }; 
  auto cert = so::make_unique(X509_new());
  ASSERT_TRUE(cert);
  auto maybeData = so::asn1::encodeOctet(expected.data);
  ASSERT_TRUE(maybeData);
  auto data = maybeData.moveValue();

  // WHEN
  const auto addResult = x509::setExtension(*cert, expected);
  auto getResult = x509::getExtensions(*cert);

  // THEN
  ASSERT_TRUE(addResult);
  ASSERT_TRUE(getResult);
  ASSERT_EQ(1, (getResult.value).size());
  EXPECT_EQ(expected, (getResult.value).at(0));
}

TEST(X509CertExtensionsUT, addExtensionUsingLibraryStructure)
{
  // GIVEN
  const x509::CertExtension expected {
    x509::CertExtensionId::BASIC_CONSTRAINTS,
    false,
    "",
    "",
    internal::bytes::fromString("CA:TRUE")
  }; 
  auto cert = so::make_unique(X509_new());
  ASSERT_TRUE(cert);
  auto maybeData = so::asn1::encodeOctet(expected.data);
  ASSERT_TRUE(maybeData);
  auto data = maybeData.moveValue();

  // WHEN
  const auto addResult = x509::setExtension(*cert, expected);
  auto getResult = x509::getExtension(*cert, x509::CertExtensionId::BASIC_CONSTRAINTS);

  // THEN
  ASSERT_TRUE(addResult);
  ASSERT_TRUE(getResult);
  EXPECT_EQ(x509::CertExtensionId::BASIC_CONSTRAINTS, (getResult.value).id);
  EXPECT_EQ(false, (getResult.value).critical);
  EXPECT_EQ("X509v3 Basic Constraints", (getResult.value).name);
  EXPECT_EQ("2.5.29.19", (getResult.value).oidNumerical);
  EXPECT_EQ(expected.data, (getResult.value).data);
}

TEST(X509CertExtensionsUT, addCustomExtensionAndGetByOID_APIIntegrity)
{
  // GIVEN 
  // intel net adapter found at http://oid-info.com
  const std::string oidToFind = "1.3.6.1.4.1.343.2.7.2";
  const x509::CertExtension expected {
    x509::CertExtensionId::UNDEF,
    false,
    "",
    oidToFind,
    {0xaa, 0xbb}
  }; 
  auto cert = so::make_unique(X509_new());
  ASSERT_TRUE(cert);
  auto maybeData = so::asn1::encodeOctet(expected.data);
  ASSERT_TRUE(maybeData);
  auto data = maybeData.moveValue();

  // WHEN
  const auto addResult = x509::setCustomExtension(*cert, expected.oidNumerical, *data);
  auto getResult = x509::getExtension(*cert, oidToFind);

  // THEN
  ASSERT_TRUE(addResult);
  ASSERT_TRUE(getResult);
  EXPECT_EQ(expected, (getResult.value));
}

TEST(X509CertExtensionsUT, addCustomExtensionToAlreadyExistingStandardExtensions)
{
  // GIVEN
  const x509::CertExtension expected {
    x509::CertExtensionId::UNDEF,
    false,
    "",
    // intel net adapter found at http://oid-info.com
    "1.3.6.1.4.1.343.2.7.2",
    {0xaa, 0xbb}
  }; 
  auto maybeCert = x509::convertPemToX509(data::selfSignedCAPemCert);
  ASSERT_TRUE(maybeCert);
  auto cert = maybeCert.moveValue();
  auto maybeData = so::asn1::encodeOctet(expected.data);
  ASSERT_TRUE(maybeData);
  auto data = maybeData.moveValue();

  // WHEN
  const auto addResult = x509::setCustomExtension(*cert, expected.oidNumerical, *data);
  auto getResult = x509::getExtensions(*cert);

  // THEN
  ASSERT_TRUE(addResult);
  ASSERT_TRUE(getResult);
  ASSERT_EQ(4, (getResult.value).size());
  EXPECT_EQ(expected, (getResult.value).at(3));
}

TEST(X509CertExtensionsUT, addBasicConstraintsExtension)
{
  // GIVEN 
  const auto basicConstraints = x509::CertExtensionId::BASIC_CONSTRAINTS;
  const auto basicConstraintsOid = "2.5.29.19"; 
  const auto basicConstraintsName = "X509v3 Basic Constraints";
  auto cert = so::make_unique(X509_new());
  ASSERT_TRUE(cert);
  auto maybeData = so::asn1::encodeOctet("CA:TRUE");
  ASSERT_TRUE(maybeData);
  auto data = maybeData.moveValue();

  // WHEN
  const auto addResult = x509::setExtension(*cert, basicConstraints, *data, true);
  auto getResult = x509::getExtensions(*cert);

  // THEN
  ASSERT_TRUE(addResult);
  ASSERT_TRUE(getResult);
  ASSERT_EQ(1, (getResult.value).size());
  
  const auto &ext = (getResult.value).at(0);
  EXPECT_EQ(basicConstraints, ext.id);
  EXPECT_EQ(basicConstraintsOid, ext.oidNumerical);
  EXPECT_EQ(basicConstraintsName, ext.name);
  EXPECT_EQ(true, ext.critical);
  EXPECT_EQ("CA:TRUE", internal::bytes::toString(ext.data));
}

TEST(X509CertExtensionsUT, addBasicConstraintsExtensionUsingNid)
{
  // GIVEN 
  const auto basicConstraints = nid::Nid::BASIC_CONSTRAINTS;
  const auto basicConstraintsOid = "2.5.29.19"; 
  const auto basicConstraintsName = "X509v3 Basic Constraints";
  auto cert = so::make_unique(X509_new());
  ASSERT_TRUE(cert);
  auto maybeData = so::asn1::encodeOctet("CA:TRUE");
  ASSERT_TRUE(maybeData);
  auto data = maybeData.moveValue();

  // WHEN
  const auto addResult = x509::setExtension(*cert, basicConstraints, *data, true);
  auto getResult = x509::getExtensions(*cert);

  // THEN
  ASSERT_TRUE(addResult);
  ASSERT_TRUE(getResult);
  ASSERT_EQ(1, (getResult.value).size());
  
  const auto &ext = (getResult.value).at(0);
  EXPECT_EQ(basicConstraints, ext.nid());
  EXPECT_EQ(basicConstraintsOid, ext.oidNumerical);
  EXPECT_EQ(basicConstraintsName, ext.name);
  EXPECT_EQ(true, ext.critical);
  EXPECT_EQ("CA:TRUE", internal::bytes::toString(ext.data));
}

TEST(X509CertExtensionsUT, addBasicConstraintsExtensionSingleExtraction)
{
  // GIVEN 
  const auto basicConstraints = x509::CertExtensionId::BASIC_CONSTRAINTS;
  const auto basicConstraintsOid = "2.5.29.19"; 
  const auto basicConstraintsName = "X509v3 Basic Constraints";
  auto cert = so::make_unique(X509_new());
  ASSERT_TRUE(cert);
  auto maybeData = so::asn1::encodeOctet("CA:TRUE");
  ASSERT_TRUE(maybeData);
  auto data = maybeData.moveValue();

  // WHEN
  const auto addResult = x509::setExtension(*cert, basicConstraints, *data, true);
  auto getResult = x509::getExtension(*cert, x509::CertExtensionId::BASIC_CONSTRAINTS);

  // THEN
  ASSERT_TRUE(addResult);
  ASSERT_TRUE(getResult);
  
  const auto &ext = (getResult.value);
  EXPECT_EQ(basicConstraints, ext.id);
  EXPECT_EQ(basicConstraintsOid, ext.oidNumerical);
  EXPECT_EQ(basicConstraintsName, ext.name);
  EXPECT_EQ(true, ext.critical);
  EXPECT_EQ("CA:TRUE", internal::bytes::toString(ext.data));
}

TEST(X509CertExtensionsUT, basicCertExtType_Equals)
{
  const auto expected = x509::CertExtension{
      x509::CertExtensionId::KEY_USAGE,
      true,
      "name",
      "1.2.3.4",
      {0x01, 0x02}
  };

  const auto actual = x509::CertExtension{
      x509::CertExtensionId::KEY_USAGE,
      true,
      "name",
      "1.2.3.4",
      {0x01, 0x02}
  };

  EXPECT_EQ(expected, actual); 
}

TEST(X509CertExtensionsUT, basicCertExtType_DiffrentId)
{
  const auto expected = x509::CertExtension{
      x509::CertExtensionId::KEY_USAGE,
      true,
      "name",
      "1.2.3.4",
      {0x01, 0x02}
  };

  const auto actual = x509::CertExtension{
      x509::CertExtensionId::EXT_KEY_USAGE,
      true,
      "name",
      "1.2.3.4",
      {0x01, 0x02}
  };

  EXPECT_NE(expected, actual); 
}

TEST(X509CertExtensionsUT, basicCertExtType_DiffrentCritical)
{
  const auto expected = x509::CertExtension{
      x509::CertExtensionId::KEY_USAGE,
      true,
      "name",
      "1.2.3.4",
      {0x01, 0x02}
  };

  const auto actual = x509::CertExtension{
      x509::CertExtensionId::EXT_KEY_USAGE,
      false,
      "name",
      "1.2.3.4",
      {0x01, 0x02}
  };

  EXPECT_NE(expected, actual); 
}

TEST(X509CertExtensionsUT, basicCertExtType_DiffrentName)
{
  const auto expected = x509::CertExtension{
      x509::CertExtensionId::KEY_USAGE,
      true,
      "name",
      "1.2.3.4",
      {0x01, 0x02}
  };

  const auto actual = x509::CertExtension{
      x509::CertExtensionId::EXT_KEY_USAGE,
      true,
      "namename",
      "1.2.3.4",
      {0x01, 0x02}
  };

  EXPECT_NE(expected, actual); 
}

TEST(X509CertExtensionsUT, basicCertExtType_DiffrentOidNumerical)
{
  const auto expected = x509::CertExtension{
      x509::CertExtensionId::KEY_USAGE,
      true,
      "name",
      "1.2.3.4",
      {0x01, 0x02}
  };

  const auto actual = x509::CertExtension{
      x509::CertExtensionId::EXT_KEY_USAGE,
      true,
      "name",
      "1.2.3.5",
      {0x01, 0x02}
  };

  EXPECT_NE(expected, actual); 
}

TEST(X509CertExtensionsUT, basicCertExtType_DiffrentData)
{
  const auto expected = x509::CertExtension{
      x509::CertExtensionId::KEY_USAGE,
      true,
      "name",
      "1.2.3.4",
      {0x01, 0x02}
  };

  const auto actual = x509::CertExtension{
      x509::CertExtensionId::EXT_KEY_USAGE,
      true,
      "name",
      "1.2.3.4",
      {0x01, 0x02, 0x03}
  };

  EXPECT_NE(expected, actual); 
}

TEST(X509CertExtensionsUT, basicCertExtType_DiffrentData2)
{
  const auto expected = x509::CertExtension{
      x509::CertExtensionId::KEY_USAGE,
      true,
      "name",
      "1.2.3.4",
      {0x01, 0x02}
  };

  const auto actual = x509::CertExtension{
      x509::CertExtensionId::EXT_KEY_USAGE,
      true,
      "name",
      "1.2.3.4",
      {0x01, 0x03}
  };

  EXPECT_NE(expected, actual); 
}

}}}
