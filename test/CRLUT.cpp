#include <gtest/gtest.h>

#include <simpleopenssl/simpleopenssl.h>
#include "precalculated.h"
#include "utils.h"
#include <ctime>

namespace so { namespace ut { namespace x509 {

namespace x509 = ::so::x509;

TEST(CRLUT, version)
{
  // GIVEN 
  auto mcrl = x509::convertPemToCRL(data::validPemCRL);
  ASSERT_TRUE(mcrl);
  auto crl = mcrl.moveValue();

  // WHEN
  const auto version = x509::getVersion(*crl);

  // THEN
  EXPECT_EQ(x509::Version::v2, std::get<0>(version));
  EXPECT_EQ(1, std::get<1>(version));
}

TEST(CRLUT, getIssuer)
{
  // GIVEN 
  auto mcrl = x509::convertPemToCRL(data::validPemCRL);
  ASSERT_TRUE(mcrl);
  auto crl = mcrl.moveValue(); 


  // WHEN
  const auto issuer = x509::getIssuer(*crl);
 
  // THEN 
  ASSERT_TRUE(issuer);
  EXPECT_EQ("Sample Signer Cert", issuer->commonName);
  EXPECT_EQ("Sample Signer Organization", issuer->organizationName);
  EXPECT_EQ("Sample Signer Unit", issuer->organizationalUnitName);

}

TEST(CRLUT, getIssuerString)
{
  // GIVEN 
  auto mcrl = x509::convertPemToCRL(data::validPemCRL);
  ASSERT_TRUE(mcrl);
  auto crl = mcrl.moveValue(); 
  const std::string expected = "CN=Sample Signer Cert,OU=Sample Signer Unit,O=Sample Signer Organization";


  // WHEN
  const auto issuer = x509::getIssuerString(*crl);
 
  // THEN 
  ASSERT_TRUE(issuer);
  EXPECT_EQ(expected, *issuer); 
}

TEST(CRLUT, getCrlExtensionsCount)
{
  // GIVEN 
  auto mcrl = x509::convertPemToCRL(data::validPemCRL);
  ASSERT_TRUE(mcrl);
  auto crl = mcrl.moveValue(); 


  // WHEN
  const auto count = x509::getExtensionsCount(*crl);
 
  // THEN 
  ASSERT_TRUE(count);
  EXPECT_EQ(2, *count);
}

TEST(CRLUT, getCrlExtensions)
{
  // GIVEN 
  auto mcrl = x509::convertPemToCRL(data::validPemCRL);
  ASSERT_TRUE(mcrl);
  auto crl = mcrl.moveValue(); 


  // WHEN
  const auto exts = x509::getExtensions(*crl);
 
  // THEN 
  ASSERT_TRUE(exts);
  ASSERT_EQ(2, exts->size());
  
  const auto first = exts->at(0);
  EXPECT_EQ(nid::Nid::AUTHORITY_KEY_IDENTIFIER, static_cast<nid::Nid>(first.id));
  EXPECT_EQ(std::string("keyid:BE:12:01:CC:AA:EA:11:80:DA:2E:AD:B2:EA:C7:B5:FB:9F:F9:AD:34\n"),
            utils::toString(first.data));

  const auto sec = exts->at(1);
  EXPECT_EQ(x509::CrlExtensionId::CRL_NUMBER, sec.id);
  EXPECT_EQ("3", utils::toString(sec.data));
}

TEST(CRLUT, getCrlSignature)
{
  // GIVEN 
  auto mcrl = x509::convertPemToCRL(data::validPemCRL);
  ASSERT_TRUE(mcrl);
  auto crl = mcrl.moveValue(); 
  const so::Bytes expected{
    0x42, 0x21, 0xbe, 0x81, 0xf1, 0xc3, 0x79, 0x76, 0x66, 0x5b, 0xce, 0x21, 0x13, 0x8a, 0x68, 0xa8, 0xb4, 0x3c, 0xbe, 0x16, 0xc3, 0xaf, 0x4b, 0xdd, 0xcb, 0x78, 0x35, 0x92, 0x90, 0xd8, 0xd7, 0x4c, 0x6f, 0xfe, 0x6c, 0x68, 0x27, 0xae, 0x6d, 0xda, 0x42, 0x98, 0x01, 0xee, 0x17, 0x93, 0xf0, 0xbd, 0xa8, 0xee, 0xcd, 0x90, 0xb6, 0x35, 0xf6, 0x0d, 0xa4, 0xce, 0x49, 0x82, 0xf7, 0x9d, 0x9f, 0xc8, 0x6e, 0x7f, 0xd1, 0xf1, 0x2d, 0x20, 0xf8, 0x46, 0xcd, 0x43, 0x17, 0x64, 0xe7, 0xf9, 0x5a, 0xe8, 0x21, 0x11, 0xc6, 0x24, 0x69, 0xf8, 0x4d, 0x93, 0x50, 0x6f, 0x0b, 0x0d, 0xbd, 0x78, 0x61, 0x53, 0x21, 0x44, 0x62, 0xaf, 0x0a, 0x0b, 0x92, 0x23, 0x25, 0x06, 0xd0, 0xcc, 0x06, 0x5b, 0xac, 0x1a, 0xa9, 0x5b, 0x5d, 0xe8, 0xae, 0xf5, 0xbb, 0xbb, 0xe1, 0x21, 0x4f, 0xd3, 0x89, 0xd7, 0xfa, 0x65, 0x27, 0x6c, 0x4c, 0xc8, 0x69, 0x3c, 0xf1, 0x6e, 0x3d, 0x48, 0x9d, 0xe2, 0x3d, 0xbd, 0x53, 0x7a, 0xb5, 0xd1, 0x21, 0x85, 0x17, 0xa7, 0x02, 0xb7, 0x50, 0xf3, 0x8e, 0xf5, 0x1c, 0x0b, 0x01, 0xc6, 0x84, 0x70, 0x34, 0xd8, 0xc7, 0xa7, 0xef, 0x41, 0x20, 0x64, 0x50, 0x03, 0x3c, 0xb5, 0xa6, 0x2e, 0x0d, 0x07, 0x82, 0x52, 0x94, 0x87, 0x58, 0x99, 0x59, 0xc0, 0x46, 0xb5, 0xeb, 0xff, 0xf1, 0x5b, 0x14, 0x8a, 0x3c, 0xa3, 0xb0, 0xcd, 0x3b, 0xd8, 0x2e, 0x94, 0xb7, 0x94, 0xf0, 0x37, 0x2a, 0xeb, 0xb6, 0x16, 0xfd, 0xe7, 0x6f, 0x9e, 0x2a, 0x59, 0xb1, 0x2c, 0xd8, 0x13, 0xd2, 0x8e, 0x61, 0x55, 0x8c, 0x63, 0x5e, 0x1b, 0x70, 0x2d, 0x0b, 0x0b, 0xed, 0x06, 0x61, 0xaf, 0x2a, 0x40, 0x33, 0x50, 0xcb, 0x62, 0xa4, 0x23, 0x92, 0x20, 0xc8, 0xee, 0x19, 0x6f, 0xb7, 0xb4, 0x2e, 0x0c, 0x64, 0xc9
  };

  // WHEN
  const auto sig = x509::getSignature(*crl);
 
  // THEN 
  ASSERT_TRUE(sig);
  EXPECT_EQ(expected, sig.value());
}

TEST(CRLUT, getCrlSignarueAlgo)
{
  // GIVEN 
  auto mcrl = x509::convertPemToCRL(data::validPemCRL);
  ASSERT_TRUE(mcrl);
  auto crl = mcrl.moveValue(); 


  // WHEN
  const auto algo = x509::getSignatureAlgorithm(*crl);
 
  // THEN 
  EXPECT_EQ(nid::Nid::SHA1WITHRSAENCRYPTION, algo);
}

TEST(CRLUT, revCount)
{
  // GIVEN 
  auto mcrl = x509::convertPemToCRL(data::validPemCRL);
  ASSERT_TRUE(mcrl);
  auto crl = mcrl.moveValue();

  // WHEN
  const auto revCount = x509::getRevokedCount(*crl);
 
  // THEN 
  EXPECT_EQ(5, revCount);
}

TEST(CRLUT, getRevokedFromPrecalculated)
{
  // GIVEN 
  auto mcrl = x509::convertPemToCRL(data::validPemCRL);
  ASSERT_TRUE(mcrl);
  auto crl = mcrl.moveValue(); 


  // Feb 18 10:22:00 2013 GMT
  // 20130218102200Z plus asn1 header 0x18 0x0f
  const auto btTime = utils::toString({0x18, 0x0f}) + "20130218102200Z";
  const x509::Revoked expected []{
    x509::Revoked{
      "Feb 18 10:22:12 2013 GMT",
      std::time_t{}, 
      so::Bytes{0x14, 0x79, 0x47},
      {
        x509::CrlEntryExtension{
          x509::CrlEntryExtensionId::REASON,
          false,
          "", "",
          utils::toBytes("Affiliation Changed")
        },
        x509::CrlEntryExtension{
          static_cast<x509::CrlEntryExtensionId>(nid::Nid::INVALIDITY_DATE),
          false,
          "", "",
          utils::toBytes(btTime)
        }
      }
    },
    x509::Revoked{
      "Feb 18 10:22:22 2013 GMT",
      std::time_t{},
      so::Bytes{0x14, 0x79, 0x48},
      {
        x509::CrlEntryExtension{
          x509::CrlEntryExtensionId::REASON,
          false,
          "", "",
          utils::toBytes("Certificate Hold")
        },
        x509::CrlEntryExtension{
          static_cast<x509::CrlEntryExtensionId>(nid::Nid::INVALIDITY_DATE),
          false,
          "", "",
          utils::toBytes(btTime)
        }
      }
    },
    x509::Revoked{
      "Feb 18 10:22:32 2013 GMT",
      std::time_t{},
      so::Bytes{0x14, 0x79, 0x49},
      {
        x509::CrlEntryExtension{
          x509::CrlEntryExtensionId::REASON,
          false,
          "", "",
          utils::toBytes("Superseded")
        },
        x509::CrlEntryExtension{
          static_cast<x509::CrlEntryExtensionId>(nid::Nid::INVALIDITY_DATE),
          false,
          "", "",
          utils::toBytes(btTime)
        }
      }
    },
    x509::Revoked{
      "Feb 18 10:22:42 2013 GMT",
      std::time_t{},
      so::Bytes{0x14, 0x79, 0x4A},
      {
        x509::CrlEntryExtension{
          x509::CrlEntryExtensionId::REASON,
          false,
          "", "",
          utils::toBytes("Key Compromise")
        },
        x509::CrlEntryExtension{
          static_cast<x509::CrlEntryExtensionId>(nid::Nid::INVALIDITY_DATE),
          false,
          "", "",
          utils::toBytes(btTime)
        }
      }
    },
    x509::Revoked{
      "Feb 18 10:22:51 2013 GMT",
      std::time_t{},
      so::Bytes{0x14, 0x79, 0x4B},
      {
        x509::CrlEntryExtension{
          x509::CrlEntryExtensionId::REASON,
          false,
          "", "",
          utils::toBytes("Cessation Of Operation")
        },
        x509::CrlEntryExtension{
          static_cast<x509::CrlEntryExtensionId>(nid::Nid::INVALIDITY_DATE),
          false,
          "", "",
          utils::toBytes(btTime)
        }
      }
    },
  };
    

  // WHEN
  const auto revoked = x509::getRevoked(*crl);
 
  // THEN 
  ASSERT_TRUE(revoked);
  ASSERT_EQ(5, revoked->size());
  for(size_t i = 0; i < 5; ++i)
  {
    const auto &rev = revoked->at(i);
    EXPECT_EQ(expected[i].dateISO860, rev.dateISO860);
//    EXPECT_EQ(exp1.date, rev.date);
    EXPECT_EQ(expected[i].serialNumAsn1, rev.serialNumAsn1);

    const auto &exts = rev.extensions;
    ASSERT_EQ(2, exts.size());
    for(size_t j = 0; j < exts.size(); ++j)
    {
      EXPECT_EQ(expected[i].extensions[j].id , exts[j].id);
      EXPECT_EQ(expected[i].extensions[j].data, exts[j].data);
    }
  }
}

}}} // namespace so { namespace ut { namespace x509 {
