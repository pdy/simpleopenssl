#include <simpleopenssl/simpleopenssl.h>
#include <gtest/gtest.h>
#include "utils.h"

using namespace so;

struct NidUTInput
{
  int rawNid;
  nid::Nid soNid;
};

static std::ostream& operator<<(std::ostream &ss, const NidUTInput &input)
{
  return ss << OBJ_nid2sn(input.rawNid) << " [" << input.rawNid << "]";
}

class NidValidityUT : public ::testing::TestWithParam<NidUTInput>
{};

TEST_P(NidValidityUT, cmp)
{
  const auto input {GetParam()};
  
  EXPECT_EQ(input.rawNid, input.soNid.getRaw());
}

const static NidUTInput NID_VALIDITY_UT_VALUES[] {
 NidUTInput {
  NID_undef, nid::UNDEF
 },
 NidUTInput {
  NID_itu_t, nid::ITU_T
 },
 NidUTInput {
  NID_ccitt, nid::CCITT
 },
 NidUTInput {
  NID_iso, nid::ISO
 },
 NidUTInput {
  NID_joint_iso_itu_t, nid::JOINT_ISO_ITU_T
 },
 NidUTInput {
  NID_joint_iso_ccitt, nid::JOINT_ISO_CCITT
 },
 NidUTInput {
  NID_member_body, nid::MEMBER_BODY
 },
 NidUTInput {
  NID_identified_organization, nid::IDENTIFIED_ORGANIZATION
 },
 NidUTInput {
  NID_hmac_md5, nid::HMAC_MD5
 },
 NidUTInput {
  NID_hmac_sha1, nid::HMAC_SHA1
 },
 NidUTInput {
  NID_certicom_arc, nid::CERTICOM_ARC
 },
 NidUTInput {
  NID_international_organizations, nid::INTERNATIONAL_ORGANIZATIONS
 },
 NidUTInput {
  NID_wap, nid::WAP
 },
 NidUTInput {
  NID_wap_wsg, nid::WAP_WSG
 },
 NidUTInput {
  NID_selected_attribute_types, nid::SELECTED_ATTRIBUTE_TYPES
 },
 NidUTInput {
  NID_clearance, nid::CLEARANCE
 },
 NidUTInput {
  NID_ISO_US, nid::ISO_US
 },
 NidUTInput {
  NID_X9_57, nid::X9_57
 },
 NidUTInput {
  NID_X9cm, nid::X9CM
 },
 NidUTInput {
  NID_dsa, nid::DSA
 },
 NidUTInput {
  NID_dsaWithSHA1, nid::DSAWITHSHA1
 },
 NidUTInput {
  NID_ansi_X9_62, nid::ANSI_X9_62
 },
 NidUTInput {
  NID_X9_62_prime_field, nid::X9_62_PRIME_FIELD
 },
 NidUTInput {
  NID_X9_62_characteristic_two_field, nid::X9_62_CHARACTERISTIC_TWO_FIELD
 },
 NidUTInput {
  NID_X9_62_id_characteristic_two_basis, nid::X9_62_ID_CHARACTERISTIC_TWO_BASIS
 },
 NidUTInput {
  NID_X9_62_onBasis, nid::X9_62_ONBASIS
 },
 NidUTInput {
  NID_X9_62_tpBasis, nid::X9_62_TPBASIS
 },
 NidUTInput {
  NID_X9_62_ppBasis, nid::X9_62_PPBASIS
 },
 NidUTInput {
  NID_X9_62_id_ecPublicKey, nid::X9_62_ID_ECPUBLICKEY
 },
 NidUTInput {
  NID_X9_62_c2pnb163v1, nid::X9_62_C2PNB163V1
 },
 NidUTInput {
  NID_X9_62_c2pnb163v2, nid::X9_62_C2PNB163V2
 },
 NidUTInput {
  NID_X9_62_c2pnb163v3, nid::X9_62_C2PNB163V3
 },
 NidUTInput {
  NID_X9_62_c2pnb176v1, nid::X9_62_C2PNB176V1
 },
 NidUTInput {
  NID_X9_62_c2tnb191v1, nid::X9_62_C2TNB191V1
 },
 NidUTInput {
  NID_X9_62_c2tnb191v2, nid::X9_62_C2TNB191V2
 },
 NidUTInput {
  NID_X9_62_c2tnb191v3, nid::X9_62_C2TNB191V3
 },
 NidUTInput {
  NID_X9_62_c2onb191v4, nid::X9_62_C2ONB191V4
 },
 NidUTInput {
  NID_X9_62_c2onb191v5, nid::X9_62_C2ONB191V5
 },
 NidUTInput {
  NID_X9_62_c2pnb208w1, nid::X9_62_C2PNB208W1
 },
 NidUTInput {
  NID_X9_62_c2tnb239v1, nid::X9_62_C2TNB239V1
 },
 NidUTInput {
  NID_X9_62_c2tnb239v2, nid::X9_62_C2TNB239V2
 },
 NidUTInput {
  NID_X9_62_c2tnb239v3, nid::X9_62_C2TNB239V3
 },
 NidUTInput {
  NID_X9_62_c2onb239v4, nid::X9_62_C2ONB239V4
 },
 NidUTInput {
  NID_X9_62_c2onb239v5, nid::X9_62_C2ONB239V5
 },
 NidUTInput {
  NID_X9_62_c2pnb272w1, nid::X9_62_C2PNB272W1
 },
 NidUTInput {
  NID_X9_62_c2pnb304w1, nid::X9_62_C2PNB304W1
 },
 NidUTInput {
  NID_X9_62_c2tnb359v1, nid::X9_62_C2TNB359V1
 },
 NidUTInput {
  NID_X9_62_c2pnb368w1, nid::X9_62_C2PNB368W1
 },
 NidUTInput {
  NID_X9_62_c2tnb431r1, nid::X9_62_C2TNB431R1
 },
 NidUTInput {
  NID_X9_62_prime192v1, nid::X9_62_PRIME192V1
 },
 NidUTInput {
  NID_X9_62_prime192v2, nid::X9_62_PRIME192V2
 },
 NidUTInput {
  NID_X9_62_prime192v3, nid::X9_62_PRIME192V3
 },
 NidUTInput {
  NID_X9_62_prime239v1, nid::X9_62_PRIME239V1
 },
 NidUTInput {
  NID_X9_62_prime239v2, nid::X9_62_PRIME239V2
 },
 NidUTInput {
  NID_X9_62_prime239v3, nid::X9_62_PRIME239V3
 },
 NidUTInput {
  NID_X9_62_prime256v1, nid::X9_62_PRIME256V1
 },
 NidUTInput {
  NID_ecdsa_with_SHA1, nid::ECDSA_WITH_SHA1
 },
 NidUTInput {
  NID_ecdsa_with_Recommended, nid::ECDSA_WITH_RECOMMENDED
 },
 NidUTInput {
  NID_ecdsa_with_Specified, nid::ECDSA_WITH_SPECIFIED
 },
 NidUTInput {
  NID_ecdsa_with_SHA224, nid::ECDSA_WITH_SHA224
 },
 NidUTInput {
  NID_ecdsa_with_SHA256, nid::ECDSA_WITH_SHA256
 },
 NidUTInput {
  NID_ecdsa_with_SHA384, nid::ECDSA_WITH_SHA384
 },
 NidUTInput {
  NID_ecdsa_with_SHA512, nid::ECDSA_WITH_SHA512
 },
 NidUTInput {
  NID_secp112r1, nid::SECP112R1
 },
 NidUTInput {
  NID_secp112r2, nid::SECP112R2
 },
 NidUTInput {
  NID_secp128r1, nid::SECP128R1
 },
 NidUTInput {
  NID_secp128r2, nid::SECP128R2
 },
 NidUTInput {
  NID_secp160k1, nid::SECP160K1
 },
 NidUTInput {
  NID_secp160r1, nid::SECP160R1
 },
 NidUTInput {
  NID_secp160r2, nid::SECP160R2
 },
 NidUTInput {
  NID_secp192k1, nid::SECP192K1
 },
 NidUTInput {
  NID_secp224k1, nid::SECP224K1
 },
 NidUTInput {
  NID_secp224r1, nid::SECP224R1
 },
 NidUTInput {
  NID_secp256k1, nid::SECP256K1
 },
 NidUTInput {
  NID_secp384r1, nid::SECP384R1
 },
 NidUTInput {
  NID_secp521r1, nid::SECP521R1
 },
 NidUTInput {
  NID_sect113r1, nid::SECT113R1
 },
 NidUTInput {
  NID_sect113r2, nid::SECT113R2
 },
 NidUTInput {
  NID_sect131r1, nid::SECT131R1
 },
 NidUTInput {
  NID_sect131r2, nid::SECT131R2
 },
 NidUTInput {
  NID_sect163k1, nid::SECT163K1
 },
 NidUTInput {
  NID_sect163r1, nid::SECT163R1
 },
 NidUTInput {
  NID_sect163r2, nid::SECT163R2
 },
 NidUTInput {
  NID_sect193r1, nid::SECT193R1
 },
 NidUTInput {
  NID_sect193r2, nid::SECT193R2
 },
 NidUTInput {
  NID_sect233k1, nid::SECT233K1
 },
 NidUTInput {
  NID_sect233r1, nid::SECT233R1
 },
 NidUTInput {
  NID_sect239k1, nid::SECT239K1
 },
 NidUTInput {
  NID_sect283k1, nid::SECT283K1
 },
 NidUTInput {
  NID_sect283r1, nid::SECT283R1
 },
 NidUTInput {
  NID_sect409k1, nid::SECT409K1
 },
 NidUTInput {
  NID_sect409r1, nid::SECT409R1
 },
 NidUTInput {
  NID_sect571k1, nid::SECT571K1
 },
 NidUTInput {
  NID_sect571r1, nid::SECT571R1
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls1, nid::WAP_WSG_IDM_ECID_WTLS1
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls3, nid::WAP_WSG_IDM_ECID_WTLS3
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls4, nid::WAP_WSG_IDM_ECID_WTLS4
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls5, nid::WAP_WSG_IDM_ECID_WTLS5
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls6, nid::WAP_WSG_IDM_ECID_WTLS6
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls7, nid::WAP_WSG_IDM_ECID_WTLS7
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls8, nid::WAP_WSG_IDM_ECID_WTLS8
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls9, nid::WAP_WSG_IDM_ECID_WTLS9
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls10, nid::WAP_WSG_IDM_ECID_WTLS10
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls11, nid::WAP_WSG_IDM_ECID_WTLS11
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls12, nid::WAP_WSG_IDM_ECID_WTLS12
 },
 NidUTInput {
  NID_cast5_cbc, nid::CAST5_CBC
 },
 NidUTInput {
  NID_cast5_ecb, nid::CAST5_ECB
 },
 NidUTInput {
  NID_cast5_cfb64, nid::CAST5_CFB64
 },
 NidUTInput {
  NID_cast5_ofb64, nid::CAST5_OFB64
 },
 NidUTInput {
  NID_pbeWithMD5AndCast5_CBC, nid::PBEWITHMD5ANDCAST5_CBC
 },
 NidUTInput {
  NID_id_PasswordBasedMAC, nid::ID_PASSWORDBASEDMAC
 },
 NidUTInput {
  NID_id_DHBasedMac, nid::ID_DHBASEDMAC
 },
 NidUTInput {
  NID_rsadsi, nid::RSADSI
 },
 NidUTInput {
  NID_pkcs, nid::PKCS
 },
 NidUTInput {
  NID_pkcs1, nid::PKCS1
 },
 NidUTInput {
  NID_rsaEncryption, nid::RSAENCRYPTION
 },
 NidUTInput {
  NID_md2WithRSAEncryption, nid::MD2WITHRSAENCRYPTION
 },
 NidUTInput {
  NID_md4WithRSAEncryption, nid::MD4WITHRSAENCRYPTION
 },
 NidUTInput {
  NID_md5WithRSAEncryption, nid::MD5WITHRSAENCRYPTION
 },
 NidUTInput {
  NID_sha1WithRSAEncryption, nid::SHA1WITHRSAENCRYPTION
 },
 NidUTInput {
  NID_rsaesOaep, nid::RSAESOAEP
 },
 NidUTInput {
  NID_mgf1, nid::MGF1
 },
 NidUTInput {
  NID_pSpecified, nid::PSPECIFIED
 },
 NidUTInput {
  NID_rsassaPss, nid::RSASSAPSS
 },
 NidUTInput {
  NID_sha256WithRSAEncryption, nid::SHA256WITHRSAENCRYPTION
 },
 NidUTInput {
  NID_sha384WithRSAEncryption, nid::SHA384WITHRSAENCRYPTION
 },
 NidUTInput {
  NID_sha512WithRSAEncryption, nid::SHA512WITHRSAENCRYPTION
 },
 NidUTInput {
  NID_sha224WithRSAEncryption, nid::SHA224WITHRSAENCRYPTION
 },
 NidUTInput {
  NID_pkcs3, nid::PKCS3
 },
 NidUTInput {
  NID_dhKeyAgreement, nid::DHKEYAGREEMENT
 },
 NidUTInput {
  NID_pkcs5, nid::PKCS5
 },
 NidUTInput {
  NID_pbeWithMD2AndDES_CBC, nid::PBEWITHMD2ANDDES_CBC
 },
 NidUTInput {
  NID_pbeWithMD5AndDES_CBC, nid::PBEWITHMD5ANDDES_CBC
 },
 NidUTInput {
  NID_pbeWithMD2AndRC2_CBC, nid::PBEWITHMD2ANDRC2_CBC
 },
 NidUTInput {
  NID_pbeWithMD5AndRC2_CBC, nid::PBEWITHMD5ANDRC2_CBC
 },
 NidUTInput {
  NID_pbeWithSHA1AndDES_CBC, nid::PBEWITHSHA1ANDDES_CBC
 },
 NidUTInput {
  NID_pbeWithSHA1AndRC2_CBC, nid::PBEWITHSHA1ANDRC2_CBC
 },
 NidUTInput {
  NID_id_pbkdf2, nid::ID_PBKDF2
 },
 NidUTInput {
  NID_pbes2, nid::PBES2
 },
 NidUTInput {
  NID_pbmac1, nid::PBMAC1
 },
 NidUTInput {
  NID_pkcs7, nid::PKCS7
 },
 NidUTInput {
  NID_pkcs7_data, nid::PKCS7_DATA
 },
 NidUTInput {
  NID_pkcs7_signed, nid::PKCS7_SIGNED
 },
 NidUTInput {
  NID_pkcs7_enveloped, nid::PKCS7_ENVELOPED
 },
 NidUTInput {
  NID_pkcs7_signedAndEnveloped, nid::PKCS7_SIGNEDANDENVELOPED
 },
 NidUTInput {
  NID_pkcs7_digest, nid::PKCS7_DIGEST
 },
 NidUTInput {
  NID_pkcs7_encrypted, nid::PKCS7_ENCRYPTED
 },
 NidUTInput {
  NID_pkcs9, nid::PKCS9
 },
 NidUTInput {
  NID_pkcs9_emailAddress, nid::PKCS9_EMAILADDRESS
 },
 NidUTInput {
  NID_pkcs9_unstructuredName, nid::PKCS9_UNSTRUCTUREDNAME
 },
 NidUTInput {
  NID_pkcs9_contentType, nid::PKCS9_CONTENTTYPE
 },
 NidUTInput {
  NID_pkcs9_messageDigest, nid::PKCS9_MESSAGEDIGEST
 },
 NidUTInput {
  NID_pkcs9_signingTime, nid::PKCS9_SIGNINGTIME
 },
 NidUTInput {
  NID_pkcs9_countersignature, nid::PKCS9_COUNTERSIGNATURE
 },
 NidUTInput {
  NID_pkcs9_challengePassword, nid::PKCS9_CHALLENGEPASSWORD
 },
 NidUTInput {
  NID_pkcs9_unstructuredAddress, nid::PKCS9_UNSTRUCTUREDADDRESS
 },
 NidUTInput {
  NID_pkcs9_extCertAttributes, nid::PKCS9_EXTCERTATTRIBUTES
 },
 NidUTInput {
  NID_ext_req, nid::EXT_REQ
 },
 NidUTInput {
  NID_SMIMECapabilities, nid::SMIMECAPABILITIES
 },
 NidUTInput {
  NID_SMIME, nid::SMIME
 },
 NidUTInput {
  NID_id_smime_mod, nid::ID_SMIME_MOD
 },
 NidUTInput {
  NID_id_smime_ct, nid::ID_SMIME_CT
 },
 NidUTInput {
  NID_id_smime_aa, nid::ID_SMIME_AA
 },
 NidUTInput {
  NID_id_smime_alg, nid::ID_SMIME_ALG
 },
 NidUTInput {
  NID_id_smime_cd, nid::ID_SMIME_CD
 },
 NidUTInput {
  NID_id_smime_spq, nid::ID_SMIME_SPQ
 },
 NidUTInput {
  NID_id_smime_cti, nid::ID_SMIME_CTI
 },
 NidUTInput {
  NID_id_smime_mod_cms, nid::ID_SMIME_MOD_CMS
 },
 NidUTInput {
  NID_id_smime_mod_ess, nid::ID_SMIME_MOD_ESS
 },
 NidUTInput {
  NID_id_smime_mod_oid, nid::ID_SMIME_MOD_OID
 },
 NidUTInput {
  NID_id_smime_mod_msg_v3, nid::ID_SMIME_MOD_MSG_V3
 },
 NidUTInput {
  NID_id_smime_mod_ets_eSignature_88, nid::ID_SMIME_MOD_ETS_ESIGNATURE_88
 },
 NidUTInput {
  NID_id_smime_mod_ets_eSignature_97, nid::ID_SMIME_MOD_ETS_ESIGNATURE_97
 },
 NidUTInput {
  NID_id_smime_mod_ets_eSigPolicy_88, nid::ID_SMIME_MOD_ETS_ESIGPOLICY_88
 },
 NidUTInput {
  NID_id_smime_mod_ets_eSigPolicy_97, nid::ID_SMIME_MOD_ETS_ESIGPOLICY_97
 },
 NidUTInput {
  NID_id_smime_ct_receipt, nid::ID_SMIME_CT_RECEIPT
 },
 NidUTInput {
  NID_id_smime_ct_authData, nid::ID_SMIME_CT_AUTHDATA
 },
 NidUTInput {
  NID_id_smime_ct_publishCert, nid::ID_SMIME_CT_PUBLISHCERT
 },
 NidUTInput {
  NID_id_smime_ct_TSTInfo, nid::ID_SMIME_CT_TSTINFO
 },
 NidUTInput {
  NID_id_smime_ct_TDTInfo, nid::ID_SMIME_CT_TDTINFO
 },
 NidUTInput {
  NID_id_smime_ct_contentInfo, nid::ID_SMIME_CT_CONTENTINFO
 },
 NidUTInput {
  NID_id_smime_ct_DVCSRequestData, nid::ID_SMIME_CT_DVCSREQUESTDATA
 },
 NidUTInput {
  NID_id_smime_ct_DVCSResponseData, nid::ID_SMIME_CT_DVCSRESPONSEDATA
 },
 NidUTInput {
  NID_id_smime_ct_compressedData, nid::ID_SMIME_CT_COMPRESSEDDATA
 },
 NidUTInput {
  NID_id_smime_ct_contentCollection, nid::ID_SMIME_CT_CONTENTCOLLECTION
 },
 NidUTInput {
  NID_id_smime_ct_authEnvelopedData, nid::ID_SMIME_CT_AUTHENVELOPEDDATA
 },
 NidUTInput {
  NID_id_ct_asciiTextWithCRLF, nid::ID_CT_ASCIITEXTWITHCRLF
 },
 NidUTInput {
  NID_id_ct_xml, nid::ID_CT_XML
 },
 NidUTInput {
  NID_id_smime_aa_receiptRequest, nid::ID_SMIME_AA_RECEIPTREQUEST
 },
 NidUTInput {
  NID_id_smime_aa_securityLabel, nid::ID_SMIME_AA_SECURITYLABEL
 },
 NidUTInput {
  NID_id_smime_aa_mlExpandHistory, nid::ID_SMIME_AA_MLEXPANDHISTORY
 },
 NidUTInput {
  NID_id_smime_aa_contentHint, nid::ID_SMIME_AA_CONTENTHINT
 },
 NidUTInput {
  NID_id_smime_aa_msgSigDigest, nid::ID_SMIME_AA_MSGSIGDIGEST
 },
 NidUTInput {
  NID_id_smime_aa_encapContentType, nid::ID_SMIME_AA_ENCAPCONTENTTYPE
 },
 NidUTInput {
  NID_id_smime_aa_contentIdentifier, nid::ID_SMIME_AA_CONTENTIDENTIFIER
 },
 NidUTInput {
  NID_id_smime_aa_macValue, nid::ID_SMIME_AA_MACVALUE
 },
 NidUTInput {
  NID_id_smime_aa_equivalentLabels, nid::ID_SMIME_AA_EQUIVALENTLABELS
 },
 NidUTInput {
  NID_id_smime_aa_contentReference, nid::ID_SMIME_AA_CONTENTREFERENCE
 },
 NidUTInput {
  NID_id_smime_aa_encrypKeyPref, nid::ID_SMIME_AA_ENCRYPKEYPREF
 },
 NidUTInput {
  NID_id_smime_aa_signingCertificate, nid::ID_SMIME_AA_SIGNINGCERTIFICATE
 },
 NidUTInput {
  NID_id_smime_aa_smimeEncryptCerts, nid::ID_SMIME_AA_SMIMEENCRYPTCERTS
 },
 NidUTInput {
  NID_id_smime_aa_timeStampToken, nid::ID_SMIME_AA_TIMESTAMPTOKEN
 },
 NidUTInput {
  NID_id_smime_aa_ets_sigPolicyId, nid::ID_SMIME_AA_ETS_SIGPOLICYID
 },
 NidUTInput {
  NID_id_smime_aa_ets_commitmentType, nid::ID_SMIME_AA_ETS_COMMITMENTTYPE
 },
 NidUTInput {
  NID_id_smime_aa_ets_signerLocation, nid::ID_SMIME_AA_ETS_SIGNERLOCATION
 },
 NidUTInput {
  NID_id_smime_aa_ets_signerAttr, nid::ID_SMIME_AA_ETS_SIGNERATTR
 },
 NidUTInput {
  NID_id_smime_aa_ets_otherSigCert, nid::ID_SMIME_AA_ETS_OTHERSIGCERT
 },
 NidUTInput {
  NID_id_smime_aa_ets_contentTimestamp, nid::ID_SMIME_AA_ETS_CONTENTTIMESTAMP
 },
 NidUTInput {
  NID_id_smime_aa_ets_CertificateRefs, nid::ID_SMIME_AA_ETS_CERTIFICATEREFS
 },
 NidUTInput {
  NID_id_smime_aa_ets_RevocationRefs, nid::ID_SMIME_AA_ETS_REVOCATIONREFS
 },
 NidUTInput {
  NID_id_smime_aa_ets_certValues, nid::ID_SMIME_AA_ETS_CERTVALUES
 },
 NidUTInput {
  NID_id_smime_aa_ets_revocationValues, nid::ID_SMIME_AA_ETS_REVOCATIONVALUES
 },
 NidUTInput {
  NID_id_smime_aa_ets_escTimeStamp, nid::ID_SMIME_AA_ETS_ESCTIMESTAMP
 },
 NidUTInput {
  NID_id_smime_aa_ets_certCRLTimestamp, nid::ID_SMIME_AA_ETS_CERTCRLTIMESTAMP
 },
 NidUTInput {
  NID_id_smime_aa_ets_archiveTimeStamp, nid::ID_SMIME_AA_ETS_ARCHIVETIMESTAMP
 },
 NidUTInput {
  NID_id_smime_aa_signatureType, nid::ID_SMIME_AA_SIGNATURETYPE
 },
 NidUTInput {
  NID_id_smime_aa_dvcs_dvc, nid::ID_SMIME_AA_DVCS_DVC
 },
 NidUTInput {
  NID_id_smime_alg_ESDHwith3DES, nid::ID_SMIME_ALG_ESDHWITH3DES
 },
 NidUTInput {
  NID_id_smime_alg_ESDHwithRC2, nid::ID_SMIME_ALG_ESDHWITHRC2
 },
 NidUTInput {
  NID_id_smime_alg_3DESwrap, nid::ID_SMIME_ALG_3DESWRAP
 },
 NidUTInput {
  NID_id_smime_alg_RC2wrap, nid::ID_SMIME_ALG_RC2WRAP
 },
 NidUTInput {
  NID_id_smime_alg_ESDH, nid::ID_SMIME_ALG_ESDH
 },
 NidUTInput {
  NID_id_smime_alg_CMS3DESwrap, nid::ID_SMIME_ALG_CMS3DESWRAP
 },
 NidUTInput {
  NID_id_smime_alg_CMSRC2wrap, nid::ID_SMIME_ALG_CMSRC2WRAP
 },
 NidUTInput {
  NID_id_alg_PWRI_KEK, nid::ID_ALG_PWRI_KEK
 },
 NidUTInput {
  NID_id_smime_cd_ldap, nid::ID_SMIME_CD_LDAP
 },
 NidUTInput {
  NID_id_smime_spq_ets_sqt_uri, nid::ID_SMIME_SPQ_ETS_SQT_URI
 },
 NidUTInput {
  NID_id_smime_spq_ets_sqt_unotice, nid::ID_SMIME_SPQ_ETS_SQT_UNOTICE
 },
 NidUTInput {
  NID_id_smime_cti_ets_proofOfOrigin, nid::ID_SMIME_CTI_ETS_PROOFOFORIGIN
 },
 NidUTInput {
  NID_id_smime_cti_ets_proofOfReceipt, nid::ID_SMIME_CTI_ETS_PROOFOFRECEIPT
 },
 NidUTInput {
  NID_id_smime_cti_ets_proofOfDelivery, nid::ID_SMIME_CTI_ETS_PROOFOFDELIVERY
 },
 NidUTInput {
  NID_id_smime_cti_ets_proofOfSender, nid::ID_SMIME_CTI_ETS_PROOFOFSENDER
 },
 NidUTInput {
  NID_id_smime_cti_ets_proofOfApproval, nid::ID_SMIME_CTI_ETS_PROOFOFAPPROVAL
 },
 NidUTInput {
  NID_id_smime_cti_ets_proofOfCreation, nid::ID_SMIME_CTI_ETS_PROOFOFCREATION
 },
 NidUTInput {
  NID_friendlyName, nid::FRIENDLYNAME
 },
 NidUTInput {
  NID_localKeyID, nid::LOCALKEYID
 },
 NidUTInput {
  NID_ms_csp_name, nid::MS_CSP_NAME
 },
 NidUTInput {
  NID_LocalKeySet, nid::LOCALKEYSET
 },
 NidUTInput {
  NID_x509Certificate, nid::X509CERTIFICATE
 },
 NidUTInput {
  NID_sdsiCertificate, nid::SDSICERTIFICATE
 },
 NidUTInput {
  NID_x509Crl, nid::X509CRL
 },
 NidUTInput {
  NID_pbe_WithSHA1And128BitRC4, nid::PBE_WITHSHA1AND128BITRC4
 },
 NidUTInput {
  NID_pbe_WithSHA1And40BitRC4, nid::PBE_WITHSHA1AND40BITRC4
 },
 NidUTInput {
  NID_pbe_WithSHA1And3_Key_TripleDES_CBC, nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC
 },
 NidUTInput {
  NID_pbe_WithSHA1And2_Key_TripleDES_CBC, nid::PBE_WITHSHA1AND2_KEY_TRIPLEDES_CBC
 },
 NidUTInput {
  NID_pbe_WithSHA1And128BitRC2_CBC, nid::PBE_WITHSHA1AND128BITRC2_CBC
 },
 NidUTInput {
  NID_pbe_WithSHA1And40BitRC2_CBC, nid::PBE_WITHSHA1AND40BITRC2_CBC
 },
 NidUTInput {
  NID_keyBag, nid::KEYBAG
 },
 NidUTInput {
  NID_pkcs8ShroudedKeyBag, nid::PKCS8SHROUDEDKEYBAG
 },
 NidUTInput {
  NID_certBag, nid::CERTBAG
 },
 NidUTInput {
  NID_crlBag, nid::CRLBAG
 },
 NidUTInput {
  NID_secretBag, nid::SECRETBAG
 },
 NidUTInput {
  NID_safeContentsBag, nid::SAFECONTENTSBAG
 },
 NidUTInput {
  NID_md2, nid::MD2
 },
 NidUTInput {
  NID_md4, nid::MD4
 },
 NidUTInput {
  NID_md5, nid::MD5
 },
 NidUTInput {
  NID_md5_sha1, nid::MD5_SHA1
 },
 NidUTInput {
  NID_hmacWithMD5, nid::HMACWITHMD5
 },
 NidUTInput {
  NID_hmacWithSHA1, nid::HMACWITHSHA1
 },
 NidUTInput {
  NID_hmacWithSHA224, nid::HMACWITHSHA224
 },
 NidUTInput {
  NID_hmacWithSHA256, nid::HMACWITHSHA256
 },
 NidUTInput {
  NID_hmacWithSHA384, nid::HMACWITHSHA384
 },
 NidUTInput {
  NID_hmacWithSHA512, nid::HMACWITHSHA512
 },
 NidUTInput {
  NID_rc2_cbc, nid::RC2_CBC
 },
 NidUTInput {
  NID_rc2_ecb, nid::RC2_ECB
 },
 NidUTInput {
  NID_rc2_cfb64, nid::RC2_CFB64
 },
 NidUTInput {
  NID_rc2_ofb64, nid::RC2_OFB64
 },
 NidUTInput {
  NID_rc2_40_cbc, nid::RC2_40_CBC
 },
 NidUTInput {
  NID_rc2_64_cbc, nid::RC2_64_CBC
 },
 NidUTInput {
  NID_rc4, nid::RC4
 },
 NidUTInput {
  NID_rc4_40, nid::RC4_40
 },
 NidUTInput {
  NID_des_ede3_cbc, nid::DES_EDE3_CBC
 },
 NidUTInput {
  NID_rc5_cbc, nid::RC5_CBC
 },
 NidUTInput {
  NID_rc5_ecb, nid::RC5_ECB
 },
 NidUTInput {
  NID_rc5_cfb64, nid::RC5_CFB64
 },
 NidUTInput {
  NID_rc5_ofb64, nid::RC5_OFB64
 },
 NidUTInput {
  NID_ms_ext_req, nid::MS_EXT_REQ
 },
 NidUTInput {
  NID_ms_code_ind, nid::MS_CODE_IND
 },
 NidUTInput {
  NID_ms_code_com, nid::MS_CODE_COM
 },
 NidUTInput {
  NID_ms_ctl_sign, nid::MS_CTL_SIGN
 },
 NidUTInput {
  NID_ms_sgc, nid::MS_SGC
 },
 NidUTInput {
  NID_ms_efs, nid::MS_EFS
 },
 NidUTInput {
  NID_ms_smartcard_login, nid::MS_SMARTCARD_LOGIN
 },
 NidUTInput {
  NID_ms_upn, nid::MS_UPN
 },
 NidUTInput {
  NID_idea_cbc, nid::IDEA_CBC
 },
 NidUTInput {
  NID_idea_ecb, nid::IDEA_ECB
 },
 NidUTInput {
  NID_idea_cfb64, nid::IDEA_CFB64
 },
 NidUTInput {
  NID_idea_ofb64, nid::IDEA_OFB64
 },
 NidUTInput {
  NID_bf_cbc, nid::BF_CBC
 },
 NidUTInput {
  NID_bf_ecb, nid::BF_ECB
 },
 NidUTInput {
  NID_bf_cfb64, nid::BF_CFB64
 },
 NidUTInput {
  NID_bf_ofb64, nid::BF_OFB64
 },
 NidUTInput {
  NID_id_pkix, nid::ID_PKIX
 },
 NidUTInput {
  NID_id_pkix_mod, nid::ID_PKIX_MOD
 },
 NidUTInput {
  NID_id_pe, nid::ID_PE
 },
 NidUTInput {
  NID_id_qt, nid::ID_QT
 },
 NidUTInput {
  NID_id_kp, nid::ID_KP
 },
 NidUTInput {
  NID_id_it, nid::ID_IT
 },
 NidUTInput {
  NID_id_pkip, nid::ID_PKIP
 },
 NidUTInput {
  NID_id_alg, nid::ID_ALG
 },
 NidUTInput {
  NID_id_cmc, nid::ID_CMC
 },
 NidUTInput {
  NID_id_on, nid::ID_ON
 },
 NidUTInput {
  NID_id_pda, nid::ID_PDA
 },
 NidUTInput {
  NID_id_aca, nid::ID_ACA
 },
 NidUTInput {
  NID_id_qcs, nid::ID_QCS
 },
 NidUTInput {
  NID_id_cct, nid::ID_CCT
 },
 NidUTInput {
  NID_id_ppl, nid::ID_PPL
 },
 NidUTInput {
  NID_id_ad, nid::ID_AD
 },
 NidUTInput {
  NID_id_pkix1_explicit_88, nid::ID_PKIX1_EXPLICIT_88
 },
 NidUTInput {
  NID_id_pkix1_implicit_88, nid::ID_PKIX1_IMPLICIT_88
 },
 NidUTInput {
  NID_id_pkix1_explicit_93, nid::ID_PKIX1_EXPLICIT_93
 },
 NidUTInput {
  NID_id_pkix1_implicit_93, nid::ID_PKIX1_IMPLICIT_93
 },
 NidUTInput {
  NID_id_mod_crmf, nid::ID_MOD_CRMF
 },
 NidUTInput {
  NID_id_mod_cmc, nid::ID_MOD_CMC
 },
 NidUTInput {
  NID_id_mod_kea_profile_88, nid::ID_MOD_KEA_PROFILE_88
 },
 NidUTInput {
  NID_id_mod_kea_profile_93, nid::ID_MOD_KEA_PROFILE_93
 },
 NidUTInput {
  NID_id_mod_cmp, nid::ID_MOD_CMP
 },
 NidUTInput {
  NID_id_mod_qualified_cert_88, nid::ID_MOD_QUALIFIED_CERT_88
 },
 NidUTInput {
  NID_id_mod_qualified_cert_93, nid::ID_MOD_QUALIFIED_CERT_93
 },
 NidUTInput {
  NID_id_mod_attribute_cert, nid::ID_MOD_ATTRIBUTE_CERT
 },
 NidUTInput {
  NID_id_mod_timestamp_protocol, nid::ID_MOD_TIMESTAMP_PROTOCOL
 },
 NidUTInput {
  NID_id_mod_ocsp, nid::ID_MOD_OCSP
 },
 NidUTInput {
  NID_id_mod_dvcs, nid::ID_MOD_DVCS
 },
 NidUTInput {
  NID_id_mod_cmp2000, nid::ID_MOD_CMP2000
 },
 NidUTInput {
  NID_info_access, nid::INFO_ACCESS
 },
 NidUTInput {
  NID_biometricInfo, nid::BIOMETRICINFO
 },
 NidUTInput {
  NID_qcStatements, nid::QCSTATEMENTS
 },
 NidUTInput {
  NID_ac_auditEntity, nid::AC_AUDITENTITY
 },
 NidUTInput {
  NID_ac_targeting, nid::AC_TARGETING
 },
 NidUTInput {
  NID_aaControls, nid::AACONTROLS
 },
 NidUTInput {
  NID_sbgp_ipAddrBlock, nid::SBGP_IPADDRBLOCK
 },
 NidUTInput {
  NID_sbgp_autonomousSysNum, nid::SBGP_AUTONOMOUSSYSNUM
 },
 NidUTInput {
  NID_sbgp_routerIdentifier, nid::SBGP_ROUTERIDENTIFIER
 },
 NidUTInput {
  NID_ac_proxying, nid::AC_PROXYING
 },
 NidUTInput {
  NID_sinfo_access, nid::SINFO_ACCESS
 },
 NidUTInput {
  NID_proxyCertInfo, nid::PROXYCERTINFO
 },
 NidUTInput {
  NID_tlsfeature, nid::TLSFEATURE
 },
 NidUTInput {
  NID_id_qt_cps, nid::ID_QT_CPS
 },
 NidUTInput {
  NID_id_qt_unotice, nid::ID_QT_UNOTICE
 },
 NidUTInput {
  NID_textNotice, nid::TEXTNOTICE
 },
 NidUTInput {
  NID_server_auth, nid::SERVER_AUTH
 },
 NidUTInput {
  NID_client_auth, nid::CLIENT_AUTH
 },
 NidUTInput {
  NID_code_sign, nid::CODE_SIGN
 },
 NidUTInput {
  NID_email_protect, nid::EMAIL_PROTECT
 },
 NidUTInput {
  NID_ipsecEndSystem, nid::IPSECENDSYSTEM
 },
 NidUTInput {
  NID_ipsecTunnel, nid::IPSECTUNNEL
 },
 NidUTInput {
  NID_ipsecUser, nid::IPSECUSER
 },
 NidUTInput {
  NID_time_stamp, nid::TIME_STAMP
 },
 NidUTInput {
  NID_OCSP_sign, nid::OCSP_SIGN
 },
 NidUTInput {
  NID_dvcs, nid::DVCS
 },
 NidUTInput {
  NID_ipsec_IKE, nid::IPSEC_IKE
 },
 NidUTInput {
  NID_capwapAC, nid::CAPWAPAC
 },
 NidUTInput {
  NID_capwapWTP, nid::CAPWAPWTP
 },
 NidUTInput {
  NID_sshClient, nid::SSHCLIENT
 },
 NidUTInput {
  NID_sshServer, nid::SSHSERVER
 },
 NidUTInput {
  NID_sendRouter, nid::SENDROUTER
 },
 NidUTInput {
  NID_sendProxiedRouter, nid::SENDPROXIEDROUTER
 },
 NidUTInput {
  NID_sendOwner, nid::SENDOWNER
 },
 NidUTInput {
  NID_sendProxiedOwner, nid::SENDPROXIEDOWNER
 },
 NidUTInput {
  NID_id_it_caProtEncCert, nid::ID_IT_CAPROTENCCERT
 },
 NidUTInput {
  NID_id_it_signKeyPairTypes, nid::ID_IT_SIGNKEYPAIRTYPES
 },
 NidUTInput {
  NID_id_it_encKeyPairTypes, nid::ID_IT_ENCKEYPAIRTYPES
 },
 NidUTInput {
  NID_id_it_preferredSymmAlg, nid::ID_IT_PREFERREDSYMMALG
 },
 NidUTInput {
  NID_id_it_caKeyUpdateInfo, nid::ID_IT_CAKEYUPDATEINFO
 },
 NidUTInput {
  NID_id_it_currentCRL, nid::ID_IT_CURRENTCRL
 },
 NidUTInput {
  NID_id_it_unsupportedOIDs, nid::ID_IT_UNSUPPORTEDOIDS
 },
 NidUTInput {
  NID_id_it_subscriptionRequest, nid::ID_IT_SUBSCRIPTIONREQUEST
 },
 NidUTInput {
  NID_id_it_subscriptionResponse, nid::ID_IT_SUBSCRIPTIONRESPONSE
 },
 NidUTInput {
  NID_id_it_keyPairParamReq, nid::ID_IT_KEYPAIRPARAMREQ
 },
 NidUTInput {
  NID_id_it_keyPairParamRep, nid::ID_IT_KEYPAIRPARAMREP
 },
 NidUTInput {
  NID_id_it_revPassphrase, nid::ID_IT_REVPASSPHRASE
 },
 NidUTInput {
  NID_id_it_implicitConfirm, nid::ID_IT_IMPLICITCONFIRM
 },
 NidUTInput {
  NID_id_it_confirmWaitTime, nid::ID_IT_CONFIRMWAITTIME
 },
 NidUTInput {
  NID_id_it_origPKIMessage, nid::ID_IT_ORIGPKIMESSAGE
 },
 NidUTInput {
  NID_id_it_suppLangTags, nid::ID_IT_SUPPLANGTAGS
 },
 NidUTInput {
  NID_id_regCtrl, nid::ID_REGCTRL
 },
 NidUTInput {
  NID_id_regInfo, nid::ID_REGINFO
 },
 NidUTInput {
  NID_id_regCtrl_regToken, nid::ID_REGCTRL_REGTOKEN
 },
 NidUTInput {
  NID_id_regCtrl_authenticator, nid::ID_REGCTRL_AUTHENTICATOR
 },
 NidUTInput {
  NID_id_regCtrl_pkiPublicationInfo, nid::ID_REGCTRL_PKIPUBLICATIONINFO
 },
 NidUTInput {
  NID_id_regCtrl_pkiArchiveOptions, nid::ID_REGCTRL_PKIARCHIVEOPTIONS
 },
 NidUTInput {
  NID_id_regCtrl_oldCertID, nid::ID_REGCTRL_OLDCERTID
 },
 NidUTInput {
  NID_id_regCtrl_protocolEncrKey, nid::ID_REGCTRL_PROTOCOLENCRKEY
 },
 NidUTInput {
  NID_id_regInfo_utf8Pairs, nid::ID_REGINFO_UTF8PAIRS
 },
 NidUTInput {
  NID_id_regInfo_certReq, nid::ID_REGINFO_CERTREQ
 },
 NidUTInput {
  NID_id_alg_des40, nid::ID_ALG_DES40
 },
 NidUTInput {
  NID_id_alg_noSignature, nid::ID_ALG_NOSIGNATURE
 },
 NidUTInput {
  NID_id_alg_dh_sig_hmac_sha1, nid::ID_ALG_DH_SIG_HMAC_SHA1
 },
 NidUTInput {
  NID_id_alg_dh_pop, nid::ID_ALG_DH_POP
 },
 NidUTInput {
  NID_id_cmc_statusInfo, nid::ID_CMC_STATUSINFO
 },
 NidUTInput {
  NID_id_cmc_identification, nid::ID_CMC_IDENTIFICATION
 },
 NidUTInput {
  NID_id_cmc_identityProof, nid::ID_CMC_IDENTITYPROOF
 },
 NidUTInput {
  NID_id_cmc_dataReturn, nid::ID_CMC_DATARETURN
 },
 NidUTInput {
  NID_id_cmc_transactionId, nid::ID_CMC_TRANSACTIONID
 },
 NidUTInput {
  NID_id_cmc_senderNonce, nid::ID_CMC_SENDERNONCE
 },
 NidUTInput {
  NID_id_cmc_recipientNonce, nid::ID_CMC_RECIPIENTNONCE
 },
 NidUTInput {
  NID_id_cmc_addExtensions, nid::ID_CMC_ADDEXTENSIONS
 },
 NidUTInput {
  NID_id_cmc_encryptedPOP, nid::ID_CMC_ENCRYPTEDPOP
 },
 NidUTInput {
  NID_id_cmc_decryptedPOP, nid::ID_CMC_DECRYPTEDPOP
 },
 NidUTInput {
  NID_id_cmc_lraPOPWitness, nid::ID_CMC_LRAPOPWITNESS
 },
 NidUTInput {
  NID_id_cmc_getCert, nid::ID_CMC_GETCERT
 },
 NidUTInput {
  NID_id_cmc_getCRL, nid::ID_CMC_GETCRL
 },
 NidUTInput {
  NID_id_cmc_revokeRequest, nid::ID_CMC_REVOKEREQUEST
 },
 NidUTInput {
  NID_id_cmc_regInfo, nid::ID_CMC_REGINFO
 },
 NidUTInput {
  NID_id_cmc_responseInfo, nid::ID_CMC_RESPONSEINFO
 },
 NidUTInput {
  NID_id_cmc_queryPending, nid::ID_CMC_QUERYPENDING
 },
 NidUTInput {
  NID_id_cmc_popLinkRandom, nid::ID_CMC_POPLINKRANDOM
 },
 NidUTInput {
  NID_id_cmc_popLinkWitness, nid::ID_CMC_POPLINKWITNESS
 },
 NidUTInput {
  NID_id_cmc_confirmCertAcceptance, nid::ID_CMC_CONFIRMCERTACCEPTANCE
 },
 NidUTInput {
  NID_id_on_personalData, nid::ID_ON_PERSONALDATA
 },
 NidUTInput {
  NID_id_on_permanentIdentifier, nid::ID_ON_PERMANENTIDENTIFIER
 },
 NidUTInput {
  NID_id_pda_dateOfBirth, nid::ID_PDA_DATEOFBIRTH
 },
 NidUTInput {
  NID_id_pda_placeOfBirth, nid::ID_PDA_PLACEOFBIRTH
 },
 NidUTInput {
  NID_id_pda_gender, nid::ID_PDA_GENDER
 },
 NidUTInput {
  NID_id_pda_countryOfCitizenship, nid::ID_PDA_COUNTRYOFCITIZENSHIP
 },
 NidUTInput {
  NID_id_pda_countryOfResidence, nid::ID_PDA_COUNTRYOFRESIDENCE
 },
 NidUTInput {
  NID_id_aca_authenticationInfo, nid::ID_ACA_AUTHENTICATIONINFO
 },
 NidUTInput {
  NID_id_aca_accessIdentity, nid::ID_ACA_ACCESSIDENTITY
 },
 NidUTInput {
  NID_id_aca_chargingIdentity, nid::ID_ACA_CHARGINGIDENTITY
 },
 NidUTInput {
  NID_id_aca_group, nid::ID_ACA_GROUP
 },
 NidUTInput {
  NID_id_aca_role, nid::ID_ACA_ROLE
 },
 NidUTInput {
  NID_id_aca_encAttrs, nid::ID_ACA_ENCATTRS
 },
 NidUTInput {
  NID_id_qcs_pkixQCSyntax_v1, nid::ID_QCS_PKIXQCSYNTAX_V1
 },
 NidUTInput {
  NID_id_cct_crs, nid::ID_CCT_CRS
 },
 NidUTInput {
  NID_id_cct_PKIData, nid::ID_CCT_PKIDATA
 },
 NidUTInput {
  NID_id_cct_PKIResponse, nid::ID_CCT_PKIRESPONSE
 },
 NidUTInput {
  NID_id_ppl_anyLanguage, nid::ID_PPL_ANYLANGUAGE
 },
 NidUTInput {
  NID_id_ppl_inheritAll, nid::ID_PPL_INHERITALL
 },
 NidUTInput {
  NID_Independent, nid::INDEPENDENT
 },
 NidUTInput {
  NID_ad_OCSP, nid::AD_OCSP
 },
 NidUTInput {
  NID_ad_ca_issuers, nid::AD_CA_ISSUERS
 },
 NidUTInput {
  NID_ad_timeStamping, nid::AD_TIMESTAMPING
 },
 NidUTInput {
  NID_ad_dvcs, nid::AD_DVCS
 },
 NidUTInput {
  NID_caRepository, nid::CAREPOSITORY
 },
 NidUTInput {
  NID_id_pkix_OCSP_basic, nid::ID_PKIX_OCSP_BASIC
 },
 NidUTInput {
  NID_id_pkix_OCSP_Nonce, nid::ID_PKIX_OCSP_NONCE
 },
 NidUTInput {
  NID_id_pkix_OCSP_CrlID, nid::ID_PKIX_OCSP_CRLID
 },
 NidUTInput {
  NID_id_pkix_OCSP_acceptableResponses, nid::ID_PKIX_OCSP_ACCEPTABLERESPONSES
 },
 NidUTInput {
  NID_id_pkix_OCSP_noCheck, nid::ID_PKIX_OCSP_NOCHECK
 },
 NidUTInput {
  NID_id_pkix_OCSP_archiveCutoff, nid::ID_PKIX_OCSP_ARCHIVECUTOFF
 },
 NidUTInput {
  NID_id_pkix_OCSP_serviceLocator, nid::ID_PKIX_OCSP_SERVICELOCATOR
 },
 NidUTInput {
  NID_id_pkix_OCSP_extendedStatus, nid::ID_PKIX_OCSP_EXTENDEDSTATUS
 },
 NidUTInput {
  NID_id_pkix_OCSP_valid, nid::ID_PKIX_OCSP_VALID
 },
 NidUTInput {
  NID_id_pkix_OCSP_path, nid::ID_PKIX_OCSP_PATH
 },
 NidUTInput {
  NID_id_pkix_OCSP_trustRoot, nid::ID_PKIX_OCSP_TRUSTROOT
 },
 NidUTInput {
  NID_algorithm, nid::ALGORITHM
 },
 NidUTInput {
  NID_md5WithRSA, nid::MD5WITHRSA
 },
 NidUTInput {
  NID_des_ecb, nid::DES_ECB
 },
 NidUTInput {
  NID_des_cbc, nid::DES_CBC
 },
 NidUTInput {
  NID_des_ofb64, nid::DES_OFB64
 },
 NidUTInput {
  NID_des_cfb64, nid::DES_CFB64
 },
 NidUTInput {
  NID_rsaSignature, nid::RSASIGNATURE
 },
 NidUTInput {
  NID_dsa_2, nid::DSA_2
 },
 NidUTInput {
  NID_dsaWithSHA, nid::DSAWITHSHA
 },
 NidUTInput {
  NID_shaWithRSAEncryption, nid::SHAWITHRSAENCRYPTION
 },
 NidUTInput {
  NID_des_ede_ecb, nid::DES_EDE_ECB
 },
 NidUTInput {
  NID_des_ede3_ecb, nid::DES_EDE3_ECB
 },
 NidUTInput {
  NID_des_ede_cbc, nid::DES_EDE_CBC
 },
 NidUTInput {
  NID_des_ede_cfb64, nid::DES_EDE_CFB64
 },
 NidUTInput {
  NID_des_ede3_cfb64, nid::DES_EDE3_CFB64
 },
 NidUTInput {
  NID_des_ede_ofb64, nid::DES_EDE_OFB64
 },
 NidUTInput {
  NID_des_ede3_ofb64, nid::DES_EDE3_OFB64
 },
 NidUTInput {
  NID_desx_cbc, nid::DESX_CBC
 },
 NidUTInput {
  NID_sha, nid::SHA
 },
 NidUTInput {
  NID_sha1, nid::SHA1
 },
 NidUTInput {
  NID_dsaWithSHA1_2, nid::DSAWITHSHA1_2
 },
 NidUTInput {
  NID_sha1WithRSA, nid::SHA1WITHRSA
 },
 NidUTInput {
  NID_ripemd160, nid::RIPEMD160
 },
 NidUTInput {
  NID_ripemd160WithRSA, nid::RIPEMD160WITHRSA
 },
 NidUTInput {
  NID_blake2b512, nid::BLAKE2B512
 },
 NidUTInput {
  NID_blake2s256, nid::BLAKE2S256
 },
 NidUTInput {
  NID_sxnet, nid::SXNET
 },
 NidUTInput {
  NID_X500, nid::X500
 },
 NidUTInput {
  NID_X509, nid::X509
 },
 NidUTInput {
  NID_commonName, nid::COMMONNAME
 },
 NidUTInput {
  NID_surname, nid::SURNAME
 },
 NidUTInput {
  NID_serialNumber, nid::SERIALNUMBER
 },
 NidUTInput {
  NID_countryName, nid::COUNTRYNAME
 },
 NidUTInput {
  NID_localityName, nid::LOCALITYNAME
 },
 NidUTInput {
  NID_stateOrProvinceName, nid::STATEORPROVINCENAME
 },
 NidUTInput {
  NID_streetAddress, nid::STREETADDRESS
 },
 NidUTInput {
  NID_organizationName, nid::ORGANIZATIONNAME
 },
 NidUTInput {
  NID_organizationalUnitName, nid::ORGANIZATIONALUNITNAME
 },
 NidUTInput {
  NID_title, nid::TITLE
 },
 NidUTInput {
  NID_description, nid::DESCRIPTION
 },
 NidUTInput {
  NID_searchGuide, nid::SEARCHGUIDE
 },
 NidUTInput {
  NID_businessCategory, nid::BUSINESSCATEGORY
 },
 NidUTInput {
  NID_postalAddress, nid::POSTALADDRESS
 },
 NidUTInput {
  NID_postalCode, nid::POSTALCODE
 },
 NidUTInput {
  NID_postOfficeBox, nid::POSTOFFICEBOX
 },
 NidUTInput {
  NID_physicalDeliveryOfficeName, nid::PHYSICALDELIVERYOFFICENAME
 },
 NidUTInput {
  NID_telephoneNumber, nid::TELEPHONENUMBER
 },
 NidUTInput {
  NID_telexNumber, nid::TELEXNUMBER
 },
 NidUTInput {
  NID_teletexTerminalIdentifier, nid::TELETEXTERMINALIDENTIFIER
 },
 NidUTInput {
  NID_facsimileTelephoneNumber, nid::FACSIMILETELEPHONENUMBER
 },
 NidUTInput {
  NID_x121Address, nid::X121ADDRESS
 },
 NidUTInput {
  NID_internationaliSDNNumber, nid::INTERNATIONALISDNNUMBER
 },
 NidUTInput {
  NID_registeredAddress, nid::REGISTEREDADDRESS
 },
 NidUTInput {
  NID_destinationIndicator, nid::DESTINATIONINDICATOR
 },
 NidUTInput {
  NID_preferredDeliveryMethod, nid::PREFERREDDELIVERYMETHOD
 },
 NidUTInput {
  NID_presentationAddress, nid::PRESENTATIONADDRESS
 },
 NidUTInput {
  NID_supportedApplicationContext, nid::SUPPORTEDAPPLICATIONCONTEXT
 },
 NidUTInput {
  NID_member, nid::MEMBER
 },
 NidUTInput {
  NID_owner, nid::OWNER
 },
 NidUTInput {
  NID_roleOccupant, nid::ROLEOCCUPANT
 },
 NidUTInput {
  NID_seeAlso, nid::SEEALSO
 },
 NidUTInput {
  NID_userPassword, nid::USERPASSWORD
 },
 NidUTInput {
  NID_userCertificate, nid::USERCERTIFICATE
 },
 NidUTInput {
  NID_cACertificate, nid::CACERTIFICATE
 },
 NidUTInput {
  NID_authorityRevocationList, nid::AUTHORITYREVOCATIONLIST
 },
 NidUTInput {
  NID_certificateRevocationList, nid::CERTIFICATEREVOCATIONLIST
 },
 NidUTInput {
  NID_crossCertificatePair, nid::CROSSCERTIFICATEPAIR
 },
 NidUTInput {
  NID_name, nid::NAME
 },
 NidUTInput {
  NID_givenName, nid::GIVENNAME
 },
 NidUTInput {
  NID_initials, nid::INITIALS
 },
 NidUTInput {
  NID_generationQualifier, nid::GENERATIONQUALIFIER
 },
 NidUTInput {
  NID_x500UniqueIdentifier, nid::X500UNIQUEIDENTIFIER
 },
 NidUTInput {
  NID_dnQualifier, nid::DNQUALIFIER
 },
 NidUTInput {
  NID_enhancedSearchGuide, nid::ENHANCEDSEARCHGUIDE
 },
 NidUTInput {
  NID_protocolInformation, nid::PROTOCOLINFORMATION
 },
 NidUTInput {
  NID_distinguishedName, nid::DISTINGUISHEDNAME
 },
 NidUTInput {
  NID_uniqueMember, nid::UNIQUEMEMBER
 },
 NidUTInput {
  NID_houseIdentifier, nid::HOUSEIDENTIFIER
 },
 NidUTInput {
  NID_supportedAlgorithms, nid::SUPPORTEDALGORITHMS
 },
 NidUTInput {
  NID_deltaRevocationList, nid::DELTAREVOCATIONLIST
 },
 NidUTInput {
  NID_dmdName, nid::DMDNAME
 },
 NidUTInput {
  NID_pseudonym, nid::PSEUDONYM
 },
 NidUTInput {
  NID_role, nid::ROLE
 },
 NidUTInput {
  NID_X500algorithms, nid::X500ALGORITHMS
 },
 NidUTInput {
  NID_rsa, nid::RSA
 },
 NidUTInput {
  NID_mdc2WithRSA, nid::MDC2WITHRSA
 },
 NidUTInput {
  NID_mdc2, nid::MDC2
 },
 NidUTInput {
  NID_id_ce, nid::ID_CE
 },
 NidUTInput {
  NID_subject_directory_attributes, nid::SUBJECT_DIRECTORY_ATTRIBUTES
 },
 NidUTInput {
  NID_subject_key_identifier, nid::SUBJECT_KEY_IDENTIFIER
 },
 NidUTInput {
  NID_key_usage, nid::KEY_USAGE
 },
 NidUTInput {
  NID_private_key_usage_period, nid::PRIVATE_KEY_USAGE_PERIOD
 },
 NidUTInput {
  NID_subject_alt_name, nid::SUBJECT_ALT_NAME
 },
 NidUTInput {
  NID_issuer_alt_name, nid::ISSUER_ALT_NAME
 },
 NidUTInput {
  NID_basic_constraints, nid::BASIC_CONSTRAINTS
 },
 NidUTInput {
  NID_crl_number, nid::CRL_NUMBER
 },
 NidUTInput {
  NID_crl_reason, nid::CRL_REASON
 },
 NidUTInput {
  NID_invalidity_date, nid::INVALIDITY_DATE
 },
 NidUTInput {
  NID_delta_crl, nid::DELTA_CRL
 },
 NidUTInput {
  NID_issuing_distribution_point, nid::ISSUING_DISTRIBUTION_POINT
 },
 NidUTInput {
  NID_certificate_issuer, nid::CERTIFICATE_ISSUER
 },
 NidUTInput {
  NID_name_constraints, nid::NAME_CONSTRAINTS
 },
 NidUTInput {
  NID_crl_distribution_points, nid::CRL_DISTRIBUTION_POINTS
 },
 NidUTInput {
  NID_certificate_policies, nid::CERTIFICATE_POLICIES
 },
 NidUTInput {
  NID_any_policy, nid::ANY_POLICY
 },
 NidUTInput {
  NID_policy_mappings, nid::POLICY_MAPPINGS
 },
 NidUTInput {
  NID_authority_key_identifier, nid::AUTHORITY_KEY_IDENTIFIER
 },
 NidUTInput {
  NID_policy_constraints, nid::POLICY_CONSTRAINTS
 },
 NidUTInput {
  NID_ext_key_usage, nid::EXT_KEY_USAGE
 },
 NidUTInput {
  NID_freshest_crl, nid::FRESHEST_CRL
 },
 NidUTInput {
  NID_inhibit_any_policy, nid::INHIBIT_ANY_POLICY
 },
 NidUTInput {
  NID_target_information, nid::TARGET_INFORMATION
 },
 NidUTInput {
  NID_no_rev_avail, nid::NO_REV_AVAIL
 },
 NidUTInput {
  NID_anyExtendedKeyUsage, nid::ANYEXTENDEDKEYUSAGE
 },
 NidUTInput {
  NID_netscape, nid::NETSCAPE
 },
 NidUTInput {
  NID_netscape_cert_extension, nid::NETSCAPE_CERT_EXTENSION
 },
 NidUTInput {
  NID_netscape_data_type, nid::NETSCAPE_DATA_TYPE
 },
 NidUTInput {
  NID_netscape_cert_type, nid::NETSCAPE_CERT_TYPE
 },
 NidUTInput {
  NID_netscape_base_url, nid::NETSCAPE_BASE_URL
 },
 NidUTInput {
  NID_netscape_revocation_url, nid::NETSCAPE_REVOCATION_URL
 },
 NidUTInput {
  NID_netscape_ca_revocation_url, nid::NETSCAPE_CA_REVOCATION_URL
 },
 NidUTInput {
  NID_netscape_renewal_url, nid::NETSCAPE_RENEWAL_URL
 },
 NidUTInput {
  NID_netscape_ca_policy_url, nid::NETSCAPE_CA_POLICY_URL
 },
 NidUTInput {
  NID_netscape_ssl_server_name, nid::NETSCAPE_SSL_SERVER_NAME
 },
 NidUTInput {
  NID_netscape_comment, nid::NETSCAPE_COMMENT
 },
 NidUTInput {
  NID_netscape_cert_sequence, nid::NETSCAPE_CERT_SEQUENCE
 },
 NidUTInput {
  NID_ns_sgc, nid::NS_SGC
 },
 NidUTInput {
  NID_org, nid::ORG
 },
 NidUTInput {
  NID_dod, nid::DOD
 },
 NidUTInput {
  NID_iana, nid::IANA
 },
 NidUTInput {
  NID_Directory, nid::DIRECTORY
 },
 NidUTInput {
  NID_Management, nid::MANAGEMENT
 },
 NidUTInput {
  NID_Experimental, nid::EXPERIMENTAL
 },
 NidUTInput {
  NID_Private, nid::PRIVATE
 },
 NidUTInput {
  NID_Security, nid::SECURITY
 },
 NidUTInput {
  NID_SNMPv2, nid::SNMPV2
 },
 NidUTInput {
  NID_Mail, nid::MAIL
 },
 NidUTInput {
  NID_Enterprises, nid::ENTERPRISES
 },
 NidUTInput {
  NID_dcObject, nid::DCOBJECT
 },
 NidUTInput {
  NID_mime_mhs, nid::MIME_MHS
 },
 NidUTInput {
  NID_mime_mhs_headings, nid::MIME_MHS_HEADINGS
 },
 NidUTInput {
  NID_mime_mhs_bodies, nid::MIME_MHS_BODIES
 },
 NidUTInput {
  NID_id_hex_partial_message, nid::ID_HEX_PARTIAL_MESSAGE
 },
 NidUTInput {
  NID_id_hex_multipart_message, nid::ID_HEX_MULTIPART_MESSAGE
 },
 NidUTInput {
  NID_zlib_compression, nid::ZLIB_COMPRESSION
 },
 NidUTInput {
  NID_aes_128_ecb, nid::AES_128_ECB
 },
 NidUTInput {
  NID_aes_128_cbc, nid::AES_128_CBC
 },
 NidUTInput {
  NID_aes_128_ofb128, nid::AES_128_OFB128
 },
 NidUTInput {
  NID_aes_128_cfb128, nid::AES_128_CFB128
 },
 NidUTInput {
  NID_id_aes128_wrap, nid::ID_AES128_WRAP
 },
 NidUTInput {
  NID_aes_128_gcm, nid::AES_128_GCM
 },
 NidUTInput {
  NID_aes_128_ccm, nid::AES_128_CCM
 },
 NidUTInput {
  NID_id_aes128_wrap_pad, nid::ID_AES128_WRAP_PAD
 },
 NidUTInput {
  NID_aes_192_ecb, nid::AES_192_ECB
 },
 NidUTInput {
  NID_aes_192_cbc, nid::AES_192_CBC
 },
 NidUTInput {
  NID_aes_192_ofb128, nid::AES_192_OFB128
 },
 NidUTInput {
  NID_aes_192_cfb128, nid::AES_192_CFB128
 },
 NidUTInput {
  NID_id_aes192_wrap, nid::ID_AES192_WRAP
 },
 NidUTInput {
  NID_aes_192_gcm, nid::AES_192_GCM
 },
 NidUTInput {
  NID_aes_192_ccm, nid::AES_192_CCM
 },
 NidUTInput {
  NID_id_aes192_wrap_pad, nid::ID_AES192_WRAP_PAD
 },
 NidUTInput {
  NID_aes_256_ecb, nid::AES_256_ECB
 },
 NidUTInput {
  NID_aes_256_cbc, nid::AES_256_CBC
 },
 NidUTInput {
  NID_aes_256_ofb128, nid::AES_256_OFB128
 },
 NidUTInput {
  NID_aes_256_cfb128, nid::AES_256_CFB128
 },
 NidUTInput {
  NID_id_aes256_wrap, nid::ID_AES256_WRAP
 },
 NidUTInput {
  NID_aes_256_gcm, nid::AES_256_GCM
 },
 NidUTInput {
  NID_aes_256_ccm, nid::AES_256_CCM
 },
 NidUTInput {
  NID_id_aes256_wrap_pad, nid::ID_AES256_WRAP_PAD
 },
 NidUTInput {
  NID_aes_128_cfb1, nid::AES_128_CFB1
 },
 NidUTInput {
  NID_aes_192_cfb1, nid::AES_192_CFB1
 },
 NidUTInput {
  NID_aes_256_cfb1, nid::AES_256_CFB1
 },
 NidUTInput {
  NID_aes_128_cfb8, nid::AES_128_CFB8
 },
 NidUTInput {
  NID_aes_192_cfb8, nid::AES_192_CFB8
 },
 NidUTInput {
  NID_aes_256_cfb8, nid::AES_256_CFB8
 },
 NidUTInput {
  NID_aes_128_ctr, nid::AES_128_CTR
 },
 NidUTInput {
  NID_aes_192_ctr, nid::AES_192_CTR
 },
 NidUTInput {
  NID_aes_256_ctr, nid::AES_256_CTR
 },
 NidUTInput {
  NID_aes_128_ocb, nid::AES_128_OCB
 },
 NidUTInput {
  NID_aes_192_ocb, nid::AES_192_OCB
 },
 NidUTInput {
  NID_aes_256_ocb, nid::AES_256_OCB
 },
 NidUTInput {
  NID_aes_128_xts, nid::AES_128_XTS
 },
 NidUTInput {
  NID_aes_256_xts, nid::AES_256_XTS
 },
 NidUTInput {
  NID_des_cfb1, nid::DES_CFB1
 },
 NidUTInput {
  NID_des_cfb8, nid::DES_CFB8
 },
 NidUTInput {
  NID_des_ede3_cfb1, nid::DES_EDE3_CFB1
 },
 NidUTInput {
  NID_des_ede3_cfb8, nid::DES_EDE3_CFB8
 },
 NidUTInput {
  NID_sha256, nid::SHA256
 },
 NidUTInput {
  NID_sha384, nid::SHA384
 },
 NidUTInput {
  NID_sha512, nid::SHA512
 },
 NidUTInput {
  NID_sha224, nid::SHA224
 },
 NidUTInput {
  NID_dsa_with_SHA224, nid::DSA_WITH_SHA224
 },
 NidUTInput {
  NID_dsa_with_SHA256, nid::DSA_WITH_SHA256
 },
 NidUTInput {
  NID_hold_instruction_code, nid::HOLD_INSTRUCTION_CODE
 },
 NidUTInput {
  NID_hold_instruction_none, nid::HOLD_INSTRUCTION_NONE
 },
 NidUTInput {
  NID_hold_instruction_call_issuer, nid::HOLD_INSTRUCTION_CALL_ISSUER
 },
 NidUTInput {
  NID_hold_instruction_reject, nid::HOLD_INSTRUCTION_REJECT
 },
 NidUTInput {
  NID_data, nid::DATA
 },
 NidUTInput {
  NID_pss, nid::PSS
 },
 NidUTInput {
  NID_ucl, nid::UCL
 },
 NidUTInput {
  NID_pilot, nid::PILOT
 },
 NidUTInput {
  NID_pilotAttributeType, nid::PILOTATTRIBUTETYPE
 },
 NidUTInput {
  NID_pilotAttributeSyntax, nid::PILOTATTRIBUTESYNTAX
 },
 NidUTInput {
  NID_pilotObjectClass, nid::PILOTOBJECTCLASS
 },
 NidUTInput {
  NID_pilotGroups, nid::PILOTGROUPS
 },
 NidUTInput {
  NID_iA5StringSyntax, nid::IA5STRINGSYNTAX
 },
 NidUTInput {
  NID_caseIgnoreIA5StringSyntax, nid::CASEIGNOREIA5STRINGSYNTAX
 },
 NidUTInput {
  NID_pilotObject, nid::PILOTOBJECT
 },
 NidUTInput {
  NID_pilotPerson, nid::PILOTPERSON
 },
 NidUTInput {
  NID_account, nid::ACCOUNT
 },
 NidUTInput {
  NID_document, nid::DOCUMENT
 },
 NidUTInput {
  NID_room, nid::ROOM
 },
 NidUTInput {
  NID_documentSeries, nid::DOCUMENTSERIES
 },
 NidUTInput {
  NID_Domain, nid::DOMAIN
 },
 NidUTInput {
  NID_rFC822localPart, nid::RFC822LOCALPART
 },
 NidUTInput {
  NID_dNSDomain, nid::DNSDOMAIN
 },
 NidUTInput {
  NID_domainRelatedObject, nid::DOMAINRELATEDOBJECT
 },
 NidUTInput {
  NID_friendlyCountry, nid::FRIENDLYCOUNTRY
 },
 NidUTInput {
  NID_simpleSecurityObject, nid::SIMPLESECURITYOBJECT
 },
 NidUTInput {
  NID_pilotOrganization, nid::PILOTORGANIZATION
 },
 NidUTInput {
  NID_pilotDSA, nid::PILOTDSA
 },
 NidUTInput {
  NID_qualityLabelledData, nid::QUALITYLABELLEDDATA
 },
 NidUTInput {
  NID_userId, nid::USERID
 },
 NidUTInput {
  NID_textEncodedORAddress, nid::TEXTENCODEDORADDRESS
 },
 NidUTInput {
  NID_rfc822Mailbox, nid::RFC822MAILBOX
 },
 NidUTInput {
  NID_info, nid::INFO
 },
 NidUTInput {
  NID_favouriteDrink, nid::FAVOURITEDRINK
 },
 NidUTInput {
  NID_roomNumber, nid::ROOMNUMBER
 },
 NidUTInput {
  NID_photo, nid::PHOTO
 },
 NidUTInput {
  NID_userClass, nid::USERCLASS
 },
 NidUTInput {
  NID_host, nid::HOST
 },
 NidUTInput {
  NID_manager, nid::MANAGER
 },
 NidUTInput {
  NID_documentIdentifier, nid::DOCUMENTIDENTIFIER
 },
 NidUTInput {
  NID_documentTitle, nid::DOCUMENTTITLE
 },
 NidUTInput {
  NID_documentVersion, nid::DOCUMENTVERSION
 },
 NidUTInput {
  NID_documentAuthor, nid::DOCUMENTAUTHOR
 },
 NidUTInput {
  NID_documentLocation, nid::DOCUMENTLOCATION
 },
 NidUTInput {
  NID_homeTelephoneNumber, nid::HOMETELEPHONENUMBER
 },
 NidUTInput {
  NID_secretary, nid::SECRETARY
 },
 NidUTInput {
  NID_otherMailbox, nid::OTHERMAILBOX
 },
 NidUTInput {
  NID_lastModifiedTime, nid::LASTMODIFIEDTIME
 },
 NidUTInput {
  NID_lastModifiedBy, nid::LASTMODIFIEDBY
 },
 NidUTInput {
  NID_domainComponent, nid::DOMAINCOMPONENT
 },
 NidUTInput {
  NID_aRecord, nid::ARECORD
 },
 NidUTInput {
  NID_pilotAttributeType27, nid::PILOTATTRIBUTETYPE27
 },
 NidUTInput {
  NID_mXRecord, nid::MXRECORD
 },
 NidUTInput {
  NID_nSRecord, nid::NSRECORD
 },
 NidUTInput {
  NID_sOARecord, nid::SOARECORD
 },
 NidUTInput {
  NID_cNAMERecord, nid::CNAMERECORD
 },
 NidUTInput {
  NID_associatedDomain, nid::ASSOCIATEDDOMAIN
 },
 NidUTInput {
  NID_associatedName, nid::ASSOCIATEDNAME
 },
 NidUTInput {
  NID_homePostalAddress, nid::HOMEPOSTALADDRESS
 },
 NidUTInput {
  NID_personalTitle, nid::PERSONALTITLE
 },
 NidUTInput {
  NID_mobileTelephoneNumber, nid::MOBILETELEPHONENUMBER
 },
 NidUTInput {
  NID_pagerTelephoneNumber, nid::PAGERTELEPHONENUMBER
 },
 NidUTInput {
  NID_friendlyCountryName, nid::FRIENDLYCOUNTRYNAME
 },
 NidUTInput {
  NID_uniqueIdentifier, nid::UNIQUEIDENTIFIER
 },
 NidUTInput {
  NID_organizationalStatus, nid::ORGANIZATIONALSTATUS
 },
 NidUTInput {
  NID_janetMailbox, nid::JANETMAILBOX
 },
 NidUTInput {
  NID_mailPreferenceOption, nid::MAILPREFERENCEOPTION
 },
 NidUTInput {
  NID_buildingName, nid::BUILDINGNAME
 },
 NidUTInput {
  NID_dSAQuality, nid::DSAQUALITY
 },
 NidUTInput {
  NID_singleLevelQuality, nid::SINGLELEVELQUALITY
 },
 NidUTInput {
  NID_subtreeMinimumQuality, nid::SUBTREEMINIMUMQUALITY
 },
 NidUTInput {
  NID_subtreeMaximumQuality, nid::SUBTREEMAXIMUMQUALITY
 },
 NidUTInput {
  NID_personalSignature, nid::PERSONALSIGNATURE
 },
 NidUTInput {
  NID_dITRedirect, nid::DITREDIRECT
 },
 NidUTInput {
  NID_audio, nid::AUDIO
 },
 NidUTInput {
  NID_documentPublisher, nid::DOCUMENTPUBLISHER
 },
 NidUTInput {
  NID_id_set, nid::ID_SET
 },
 NidUTInput {
  NID_set_ctype, nid::SET_CTYPE
 },
 NidUTInput {
  NID_set_msgExt, nid::SET_MSGEXT
 },
 NidUTInput {
  NID_set_attr, nid::SET_ATTR
 },
 NidUTInput {
  NID_set_policy, nid::SET_POLICY
 },
 NidUTInput {
  NID_set_certExt, nid::SET_CERTEXT
 },
 NidUTInput {
  NID_set_brand, nid::SET_BRAND
 },
 NidUTInput {
  NID_setct_PANData, nid::SETCT_PANDATA
 },
 NidUTInput {
  NID_setct_PANToken, nid::SETCT_PANTOKEN
 },
 NidUTInput {
  NID_setct_PANOnly, nid::SETCT_PANONLY
 },
 NidUTInput {
  NID_setct_OIData, nid::SETCT_OIDATA
 },
 NidUTInput {
  NID_setct_PI, nid::SETCT_PI
 },
 NidUTInput {
  NID_setct_PIData, nid::SETCT_PIDATA
 },
 NidUTInput {
  NID_setct_PIDataUnsigned, nid::SETCT_PIDATAUNSIGNED
 },
 NidUTInput {
  NID_setct_HODInput, nid::SETCT_HODINPUT
 },
 NidUTInput {
  NID_setct_AuthResBaggage, nid::SETCT_AUTHRESBAGGAGE
 },
 NidUTInput {
  NID_setct_AuthRevReqBaggage, nid::SETCT_AUTHREVREQBAGGAGE
 },
 NidUTInput {
  NID_setct_AuthRevResBaggage, nid::SETCT_AUTHREVRESBAGGAGE
 },
 NidUTInput {
  NID_setct_CapTokenSeq, nid::SETCT_CAPTOKENSEQ
 },
 NidUTInput {
  NID_setct_PInitResData, nid::SETCT_PINITRESDATA
 },
 NidUTInput {
  NID_setct_PI_TBS, nid::SETCT_PI_TBS
 },
 NidUTInput {
  NID_setct_PResData, nid::SETCT_PRESDATA
 },
 NidUTInput {
  NID_setct_AuthReqTBS, nid::SETCT_AUTHREQTBS
 },
 NidUTInput {
  NID_setct_AuthResTBS, nid::SETCT_AUTHRESTBS
 },
 NidUTInput {
  NID_setct_AuthResTBSX, nid::SETCT_AUTHRESTBSX
 },
 NidUTInput {
  NID_setct_AuthTokenTBS, nid::SETCT_AUTHTOKENTBS
 },
 NidUTInput {
  NID_setct_CapTokenData, nid::SETCT_CAPTOKENDATA
 },
 NidUTInput {
  NID_setct_CapTokenTBS, nid::SETCT_CAPTOKENTBS
 },
 NidUTInput {
  NID_setct_AcqCardCodeMsg, nid::SETCT_ACQCARDCODEMSG
 },
 NidUTInput {
  NID_setct_AuthRevReqTBS, nid::SETCT_AUTHREVREQTBS
 },
 NidUTInput {
  NID_setct_AuthRevResData, nid::SETCT_AUTHREVRESDATA
 },
 NidUTInput {
  NID_setct_AuthRevResTBS, nid::SETCT_AUTHREVRESTBS
 },
 NidUTInput {
  NID_setct_CapReqTBS, nid::SETCT_CAPREQTBS
 },
 NidUTInput {
  NID_setct_CapReqTBSX, nid::SETCT_CAPREQTBSX
 },
 NidUTInput {
  NID_setct_CapResData, nid::SETCT_CAPRESDATA
 },
 NidUTInput {
  NID_setct_CapRevReqTBS, nid::SETCT_CAPREVREQTBS
 },
 NidUTInput {
  NID_setct_CapRevReqTBSX, nid::SETCT_CAPREVREQTBSX
 },
 NidUTInput {
  NID_setct_CapRevResData, nid::SETCT_CAPREVRESDATA
 },
 NidUTInput {
  NID_setct_CredReqTBS, nid::SETCT_CREDREQTBS
 },
 NidUTInput {
  NID_setct_CredReqTBSX, nid::SETCT_CREDREQTBSX
 },
 NidUTInput {
  NID_setct_CredResData, nid::SETCT_CREDRESDATA
 },
 NidUTInput {
  NID_setct_CredRevReqTBS, nid::SETCT_CREDREVREQTBS
 },
 NidUTInput {
  NID_setct_CredRevReqTBSX, nid::SETCT_CREDREVREQTBSX
 },
 NidUTInput {
  NID_setct_CredRevResData, nid::SETCT_CREDREVRESDATA
 },
 NidUTInput {
  NID_setct_PCertReqData, nid::SETCT_PCERTREQDATA
 },
 NidUTInput {
  NID_setct_PCertResTBS, nid::SETCT_PCERTRESTBS
 },
 NidUTInput {
  NID_setct_BatchAdminReqData, nid::SETCT_BATCHADMINREQDATA
 },
 NidUTInput {
  NID_setct_BatchAdminResData, nid::SETCT_BATCHADMINRESDATA
 },
 NidUTInput {
  NID_setct_CardCInitResTBS, nid::SETCT_CARDCINITRESTBS
 },
 NidUTInput {
  NID_setct_MeAqCInitResTBS, nid::SETCT_MEAQCINITRESTBS
 },
 NidUTInput {
  NID_setct_RegFormResTBS, nid::SETCT_REGFORMRESTBS
 },
 NidUTInput {
  NID_setct_CertReqData, nid::SETCT_CERTREQDATA
 },
 NidUTInput {
  NID_setct_CertReqTBS, nid::SETCT_CERTREQTBS
 },
 NidUTInput {
  NID_setct_CertResData, nid::SETCT_CERTRESDATA
 },
 NidUTInput {
  NID_setct_CertInqReqTBS, nid::SETCT_CERTINQREQTBS
 },
 NidUTInput {
  NID_setct_ErrorTBS, nid::SETCT_ERRORTBS
 },
 NidUTInput {
  NID_setct_PIDualSignedTBE, nid::SETCT_PIDUALSIGNEDTBE
 },
 NidUTInput {
  NID_setct_PIUnsignedTBE, nid::SETCT_PIUNSIGNEDTBE
 },
 NidUTInput {
  NID_setct_AuthReqTBE, nid::SETCT_AUTHREQTBE
 },
 NidUTInput {
  NID_setct_AuthResTBE, nid::SETCT_AUTHRESTBE
 },
 NidUTInput {
  NID_setct_AuthResTBEX, nid::SETCT_AUTHRESTBEX
 },
 NidUTInput {
  NID_setct_AuthTokenTBE, nid::SETCT_AUTHTOKENTBE
 },
 NidUTInput {
  NID_setct_CapTokenTBE, nid::SETCT_CAPTOKENTBE
 },
 NidUTInput {
  NID_setct_CapTokenTBEX, nid::SETCT_CAPTOKENTBEX
 },
 NidUTInput {
  NID_setct_AcqCardCodeMsgTBE, nid::SETCT_ACQCARDCODEMSGTBE
 },
 NidUTInput {
  NID_setct_AuthRevReqTBE, nid::SETCT_AUTHREVREQTBE
 },
 NidUTInput {
  NID_setct_AuthRevResTBE, nid::SETCT_AUTHREVRESTBE
 },
 NidUTInput {
  NID_setct_AuthRevResTBEB, nid::SETCT_AUTHREVRESTBEB
 },
 NidUTInput {
  NID_setct_CapReqTBE, nid::SETCT_CAPREQTBE
 },
 NidUTInput {
  NID_setct_CapReqTBEX, nid::SETCT_CAPREQTBEX
 },
 NidUTInput {
  NID_setct_CapResTBE, nid::SETCT_CAPRESTBE
 },
 NidUTInput {
  NID_setct_CapRevReqTBE, nid::SETCT_CAPREVREQTBE
 },
 NidUTInput {
  NID_setct_CapRevReqTBEX, nid::SETCT_CAPREVREQTBEX
 },
 NidUTInput {
  NID_setct_CapRevResTBE, nid::SETCT_CAPREVRESTBE
 },
 NidUTInput {
  NID_setct_CredReqTBE, nid::SETCT_CREDREQTBE
 },
 NidUTInput {
  NID_setct_CredReqTBEX, nid::SETCT_CREDREQTBEX
 },
 NidUTInput {
  NID_setct_CredResTBE, nid::SETCT_CREDRESTBE
 },
 NidUTInput {
  NID_setct_CredRevReqTBE, nid::SETCT_CREDREVREQTBE
 },
 NidUTInput {
  NID_setct_CredRevReqTBEX, nid::SETCT_CREDREVREQTBEX
 },
 NidUTInput {
  NID_setct_CredRevResTBE, nid::SETCT_CREDREVRESTBE
 },
 NidUTInput {
  NID_setct_BatchAdminReqTBE, nid::SETCT_BATCHADMINREQTBE
 },
 NidUTInput {
  NID_setct_BatchAdminResTBE, nid::SETCT_BATCHADMINRESTBE
 },
 NidUTInput {
  NID_setct_RegFormReqTBE, nid::SETCT_REGFORMREQTBE
 },
 NidUTInput {
  NID_setct_CertReqTBE, nid::SETCT_CERTREQTBE
 },
 NidUTInput {
  NID_setct_CertReqTBEX, nid::SETCT_CERTREQTBEX
 },
 NidUTInput {
  NID_setct_CertResTBE, nid::SETCT_CERTRESTBE
 },
 NidUTInput {
  NID_setct_CRLNotificationTBS, nid::SETCT_CRLNOTIFICATIONTBS
 },
 NidUTInput {
  NID_setct_CRLNotificationResTBS, nid::SETCT_CRLNOTIFICATIONRESTBS
 },
 NidUTInput {
  NID_setct_BCIDistributionTBS, nid::SETCT_BCIDISTRIBUTIONTBS
 },
 NidUTInput {
  NID_setext_genCrypt, nid::SETEXT_GENCRYPT
 },
 NidUTInput {
  NID_setext_miAuth, nid::SETEXT_MIAUTH
 },
 NidUTInput {
  NID_setext_pinSecure, nid::SETEXT_PINSECURE
 },
 NidUTInput {
  NID_setext_pinAny, nid::SETEXT_PINANY
 },
 NidUTInput {
  NID_setext_track2, nid::SETEXT_TRACK2
 },
 NidUTInput {
  NID_setext_cv, nid::SETEXT_CV
 },
 NidUTInput {
  NID_set_policy_root, nid::SET_POLICY_ROOT
 },
 NidUTInput {
  NID_setCext_hashedRoot, nid::SETCEXT_HASHEDROOT
 },
 NidUTInput {
  NID_setCext_certType, nid::SETCEXT_CERTTYPE
 },
 NidUTInput {
  NID_setCext_merchData, nid::SETCEXT_MERCHDATA
 },
 NidUTInput {
  NID_setCext_cCertRequired, nid::SETCEXT_CCERTREQUIRED
 },
 NidUTInput {
  NID_setCext_tunneling, nid::SETCEXT_TUNNELING
 },
 NidUTInput {
  NID_setCext_setExt, nid::SETCEXT_SETEXT
 },
 NidUTInput {
  NID_setCext_setQualf, nid::SETCEXT_SETQUALF
 },
 NidUTInput {
  NID_setCext_PGWYcapabilities, nid::SETCEXT_PGWYCAPABILITIES
 },
 NidUTInput {
  NID_setCext_TokenIdentifier, nid::SETCEXT_TOKENIDENTIFIER
 },
 NidUTInput {
  NID_setCext_Track2Data, nid::SETCEXT_TRACK2DATA
 },
 NidUTInput {
  NID_setCext_TokenType, nid::SETCEXT_TOKENTYPE
 },
 NidUTInput {
  NID_setCext_IssuerCapabilities, nid::SETCEXT_ISSUERCAPABILITIES
 },
 NidUTInput {
  NID_setAttr_Cert, nid::SETATTR_CERT
 },
 NidUTInput {
  NID_setAttr_PGWYcap, nid::SETATTR_PGWYCAP
 },
 NidUTInput {
  NID_setAttr_TokenType, nid::SETATTR_TOKENTYPE
 },
 NidUTInput {
  NID_setAttr_IssCap, nid::SETATTR_ISSCAP
 },
 NidUTInput {
  NID_set_rootKeyThumb, nid::SET_ROOTKEYTHUMB
 },
 NidUTInput {
  NID_set_addPolicy, nid::SET_ADDPOLICY
 },
 NidUTInput {
  NID_setAttr_Token_EMV, nid::SETATTR_TOKEN_EMV
 },
 NidUTInput {
  NID_setAttr_Token_B0Prime, nid::SETATTR_TOKEN_B0PRIME
 },
 NidUTInput {
  NID_setAttr_IssCap_CVM, nid::SETATTR_ISSCAP_CVM
 },
 NidUTInput {
  NID_setAttr_IssCap_T2, nid::SETATTR_ISSCAP_T2
 },
 NidUTInput {
  NID_setAttr_IssCap_Sig, nid::SETATTR_ISSCAP_SIG
 },
 NidUTInput {
  NID_setAttr_GenCryptgrm, nid::SETATTR_GENCRYPTGRM
 },
 NidUTInput {
  NID_setAttr_T2Enc, nid::SETATTR_T2ENC
 },
 NidUTInput {
  NID_setAttr_T2cleartxt, nid::SETATTR_T2CLEARTXT
 },
 NidUTInput {
  NID_setAttr_TokICCsig, nid::SETATTR_TOKICCSIG
 },
 NidUTInput {
  NID_setAttr_SecDevSig, nid::SETATTR_SECDEVSIG
 },
 NidUTInput {
  NID_set_brand_IATA_ATA, nid::SET_BRAND_IATA_ATA
 },
 NidUTInput {
  NID_set_brand_Diners, nid::SET_BRAND_DINERS
 },
 NidUTInput {
  NID_set_brand_AmericanExpress, nid::SET_BRAND_AMERICANEXPRESS
 },
 NidUTInput {
  NID_set_brand_JCB, nid::SET_BRAND_JCB
 },
 NidUTInput {
  NID_set_brand_Visa, nid::SET_BRAND_VISA
 },
 NidUTInput {
  NID_set_brand_MasterCard, nid::SET_BRAND_MASTERCARD
 },
 NidUTInput {
  NID_set_brand_Novus, nid::SET_BRAND_NOVUS
 },
 NidUTInput {
  NID_des_cdmf, nid::DES_CDMF
 },
 NidUTInput {
  NID_rsaOAEPEncryptionSET, nid::RSAOAEPENCRYPTIONSET
 },
 NidUTInput {
  NID_ipsec3, nid::IPSEC3
 },
 NidUTInput {
  NID_ipsec4, nid::IPSEC4
 },
 NidUTInput {
  NID_whirlpool, nid::WHIRLPOOL
 },
 NidUTInput {
  NID_cryptopro, nid::CRYPTOPRO
 },
 NidUTInput {
  NID_cryptocom, nid::CRYPTOCOM
 },
 NidUTInput {
  NID_id_tc26, nid::ID_TC26
 },
 NidUTInput {
  NID_id_GostR3411_94_with_GostR3410_2001, nid::ID_GOSTR3411_94_WITH_GOSTR3410_2001
 },
 NidUTInput {
  NID_id_GostR3411_94_with_GostR3410_94, nid::ID_GOSTR3411_94_WITH_GOSTR3410_94
 },
 NidUTInput {
  NID_id_GostR3411_94, nid::ID_GOSTR3411_94
 },
 NidUTInput {
  NID_id_HMACGostR3411_94, nid::ID_HMACGOSTR3411_94
 },
 NidUTInput {
  NID_id_GostR3410_2001, nid::ID_GOSTR3410_2001
 },
 NidUTInput {
  NID_id_GostR3410_94, nid::ID_GOSTR3410_94
 },
 NidUTInput {
  NID_id_Gost28147_89, nid::ID_GOST28147_89
 },
 NidUTInput {
  NID_gost89_cnt, nid::GOST89_CNT
 },
 NidUTInput {
  NID_gost89_cnt_12, nid::GOST89_CNT_12
 },
 NidUTInput {
  NID_gost89_cbc, nid::GOST89_CBC
 },
 NidUTInput {
  NID_gost89_ecb, nid::GOST89_ECB
 },
 NidUTInput {
  NID_gost89_ctr, nid::GOST89_CTR
 },
 NidUTInput {
  NID_id_Gost28147_89_MAC, nid::ID_GOST28147_89_MAC
 },
 NidUTInput {
  NID_gost_mac_12, nid::GOST_MAC_12
 },
 NidUTInput {
  NID_id_GostR3411_94_prf, nid::ID_GOSTR3411_94_PRF
 },
 NidUTInput {
  NID_id_GostR3410_2001DH, nid::ID_GOSTR3410_2001DH
 },
 NidUTInput {
  NID_id_GostR3410_94DH, nid::ID_GOSTR3410_94DH
 },
 NidUTInput {
  NID_id_Gost28147_89_CryptoPro_KeyMeshing, nid::ID_GOST28147_89_CRYPTOPRO_KEYMESHING
 },
 NidUTInput {
  NID_id_Gost28147_89_None_KeyMeshing, nid::ID_GOST28147_89_NONE_KEYMESHING
 },
 NidUTInput {
  NID_id_GostR3411_94_TestParamSet, nid::ID_GOSTR3411_94_TESTPARAMSET
 },
 NidUTInput {
  NID_id_GostR3411_94_CryptoProParamSet, nid::ID_GOSTR3411_94_CRYPTOPROPARAMSET
 },
 NidUTInput {
  NID_id_Gost28147_89_TestParamSet, nid::ID_GOST28147_89_TESTPARAMSET
 },
 NidUTInput {
  NID_id_Gost28147_89_CryptoPro_A_ParamSet, nid::ID_GOST28147_89_CRYPTOPRO_A_PARAMSET
 },
 NidUTInput {
  NID_id_Gost28147_89_CryptoPro_B_ParamSet, nid::ID_GOST28147_89_CRYPTOPRO_B_PARAMSET
 },
 NidUTInput {
  NID_id_Gost28147_89_CryptoPro_C_ParamSet, nid::ID_GOST28147_89_CRYPTOPRO_C_PARAMSET
 },
 NidUTInput {
  NID_id_Gost28147_89_CryptoPro_D_ParamSet, nid::ID_GOST28147_89_CRYPTOPRO_D_PARAMSET
 },
 NidUTInput {
  NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet, nid::ID_GOST28147_89_CRYPTOPRO_OSCAR_1_1_PARAMSET
 },
 NidUTInput {
  NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet, nid::ID_GOST28147_89_CRYPTOPRO_OSCAR_1_0_PARAMSET
 },
 NidUTInput {
  NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet, nid::ID_GOST28147_89_CRYPTOPRO_RIC_1_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_94_TestParamSet, nid::ID_GOSTR3410_94_TESTPARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_94_CryptoPro_A_ParamSet, nid::ID_GOSTR3410_94_CRYPTOPRO_A_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_94_CryptoPro_B_ParamSet, nid::ID_GOSTR3410_94_CRYPTOPRO_B_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_94_CryptoPro_C_ParamSet, nid::ID_GOSTR3410_94_CRYPTOPRO_C_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_94_CryptoPro_D_ParamSet, nid::ID_GOSTR3410_94_CRYPTOPRO_D_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_94_CryptoPro_XchA_ParamSet, nid::ID_GOSTR3410_94_CRYPTOPRO_XCHA_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_94_CryptoPro_XchB_ParamSet, nid::ID_GOSTR3410_94_CRYPTOPRO_XCHB_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_94_CryptoPro_XchC_ParamSet, nid::ID_GOSTR3410_94_CRYPTOPRO_XCHC_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_2001_TestParamSet, nid::ID_GOSTR3410_2001_TESTPARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_2001_CryptoPro_A_ParamSet, nid::ID_GOSTR3410_2001_CRYPTOPRO_A_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_2001_CryptoPro_B_ParamSet, nid::ID_GOSTR3410_2001_CRYPTOPRO_B_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_2001_CryptoPro_C_ParamSet, nid::ID_GOSTR3410_2001_CRYPTOPRO_C_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet, nid::ID_GOSTR3410_2001_CRYPTOPRO_XCHA_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet, nid::ID_GOSTR3410_2001_CRYPTOPRO_XCHB_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_94_a, nid::ID_GOSTR3410_94_A
 },
 NidUTInput {
  NID_id_GostR3410_94_aBis, nid::ID_GOSTR3410_94_ABIS
 },
 NidUTInput {
  NID_id_GostR3410_94_b, nid::ID_GOSTR3410_94_B
 },
 NidUTInput {
  NID_id_GostR3410_94_bBis, nid::ID_GOSTR3410_94_BBIS
 },
 NidUTInput {
  NID_id_Gost28147_89_cc, nid::ID_GOST28147_89_CC
 },
 NidUTInput {
  NID_id_GostR3410_94_cc, nid::ID_GOSTR3410_94_CC
 },
 NidUTInput {
  NID_id_GostR3410_2001_cc, nid::ID_GOSTR3410_2001_CC
 },
 NidUTInput {
  NID_id_GostR3411_94_with_GostR3410_94_cc, nid::ID_GOSTR3411_94_WITH_GOSTR3410_94_CC
 },
 NidUTInput {
  NID_id_GostR3411_94_with_GostR3410_2001_cc, nid::ID_GOSTR3411_94_WITH_GOSTR3410_2001_CC
 },
 NidUTInput {
  NID_id_GostR3410_2001_ParamSet_cc, nid::ID_GOSTR3410_2001_PARAMSET_CC
 },
 NidUTInput {
  NID_id_tc26_algorithms, nid::ID_TC26_ALGORITHMS
 },
 NidUTInput {
  NID_id_tc26_sign, nid::ID_TC26_SIGN
 },
 NidUTInput {
  NID_id_GostR3410_2012_256, nid::ID_GOSTR3410_2012_256
 },
 NidUTInput {
  NID_id_GostR3410_2012_512, nid::ID_GOSTR3410_2012_512
 },
 NidUTInput {
  NID_id_tc26_digest, nid::ID_TC26_DIGEST
 },
 NidUTInput {
  NID_id_GostR3411_2012_256, nid::ID_GOSTR3411_2012_256
 },
 NidUTInput {
  NID_id_GostR3411_2012_512, nid::ID_GOSTR3411_2012_512
 },
 NidUTInput {
  NID_id_tc26_signwithdigest, nid::ID_TC26_SIGNWITHDIGEST
 },
 NidUTInput {
  NID_id_tc26_signwithdigest_gost3410_2012_256, nid::ID_TC26_SIGNWITHDIGEST_GOST3410_2012_256
 },
 NidUTInput {
  NID_id_tc26_signwithdigest_gost3410_2012_512, nid::ID_TC26_SIGNWITHDIGEST_GOST3410_2012_512
 },
 NidUTInput {
  NID_id_tc26_mac, nid::ID_TC26_MAC
 },
 NidUTInput {
  NID_id_tc26_hmac_gost_3411_2012_256, nid::ID_TC26_HMAC_GOST_3411_2012_256
 },
 NidUTInput {
  NID_id_tc26_hmac_gost_3411_2012_512, nid::ID_TC26_HMAC_GOST_3411_2012_512
 },
 NidUTInput {
  NID_id_tc26_cipher, nid::ID_TC26_CIPHER
 },
 NidUTInput {
  NID_id_tc26_agreement, nid::ID_TC26_AGREEMENT
 },
 NidUTInput {
  NID_id_tc26_agreement_gost_3410_2012_256, nid::ID_TC26_AGREEMENT_GOST_3410_2012_256
 },
 NidUTInput {
  NID_id_tc26_agreement_gost_3410_2012_512, nid::ID_TC26_AGREEMENT_GOST_3410_2012_512
 },
 NidUTInput {
  NID_id_tc26_constants, nid::ID_TC26_CONSTANTS
 },
 NidUTInput {
  NID_id_tc26_sign_constants, nid::ID_TC26_SIGN_CONSTANTS
 },
 NidUTInput {
  NID_id_tc26_gost_3410_2012_512_constants, nid::ID_TC26_GOST_3410_2012_512_CONSTANTS
 },
 NidUTInput {
  NID_id_tc26_gost_3410_2012_512_paramSetTest, nid::ID_TC26_GOST_3410_2012_512_PARAMSETTEST
 },
 NidUTInput {
  NID_id_tc26_gost_3410_2012_512_paramSetA, nid::ID_TC26_GOST_3410_2012_512_PARAMSETA
 },
 NidUTInput {
  NID_id_tc26_gost_3410_2012_512_paramSetB, nid::ID_TC26_GOST_3410_2012_512_PARAMSETB
 },
 NidUTInput {
  NID_id_tc26_digest_constants, nid::ID_TC26_DIGEST_CONSTANTS
 },
 NidUTInput {
  NID_id_tc26_cipher_constants, nid::ID_TC26_CIPHER_CONSTANTS
 },
 NidUTInput {
  NID_id_tc26_gost_28147_constants, nid::ID_TC26_GOST_28147_CONSTANTS
 },
 NidUTInput {
  NID_id_tc26_gost_28147_param_Z, nid::ID_TC26_GOST_28147_PARAM_Z
 },
 NidUTInput {
  NID_INN, nid::INN
 },
 NidUTInput {
  NID_OGRN, nid::OGRN
 },
 NidUTInput {
  NID_SNILS, nid::SNILS
 },
 NidUTInput {
  NID_subjectSignTool, nid::SUBJECTSIGNTOOL
 },
 NidUTInput {
  NID_issuerSignTool, nid::ISSUERSIGNTOOL
 },
 NidUTInput {
  NID_grasshopper_ecb, nid::GRASSHOPPER_ECB
 },
 NidUTInput {
  NID_grasshopper_ctr, nid::GRASSHOPPER_CTR
 },
 NidUTInput {
  NID_grasshopper_ofb, nid::GRASSHOPPER_OFB
 },
 NidUTInput {
  NID_grasshopper_cbc, nid::GRASSHOPPER_CBC
 },
 NidUTInput {
  NID_grasshopper_cfb, nid::GRASSHOPPER_CFB
 },
 NidUTInput {
  NID_grasshopper_mac, nid::GRASSHOPPER_MAC
 },
 NidUTInput {
  NID_camellia_128_cbc, nid::CAMELLIA_128_CBC
 },
 NidUTInput {
  NID_camellia_192_cbc, nid::CAMELLIA_192_CBC
 },
 NidUTInput {
  NID_camellia_256_cbc, nid::CAMELLIA_256_CBC
 },
 NidUTInput {
  NID_id_camellia128_wrap, nid::ID_CAMELLIA128_WRAP
 },
 NidUTInput {
  NID_id_camellia192_wrap, nid::ID_CAMELLIA192_WRAP
 },
 NidUTInput {
  NID_id_camellia256_wrap, nid::ID_CAMELLIA256_WRAP
 },
 NidUTInput {
  NID_camellia_128_ecb, nid::CAMELLIA_128_ECB
 },
 NidUTInput {
  NID_camellia_128_ofb128, nid::CAMELLIA_128_OFB128
 },
 NidUTInput {
  NID_camellia_128_cfb128, nid::CAMELLIA_128_CFB128
 },
 NidUTInput {
  NID_camellia_128_gcm, nid::CAMELLIA_128_GCM
 },
 NidUTInput {
  NID_camellia_128_ccm, nid::CAMELLIA_128_CCM
 },
 NidUTInput {
  NID_camellia_128_ctr, nid::CAMELLIA_128_CTR
 },
 NidUTInput {
  NID_camellia_128_cmac, nid::CAMELLIA_128_CMAC
 },
 NidUTInput {
  NID_camellia_192_ecb, nid::CAMELLIA_192_ECB
 },
 NidUTInput {
  NID_camellia_192_ofb128, nid::CAMELLIA_192_OFB128
 },
 NidUTInput {
  NID_camellia_192_cfb128, nid::CAMELLIA_192_CFB128
 },
 NidUTInput {
  NID_camellia_192_gcm, nid::CAMELLIA_192_GCM
 },
 NidUTInput {
  NID_camellia_192_ccm, nid::CAMELLIA_192_CCM
 },
 NidUTInput {
  NID_camellia_192_ctr, nid::CAMELLIA_192_CTR
 },
 NidUTInput {
  NID_camellia_192_cmac, nid::CAMELLIA_192_CMAC
 },
 NidUTInput {
  NID_camellia_256_ecb, nid::CAMELLIA_256_ECB
 },
 NidUTInput {
  NID_camellia_256_ofb128, nid::CAMELLIA_256_OFB128
 },
 NidUTInput {
  NID_camellia_256_cfb128, nid::CAMELLIA_256_CFB128
 },
 NidUTInput {
  NID_camellia_256_gcm, nid::CAMELLIA_256_GCM
 },
 NidUTInput {
  NID_camellia_256_ccm, nid::CAMELLIA_256_CCM
 },
 NidUTInput {
  NID_camellia_256_ctr, nid::CAMELLIA_256_CTR
 },
 NidUTInput {
  NID_camellia_256_cmac, nid::CAMELLIA_256_CMAC
 },
 NidUTInput {
  NID_camellia_128_cfb1, nid::CAMELLIA_128_CFB1
 },
 NidUTInput {
  NID_camellia_192_cfb1, nid::CAMELLIA_192_CFB1
 },
 NidUTInput {
  NID_camellia_256_cfb1, nid::CAMELLIA_256_CFB1
 },
 NidUTInput {
  NID_camellia_128_cfb8, nid::CAMELLIA_128_CFB8
 },
 NidUTInput {
  NID_camellia_192_cfb8, nid::CAMELLIA_192_CFB8
 },
 NidUTInput {
  NID_camellia_256_cfb8, nid::CAMELLIA_256_CFB8
 },
 NidUTInput {
  NID_kisa, nid::KISA
 },
 NidUTInput {
  NID_seed_ecb, nid::SEED_ECB
 },
 NidUTInput {
  NID_seed_cbc, nid::SEED_CBC
 },
 NidUTInput {
  NID_seed_cfb128, nid::SEED_CFB128
 },
 NidUTInput {
  NID_seed_ofb128, nid::SEED_OFB128
 },
 NidUTInput {
  NID_hmac, nid::HMAC
 },
 NidUTInput {
  NID_cmac, nid::CMAC
 },
 NidUTInput {
  NID_rc4_hmac_md5, nid::RC4_HMAC_MD5
 },
 NidUTInput {
  NID_aes_128_cbc_hmac_sha1, nid::AES_128_CBC_HMAC_SHA1
 },
 NidUTInput {
  NID_aes_192_cbc_hmac_sha1, nid::AES_192_CBC_HMAC_SHA1
 },
 NidUTInput {
  NID_aes_256_cbc_hmac_sha1, nid::AES_256_CBC_HMAC_SHA1
 },
 NidUTInput {
  NID_aes_128_cbc_hmac_sha256, nid::AES_128_CBC_HMAC_SHA256
 },
 NidUTInput {
  NID_aes_192_cbc_hmac_sha256, nid::AES_192_CBC_HMAC_SHA256
 },
 NidUTInput {
  NID_aes_256_cbc_hmac_sha256, nid::AES_256_CBC_HMAC_SHA256
 },
 NidUTInput {
  NID_chacha20_poly1305, nid::CHACHA20_POLY1305
 },
 NidUTInput {
  NID_chacha20, nid::CHACHA20
 },
 NidUTInput {
  NID_dhpublicnumber, nid::DHPUBLICNUMBER
 },
 NidUTInput {
  NID_brainpoolP160r1, nid::BRAINPOOLP160R1
 },
 NidUTInput {
  NID_brainpoolP160t1, nid::BRAINPOOLP160T1
 },
 NidUTInput {
  NID_brainpoolP192r1, nid::BRAINPOOLP192R1
 },
 NidUTInput {
  NID_brainpoolP192t1, nid::BRAINPOOLP192T1
 },
 NidUTInput {
  NID_brainpoolP224r1, nid::BRAINPOOLP224R1
 },
 NidUTInput {
  NID_brainpoolP224t1, nid::BRAINPOOLP224T1
 },
 NidUTInput {
  NID_brainpoolP256r1, nid::BRAINPOOLP256R1
 },
 NidUTInput {
  NID_brainpoolP256t1, nid::BRAINPOOLP256T1
 },
 NidUTInput {
  NID_brainpoolP320r1, nid::BRAINPOOLP320R1
 },
 NidUTInput {
  NID_brainpoolP320t1, nid::BRAINPOOLP320T1
 },
 NidUTInput {
  NID_brainpoolP384r1, nid::BRAINPOOLP384R1
 },
 NidUTInput {
  NID_brainpoolP384t1, nid::BRAINPOOLP384T1
 },
 NidUTInput {
  NID_brainpoolP512r1, nid::BRAINPOOLP512R1
 },
 NidUTInput {
  NID_brainpoolP512t1, nid::BRAINPOOLP512T1
 },
 NidUTInput {
  NID_dhSinglePass_stdDH_sha1kdf_scheme, nid::DHSINGLEPASS_STDDH_SHA1KDF_SCHEME
 },
 NidUTInput {
  NID_dhSinglePass_stdDH_sha224kdf_scheme, nid::DHSINGLEPASS_STDDH_SHA224KDF_SCHEME
 },
 NidUTInput {
  NID_dhSinglePass_stdDH_sha256kdf_scheme, nid::DHSINGLEPASS_STDDH_SHA256KDF_SCHEME
 },
 NidUTInput {
  NID_dhSinglePass_stdDH_sha384kdf_scheme, nid::DHSINGLEPASS_STDDH_SHA384KDF_SCHEME
 },
 NidUTInput {
  NID_dhSinglePass_stdDH_sha512kdf_scheme, nid::DHSINGLEPASS_STDDH_SHA512KDF_SCHEME
 },
 NidUTInput {
  NID_dhSinglePass_cofactorDH_sha1kdf_scheme, nid::DHSINGLEPASS_COFACTORDH_SHA1KDF_SCHEME
 },
 NidUTInput {
  NID_dhSinglePass_cofactorDH_sha224kdf_scheme, nid::DHSINGLEPASS_COFACTORDH_SHA224KDF_SCHEME
 },
 NidUTInput {
  NID_dhSinglePass_cofactorDH_sha256kdf_scheme, nid::DHSINGLEPASS_COFACTORDH_SHA256KDF_SCHEME
 },
 NidUTInput {
  NID_dhSinglePass_cofactorDH_sha384kdf_scheme, nid::DHSINGLEPASS_COFACTORDH_SHA384KDF_SCHEME
 },
 NidUTInput {
  NID_dhSinglePass_cofactorDH_sha512kdf_scheme, nid::DHSINGLEPASS_COFACTORDH_SHA512KDF_SCHEME
 },
 NidUTInput {
  NID_dh_std_kdf, nid::DH_STD_KDF
 },
 NidUTInput {
  NID_dh_cofactor_kdf, nid::DH_COFACTOR_KDF
 },
 NidUTInput {
  NID_ct_precert_scts, nid::CT_PRECERT_SCTS
 },
 NidUTInput {
  NID_ct_precert_poison, nid::CT_PRECERT_POISON
 },
 NidUTInput {
  NID_ct_precert_signer, nid::CT_PRECERT_SIGNER
 },
 NidUTInput {
  NID_ct_cert_scts, nid::CT_CERT_SCTS
 },
 NidUTInput {
  NID_jurisdictionLocalityName, nid::JURISDICTIONLOCALITYNAME
 },
 NidUTInput {
  NID_jurisdictionStateOrProvinceName, nid::JURISDICTIONSTATEORPROVINCENAME
 },
 NidUTInput {
  NID_jurisdictionCountryName, nid::JURISDICTIONCOUNTRYNAME
 },
 NidUTInput {
  NID_id_scrypt, nid::ID_SCRYPT
 },
 NidUTInput {
  NID_tls1_prf, nid::TLS1_PRF
 },
 NidUTInput {
  NID_hkdf, nid::HKDF
 },
 NidUTInput {
  NID_id_pkinit, nid::ID_PKINIT
 },
 NidUTInput {
  NID_pkInitClientAuth, nid::PKINITCLIENTAUTH
 },
 NidUTInput {
  NID_pkInitKDC, nid::PKINITKDC
 },
 NidUTInput {
  NID_X25519, nid::X25519
 },
 NidUTInput {
  NID_X448, nid::X448
 },
 NidUTInput {
  NID_kx_rsa, nid::KX_RSA
 },
 NidUTInput {
  NID_kx_ecdhe, nid::KX_ECDHE
 },
 NidUTInput {
  NID_kx_dhe, nid::KX_DHE
 },
 NidUTInput {
  NID_kx_ecdhe_psk, nid::KX_ECDHE_PSK
 },
 NidUTInput {
  NID_kx_dhe_psk, nid::KX_DHE_PSK
 },
 NidUTInput {
  NID_kx_rsa_psk, nid::KX_RSA_PSK
 },
 NidUTInput {
  NID_kx_psk, nid::KX_PSK
 },
 NidUTInput {
  NID_kx_srp, nid::KX_SRP
 },
 NidUTInput {
  NID_kx_gost, nid::KX_GOST
 },
 NidUTInput {
  NID_auth_rsa, nid::AUTH_RSA
 },
 NidUTInput {
  NID_auth_ecdsa, nid::AUTH_ECDSA
 },
 NidUTInput {
  NID_auth_psk, nid::AUTH_PSK
 },
 NidUTInput {
  NID_auth_dss, nid::AUTH_DSS
 },
 NidUTInput {
  NID_auth_gost01, nid::AUTH_GOST01
 },
 NidUTInput {
  NID_auth_gost12, nid::AUTH_GOST12
 },
 NidUTInput {
  NID_auth_srp, nid::AUTH_SRP
 },
 NidUTInput {
  NID_auth_null, nid::AUTH_NULL
 }
};

INSTANTIATE_TEST_CASE_P(
    Nid,
    NidValidityUT,
    ::testing::ValuesIn(NID_VALIDITY_UT_VALUES)
);
