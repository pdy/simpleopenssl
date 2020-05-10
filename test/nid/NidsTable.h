#include <simpleopenssl/simpleopenssl.h>

struct NidUTInput
{
  int rawNid;
  so::nid::Nid soNid;
};

static constexpr NidUTInput NID_VALIDITY_UT_VALUES[] {
 NidUTInput {
  NID_undef, so::nid::Nid::UNDEF
 },
 NidUTInput {
  NID_itu_t, so::nid::Nid::ITU_T
 },
 NidUTInput {
  NID_ccitt, so::nid::Nid::CCITT
 },
 NidUTInput {
  NID_iso, so::nid::Nid::ISO
 },
 NidUTInput {
  NID_joint_iso_itu_t, so::nid::Nid::JOINT_ISO_ITU_T
 },
 NidUTInput {
  NID_joint_iso_ccitt, so::nid::Nid::JOINT_ISO_CCITT
 },
 NidUTInput {
  NID_member_body, so::nid::Nid::MEMBER_BODY
 },
 NidUTInput {
  NID_identified_organization, so::nid::Nid::IDENTIFIED_ORGANIZATION
 },
 NidUTInput {
  NID_hmac_md5, so::nid::Nid::HMAC_MD5
 },
 NidUTInput {
  NID_hmac_sha1, so::nid::Nid::HMAC_SHA1
 },
 NidUTInput {
  NID_certicom_arc, so::nid::Nid::CERTICOM_ARC
 },
 NidUTInput {
  NID_international_organizations, so::nid::Nid::INTERNATIONAL_ORGANIZATIONS
 },
 NidUTInput {
  NID_wap, so::nid::Nid::WAP
 },
 NidUTInput {
  NID_wap_wsg, so::nid::Nid::WAP_WSG
 },
 NidUTInput {
  NID_selected_attribute_types, so::nid::Nid::SELECTED_ATTRIBUTE_TYPES
 },
 NidUTInput {
  NID_clearance, so::nid::Nid::CLEARANCE
 },
 NidUTInput {
  NID_ISO_US, so::nid::Nid::ISO_US
 },
 NidUTInput {
  NID_X9_57, so::nid::Nid::X9_57
 },
 NidUTInput {
  NID_X9cm, so::nid::Nid::X9CM
 },
 NidUTInput {
  NID_dsa, so::nid::Nid::DSA
 },
 NidUTInput {
  NID_dsaWithSHA1, so::nid::Nid::DSAWITHSHA1
 },
 NidUTInput {
  NID_ansi_X9_62, so::nid::Nid::ANSI_X9_62
 },
 NidUTInput {
  NID_X9_62_prime_field, so::nid::Nid::X9_62_PRIME_FIELD
 },
 NidUTInput {
  NID_X9_62_characteristic_two_field, so::nid::Nid::X9_62_CHARACTERISTIC_TWO_FIELD
 },
 NidUTInput {
  NID_X9_62_id_characteristic_two_basis, so::nid::Nid::X9_62_ID_CHARACTERISTIC_TWO_BASIS
 },
 NidUTInput {
  NID_X9_62_onBasis, so::nid::Nid::X9_62_ONBASIS
 },
 NidUTInput {
  NID_X9_62_tpBasis, so::nid::Nid::X9_62_TPBASIS
 },
 NidUTInput {
  NID_X9_62_ppBasis, so::nid::Nid::X9_62_PPBASIS
 },
 NidUTInput {
  NID_X9_62_id_ecPublicKey, so::nid::Nid::X9_62_ID_ECPUBLICKEY
 },
 NidUTInput {
  NID_X9_62_c2pnb163v1, so::nid::Nid::X9_62_C2PNB163V1
 },
 NidUTInput {
  NID_X9_62_c2pnb163v2, so::nid::Nid::X9_62_C2PNB163V2
 },
 NidUTInput {
  NID_X9_62_c2pnb163v3, so::nid::Nid::X9_62_C2PNB163V3
 },
 NidUTInput {
  NID_X9_62_c2pnb176v1, so::nid::Nid::X9_62_C2PNB176V1
 },
 NidUTInput {
  NID_X9_62_c2tnb191v1, so::nid::Nid::X9_62_C2TNB191V1
 },
 NidUTInput {
  NID_X9_62_c2tnb191v2, so::nid::Nid::X9_62_C2TNB191V2
 },
 NidUTInput {
  NID_X9_62_c2tnb191v3, so::nid::Nid::X9_62_C2TNB191V3
 },
 NidUTInput {
  NID_X9_62_c2onb191v4, so::nid::Nid::X9_62_C2ONB191V4
 },
 NidUTInput {
  NID_X9_62_c2onb191v5, so::nid::Nid::X9_62_C2ONB191V5
 },
 NidUTInput {
  NID_X9_62_c2pnb208w1, so::nid::Nid::X9_62_C2PNB208W1
 },
 NidUTInput {
  NID_X9_62_c2tnb239v1, so::nid::Nid::X9_62_C2TNB239V1
 },
 NidUTInput {
  NID_X9_62_c2tnb239v2, so::nid::Nid::X9_62_C2TNB239V2
 },
 NidUTInput {
  NID_X9_62_c2tnb239v3, so::nid::Nid::X9_62_C2TNB239V3
 },
 NidUTInput {
  NID_X9_62_c2onb239v4, so::nid::Nid::X9_62_C2ONB239V4
 },
 NidUTInput {
  NID_X9_62_c2onb239v5, so::nid::Nid::X9_62_C2ONB239V5
 },
 NidUTInput {
  NID_X9_62_c2pnb272w1, so::nid::Nid::X9_62_C2PNB272W1
 },
 NidUTInput {
  NID_X9_62_c2pnb304w1, so::nid::Nid::X9_62_C2PNB304W1
 },
 NidUTInput {
  NID_X9_62_c2tnb359v1, so::nid::Nid::X9_62_C2TNB359V1
 },
 NidUTInput {
  NID_X9_62_c2pnb368w1, so::nid::Nid::X9_62_C2PNB368W1
 },
 NidUTInput {
  NID_X9_62_c2tnb431r1, so::nid::Nid::X9_62_C2TNB431R1
 },
 NidUTInput {
  NID_X9_62_prime192v1, so::nid::Nid::X9_62_PRIME192V1
 },
 NidUTInput {
  NID_X9_62_prime192v2, so::nid::Nid::X9_62_PRIME192V2
 },
 NidUTInput {
  NID_X9_62_prime192v3, so::nid::Nid::X9_62_PRIME192V3
 },
 NidUTInput {
  NID_X9_62_prime239v1, so::nid::Nid::X9_62_PRIME239V1
 },
 NidUTInput {
  NID_X9_62_prime239v2, so::nid::Nid::X9_62_PRIME239V2
 },
 NidUTInput {
  NID_X9_62_prime239v3, so::nid::Nid::X9_62_PRIME239V3
 },
 NidUTInput {
  NID_X9_62_prime256v1, so::nid::Nid::X9_62_PRIME256V1
 },
 NidUTInput {
  NID_ecdsa_with_SHA1, so::nid::Nid::ECDSA_WITH_SHA1
 },
 NidUTInput {
  NID_ecdsa_with_Recommended, so::nid::Nid::ECDSA_WITH_RECOMMENDED
 },
 NidUTInput {
  NID_ecdsa_with_Specified, so::nid::Nid::ECDSA_WITH_SPECIFIED
 },
 NidUTInput {
  NID_ecdsa_with_SHA224, so::nid::Nid::ECDSA_WITH_SHA224
 },
 NidUTInput {
  NID_ecdsa_with_SHA256, so::nid::Nid::ECDSA_WITH_SHA256
 },
 NidUTInput {
  NID_ecdsa_with_SHA384, so::nid::Nid::ECDSA_WITH_SHA384
 },
 NidUTInput {
  NID_ecdsa_with_SHA512, so::nid::Nid::ECDSA_WITH_SHA512
 },
 NidUTInput {
  NID_secp112r1, so::nid::Nid::SECP112R1
 },
 NidUTInput {
  NID_secp112r2, so::nid::Nid::SECP112R2
 },
 NidUTInput {
  NID_secp128r1, so::nid::Nid::SECP128R1
 },
 NidUTInput {
  NID_secp128r2, so::nid::Nid::SECP128R2
 },
 NidUTInput {
  NID_secp160k1, so::nid::Nid::SECP160K1
 },
 NidUTInput {
  NID_secp160r1, so::nid::Nid::SECP160R1
 },
 NidUTInput {
  NID_secp160r2, so::nid::Nid::SECP160R2
 },
 NidUTInput {
  NID_secp192k1, so::nid::Nid::SECP192K1
 },
 NidUTInput {
  NID_secp224k1, so::nid::Nid::SECP224K1
 },
 NidUTInput {
  NID_secp224r1, so::nid::Nid::SECP224R1
 },
 NidUTInput {
  NID_secp256k1, so::nid::Nid::SECP256K1
 },
 NidUTInput {
  NID_secp384r1, so::nid::Nid::SECP384R1
 },
 NidUTInput {
  NID_secp521r1, so::nid::Nid::SECP521R1
 },
 NidUTInput {
  NID_sect113r1, so::nid::Nid::SECT113R1
 },
 NidUTInput {
  NID_sect113r2, so::nid::Nid::SECT113R2
 },
 NidUTInput {
  NID_sect131r1, so::nid::Nid::SECT131R1
 },
 NidUTInput {
  NID_sect131r2, so::nid::Nid::SECT131R2
 },
 NidUTInput {
  NID_sect163k1, so::nid::Nid::SECT163K1
 },
 NidUTInput {
  NID_sect163r1, so::nid::Nid::SECT163R1
 },
 NidUTInput {
  NID_sect163r2, so::nid::Nid::SECT163R2
 },
 NidUTInput {
  NID_sect193r1, so::nid::Nid::SECT193R1
 },
 NidUTInput {
  NID_sect193r2, so::nid::Nid::SECT193R2
 },
 NidUTInput {
  NID_sect233k1, so::nid::Nid::SECT233K1
 },
 NidUTInput {
  NID_sect233r1, so::nid::Nid::SECT233R1
 },
 NidUTInput {
  NID_sect239k1, so::nid::Nid::SECT239K1
 },
 NidUTInput {
  NID_sect283k1, so::nid::Nid::SECT283K1
 },
 NidUTInput {
  NID_sect283r1, so::nid::Nid::SECT283R1
 },
 NidUTInput {
  NID_sect409k1, so::nid::Nid::SECT409K1
 },
 NidUTInput {
  NID_sect409r1, so::nid::Nid::SECT409R1
 },
 NidUTInput {
  NID_sect571k1, so::nid::Nid::SECT571K1
 },
 NidUTInput {
  NID_sect571r1, so::nid::Nid::SECT571R1
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls1, so::nid::Nid::WAP_WSG_IDM_ECID_WTLS1
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls3, so::nid::Nid::WAP_WSG_IDM_ECID_WTLS3
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls4, so::nid::Nid::WAP_WSG_IDM_ECID_WTLS4
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls5, so::nid::Nid::WAP_WSG_IDM_ECID_WTLS5
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls6, so::nid::Nid::WAP_WSG_IDM_ECID_WTLS6
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls7, so::nid::Nid::WAP_WSG_IDM_ECID_WTLS7
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls8, so::nid::Nid::WAP_WSG_IDM_ECID_WTLS8
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls9, so::nid::Nid::WAP_WSG_IDM_ECID_WTLS9
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls10, so::nid::Nid::WAP_WSG_IDM_ECID_WTLS10
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls11, so::nid::Nid::WAP_WSG_IDM_ECID_WTLS11
 },
 NidUTInput {
  NID_wap_wsg_idm_ecid_wtls12, so::nid::Nid::WAP_WSG_IDM_ECID_WTLS12
 },
 NidUTInput {
  NID_cast5_cbc, so::nid::Nid::CAST5_CBC
 },
 NidUTInput {
  NID_cast5_ecb, so::nid::Nid::CAST5_ECB
 },
 NidUTInput {
  NID_cast5_cfb64, so::nid::Nid::CAST5_CFB64
 },
 NidUTInput {
  NID_cast5_ofb64, so::nid::Nid::CAST5_OFB64
 },
 NidUTInput {
  NID_pbeWithMD5AndCast5_CBC, so::nid::Nid::PBEWITHMD5ANDCAST5_CBC
 },
 NidUTInput {
  NID_id_PasswordBasedMAC, so::nid::Nid::ID_PASSWORDBASEDMAC
 },
 NidUTInput {
  NID_id_DHBasedMac, so::nid::Nid::ID_DHBASEDMAC
 },
 NidUTInput {
  NID_rsadsi, so::nid::Nid::RSADSI
 },
 NidUTInput {
  NID_pkcs, so::nid::Nid::PKCS
 },
 NidUTInput {
  NID_pkcs1, so::nid::Nid::PKCS1
 },
 NidUTInput {
  NID_rsaEncryption, so::nid::Nid::RSAENCRYPTION
 },
 NidUTInput {
  NID_md2WithRSAEncryption, so::nid::Nid::MD2WITHRSAENCRYPTION
 },
 NidUTInput {
  NID_md4WithRSAEncryption, so::nid::Nid::MD4WITHRSAENCRYPTION
 },
 NidUTInput {
  NID_md5WithRSAEncryption, so::nid::Nid::MD5WITHRSAENCRYPTION
 },
 NidUTInput {
  NID_sha1WithRSAEncryption, so::nid::Nid::SHA1WITHRSAENCRYPTION
 },
 NidUTInput {
  NID_rsaesOaep, so::nid::Nid::RSAESOAEP
 },
 NidUTInput {
  NID_mgf1, so::nid::Nid::MGF1
 },
 NidUTInput {
  NID_pSpecified, so::nid::Nid::PSPECIFIED
 },
 NidUTInput {
  NID_rsassaPss, so::nid::Nid::RSASSAPSS
 },
 NidUTInput {
  NID_sha256WithRSAEncryption, so::nid::Nid::SHA256WITHRSAENCRYPTION
 },
 NidUTInput {
  NID_sha384WithRSAEncryption, so::nid::Nid::SHA384WITHRSAENCRYPTION
 },
 NidUTInput {
  NID_sha512WithRSAEncryption, so::nid::Nid::SHA512WITHRSAENCRYPTION
 },
 NidUTInput {
  NID_sha224WithRSAEncryption, so::nid::Nid::SHA224WITHRSAENCRYPTION
 },
 NidUTInput {
  NID_pkcs3, so::nid::Nid::PKCS3
 },
 NidUTInput {
  NID_dhKeyAgreement, so::nid::Nid::DHKEYAGREEMENT
 },
 NidUTInput {
  NID_pkcs5, so::nid::Nid::PKCS5
 },
 NidUTInput {
  NID_pbeWithMD2AndDES_CBC, so::nid::Nid::PBEWITHMD2ANDDES_CBC
 },
 NidUTInput {
  NID_pbeWithMD5AndDES_CBC, so::nid::Nid::PBEWITHMD5ANDDES_CBC
 },
 NidUTInput {
  NID_pbeWithMD2AndRC2_CBC, so::nid::Nid::PBEWITHMD2ANDRC2_CBC
 },
 NidUTInput {
  NID_pbeWithMD5AndRC2_CBC, so::nid::Nid::PBEWITHMD5ANDRC2_CBC
 },
 NidUTInput {
  NID_pbeWithSHA1AndDES_CBC, so::nid::Nid::PBEWITHSHA1ANDDES_CBC
 },
 NidUTInput {
  NID_pbeWithSHA1AndRC2_CBC, so::nid::Nid::PBEWITHSHA1ANDRC2_CBC
 },
 NidUTInput {
  NID_id_pbkdf2, so::nid::Nid::ID_PBKDF2
 },
 NidUTInput {
  NID_pbes2, so::nid::Nid::PBES2
 },
 NidUTInput {
  NID_pbmac1, so::nid::Nid::PBMAC1
 },
 NidUTInput {
  NID_pkcs7, so::nid::Nid::PKCS7
 },
 NidUTInput {
  NID_pkcs7_data, so::nid::Nid::PKCS7_DATA
 },
 NidUTInput {
  NID_pkcs7_signed, so::nid::Nid::PKCS7_SIGNED
 },
 NidUTInput {
  NID_pkcs7_enveloped, so::nid::Nid::PKCS7_ENVELOPED
 },
 NidUTInput {
  NID_pkcs7_signedAndEnveloped, so::nid::Nid::PKCS7_SIGNEDANDENVELOPED
 },
 NidUTInput {
  NID_pkcs7_digest, so::nid::Nid::PKCS7_DIGEST
 },
 NidUTInput {
  NID_pkcs7_encrypted, so::nid::Nid::PKCS7_ENCRYPTED
 },
 NidUTInput {
  NID_pkcs9, so::nid::Nid::PKCS9
 },
 NidUTInput {
  NID_pkcs9_emailAddress, so::nid::Nid::PKCS9_EMAILADDRESS
 },
 NidUTInput {
  NID_pkcs9_unstructuredName, so::nid::Nid::PKCS9_UNSTRUCTUREDNAME
 },
 NidUTInput {
  NID_pkcs9_contentType, so::nid::Nid::PKCS9_CONTENTTYPE
 },
 NidUTInput {
  NID_pkcs9_messageDigest, so::nid::Nid::PKCS9_MESSAGEDIGEST
 },
 NidUTInput {
  NID_pkcs9_signingTime, so::nid::Nid::PKCS9_SIGNINGTIME
 },
 NidUTInput {
  NID_pkcs9_countersignature, so::nid::Nid::PKCS9_COUNTERSIGNATURE
 },
 NidUTInput {
  NID_pkcs9_challengePassword, so::nid::Nid::PKCS9_CHALLENGEPASSWORD
 },
 NidUTInput {
  NID_pkcs9_unstructuredAddress, so::nid::Nid::PKCS9_UNSTRUCTUREDADDRESS
 },
 NidUTInput {
  NID_pkcs9_extCertAttributes, so::nid::Nid::PKCS9_EXTCERTATTRIBUTES
 },
 NidUTInput {
  NID_ext_req, so::nid::Nid::EXT_REQ
 },
 NidUTInput {
  NID_SMIMECapabilities, so::nid::Nid::SMIMECAPABILITIES
 },
 NidUTInput {
  NID_SMIME, so::nid::Nid::SMIME
 },
 NidUTInput {
  NID_id_smime_mod, so::nid::Nid::ID_SMIME_MOD
 },
 NidUTInput {
  NID_id_smime_ct, so::nid::Nid::ID_SMIME_CT
 },
 NidUTInput {
  NID_id_smime_aa, so::nid::Nid::ID_SMIME_AA
 },
 NidUTInput {
  NID_id_smime_alg, so::nid::Nid::ID_SMIME_ALG
 },
 NidUTInput {
  NID_id_smime_cd, so::nid::Nid::ID_SMIME_CD
 },
 NidUTInput {
  NID_id_smime_spq, so::nid::Nid::ID_SMIME_SPQ
 },
 NidUTInput {
  NID_id_smime_cti, so::nid::Nid::ID_SMIME_CTI
 },
 NidUTInput {
  NID_id_smime_mod_cms, so::nid::Nid::ID_SMIME_MOD_CMS
 },
 NidUTInput {
  NID_id_smime_mod_ess, so::nid::Nid::ID_SMIME_MOD_ESS
 },
 NidUTInput {
  NID_id_smime_mod_oid, so::nid::Nid::ID_SMIME_MOD_OID
 },
 NidUTInput {
  NID_id_smime_mod_msg_v3, so::nid::Nid::ID_SMIME_MOD_MSG_V3
 },
 NidUTInput {
  NID_id_smime_mod_ets_eSignature_88, so::nid::Nid::ID_SMIME_MOD_ETS_ESIGNATURE_88
 },
 NidUTInput {
  NID_id_smime_mod_ets_eSignature_97, so::nid::Nid::ID_SMIME_MOD_ETS_ESIGNATURE_97
 },
 NidUTInput {
  NID_id_smime_mod_ets_eSigPolicy_88, so::nid::Nid::ID_SMIME_MOD_ETS_ESIGPOLICY_88
 },
 NidUTInput {
  NID_id_smime_mod_ets_eSigPolicy_97, so::nid::Nid::ID_SMIME_MOD_ETS_ESIGPOLICY_97
 },
 NidUTInput {
  NID_id_smime_ct_receipt, so::nid::Nid::ID_SMIME_CT_RECEIPT
 },
 NidUTInput {
  NID_id_smime_ct_authData, so::nid::Nid::ID_SMIME_CT_AUTHDATA
 },
 NidUTInput {
  NID_id_smime_ct_publishCert, so::nid::Nid::ID_SMIME_CT_PUBLISHCERT
 },
 NidUTInput {
  NID_id_smime_ct_TSTInfo, so::nid::Nid::ID_SMIME_CT_TSTINFO
 },
 NidUTInput {
  NID_id_smime_ct_TDTInfo, so::nid::Nid::ID_SMIME_CT_TDTINFO
 },
 NidUTInput {
  NID_id_smime_ct_contentInfo, so::nid::Nid::ID_SMIME_CT_CONTENTINFO
 },
 NidUTInput {
  NID_id_smime_ct_DVCSRequestData, so::nid::Nid::ID_SMIME_CT_DVCSREQUESTDATA
 },
 NidUTInput {
  NID_id_smime_ct_DVCSResponseData, so::nid::Nid::ID_SMIME_CT_DVCSRESPONSEDATA
 },
 NidUTInput {
  NID_id_smime_ct_compressedData, so::nid::Nid::ID_SMIME_CT_COMPRESSEDDATA
 },
 NidUTInput {
  NID_id_smime_ct_contentCollection, so::nid::Nid::ID_SMIME_CT_CONTENTCOLLECTION
 },
 NidUTInput {
  NID_id_smime_ct_authEnvelopedData, so::nid::Nid::ID_SMIME_CT_AUTHENVELOPEDDATA
 },
 NidUTInput {
  NID_id_ct_asciiTextWithCRLF, so::nid::Nid::ID_CT_ASCIITEXTWITHCRLF
 },
 NidUTInput {
  NID_id_ct_xml, so::nid::Nid::ID_CT_XML
 },
 NidUTInput {
  NID_id_smime_aa_receiptRequest, so::nid::Nid::ID_SMIME_AA_RECEIPTREQUEST
 },
 NidUTInput {
  NID_id_smime_aa_securityLabel, so::nid::Nid::ID_SMIME_AA_SECURITYLABEL
 },
 NidUTInput {
  NID_id_smime_aa_mlExpandHistory, so::nid::Nid::ID_SMIME_AA_MLEXPANDHISTORY
 },
 NidUTInput {
  NID_id_smime_aa_contentHint, so::nid::Nid::ID_SMIME_AA_CONTENTHINT
 },
 NidUTInput {
  NID_id_smime_aa_msgSigDigest, so::nid::Nid::ID_SMIME_AA_MSGSIGDIGEST
 },
 NidUTInput {
  NID_id_smime_aa_encapContentType, so::nid::Nid::ID_SMIME_AA_ENCAPCONTENTTYPE
 },
 NidUTInput {
  NID_id_smime_aa_contentIdentifier, so::nid::Nid::ID_SMIME_AA_CONTENTIDENTIFIER
 },
 NidUTInput {
  NID_id_smime_aa_macValue, so::nid::Nid::ID_SMIME_AA_MACVALUE
 },
 NidUTInput {
  NID_id_smime_aa_equivalentLabels, so::nid::Nid::ID_SMIME_AA_EQUIVALENTLABELS
 },
 NidUTInput {
  NID_id_smime_aa_contentReference, so::nid::Nid::ID_SMIME_AA_CONTENTREFERENCE
 },
 NidUTInput {
  NID_id_smime_aa_encrypKeyPref, so::nid::Nid::ID_SMIME_AA_ENCRYPKEYPREF
 },
 NidUTInput {
  NID_id_smime_aa_signingCertificate, so::nid::Nid::ID_SMIME_AA_SIGNINGCERTIFICATE
 },
 NidUTInput {
  NID_id_smime_aa_smimeEncryptCerts, so::nid::Nid::ID_SMIME_AA_SMIMEENCRYPTCERTS
 },
 NidUTInput {
  NID_id_smime_aa_timeStampToken, so::nid::Nid::ID_SMIME_AA_TIMESTAMPTOKEN
 },
 NidUTInput {
  NID_id_smime_aa_ets_sigPolicyId, so::nid::Nid::ID_SMIME_AA_ETS_SIGPOLICYID
 },
 NidUTInput {
  NID_id_smime_aa_ets_commitmentType, so::nid::Nid::ID_SMIME_AA_ETS_COMMITMENTTYPE
 },
 NidUTInput {
  NID_id_smime_aa_ets_signerLocation, so::nid::Nid::ID_SMIME_AA_ETS_SIGNERLOCATION
 },
 NidUTInput {
  NID_id_smime_aa_ets_signerAttr, so::nid::Nid::ID_SMIME_AA_ETS_SIGNERATTR
 },
 NidUTInput {
  NID_id_smime_aa_ets_otherSigCert, so::nid::Nid::ID_SMIME_AA_ETS_OTHERSIGCERT
 },
 NidUTInput {
  NID_id_smime_aa_ets_contentTimestamp, so::nid::Nid::ID_SMIME_AA_ETS_CONTENTTIMESTAMP
 },
 NidUTInput {
  NID_id_smime_aa_ets_CertificateRefs, so::nid::Nid::ID_SMIME_AA_ETS_CERTIFICATEREFS
 },
 NidUTInput {
  NID_id_smime_aa_ets_RevocationRefs, so::nid::Nid::ID_SMIME_AA_ETS_REVOCATIONREFS
 },
 NidUTInput {
  NID_id_smime_aa_ets_certValues, so::nid::Nid::ID_SMIME_AA_ETS_CERTVALUES
 },
 NidUTInput {
  NID_id_smime_aa_ets_revocationValues, so::nid::Nid::ID_SMIME_AA_ETS_REVOCATIONVALUES
 },
 NidUTInput {
  NID_id_smime_aa_ets_escTimeStamp, so::nid::Nid::ID_SMIME_AA_ETS_ESCTIMESTAMP
 },
 NidUTInput {
  NID_id_smime_aa_ets_certCRLTimestamp, so::nid::Nid::ID_SMIME_AA_ETS_CERTCRLTIMESTAMP
 },
 NidUTInput {
  NID_id_smime_aa_ets_archiveTimeStamp, so::nid::Nid::ID_SMIME_AA_ETS_ARCHIVETIMESTAMP
 },
 NidUTInput {
  NID_id_smime_aa_signatureType, so::nid::Nid::ID_SMIME_AA_SIGNATURETYPE
 },
 NidUTInput {
  NID_id_smime_aa_dvcs_dvc, so::nid::Nid::ID_SMIME_AA_DVCS_DVC
 },
 NidUTInput {
  NID_id_smime_alg_ESDHwith3DES, so::nid::Nid::ID_SMIME_ALG_ESDHWITH3DES
 },
 NidUTInput {
  NID_id_smime_alg_ESDHwithRC2, so::nid::Nid::ID_SMIME_ALG_ESDHWITHRC2
 },
 NidUTInput {
  NID_id_smime_alg_3DESwrap, so::nid::Nid::ID_SMIME_ALG_3DESWRAP
 },
 NidUTInput {
  NID_id_smime_alg_RC2wrap, so::nid::Nid::ID_SMIME_ALG_RC2WRAP
 },
 NidUTInput {
  NID_id_smime_alg_ESDH, so::nid::Nid::ID_SMIME_ALG_ESDH
 },
 NidUTInput {
  NID_id_smime_alg_CMS3DESwrap, so::nid::Nid::ID_SMIME_ALG_CMS3DESWRAP
 },
 NidUTInput {
  NID_id_smime_alg_CMSRC2wrap, so::nid::Nid::ID_SMIME_ALG_CMSRC2WRAP
 },
 NidUTInput {
  NID_id_alg_PWRI_KEK, so::nid::Nid::ID_ALG_PWRI_KEK
 },
 NidUTInput {
  NID_id_smime_cd_ldap, so::nid::Nid::ID_SMIME_CD_LDAP
 },
 NidUTInput {
  NID_id_smime_spq_ets_sqt_uri, so::nid::Nid::ID_SMIME_SPQ_ETS_SQT_URI
 },
 NidUTInput {
  NID_id_smime_spq_ets_sqt_unotice, so::nid::Nid::ID_SMIME_SPQ_ETS_SQT_UNOTICE
 },
 NidUTInput {
  NID_id_smime_cti_ets_proofOfOrigin, so::nid::Nid::ID_SMIME_CTI_ETS_PROOFOFORIGIN
 },
 NidUTInput {
  NID_id_smime_cti_ets_proofOfReceipt, so::nid::Nid::ID_SMIME_CTI_ETS_PROOFOFRECEIPT
 },
 NidUTInput {
  NID_id_smime_cti_ets_proofOfDelivery, so::nid::Nid::ID_SMIME_CTI_ETS_PROOFOFDELIVERY
 },
 NidUTInput {
  NID_id_smime_cti_ets_proofOfSender, so::nid::Nid::ID_SMIME_CTI_ETS_PROOFOFSENDER
 },
 NidUTInput {
  NID_id_smime_cti_ets_proofOfApproval, so::nid::Nid::ID_SMIME_CTI_ETS_PROOFOFAPPROVAL
 },
 NidUTInput {
  NID_id_smime_cti_ets_proofOfCreation, so::nid::Nid::ID_SMIME_CTI_ETS_PROOFOFCREATION
 },
 NidUTInput {
  NID_friendlyName, so::nid::Nid::FRIENDLYNAME
 },
 NidUTInput {
  NID_localKeyID, so::nid::Nid::LOCALKEYID
 },
 NidUTInput {
  NID_ms_csp_name, so::nid::Nid::MS_CSP_NAME
 },
 NidUTInput {
  NID_LocalKeySet, so::nid::Nid::LOCALKEYSET
 },
 NidUTInput {
  NID_x509Certificate, so::nid::Nid::X509CERTIFICATE
 },
 NidUTInput {
  NID_sdsiCertificate, so::nid::Nid::SDSICERTIFICATE
 },
 NidUTInput {
  NID_x509Crl, so::nid::Nid::X509CRL
 },
 NidUTInput {
  NID_pbe_WithSHA1And128BitRC4, so::nid::Nid::PBE_WITHSHA1AND128BITRC4
 },
 NidUTInput {
  NID_pbe_WithSHA1And40BitRC4, so::nid::Nid::PBE_WITHSHA1AND40BITRC4
 },
 NidUTInput {
  NID_pbe_WithSHA1And3_Key_TripleDES_CBC, so::nid::Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC
 },
 NidUTInput {
  NID_pbe_WithSHA1And2_Key_TripleDES_CBC, so::nid::Nid::PBE_WITHSHA1AND2_KEY_TRIPLEDES_CBC
 },
 NidUTInput {
  NID_pbe_WithSHA1And128BitRC2_CBC, so::nid::Nid::PBE_WITHSHA1AND128BITRC2_CBC
 },
 NidUTInput {
  NID_pbe_WithSHA1And40BitRC2_CBC, so::nid::Nid::PBE_WITHSHA1AND40BITRC2_CBC
 },
 NidUTInput {
  NID_keyBag, so::nid::Nid::KEYBAG
 },
 NidUTInput {
  NID_pkcs8ShroudedKeyBag, so::nid::Nid::PKCS8SHROUDEDKEYBAG
 },
 NidUTInput {
  NID_certBag, so::nid::Nid::CERTBAG
 },
 NidUTInput {
  NID_crlBag, so::nid::Nid::CRLBAG
 },
 NidUTInput {
  NID_secretBag, so::nid::Nid::SECRETBAG
 },
 NidUTInput {
  NID_safeContentsBag, so::nid::Nid::SAFECONTENTSBAG
 },
 NidUTInput {
  NID_md2, so::nid::Nid::MD2
 },
 NidUTInput {
  NID_md4, so::nid::Nid::MD4
 },
 NidUTInput {
  NID_md5, so::nid::Nid::MD5
 },
 NidUTInput {
  NID_md5_sha1, so::nid::Nid::MD5_SHA1
 },
 NidUTInput {
  NID_hmacWithMD5, so::nid::Nid::HMACWITHMD5
 },
 NidUTInput {
  NID_hmacWithSHA1, so::nid::Nid::HMACWITHSHA1
 },
 NidUTInput {
  NID_hmacWithSHA224, so::nid::Nid::HMACWITHSHA224
 },
 NidUTInput {
  NID_hmacWithSHA256, so::nid::Nid::HMACWITHSHA256
 },
 NidUTInput {
  NID_hmacWithSHA384, so::nid::Nid::HMACWITHSHA384
 },
 NidUTInput {
  NID_hmacWithSHA512, so::nid::Nid::HMACWITHSHA512
 },
 NidUTInput {
  NID_rc2_cbc, so::nid::Nid::RC2_CBC
 },
 NidUTInput {
  NID_rc2_ecb, so::nid::Nid::RC2_ECB
 },
 NidUTInput {
  NID_rc2_cfb64, so::nid::Nid::RC2_CFB64
 },
 NidUTInput {
  NID_rc2_ofb64, so::nid::Nid::RC2_OFB64
 },
 NidUTInput {
  NID_rc2_40_cbc, so::nid::Nid::RC2_40_CBC
 },
 NidUTInput {
  NID_rc2_64_cbc, so::nid::Nid::RC2_64_CBC
 },
 NidUTInput {
  NID_rc4, so::nid::Nid::RC4
 },
 NidUTInput {
  NID_rc4_40, so::nid::Nid::RC4_40
 },
 NidUTInput {
  NID_des_ede3_cbc, so::nid::Nid::DES_EDE3_CBC
 },
 NidUTInput {
  NID_rc5_cbc, so::nid::Nid::RC5_CBC
 },
 NidUTInput {
  NID_rc5_ecb, so::nid::Nid::RC5_ECB
 },
 NidUTInput {
  NID_rc5_cfb64, so::nid::Nid::RC5_CFB64
 },
 NidUTInput {
  NID_rc5_ofb64, so::nid::Nid::RC5_OFB64
 },
 NidUTInput {
  NID_ms_ext_req, so::nid::Nid::MS_EXT_REQ
 },
 NidUTInput {
  NID_ms_code_ind, so::nid::Nid::MS_CODE_IND
 },
 NidUTInput {
  NID_ms_code_com, so::nid::Nid::MS_CODE_COM
 },
 NidUTInput {
  NID_ms_ctl_sign, so::nid::Nid::MS_CTL_SIGN
 },
 NidUTInput {
  NID_ms_sgc, so::nid::Nid::MS_SGC
 },
 NidUTInput {
  NID_ms_efs, so::nid::Nid::MS_EFS
 },
 NidUTInput {
  NID_ms_smartcard_login, so::nid::Nid::MS_SMARTCARD_LOGIN
 },
 NidUTInput {
  NID_ms_upn, so::nid::Nid::MS_UPN
 },
 NidUTInput {
  NID_idea_cbc, so::nid::Nid::IDEA_CBC
 },
 NidUTInput {
  NID_idea_ecb, so::nid::Nid::IDEA_ECB
 },
 NidUTInput {
  NID_idea_cfb64, so::nid::Nid::IDEA_CFB64
 },
 NidUTInput {
  NID_idea_ofb64, so::nid::Nid::IDEA_OFB64
 },
 NidUTInput {
  NID_bf_cbc, so::nid::Nid::BF_CBC
 },
 NidUTInput {
  NID_bf_ecb, so::nid::Nid::BF_ECB
 },
 NidUTInput {
  NID_bf_cfb64, so::nid::Nid::BF_CFB64
 },
 NidUTInput {
  NID_bf_ofb64, so::nid::Nid::BF_OFB64
 },
 NidUTInput {
  NID_id_pkix, so::nid::Nid::ID_PKIX
 },
 NidUTInput {
  NID_id_pkix_mod, so::nid::Nid::ID_PKIX_MOD
 },
 NidUTInput {
  NID_id_pe, so::nid::Nid::ID_PE
 },
 NidUTInput {
  NID_id_qt, so::nid::Nid::ID_QT
 },
 NidUTInput {
  NID_id_kp, so::nid::Nid::ID_KP
 },
 NidUTInput {
  NID_id_it, so::nid::Nid::ID_IT
 },
 NidUTInput {
  NID_id_pkip, so::nid::Nid::ID_PKIP
 },
 NidUTInput {
  NID_id_alg, so::nid::Nid::ID_ALG
 },
 NidUTInput {
  NID_id_cmc, so::nid::Nid::ID_CMC
 },
 NidUTInput {
  NID_id_on, so::nid::Nid::ID_ON
 },
 NidUTInput {
  NID_id_pda, so::nid::Nid::ID_PDA
 },
 NidUTInput {
  NID_id_aca, so::nid::Nid::ID_ACA
 },
 NidUTInput {
  NID_id_qcs, so::nid::Nid::ID_QCS
 },
 NidUTInput {
  NID_id_cct, so::nid::Nid::ID_CCT
 },
 NidUTInput {
  NID_id_ppl, so::nid::Nid::ID_PPL
 },
 NidUTInput {
  NID_id_ad, so::nid::Nid::ID_AD
 },
 NidUTInput {
  NID_id_pkix1_explicit_88, so::nid::Nid::ID_PKIX1_EXPLICIT_88
 },
 NidUTInput {
  NID_id_pkix1_implicit_88, so::nid::Nid::ID_PKIX1_IMPLICIT_88
 },
 NidUTInput {
  NID_id_pkix1_explicit_93, so::nid::Nid::ID_PKIX1_EXPLICIT_93
 },
 NidUTInput {
  NID_id_pkix1_implicit_93, so::nid::Nid::ID_PKIX1_IMPLICIT_93
 },
 NidUTInput {
  NID_id_mod_crmf, so::nid::Nid::ID_MOD_CRMF
 },
 NidUTInput {
  NID_id_mod_cmc, so::nid::Nid::ID_MOD_CMC
 },
 NidUTInput {
  NID_id_mod_kea_profile_88, so::nid::Nid::ID_MOD_KEA_PROFILE_88
 },
 NidUTInput {
  NID_id_mod_kea_profile_93, so::nid::Nid::ID_MOD_KEA_PROFILE_93
 },
 NidUTInput {
  NID_id_mod_cmp, so::nid::Nid::ID_MOD_CMP
 },
 NidUTInput {
  NID_id_mod_qualified_cert_88, so::nid::Nid::ID_MOD_QUALIFIED_CERT_88
 },
 NidUTInput {
  NID_id_mod_qualified_cert_93, so::nid::Nid::ID_MOD_QUALIFIED_CERT_93
 },
 NidUTInput {
  NID_id_mod_attribute_cert, so::nid::Nid::ID_MOD_ATTRIBUTE_CERT
 },
 NidUTInput {
  NID_id_mod_timestamp_protocol, so::nid::Nid::ID_MOD_TIMESTAMP_PROTOCOL
 },
 NidUTInput {
  NID_id_mod_ocsp, so::nid::Nid::ID_MOD_OCSP
 },
 NidUTInput {
  NID_id_mod_dvcs, so::nid::Nid::ID_MOD_DVCS
 },
 NidUTInput {
  NID_id_mod_cmp2000, so::nid::Nid::ID_MOD_CMP2000
 },
 NidUTInput {
  NID_info_access, so::nid::Nid::INFO_ACCESS
 },
 NidUTInput {
  NID_biometricInfo, so::nid::Nid::BIOMETRICINFO
 },
 NidUTInput {
  NID_qcStatements, so::nid::Nid::QCSTATEMENTS
 },
 NidUTInput {
  NID_ac_auditEntity, so::nid::Nid::AC_AUDITENTITY
 },
 NidUTInput {
  NID_ac_targeting, so::nid::Nid::AC_TARGETING
 },
 NidUTInput {
  NID_aaControls, so::nid::Nid::AACONTROLS
 },
 NidUTInput {
  NID_sbgp_ipAddrBlock, so::nid::Nid::SBGP_IPADDRBLOCK
 },
 NidUTInput {
  NID_sbgp_autonomousSysNum, so::nid::Nid::SBGP_AUTONOMOUSSYSNUM
 },
 NidUTInput {
  NID_sbgp_routerIdentifier, so::nid::Nid::SBGP_ROUTERIDENTIFIER
 },
 NidUTInput {
  NID_ac_proxying, so::nid::Nid::AC_PROXYING
 },
 NidUTInput {
  NID_sinfo_access, so::nid::Nid::SINFO_ACCESS
 },
 NidUTInput {
  NID_proxyCertInfo, so::nid::Nid::PROXYCERTINFO
 },
 NidUTInput {
  NID_tlsfeature, so::nid::Nid::TLSFEATURE
 },
 NidUTInput {
  NID_id_qt_cps, so::nid::Nid::ID_QT_CPS
 },
 NidUTInput {
  NID_id_qt_unotice, so::nid::Nid::ID_QT_UNOTICE
 },
 NidUTInput {
  NID_textNotice, so::nid::Nid::TEXTNOTICE
 },
 NidUTInput {
  NID_server_auth, so::nid::Nid::SERVER_AUTH
 },
 NidUTInput {
  NID_client_auth, so::nid::Nid::CLIENT_AUTH
 },
 NidUTInput {
  NID_code_sign, so::nid::Nid::CODE_SIGN
 },
 NidUTInput {
  NID_email_protect, so::nid::Nid::EMAIL_PROTECT
 },
 NidUTInput {
  NID_ipsecEndSystem, so::nid::Nid::IPSECENDSYSTEM
 },
 NidUTInput {
  NID_ipsecTunnel, so::nid::Nid::IPSECTUNNEL
 },
 NidUTInput {
  NID_ipsecUser, so::nid::Nid::IPSECUSER
 },
 NidUTInput {
  NID_time_stamp, so::nid::Nid::TIME_STAMP
 },
 NidUTInput {
  NID_OCSP_sign, so::nid::Nid::OCSP_SIGN
 },
 NidUTInput {
  NID_dvcs, so::nid::Nid::DVCS
 },
 NidUTInput {
  NID_ipsec_IKE, so::nid::Nid::IPSEC_IKE
 },
 NidUTInput {
  NID_capwapAC, so::nid::Nid::CAPWAPAC
 },
 NidUTInput {
  NID_capwapWTP, so::nid::Nid::CAPWAPWTP
 },
 NidUTInput {
  NID_sshClient, so::nid::Nid::SSHCLIENT
 },
 NidUTInput {
  NID_sshServer, so::nid::Nid::SSHSERVER
 },
 NidUTInput {
  NID_sendRouter, so::nid::Nid::SENDROUTER
 },
 NidUTInput {
  NID_sendProxiedRouter, so::nid::Nid::SENDPROXIEDROUTER
 },
 NidUTInput {
  NID_sendOwner, so::nid::Nid::SENDOWNER
 },
 NidUTInput {
  NID_sendProxiedOwner, so::nid::Nid::SENDPROXIEDOWNER
 },
 NidUTInput {
  NID_id_it_caProtEncCert, so::nid::Nid::ID_IT_CAPROTENCCERT
 },
 NidUTInput {
  NID_id_it_signKeyPairTypes, so::nid::Nid::ID_IT_SIGNKEYPAIRTYPES
 },
 NidUTInput {
  NID_id_it_encKeyPairTypes, so::nid::Nid::ID_IT_ENCKEYPAIRTYPES
 },
 NidUTInput {
  NID_id_it_preferredSymmAlg, so::nid::Nid::ID_IT_PREFERREDSYMMALG
 },
 NidUTInput {
  NID_id_it_caKeyUpdateInfo, so::nid::Nid::ID_IT_CAKEYUPDATEINFO
 },
 NidUTInput {
  NID_id_it_currentCRL, so::nid::Nid::ID_IT_CURRENTCRL
 },
 NidUTInput {
  NID_id_it_unsupportedOIDs, so::nid::Nid::ID_IT_UNSUPPORTEDOIDS
 },
 NidUTInput {
  NID_id_it_subscriptionRequest, so::nid::Nid::ID_IT_SUBSCRIPTIONREQUEST
 },
 NidUTInput {
  NID_id_it_subscriptionResponse, so::nid::Nid::ID_IT_SUBSCRIPTIONRESPONSE
 },
 NidUTInput {
  NID_id_it_keyPairParamReq, so::nid::Nid::ID_IT_KEYPAIRPARAMREQ
 },
 NidUTInput {
  NID_id_it_keyPairParamRep, so::nid::Nid::ID_IT_KEYPAIRPARAMREP
 },
 NidUTInput {
  NID_id_it_revPassphrase, so::nid::Nid::ID_IT_REVPASSPHRASE
 },
 NidUTInput {
  NID_id_it_implicitConfirm, so::nid::Nid::ID_IT_IMPLICITCONFIRM
 },
 NidUTInput {
  NID_id_it_confirmWaitTime, so::nid::Nid::ID_IT_CONFIRMWAITTIME
 },
 NidUTInput {
  NID_id_it_origPKIMessage, so::nid::Nid::ID_IT_ORIGPKIMESSAGE
 },
 NidUTInput {
  NID_id_it_suppLangTags, so::nid::Nid::ID_IT_SUPPLANGTAGS
 },
 NidUTInput {
  NID_id_regCtrl, so::nid::Nid::ID_REGCTRL
 },
 NidUTInput {
  NID_id_regInfo, so::nid::Nid::ID_REGINFO
 },
 NidUTInput {
  NID_id_regCtrl_regToken, so::nid::Nid::ID_REGCTRL_REGTOKEN
 },
 NidUTInput {
  NID_id_regCtrl_authenticator, so::nid::Nid::ID_REGCTRL_AUTHENTICATOR
 },
 NidUTInput {
  NID_id_regCtrl_pkiPublicationInfo, so::nid::Nid::ID_REGCTRL_PKIPUBLICATIONINFO
 },
 NidUTInput {
  NID_id_regCtrl_pkiArchiveOptions, so::nid::Nid::ID_REGCTRL_PKIARCHIVEOPTIONS
 },
 NidUTInput {
  NID_id_regCtrl_oldCertID, so::nid::Nid::ID_REGCTRL_OLDCERTID
 },
 NidUTInput {
  NID_id_regCtrl_protocolEncrKey, so::nid::Nid::ID_REGCTRL_PROTOCOLENCRKEY
 },
 NidUTInput {
  NID_id_regInfo_utf8Pairs, so::nid::Nid::ID_REGINFO_UTF8PAIRS
 },
 NidUTInput {
  NID_id_regInfo_certReq, so::nid::Nid::ID_REGINFO_CERTREQ
 },
 NidUTInput {
  NID_id_alg_des40, so::nid::Nid::ID_ALG_DES40
 },
 NidUTInput {
  NID_id_alg_noSignature, so::nid::Nid::ID_ALG_NOSIGNATURE
 },
 NidUTInput {
  NID_id_alg_dh_sig_hmac_sha1, so::nid::Nid::ID_ALG_DH_SIG_HMAC_SHA1
 },
 NidUTInput {
  NID_id_alg_dh_pop, so::nid::Nid::ID_ALG_DH_POP
 },
 NidUTInput {
  NID_id_cmc_statusInfo, so::nid::Nid::ID_CMC_STATUSINFO
 },
 NidUTInput {
  NID_id_cmc_identification, so::nid::Nid::ID_CMC_IDENTIFICATION
 },
 NidUTInput {
  NID_id_cmc_identityProof, so::nid::Nid::ID_CMC_IDENTITYPROOF
 },
 NidUTInput {
  NID_id_cmc_dataReturn, so::nid::Nid::ID_CMC_DATARETURN
 },
 NidUTInput {
  NID_id_cmc_transactionId, so::nid::Nid::ID_CMC_TRANSACTIONID
 },
 NidUTInput {
  NID_id_cmc_senderNonce, so::nid::Nid::ID_CMC_SENDERNONCE
 },
 NidUTInput {
  NID_id_cmc_recipientNonce, so::nid::Nid::ID_CMC_RECIPIENTNONCE
 },
 NidUTInput {
  NID_id_cmc_addExtensions, so::nid::Nid::ID_CMC_ADDEXTENSIONS
 },
 NidUTInput {
  NID_id_cmc_encryptedPOP, so::nid::Nid::ID_CMC_ENCRYPTEDPOP
 },
 NidUTInput {
  NID_id_cmc_decryptedPOP, so::nid::Nid::ID_CMC_DECRYPTEDPOP
 },
 NidUTInput {
  NID_id_cmc_lraPOPWitness, so::nid::Nid::ID_CMC_LRAPOPWITNESS
 },
 NidUTInput {
  NID_id_cmc_getCert, so::nid::Nid::ID_CMC_GETCERT
 },
 NidUTInput {
  NID_id_cmc_getCRL, so::nid::Nid::ID_CMC_GETCRL
 },
 NidUTInput {
  NID_id_cmc_revokeRequest, so::nid::Nid::ID_CMC_REVOKEREQUEST
 },
 NidUTInput {
  NID_id_cmc_regInfo, so::nid::Nid::ID_CMC_REGINFO
 },
 NidUTInput {
  NID_id_cmc_responseInfo, so::nid::Nid::ID_CMC_RESPONSEINFO
 },
 NidUTInput {
  NID_id_cmc_queryPending, so::nid::Nid::ID_CMC_QUERYPENDING
 },
 NidUTInput {
  NID_id_cmc_popLinkRandom, so::nid::Nid::ID_CMC_POPLINKRANDOM
 },
 NidUTInput {
  NID_id_cmc_popLinkWitness, so::nid::Nid::ID_CMC_POPLINKWITNESS
 },
 NidUTInput {
  NID_id_cmc_confirmCertAcceptance, so::nid::Nid::ID_CMC_CONFIRMCERTACCEPTANCE
 },
 NidUTInput {
  NID_id_on_personalData, so::nid::Nid::ID_ON_PERSONALDATA
 },
 NidUTInput {
  NID_id_on_permanentIdentifier, so::nid::Nid::ID_ON_PERMANENTIDENTIFIER
 },
 NidUTInput {
  NID_id_pda_dateOfBirth, so::nid::Nid::ID_PDA_DATEOFBIRTH
 },
 NidUTInput {
  NID_id_pda_placeOfBirth, so::nid::Nid::ID_PDA_PLACEOFBIRTH
 },
 NidUTInput {
  NID_id_pda_gender, so::nid::Nid::ID_PDA_GENDER
 },
 NidUTInput {
  NID_id_pda_countryOfCitizenship, so::nid::Nid::ID_PDA_COUNTRYOFCITIZENSHIP
 },
 NidUTInput {
  NID_id_pda_countryOfResidence, so::nid::Nid::ID_PDA_COUNTRYOFRESIDENCE
 },
 NidUTInput {
  NID_id_aca_authenticationInfo, so::nid::Nid::ID_ACA_AUTHENTICATIONINFO
 },
 NidUTInput {
  NID_id_aca_accessIdentity, so::nid::Nid::ID_ACA_ACCESSIDENTITY
 },
 NidUTInput {
  NID_id_aca_chargingIdentity, so::nid::Nid::ID_ACA_CHARGINGIDENTITY
 },
 NidUTInput {
  NID_id_aca_group, so::nid::Nid::ID_ACA_GROUP
 },
 NidUTInput {
  NID_id_aca_role, so::nid::Nid::ID_ACA_ROLE
 },
 NidUTInput {
  NID_id_aca_encAttrs, so::nid::Nid::ID_ACA_ENCATTRS
 },
 NidUTInput {
  NID_id_qcs_pkixQCSyntax_v1, so::nid::Nid::ID_QCS_PKIXQCSYNTAX_V1
 },
 NidUTInput {
  NID_id_cct_crs, so::nid::Nid::ID_CCT_CRS
 },
 NidUTInput {
  NID_id_cct_PKIData, so::nid::Nid::ID_CCT_PKIDATA
 },
 NidUTInput {
  NID_id_cct_PKIResponse, so::nid::Nid::ID_CCT_PKIRESPONSE
 },
 NidUTInput {
  NID_id_ppl_anyLanguage, so::nid::Nid::ID_PPL_ANYLANGUAGE
 },
 NidUTInput {
  NID_id_ppl_inheritAll, so::nid::Nid::ID_PPL_INHERITALL
 },
 NidUTInput {
  NID_Independent, so::nid::Nid::INDEPENDENT
 },
 NidUTInput {
  NID_ad_OCSP, so::nid::Nid::AD_OCSP
 },
 NidUTInput {
  NID_ad_ca_issuers, so::nid::Nid::AD_CA_ISSUERS
 },
 NidUTInput {
  NID_ad_timeStamping, so::nid::Nid::AD_TIMESTAMPING
 },
 NidUTInput {
  NID_ad_dvcs, so::nid::Nid::AD_DVCS
 },
 NidUTInput {
  NID_caRepository, so::nid::Nid::CAREPOSITORY
 },
 NidUTInput {
  NID_id_pkix_OCSP_basic, so::nid::Nid::ID_PKIX_OCSP_BASIC
 },
 NidUTInput {
  NID_id_pkix_OCSP_Nonce, so::nid::Nid::ID_PKIX_OCSP_NONCE
 },
 NidUTInput {
  NID_id_pkix_OCSP_CrlID, so::nid::Nid::ID_PKIX_OCSP_CRLID
 },
 NidUTInput {
  NID_id_pkix_OCSP_acceptableResponses, so::nid::Nid::ID_PKIX_OCSP_ACCEPTABLERESPONSES
 },
 NidUTInput {
  NID_id_pkix_OCSP_noCheck, so::nid::Nid::ID_PKIX_OCSP_NOCHECK
 },
 NidUTInput {
  NID_id_pkix_OCSP_archiveCutoff, so::nid::Nid::ID_PKIX_OCSP_ARCHIVECUTOFF
 },
 NidUTInput {
  NID_id_pkix_OCSP_serviceLocator, so::nid::Nid::ID_PKIX_OCSP_SERVICELOCATOR
 },
 NidUTInput {
  NID_id_pkix_OCSP_extendedStatus, so::nid::Nid::ID_PKIX_OCSP_EXTENDEDSTATUS
 },
 NidUTInput {
  NID_id_pkix_OCSP_valid, so::nid::Nid::ID_PKIX_OCSP_VALID
 },
 NidUTInput {
  NID_id_pkix_OCSP_path, so::nid::Nid::ID_PKIX_OCSP_PATH
 },
 NidUTInput {
  NID_id_pkix_OCSP_trustRoot, so::nid::Nid::ID_PKIX_OCSP_TRUSTROOT
 },
 NidUTInput {
  NID_algorithm, so::nid::Nid::ALGORITHM
 },
 NidUTInput {
  NID_md5WithRSA, so::nid::Nid::MD5WITHRSA
 },
 NidUTInput {
  NID_des_ecb, so::nid::Nid::DES_ECB
 },
 NidUTInput {
  NID_des_cbc, so::nid::Nid::DES_CBC
 },
 NidUTInput {
  NID_des_ofb64, so::nid::Nid::DES_OFB64
 },
 NidUTInput {
  NID_des_cfb64, so::nid::Nid::DES_CFB64
 },
 NidUTInput {
  NID_rsaSignature, so::nid::Nid::RSASIGNATURE
 },
 NidUTInput {
  NID_dsa_2, so::nid::Nid::DSA_2
 },
 NidUTInput {
  NID_dsaWithSHA, so::nid::Nid::DSAWITHSHA
 },
 NidUTInput {
  NID_shaWithRSAEncryption, so::nid::Nid::SHAWITHRSAENCRYPTION
 },
 NidUTInput {
  NID_des_ede_ecb, so::nid::Nid::DES_EDE_ECB
 },
 NidUTInput {
  NID_des_ede3_ecb, so::nid::Nid::DES_EDE3_ECB
 },
 NidUTInput {
  NID_des_ede_cbc, so::nid::Nid::DES_EDE_CBC
 },
 NidUTInput {
  NID_des_ede_cfb64, so::nid::Nid::DES_EDE_CFB64
 },
 NidUTInput {
  NID_des_ede3_cfb64, so::nid::Nid::DES_EDE3_CFB64
 },
 NidUTInput {
  NID_des_ede_ofb64, so::nid::Nid::DES_EDE_OFB64
 },
 NidUTInput {
  NID_des_ede3_ofb64, so::nid::Nid::DES_EDE3_OFB64
 },
 NidUTInput {
  NID_desx_cbc, so::nid::Nid::DESX_CBC
 },
 NidUTInput {
  NID_sha, so::nid::Nid::SHA
 },
 NidUTInput {
  NID_sha1, so::nid::Nid::SHA1
 },
 NidUTInput {
  NID_dsaWithSHA1_2, so::nid::Nid::DSAWITHSHA1_2
 },
 NidUTInput {
  NID_sha1WithRSA, so::nid::Nid::SHA1WITHRSA
 },
 NidUTInput {
  NID_ripemd160, so::nid::Nid::RIPEMD160
 },
 NidUTInput {
  NID_ripemd160WithRSA, so::nid::Nid::RIPEMD160WITHRSA
 },
 NidUTInput {
  NID_blake2b512, so::nid::Nid::BLAKE2B512
 },
 NidUTInput {
  NID_blake2s256, so::nid::Nid::BLAKE2S256
 },
 NidUTInput {
  NID_sxnet, so::nid::Nid::SXNET
 },
 NidUTInput {
  NID_X500, so::nid::Nid::X500
 },
 NidUTInput {
  NID_X509, so::nid::Nid::X509
 },
 NidUTInput {
  NID_commonName, so::nid::Nid::COMMONNAME
 },
 NidUTInput {
  NID_surname, so::nid::Nid::SURNAME
 },
 NidUTInput {
  NID_serialNumber, so::nid::Nid::SERIALNUMBER
 },
 NidUTInput {
  NID_countryName, so::nid::Nid::COUNTRYNAME
 },
 NidUTInput {
  NID_localityName, so::nid::Nid::LOCALITYNAME
 },
 NidUTInput {
  NID_stateOrProvinceName, so::nid::Nid::STATEORPROVINCENAME
 },
 NidUTInput {
  NID_streetAddress, so::nid::Nid::STREETADDRESS
 },
 NidUTInput {
  NID_organizationName, so::nid::Nid::ORGANIZATIONNAME
 },
 NidUTInput {
  NID_organizationalUnitName, so::nid::Nid::ORGANIZATIONALUNITNAME
 },
 NidUTInput {
  NID_title, so::nid::Nid::TITLE
 },
 NidUTInput {
  NID_description, so::nid::Nid::DESCRIPTION
 },
 NidUTInput {
  NID_searchGuide, so::nid::Nid::SEARCHGUIDE
 },
 NidUTInput {
  NID_businessCategory, so::nid::Nid::BUSINESSCATEGORY
 },
 NidUTInput {
  NID_postalAddress, so::nid::Nid::POSTALADDRESS
 },
 NidUTInput {
  NID_postalCode, so::nid::Nid::POSTALCODE
 },
 NidUTInput {
  NID_postOfficeBox, so::nid::Nid::POSTOFFICEBOX
 },
 NidUTInput {
  NID_physicalDeliveryOfficeName, so::nid::Nid::PHYSICALDELIVERYOFFICENAME
 },
 NidUTInput {
  NID_telephoneNumber, so::nid::Nid::TELEPHONENUMBER
 },
 NidUTInput {
  NID_telexNumber, so::nid::Nid::TELEXNUMBER
 },
 NidUTInput {
  NID_teletexTerminalIdentifier, so::nid::Nid::TELETEXTERMINALIDENTIFIER
 },
 NidUTInput {
  NID_facsimileTelephoneNumber, so::nid::Nid::FACSIMILETELEPHONENUMBER
 },
 NidUTInput {
  NID_x121Address, so::nid::Nid::X121ADDRESS
 },
 NidUTInput {
  NID_internationaliSDNNumber, so::nid::Nid::INTERNATIONALISDNNUMBER
 },
 NidUTInput {
  NID_registeredAddress, so::nid::Nid::REGISTEREDADDRESS
 },
 NidUTInput {
  NID_destinationIndicator, so::nid::Nid::DESTINATIONINDICATOR
 },
 NidUTInput {
  NID_preferredDeliveryMethod, so::nid::Nid::PREFERREDDELIVERYMETHOD
 },
 NidUTInput {
  NID_presentationAddress, so::nid::Nid::PRESENTATIONADDRESS
 },
 NidUTInput {
  NID_supportedApplicationContext, so::nid::Nid::SUPPORTEDAPPLICATIONCONTEXT
 },
 NidUTInput {
  NID_member, so::nid::Nid::MEMBER
 },
 NidUTInput {
  NID_owner, so::nid::Nid::OWNER
 },
 NidUTInput {
  NID_roleOccupant, so::nid::Nid::ROLEOCCUPANT
 },
 NidUTInput {
  NID_seeAlso, so::nid::Nid::SEEALSO
 },
 NidUTInput {
  NID_userPassword, so::nid::Nid::USERPASSWORD
 },
 NidUTInput {
  NID_userCertificate, so::nid::Nid::USERCERTIFICATE
 },
 NidUTInput {
  NID_cACertificate, so::nid::Nid::CACERTIFICATE
 },
 NidUTInput {
  NID_authorityRevocationList, so::nid::Nid::AUTHORITYREVOCATIONLIST
 },
 NidUTInput {
  NID_certificateRevocationList, so::nid::Nid::CERTIFICATEREVOCATIONLIST
 },
 NidUTInput {
  NID_crossCertificatePair, so::nid::Nid::CROSSCERTIFICATEPAIR
 },
 NidUTInput {
  NID_name, so::nid::Nid::NAME
 },
 NidUTInput {
  NID_givenName, so::nid::Nid::GIVENNAME
 },
 NidUTInput {
  NID_initials, so::nid::Nid::INITIALS
 },
 NidUTInput {
  NID_generationQualifier, so::nid::Nid::GENERATIONQUALIFIER
 },
 NidUTInput {
  NID_x500UniqueIdentifier, so::nid::Nid::X500UNIQUEIDENTIFIER
 },
 NidUTInput {
  NID_dnQualifier, so::nid::Nid::DNQUALIFIER
 },
 NidUTInput {
  NID_enhancedSearchGuide, so::nid::Nid::ENHANCEDSEARCHGUIDE
 },
 NidUTInput {
  NID_protocolInformation, so::nid::Nid::PROTOCOLINFORMATION
 },
 NidUTInput {
  NID_distinguishedName, so::nid::Nid::DISTINGUISHEDNAME
 },
 NidUTInput {
  NID_uniqueMember, so::nid::Nid::UNIQUEMEMBER
 },
 NidUTInput {
  NID_houseIdentifier, so::nid::Nid::HOUSEIDENTIFIER
 },
 NidUTInput {
  NID_supportedAlgorithms, so::nid::Nid::SUPPORTEDALGORITHMS
 },
 NidUTInput {
  NID_deltaRevocationList, so::nid::Nid::DELTAREVOCATIONLIST
 },
 NidUTInput {
  NID_dmdName, so::nid::Nid::DMDNAME
 },
 NidUTInput {
  NID_pseudonym, so::nid::Nid::PSEUDONYM
 },
 NidUTInput {
  NID_role, so::nid::Nid::ROLE
 },
 NidUTInput {
  NID_X500algorithms, so::nid::Nid::X500ALGORITHMS
 },
 NidUTInput {
  NID_rsa, so::nid::Nid::RSA
 },
 NidUTInput {
  NID_mdc2WithRSA, so::nid::Nid::MDC2WITHRSA
 },
 NidUTInput {
  NID_mdc2, so::nid::Nid::MDC2
 },
 NidUTInput {
  NID_id_ce, so::nid::Nid::ID_CE
 },
 NidUTInput {
  NID_subject_directory_attributes, so::nid::Nid::SUBJECT_DIRECTORY_ATTRIBUTES
 },
 NidUTInput {
  NID_subject_key_identifier, so::nid::Nid::SUBJECT_KEY_IDENTIFIER
 },
 NidUTInput {
  NID_key_usage, so::nid::Nid::KEY_USAGE
 },
 NidUTInput {
  NID_private_key_usage_period, so::nid::Nid::PRIVATE_KEY_USAGE_PERIOD
 },
 NidUTInput {
  NID_subject_alt_name, so::nid::Nid::SUBJECT_ALT_NAME
 },
 NidUTInput {
  NID_issuer_alt_name, so::nid::Nid::ISSUER_ALT_NAME
 },
 NidUTInput {
  NID_basic_constraints, so::nid::Nid::BASIC_CONSTRAINTS
 },
 NidUTInput {
  NID_crl_number, so::nid::Nid::CRL_NUMBER
 },
 NidUTInput {
  NID_crl_reason, so::nid::Nid::CRL_REASON
 },
 NidUTInput {
  NID_invalidity_date, so::nid::Nid::INVALIDITY_DATE
 },
 NidUTInput {
  NID_delta_crl, so::nid::Nid::DELTA_CRL
 },
 NidUTInput {
  NID_issuing_distribution_point, so::nid::Nid::ISSUING_DISTRIBUTION_POINT
 },
 NidUTInput {
  NID_certificate_issuer, so::nid::Nid::CERTIFICATE_ISSUER
 },
 NidUTInput {
  NID_name_constraints, so::nid::Nid::NAME_CONSTRAINTS
 },
 NidUTInput {
  NID_crl_distribution_points, so::nid::Nid::CRL_DISTRIBUTION_POINTS
 },
 NidUTInput {
  NID_certificate_policies, so::nid::Nid::CERTIFICATE_POLICIES
 },
 NidUTInput {
  NID_any_policy, so::nid::Nid::ANY_POLICY
 },
 NidUTInput {
  NID_policy_mappings, so::nid::Nid::POLICY_MAPPINGS
 },
 NidUTInput {
  NID_authority_key_identifier, so::nid::Nid::AUTHORITY_KEY_IDENTIFIER
 },
 NidUTInput {
  NID_policy_constraints, so::nid::Nid::POLICY_CONSTRAINTS
 },
 NidUTInput {
  NID_ext_key_usage, so::nid::Nid::EXT_KEY_USAGE
 },
 NidUTInput {
  NID_freshest_crl, so::nid::Nid::FRESHEST_CRL
 },
 NidUTInput {
  NID_inhibit_any_policy, so::nid::Nid::INHIBIT_ANY_POLICY
 },
 NidUTInput {
  NID_target_information, so::nid::Nid::TARGET_INFORMATION
 },
 NidUTInput {
  NID_no_rev_avail, so::nid::Nid::NO_REV_AVAIL
 },
 NidUTInput {
  NID_anyExtendedKeyUsage, so::nid::Nid::ANYEXTENDEDKEYUSAGE
 },
 NidUTInput {
  NID_netscape, so::nid::Nid::NETSCAPE
 },
 NidUTInput {
  NID_netscape_cert_extension, so::nid::Nid::NETSCAPE_CERT_EXTENSION
 },
 NidUTInput {
  NID_netscape_data_type, so::nid::Nid::NETSCAPE_DATA_TYPE
 },
 NidUTInput {
  NID_netscape_cert_type, so::nid::Nid::NETSCAPE_CERT_TYPE
 },
 NidUTInput {
  NID_netscape_base_url, so::nid::Nid::NETSCAPE_BASE_URL
 },
 NidUTInput {
  NID_netscape_revocation_url, so::nid::Nid::NETSCAPE_REVOCATION_URL
 },
 NidUTInput {
  NID_netscape_ca_revocation_url, so::nid::Nid::NETSCAPE_CA_REVOCATION_URL
 },
 NidUTInput {
  NID_netscape_renewal_url, so::nid::Nid::NETSCAPE_RENEWAL_URL
 },
 NidUTInput {
  NID_netscape_ca_policy_url, so::nid::Nid::NETSCAPE_CA_POLICY_URL
 },
 NidUTInput {
  NID_netscape_ssl_server_name, so::nid::Nid::NETSCAPE_SSL_SERVER_NAME
 },
 NidUTInput {
  NID_netscape_comment, so::nid::Nid::NETSCAPE_COMMENT
 },
 NidUTInput {
  NID_netscape_cert_sequence, so::nid::Nid::NETSCAPE_CERT_SEQUENCE
 },
 NidUTInput {
  NID_ns_sgc, so::nid::Nid::NS_SGC
 },
 NidUTInput {
  NID_org, so::nid::Nid::ORG
 },
 NidUTInput {
  NID_dod, so::nid::Nid::DOD
 },
 NidUTInput {
  NID_iana, so::nid::Nid::IANA
 },
 NidUTInput {
  NID_Directory, so::nid::Nid::DIRECTORY
 },
 NidUTInput {
  NID_Management, so::nid::Nid::MANAGEMENT
 },
 NidUTInput {
  NID_Experimental, so::nid::Nid::EXPERIMENTAL
 },
 NidUTInput {
  NID_Private, so::nid::Nid::PRIVATE
 },
 NidUTInput {
  NID_Security, so::nid::Nid::SECURITY
 },
 NidUTInput {
  NID_SNMPv2, so::nid::Nid::SNMPV2
 },
 NidUTInput {
  NID_Mail, so::nid::Nid::MAIL
 },
 NidUTInput {
  NID_Enterprises, so::nid::Nid::ENTERPRISES
 },
 NidUTInput {
  NID_dcObject, so::nid::Nid::DCOBJECT
 },
 NidUTInput {
  NID_mime_mhs, so::nid::Nid::MIME_MHS
 },
 NidUTInput {
  NID_mime_mhs_headings, so::nid::Nid::MIME_MHS_HEADINGS
 },
 NidUTInput {
  NID_mime_mhs_bodies, so::nid::Nid::MIME_MHS_BODIES
 },
 NidUTInput {
  NID_id_hex_partial_message, so::nid::Nid::ID_HEX_PARTIAL_MESSAGE
 },
 NidUTInput {
  NID_id_hex_multipart_message, so::nid::Nid::ID_HEX_MULTIPART_MESSAGE
 },
 NidUTInput {
  NID_zlib_compression, so::nid::Nid::ZLIB_COMPRESSION
 },
 NidUTInput {
  NID_aes_128_ecb, so::nid::Nid::AES_128_ECB
 },
 NidUTInput {
  NID_aes_128_cbc, so::nid::Nid::AES_128_CBC
 },
 NidUTInput {
  NID_aes_128_ofb128, so::nid::Nid::AES_128_OFB128
 },
 NidUTInput {
  NID_aes_128_cfb128, so::nid::Nid::AES_128_CFB128
 },
 NidUTInput {
  NID_id_aes128_wrap, so::nid::Nid::ID_AES128_WRAP
 },
 NidUTInput {
  NID_aes_128_gcm, so::nid::Nid::AES_128_GCM
 },
 NidUTInput {
  NID_aes_128_ccm, so::nid::Nid::AES_128_CCM
 },
 NidUTInput {
  NID_id_aes128_wrap_pad, so::nid::Nid::ID_AES128_WRAP_PAD
 },
 NidUTInput {
  NID_aes_192_ecb, so::nid::Nid::AES_192_ECB
 },
 NidUTInput {
  NID_aes_192_cbc, so::nid::Nid::AES_192_CBC
 },
 NidUTInput {
  NID_aes_192_ofb128, so::nid::Nid::AES_192_OFB128
 },
 NidUTInput {
  NID_aes_192_cfb128, so::nid::Nid::AES_192_CFB128
 },
 NidUTInput {
  NID_id_aes192_wrap, so::nid::Nid::ID_AES192_WRAP
 },
 NidUTInput {
  NID_aes_192_gcm, so::nid::Nid::AES_192_GCM
 },
 NidUTInput {
  NID_aes_192_ccm, so::nid::Nid::AES_192_CCM
 },
 NidUTInput {
  NID_id_aes192_wrap_pad, so::nid::Nid::ID_AES192_WRAP_PAD
 },
 NidUTInput {
  NID_aes_256_ecb, so::nid::Nid::AES_256_ECB
 },
 NidUTInput {
  NID_aes_256_cbc, so::nid::Nid::AES_256_CBC
 },
 NidUTInput {
  NID_aes_256_ofb128, so::nid::Nid::AES_256_OFB128
 },
 NidUTInput {
  NID_aes_256_cfb128, so::nid::Nid::AES_256_CFB128
 },
 NidUTInput {
  NID_id_aes256_wrap, so::nid::Nid::ID_AES256_WRAP
 },
 NidUTInput {
  NID_aes_256_gcm, so::nid::Nid::AES_256_GCM
 },
 NidUTInput {
  NID_aes_256_ccm, so::nid::Nid::AES_256_CCM
 },
 NidUTInput {
  NID_id_aes256_wrap_pad, so::nid::Nid::ID_AES256_WRAP_PAD
 },
 NidUTInput {
  NID_aes_128_cfb1, so::nid::Nid::AES_128_CFB1
 },
 NidUTInput {
  NID_aes_192_cfb1, so::nid::Nid::AES_192_CFB1
 },
 NidUTInput {
  NID_aes_256_cfb1, so::nid::Nid::AES_256_CFB1
 },
 NidUTInput {
  NID_aes_128_cfb8, so::nid::Nid::AES_128_CFB8
 },
 NidUTInput {
  NID_aes_192_cfb8, so::nid::Nid::AES_192_CFB8
 },
 NidUTInput {
  NID_aes_256_cfb8, so::nid::Nid::AES_256_CFB8
 },
 NidUTInput {
  NID_aes_128_ctr, so::nid::Nid::AES_128_CTR
 },
 NidUTInput {
  NID_aes_192_ctr, so::nid::Nid::AES_192_CTR
 },
 NidUTInput {
  NID_aes_256_ctr, so::nid::Nid::AES_256_CTR
 },
 NidUTInput {
  NID_aes_128_ocb, so::nid::Nid::AES_128_OCB
 },
 NidUTInput {
  NID_aes_192_ocb, so::nid::Nid::AES_192_OCB
 },
 NidUTInput {
  NID_aes_256_ocb, so::nid::Nid::AES_256_OCB
 },
 NidUTInput {
  NID_aes_128_xts, so::nid::Nid::AES_128_XTS
 },
 NidUTInput {
  NID_aes_256_xts, so::nid::Nid::AES_256_XTS
 },
 NidUTInput {
  NID_des_cfb1, so::nid::Nid::DES_CFB1
 },
 NidUTInput {
  NID_des_cfb8, so::nid::Nid::DES_CFB8
 },
 NidUTInput {
  NID_des_ede3_cfb1, so::nid::Nid::DES_EDE3_CFB1
 },
 NidUTInput {
  NID_des_ede3_cfb8, so::nid::Nid::DES_EDE3_CFB8
 },
 NidUTInput {
  NID_sha256, so::nid::Nid::SHA256
 },
 NidUTInput {
  NID_sha384, so::nid::Nid::SHA384
 },
 NidUTInput {
  NID_sha512, so::nid::Nid::SHA512
 },
 NidUTInput {
  NID_sha224, so::nid::Nid::SHA224
 },
 NidUTInput {
  NID_dsa_with_SHA224, so::nid::Nid::DSA_WITH_SHA224
 },
 NidUTInput {
  NID_dsa_with_SHA256, so::nid::Nid::DSA_WITH_SHA256
 },
 NidUTInput {
  NID_hold_instruction_code, so::nid::Nid::HOLD_INSTRUCTION_CODE
 },
 NidUTInput {
  NID_hold_instruction_none, so::nid::Nid::HOLD_INSTRUCTION_NONE
 },
 NidUTInput {
  NID_hold_instruction_call_issuer, so::nid::Nid::HOLD_INSTRUCTION_CALL_ISSUER
 },
 NidUTInput {
  NID_hold_instruction_reject, so::nid::Nid::HOLD_INSTRUCTION_REJECT
 },
 NidUTInput {
  NID_data, so::nid::Nid::DATA
 },
 NidUTInput {
  NID_pss, so::nid::Nid::PSS
 },
 NidUTInput {
  NID_ucl, so::nid::Nid::UCL
 },
 NidUTInput {
  NID_pilot, so::nid::Nid::PILOT
 },
 NidUTInput {
  NID_pilotAttributeType, so::nid::Nid::PILOTATTRIBUTETYPE
 },
 NidUTInput {
  NID_pilotAttributeSyntax, so::nid::Nid::PILOTATTRIBUTESYNTAX
 },
 NidUTInput {
  NID_pilotObjectClass, so::nid::Nid::PILOTOBJECTCLASS
 },
 NidUTInput {
  NID_pilotGroups, so::nid::Nid::PILOTGROUPS
 },
 NidUTInput {
  NID_iA5StringSyntax, so::nid::Nid::IA5STRINGSYNTAX
 },
 NidUTInput {
  NID_caseIgnoreIA5StringSyntax, so::nid::Nid::CASEIGNOREIA5STRINGSYNTAX
 },
 NidUTInput {
  NID_pilotObject, so::nid::Nid::PILOTOBJECT
 },
 NidUTInput {
  NID_pilotPerson, so::nid::Nid::PILOTPERSON
 },
 NidUTInput {
  NID_account, so::nid::Nid::ACCOUNT
 },
 NidUTInput {
  NID_document, so::nid::Nid::DOCUMENT
 },
 NidUTInput {
  NID_room, so::nid::Nid::ROOM
 },
 NidUTInput {
  NID_documentSeries, so::nid::Nid::DOCUMENTSERIES
 },
 NidUTInput {
  NID_Domain, so::nid::Nid::DOMAIN
 },
 NidUTInput {
  NID_rFC822localPart, so::nid::Nid::RFC822LOCALPART
 },
 NidUTInput {
  NID_dNSDomain, so::nid::Nid::DNSDOMAIN
 },
 NidUTInput {
  NID_domainRelatedObject, so::nid::Nid::DOMAINRELATEDOBJECT
 },
 NidUTInput {
  NID_friendlyCountry, so::nid::Nid::FRIENDLYCOUNTRY
 },
 NidUTInput {
  NID_simpleSecurityObject, so::nid::Nid::SIMPLESECURITYOBJECT
 },
 NidUTInput {
  NID_pilotOrganization, so::nid::Nid::PILOTORGANIZATION
 },
 NidUTInput {
  NID_pilotDSA, so::nid::Nid::PILOTDSA
 },
 NidUTInput {
  NID_qualityLabelledData, so::nid::Nid::QUALITYLABELLEDDATA
 },
 NidUTInput {
  NID_userId, so::nid::Nid::USERID
 },
 NidUTInput {
  NID_textEncodedORAddress, so::nid::Nid::TEXTENCODEDORADDRESS
 },
 NidUTInput {
  NID_rfc822Mailbox, so::nid::Nid::RFC822MAILBOX
 },
 NidUTInput {
  NID_info, so::nid::Nid::INFO
 },
 NidUTInput {
  NID_favouriteDrink, so::nid::Nid::FAVOURITEDRINK
 },
 NidUTInput {
  NID_roomNumber, so::nid::Nid::ROOMNUMBER
 },
 NidUTInput {
  NID_photo, so::nid::Nid::PHOTO
 },
 NidUTInput {
  NID_userClass, so::nid::Nid::USERCLASS
 },
 NidUTInput {
  NID_host, so::nid::Nid::HOST
 },
 NidUTInput {
  NID_manager, so::nid::Nid::MANAGER
 },
 NidUTInput {
  NID_documentIdentifier, so::nid::Nid::DOCUMENTIDENTIFIER
 },
 NidUTInput {
  NID_documentTitle, so::nid::Nid::DOCUMENTTITLE
 },
 NidUTInput {
  NID_documentVersion, so::nid::Nid::DOCUMENTVERSION
 },
 NidUTInput {
  NID_documentAuthor, so::nid::Nid::DOCUMENTAUTHOR
 },
 NidUTInput {
  NID_documentLocation, so::nid::Nid::DOCUMENTLOCATION
 },
 NidUTInput {
  NID_homeTelephoneNumber, so::nid::Nid::HOMETELEPHONENUMBER
 },
 NidUTInput {
  NID_secretary, so::nid::Nid::SECRETARY
 },
 NidUTInput {
  NID_otherMailbox, so::nid::Nid::OTHERMAILBOX
 },
 NidUTInput {
  NID_lastModifiedTime, so::nid::Nid::LASTMODIFIEDTIME
 },
 NidUTInput {
  NID_lastModifiedBy, so::nid::Nid::LASTMODIFIEDBY
 },
 NidUTInput {
  NID_domainComponent, so::nid::Nid::DOMAINCOMPONENT
 },
 NidUTInput {
  NID_aRecord, so::nid::Nid::ARECORD
 },
 NidUTInput {
  NID_pilotAttributeType27, so::nid::Nid::PILOTATTRIBUTETYPE27
 },
 NidUTInput {
  NID_mXRecord, so::nid::Nid::MXRECORD
 },
 NidUTInput {
  NID_nSRecord, so::nid::Nid::NSRECORD
 },
 NidUTInput {
  NID_sOARecord, so::nid::Nid::SOARECORD
 },
 NidUTInput {
  NID_cNAMERecord, so::nid::Nid::CNAMERECORD
 },
 NidUTInput {
  NID_associatedDomain, so::nid::Nid::ASSOCIATEDDOMAIN
 },
 NidUTInput {
  NID_associatedName, so::nid::Nid::ASSOCIATEDNAME
 },
 NidUTInput {
  NID_homePostalAddress, so::nid::Nid::HOMEPOSTALADDRESS
 },
 NidUTInput {
  NID_personalTitle, so::nid::Nid::PERSONALTITLE
 },
 NidUTInput {
  NID_mobileTelephoneNumber, so::nid::Nid::MOBILETELEPHONENUMBER
 },
 NidUTInput {
  NID_pagerTelephoneNumber, so::nid::Nid::PAGERTELEPHONENUMBER
 },
 NidUTInput {
  NID_friendlyCountryName, so::nid::Nid::FRIENDLYCOUNTRYNAME
 },
 NidUTInput {
  NID_uniqueIdentifier, so::nid::Nid::UNIQUEIDENTIFIER
 },
 NidUTInput {
  NID_organizationalStatus, so::nid::Nid::ORGANIZATIONALSTATUS
 },
 NidUTInput {
  NID_janetMailbox, so::nid::Nid::JANETMAILBOX
 },
 NidUTInput {
  NID_mailPreferenceOption, so::nid::Nid::MAILPREFERENCEOPTION
 },
 NidUTInput {
  NID_buildingName, so::nid::Nid::BUILDINGNAME
 },
 NidUTInput {
  NID_dSAQuality, so::nid::Nid::DSAQUALITY
 },
 NidUTInput {
  NID_singleLevelQuality, so::nid::Nid::SINGLELEVELQUALITY
 },
 NidUTInput {
  NID_subtreeMinimumQuality, so::nid::Nid::SUBTREEMINIMUMQUALITY
 },
 NidUTInput {
  NID_subtreeMaximumQuality, so::nid::Nid::SUBTREEMAXIMUMQUALITY
 },
 NidUTInput {
  NID_personalSignature, so::nid::Nid::PERSONALSIGNATURE
 },
 NidUTInput {
  NID_dITRedirect, so::nid::Nid::DITREDIRECT
 },
 NidUTInput {
  NID_audio, so::nid::Nid::AUDIO
 },
 NidUTInput {
  NID_documentPublisher, so::nid::Nid::DOCUMENTPUBLISHER
 },
 NidUTInput {
  NID_id_set, so::nid::Nid::ID_SET
 },
 NidUTInput {
  NID_set_ctype, so::nid::Nid::SET_CTYPE
 },
 NidUTInput {
  NID_set_msgExt, so::nid::Nid::SET_MSGEXT
 },
 NidUTInput {
  NID_set_attr, so::nid::Nid::SET_ATTR
 },
 NidUTInput {
  NID_set_policy, so::nid::Nid::SET_POLICY
 },
 NidUTInput {
  NID_set_certExt, so::nid::Nid::SET_CERTEXT
 },
 NidUTInput {
  NID_set_brand, so::nid::Nid::SET_BRAND
 },
 NidUTInput {
  NID_setct_PANData, so::nid::Nid::SETCT_PANDATA
 },
 NidUTInput {
  NID_setct_PANToken, so::nid::Nid::SETCT_PANTOKEN
 },
 NidUTInput {
  NID_setct_PANOnly, so::nid::Nid::SETCT_PANONLY
 },
 NidUTInput {
  NID_setct_OIData, so::nid::Nid::SETCT_OIDATA
 },
 NidUTInput {
  NID_setct_PI, so::nid::Nid::SETCT_PI
 },
 NidUTInput {
  NID_setct_PIData, so::nid::Nid::SETCT_PIDATA
 },
 NidUTInput {
  NID_setct_PIDataUnsigned, so::nid::Nid::SETCT_PIDATAUNSIGNED
 },
 NidUTInput {
  NID_setct_HODInput, so::nid::Nid::SETCT_HODINPUT
 },
 NidUTInput {
  NID_setct_AuthResBaggage, so::nid::Nid::SETCT_AUTHRESBAGGAGE
 },
 NidUTInput {
  NID_setct_AuthRevReqBaggage, so::nid::Nid::SETCT_AUTHREVREQBAGGAGE
 },
 NidUTInput {
  NID_setct_AuthRevResBaggage, so::nid::Nid::SETCT_AUTHREVRESBAGGAGE
 },
 NidUTInput {
  NID_setct_CapTokenSeq, so::nid::Nid::SETCT_CAPTOKENSEQ
 },
 NidUTInput {
  NID_setct_PInitResData, so::nid::Nid::SETCT_PINITRESDATA
 },
 NidUTInput {
  NID_setct_PI_TBS, so::nid::Nid::SETCT_PI_TBS
 },
 NidUTInput {
  NID_setct_PResData, so::nid::Nid::SETCT_PRESDATA
 },
 NidUTInput {
  NID_setct_AuthReqTBS, so::nid::Nid::SETCT_AUTHREQTBS
 },
 NidUTInput {
  NID_setct_AuthResTBS, so::nid::Nid::SETCT_AUTHRESTBS
 },
 NidUTInput {
  NID_setct_AuthResTBSX, so::nid::Nid::SETCT_AUTHRESTBSX
 },
 NidUTInput {
  NID_setct_AuthTokenTBS, so::nid::Nid::SETCT_AUTHTOKENTBS
 },
 NidUTInput {
  NID_setct_CapTokenData, so::nid::Nid::SETCT_CAPTOKENDATA
 },
 NidUTInput {
  NID_setct_CapTokenTBS, so::nid::Nid::SETCT_CAPTOKENTBS
 },
 NidUTInput {
  NID_setct_AcqCardCodeMsg, so::nid::Nid::SETCT_ACQCARDCODEMSG
 },
 NidUTInput {
  NID_setct_AuthRevReqTBS, so::nid::Nid::SETCT_AUTHREVREQTBS
 },
 NidUTInput {
  NID_setct_AuthRevResData, so::nid::Nid::SETCT_AUTHREVRESDATA
 },
 NidUTInput {
  NID_setct_AuthRevResTBS, so::nid::Nid::SETCT_AUTHREVRESTBS
 },
 NidUTInput {
  NID_setct_CapReqTBS, so::nid::Nid::SETCT_CAPREQTBS
 },
 NidUTInput {
  NID_setct_CapReqTBSX, so::nid::Nid::SETCT_CAPREQTBSX
 },
 NidUTInput {
  NID_setct_CapResData, so::nid::Nid::SETCT_CAPRESDATA
 },
 NidUTInput {
  NID_setct_CapRevReqTBS, so::nid::Nid::SETCT_CAPREVREQTBS
 },
 NidUTInput {
  NID_setct_CapRevReqTBSX, so::nid::Nid::SETCT_CAPREVREQTBSX
 },
 NidUTInput {
  NID_setct_CapRevResData, so::nid::Nid::SETCT_CAPREVRESDATA
 },
 NidUTInput {
  NID_setct_CredReqTBS, so::nid::Nid::SETCT_CREDREQTBS
 },
 NidUTInput {
  NID_setct_CredReqTBSX, so::nid::Nid::SETCT_CREDREQTBSX
 },
 NidUTInput {
  NID_setct_CredResData, so::nid::Nid::SETCT_CREDRESDATA
 },
 NidUTInput {
  NID_setct_CredRevReqTBS, so::nid::Nid::SETCT_CREDREVREQTBS
 },
 NidUTInput {
  NID_setct_CredRevReqTBSX, so::nid::Nid::SETCT_CREDREVREQTBSX
 },
 NidUTInput {
  NID_setct_CredRevResData, so::nid::Nid::SETCT_CREDREVRESDATA
 },
 NidUTInput {
  NID_setct_PCertReqData, so::nid::Nid::SETCT_PCERTREQDATA
 },
 NidUTInput {
  NID_setct_PCertResTBS, so::nid::Nid::SETCT_PCERTRESTBS
 },
 NidUTInput {
  NID_setct_BatchAdminReqData, so::nid::Nid::SETCT_BATCHADMINREQDATA
 },
 NidUTInput {
  NID_setct_BatchAdminResData, so::nid::Nid::SETCT_BATCHADMINRESDATA
 },
 NidUTInput {
  NID_setct_CardCInitResTBS, so::nid::Nid::SETCT_CARDCINITRESTBS
 },
 NidUTInput {
  NID_setct_MeAqCInitResTBS, so::nid::Nid::SETCT_MEAQCINITRESTBS
 },
 NidUTInput {
  NID_setct_RegFormResTBS, so::nid::Nid::SETCT_REGFORMRESTBS
 },
 NidUTInput {
  NID_setct_CertReqData, so::nid::Nid::SETCT_CERTREQDATA
 },
 NidUTInput {
  NID_setct_CertReqTBS, so::nid::Nid::SETCT_CERTREQTBS
 },
 NidUTInput {
  NID_setct_CertResData, so::nid::Nid::SETCT_CERTRESDATA
 },
 NidUTInput {
  NID_setct_CertInqReqTBS, so::nid::Nid::SETCT_CERTINQREQTBS
 },
 NidUTInput {
  NID_setct_ErrorTBS, so::nid::Nid::SETCT_ERRORTBS
 },
 NidUTInput {
  NID_setct_PIDualSignedTBE, so::nid::Nid::SETCT_PIDUALSIGNEDTBE
 },
 NidUTInput {
  NID_setct_PIUnsignedTBE, so::nid::Nid::SETCT_PIUNSIGNEDTBE
 },
 NidUTInput {
  NID_setct_AuthReqTBE, so::nid::Nid::SETCT_AUTHREQTBE
 },
 NidUTInput {
  NID_setct_AuthResTBE, so::nid::Nid::SETCT_AUTHRESTBE
 },
 NidUTInput {
  NID_setct_AuthResTBEX, so::nid::Nid::SETCT_AUTHRESTBEX
 },
 NidUTInput {
  NID_setct_AuthTokenTBE, so::nid::Nid::SETCT_AUTHTOKENTBE
 },
 NidUTInput {
  NID_setct_CapTokenTBE, so::nid::Nid::SETCT_CAPTOKENTBE
 },
 NidUTInput {
  NID_setct_CapTokenTBEX, so::nid::Nid::SETCT_CAPTOKENTBEX
 },
 NidUTInput {
  NID_setct_AcqCardCodeMsgTBE, so::nid::Nid::SETCT_ACQCARDCODEMSGTBE
 },
 NidUTInput {
  NID_setct_AuthRevReqTBE, so::nid::Nid::SETCT_AUTHREVREQTBE
 },
 NidUTInput {
  NID_setct_AuthRevResTBE, so::nid::Nid::SETCT_AUTHREVRESTBE
 },
 NidUTInput {
  NID_setct_AuthRevResTBEB, so::nid::Nid::SETCT_AUTHREVRESTBEB
 },
 NidUTInput {
  NID_setct_CapReqTBE, so::nid::Nid::SETCT_CAPREQTBE
 },
 NidUTInput {
  NID_setct_CapReqTBEX, so::nid::Nid::SETCT_CAPREQTBEX
 },
 NidUTInput {
  NID_setct_CapResTBE, so::nid::Nid::SETCT_CAPRESTBE
 },
 NidUTInput {
  NID_setct_CapRevReqTBE, so::nid::Nid::SETCT_CAPREVREQTBE
 },
 NidUTInput {
  NID_setct_CapRevReqTBEX, so::nid::Nid::SETCT_CAPREVREQTBEX
 },
 NidUTInput {
  NID_setct_CapRevResTBE, so::nid::Nid::SETCT_CAPREVRESTBE
 },
 NidUTInput {
  NID_setct_CredReqTBE, so::nid::Nid::SETCT_CREDREQTBE
 },
 NidUTInput {
  NID_setct_CredReqTBEX, so::nid::Nid::SETCT_CREDREQTBEX
 },
 NidUTInput {
  NID_setct_CredResTBE, so::nid::Nid::SETCT_CREDRESTBE
 },
 NidUTInput {
  NID_setct_CredRevReqTBE, so::nid::Nid::SETCT_CREDREVREQTBE
 },
 NidUTInput {
  NID_setct_CredRevReqTBEX, so::nid::Nid::SETCT_CREDREVREQTBEX
 },
 NidUTInput {
  NID_setct_CredRevResTBE, so::nid::Nid::SETCT_CREDREVRESTBE
 },
 NidUTInput {
  NID_setct_BatchAdminReqTBE, so::nid::Nid::SETCT_BATCHADMINREQTBE
 },
 NidUTInput {
  NID_setct_BatchAdminResTBE, so::nid::Nid::SETCT_BATCHADMINRESTBE
 },
 NidUTInput {
  NID_setct_RegFormReqTBE, so::nid::Nid::SETCT_REGFORMREQTBE
 },
 NidUTInput {
  NID_setct_CertReqTBE, so::nid::Nid::SETCT_CERTREQTBE
 },
 NidUTInput {
  NID_setct_CertReqTBEX, so::nid::Nid::SETCT_CERTREQTBEX
 },
 NidUTInput {
  NID_setct_CertResTBE, so::nid::Nid::SETCT_CERTRESTBE
 },
 NidUTInput {
  NID_setct_CRLNotificationTBS, so::nid::Nid::SETCT_CRLNOTIFICATIONTBS
 },
 NidUTInput {
  NID_setct_CRLNotificationResTBS, so::nid::Nid::SETCT_CRLNOTIFICATIONRESTBS
 },
 NidUTInput {
  NID_setct_BCIDistributionTBS, so::nid::Nid::SETCT_BCIDISTRIBUTIONTBS
 },
 NidUTInput {
  NID_setext_genCrypt, so::nid::Nid::SETEXT_GENCRYPT
 },
 NidUTInput {
  NID_setext_miAuth, so::nid::Nid::SETEXT_MIAUTH
 },
 NidUTInput {
  NID_setext_pinSecure, so::nid::Nid::SETEXT_PINSECURE
 },
 NidUTInput {
  NID_setext_pinAny, so::nid::Nid::SETEXT_PINANY
 },
 NidUTInput {
  NID_setext_track2, so::nid::Nid::SETEXT_TRACK2
 },
 NidUTInput {
  NID_setext_cv, so::nid::Nid::SETEXT_CV
 },
 NidUTInput {
  NID_set_policy_root, so::nid::Nid::SET_POLICY_ROOT
 },
 NidUTInput {
  NID_setCext_hashedRoot, so::nid::Nid::SETCEXT_HASHEDROOT
 },
 NidUTInput {
  NID_setCext_certType, so::nid::Nid::SETCEXT_CERTTYPE
 },
 NidUTInput {
  NID_setCext_merchData, so::nid::Nid::SETCEXT_MERCHDATA
 },
 NidUTInput {
  NID_setCext_cCertRequired, so::nid::Nid::SETCEXT_CCERTREQUIRED
 },
 NidUTInput {
  NID_setCext_tunneling, so::nid::Nid::SETCEXT_TUNNELING
 },
 NidUTInput {
  NID_setCext_setExt, so::nid::Nid::SETCEXT_SETEXT
 },
 NidUTInput {
  NID_setCext_setQualf, so::nid::Nid::SETCEXT_SETQUALF
 },
 NidUTInput {
  NID_setCext_PGWYcapabilities, so::nid::Nid::SETCEXT_PGWYCAPABILITIES
 },
 NidUTInput {
  NID_setCext_TokenIdentifier, so::nid::Nid::SETCEXT_TOKENIDENTIFIER
 },
 NidUTInput {
  NID_setCext_Track2Data, so::nid::Nid::SETCEXT_TRACK2DATA
 },
 NidUTInput {
  NID_setCext_TokenType, so::nid::Nid::SETCEXT_TOKENTYPE
 },
 NidUTInput {
  NID_setCext_IssuerCapabilities, so::nid::Nid::SETCEXT_ISSUERCAPABILITIES
 },
 NidUTInput {
  NID_setAttr_Cert, so::nid::Nid::SETATTR_CERT
 },
 NidUTInput {
  NID_setAttr_PGWYcap, so::nid::Nid::SETATTR_PGWYCAP
 },
 NidUTInput {
  NID_setAttr_TokenType, so::nid::Nid::SETATTR_TOKENTYPE
 },
 NidUTInput {
  NID_setAttr_IssCap, so::nid::Nid::SETATTR_ISSCAP
 },
 NidUTInput {
  NID_set_rootKeyThumb, so::nid::Nid::SET_ROOTKEYTHUMB
 },
 NidUTInput {
  NID_set_addPolicy, so::nid::Nid::SET_ADDPOLICY
 },
 NidUTInput {
  NID_setAttr_Token_EMV, so::nid::Nid::SETATTR_TOKEN_EMV
 },
 NidUTInput {
  NID_setAttr_Token_B0Prime, so::nid::Nid::SETATTR_TOKEN_B0PRIME
 },
 NidUTInput {
  NID_setAttr_IssCap_CVM, so::nid::Nid::SETATTR_ISSCAP_CVM
 },
 NidUTInput {
  NID_setAttr_IssCap_T2, so::nid::Nid::SETATTR_ISSCAP_T2
 },
 NidUTInput {
  NID_setAttr_IssCap_Sig, so::nid::Nid::SETATTR_ISSCAP_SIG
 },
 NidUTInput {
  NID_setAttr_GenCryptgrm, so::nid::Nid::SETATTR_GENCRYPTGRM
 },
 NidUTInput {
  NID_setAttr_T2Enc, so::nid::Nid::SETATTR_T2ENC
 },
 NidUTInput {
  NID_setAttr_T2cleartxt, so::nid::Nid::SETATTR_T2CLEARTXT
 },
 NidUTInput {
  NID_setAttr_TokICCsig, so::nid::Nid::SETATTR_TOKICCSIG
 },
 NidUTInput {
  NID_setAttr_SecDevSig, so::nid::Nid::SETATTR_SECDEVSIG
 },
 NidUTInput {
  NID_set_brand_IATA_ATA, so::nid::Nid::SET_BRAND_IATA_ATA
 },
 NidUTInput {
  NID_set_brand_Diners, so::nid::Nid::SET_BRAND_DINERS
 },
 NidUTInput {
  NID_set_brand_AmericanExpress, so::nid::Nid::SET_BRAND_AMERICANEXPRESS
 },
 NidUTInput {
  NID_set_brand_JCB, so::nid::Nid::SET_BRAND_JCB
 },
 NidUTInput {
  NID_set_brand_Visa, so::nid::Nid::SET_BRAND_VISA
 },
 NidUTInput {
  NID_set_brand_MasterCard, so::nid::Nid::SET_BRAND_MASTERCARD
 },
 NidUTInput {
  NID_set_brand_Novus, so::nid::Nid::SET_BRAND_NOVUS
 },
 NidUTInput {
  NID_des_cdmf, so::nid::Nid::DES_CDMF
 },
 NidUTInput {
  NID_rsaOAEPEncryptionSET, so::nid::Nid::RSAOAEPENCRYPTIONSET
 },
 NidUTInput {
  NID_ipsec3, so::nid::Nid::IPSEC3
 },
 NidUTInput {
  NID_ipsec4, so::nid::Nid::IPSEC4
 },
 NidUTInput {
  NID_whirlpool, so::nid::Nid::WHIRLPOOL
 },
 NidUTInput {
  NID_cryptopro, so::nid::Nid::CRYPTOPRO
 },
 NidUTInput {
  NID_cryptocom, so::nid::Nid::CRYPTOCOM
 },
 NidUTInput {
  NID_id_tc26, so::nid::Nid::ID_TC26
 },
 NidUTInput {
  NID_id_GostR3411_94_with_GostR3410_2001, so::nid::Nid::ID_GOSTR3411_94_WITH_GOSTR3410_2001
 },
 NidUTInput {
  NID_id_GostR3411_94_with_GostR3410_94, so::nid::Nid::ID_GOSTR3411_94_WITH_GOSTR3410_94
 },
 NidUTInput {
  NID_id_GostR3411_94, so::nid::Nid::ID_GOSTR3411_94
 },
 NidUTInput {
  NID_id_HMACGostR3411_94, so::nid::Nid::ID_HMACGOSTR3411_94
 },
 NidUTInput {
  NID_id_GostR3410_2001, so::nid::Nid::ID_GOSTR3410_2001
 },
 NidUTInput {
  NID_id_GostR3410_94, so::nid::Nid::ID_GOSTR3410_94
 },
 NidUTInput {
  NID_id_Gost28147_89, so::nid::Nid::ID_GOST28147_89
 },
 NidUTInput {
  NID_gost89_cnt, so::nid::Nid::GOST89_CNT
 },
 NidUTInput {
  NID_gost89_cnt_12, so::nid::Nid::GOST89_CNT_12
 },
 NidUTInput {
  NID_gost89_cbc, so::nid::Nid::GOST89_CBC
 },
 NidUTInput {
  NID_gost89_ecb, so::nid::Nid::GOST89_ECB
 },
 NidUTInput {
  NID_gost89_ctr, so::nid::Nid::GOST89_CTR
 },
 NidUTInput {
  NID_id_Gost28147_89_MAC, so::nid::Nid::ID_GOST28147_89_MAC
 },
 NidUTInput {
  NID_gost_mac_12, so::nid::Nid::GOST_MAC_12
 },
 NidUTInput {
  NID_id_GostR3411_94_prf, so::nid::Nid::ID_GOSTR3411_94_PRF
 },
 NidUTInput {
  NID_id_GostR3410_2001DH, so::nid::Nid::ID_GOSTR3410_2001DH
 },
 NidUTInput {
  NID_id_GostR3410_94DH, so::nid::Nid::ID_GOSTR3410_94DH
 },
 NidUTInput {
  NID_id_Gost28147_89_CryptoPro_KeyMeshing, so::nid::Nid::ID_GOST28147_89_CRYPTOPRO_KEYMESHING
 },
 NidUTInput {
  NID_id_Gost28147_89_None_KeyMeshing, so::nid::Nid::ID_GOST28147_89_NONE_KEYMESHING
 },
 NidUTInput {
  NID_id_GostR3411_94_TestParamSet, so::nid::Nid::ID_GOSTR3411_94_TESTPARAMSET
 },
 NidUTInput {
  NID_id_GostR3411_94_CryptoProParamSet, so::nid::Nid::ID_GOSTR3411_94_CRYPTOPROPARAMSET
 },
 NidUTInput {
  NID_id_Gost28147_89_TestParamSet, so::nid::Nid::ID_GOST28147_89_TESTPARAMSET
 },
 NidUTInput {
  NID_id_Gost28147_89_CryptoPro_A_ParamSet, so::nid::Nid::ID_GOST28147_89_CRYPTOPRO_A_PARAMSET
 },
 NidUTInput {
  NID_id_Gost28147_89_CryptoPro_B_ParamSet, so::nid::Nid::ID_GOST28147_89_CRYPTOPRO_B_PARAMSET
 },
 NidUTInput {
  NID_id_Gost28147_89_CryptoPro_C_ParamSet, so::nid::Nid::ID_GOST28147_89_CRYPTOPRO_C_PARAMSET
 },
 NidUTInput {
  NID_id_Gost28147_89_CryptoPro_D_ParamSet, so::nid::Nid::ID_GOST28147_89_CRYPTOPRO_D_PARAMSET
 },
 NidUTInput {
  NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet, so::nid::Nid::ID_GOST28147_89_CRYPTOPRO_OSCAR_1_1_PARAMSET
 },
 NidUTInput {
  NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet, so::nid::Nid::ID_GOST28147_89_CRYPTOPRO_OSCAR_1_0_PARAMSET
 },
 NidUTInput {
  NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet, so::nid::Nid::ID_GOST28147_89_CRYPTOPRO_RIC_1_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_94_TestParamSet, so::nid::Nid::ID_GOSTR3410_94_TESTPARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_94_CryptoPro_A_ParamSet, so::nid::Nid::ID_GOSTR3410_94_CRYPTOPRO_A_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_94_CryptoPro_B_ParamSet, so::nid::Nid::ID_GOSTR3410_94_CRYPTOPRO_B_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_94_CryptoPro_C_ParamSet, so::nid::Nid::ID_GOSTR3410_94_CRYPTOPRO_C_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_94_CryptoPro_D_ParamSet, so::nid::Nid::ID_GOSTR3410_94_CRYPTOPRO_D_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_94_CryptoPro_XchA_ParamSet, so::nid::Nid::ID_GOSTR3410_94_CRYPTOPRO_XCHA_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_94_CryptoPro_XchB_ParamSet, so::nid::Nid::ID_GOSTR3410_94_CRYPTOPRO_XCHB_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_94_CryptoPro_XchC_ParamSet, so::nid::Nid::ID_GOSTR3410_94_CRYPTOPRO_XCHC_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_2001_TestParamSet, so::nid::Nid::ID_GOSTR3410_2001_TESTPARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_2001_CryptoPro_A_ParamSet, so::nid::Nid::ID_GOSTR3410_2001_CRYPTOPRO_A_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_2001_CryptoPro_B_ParamSet, so::nid::Nid::ID_GOSTR3410_2001_CRYPTOPRO_B_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_2001_CryptoPro_C_ParamSet, so::nid::Nid::ID_GOSTR3410_2001_CRYPTOPRO_C_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet, so::nid::Nid::ID_GOSTR3410_2001_CRYPTOPRO_XCHA_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet, so::nid::Nid::ID_GOSTR3410_2001_CRYPTOPRO_XCHB_PARAMSET
 },
 NidUTInput {
  NID_id_GostR3410_94_a, so::nid::Nid::ID_GOSTR3410_94_A
 },
 NidUTInput {
  NID_id_GostR3410_94_aBis, so::nid::Nid::ID_GOSTR3410_94_ABIS
 },
 NidUTInput {
  NID_id_GostR3410_94_b, so::nid::Nid::ID_GOSTR3410_94_B
 },
 NidUTInput {
  NID_id_GostR3410_94_bBis, so::nid::Nid::ID_GOSTR3410_94_BBIS
 },
 NidUTInput {
  NID_id_Gost28147_89_cc, so::nid::Nid::ID_GOST28147_89_CC
 },
 NidUTInput {
  NID_id_GostR3410_94_cc, so::nid::Nid::ID_GOSTR3410_94_CC
 },
 NidUTInput {
  NID_id_GostR3410_2001_cc, so::nid::Nid::ID_GOSTR3410_2001_CC
 },
 NidUTInput {
  NID_id_GostR3411_94_with_GostR3410_94_cc, so::nid::Nid::ID_GOSTR3411_94_WITH_GOSTR3410_94_CC
 },
 NidUTInput {
  NID_id_GostR3411_94_with_GostR3410_2001_cc, so::nid::Nid::ID_GOSTR3411_94_WITH_GOSTR3410_2001_CC
 },
 NidUTInput {
  NID_id_GostR3410_2001_ParamSet_cc, so::nid::Nid::ID_GOSTR3410_2001_PARAMSET_CC
 },
 NidUTInput {
  NID_id_tc26_algorithms, so::nid::Nid::ID_TC26_ALGORITHMS
 },
 NidUTInput {
  NID_id_tc26_sign, so::nid::Nid::ID_TC26_SIGN
 },
 NidUTInput {
  NID_id_GostR3410_2012_256, so::nid::Nid::ID_GOSTR3410_2012_256
 },
 NidUTInput {
  NID_id_GostR3410_2012_512, so::nid::Nid::ID_GOSTR3410_2012_512
 },
 NidUTInput {
  NID_id_tc26_digest, so::nid::Nid::ID_TC26_DIGEST
 },
 NidUTInput {
  NID_id_GostR3411_2012_256, so::nid::Nid::ID_GOSTR3411_2012_256
 },
 NidUTInput {
  NID_id_GostR3411_2012_512, so::nid::Nid::ID_GOSTR3411_2012_512
 },
 NidUTInput {
  NID_id_tc26_signwithdigest, so::nid::Nid::ID_TC26_SIGNWITHDIGEST
 },
 NidUTInput {
  NID_id_tc26_signwithdigest_gost3410_2012_256, so::nid::Nid::ID_TC26_SIGNWITHDIGEST_GOST3410_2012_256
 },
 NidUTInput {
  NID_id_tc26_signwithdigest_gost3410_2012_512, so::nid::Nid::ID_TC26_SIGNWITHDIGEST_GOST3410_2012_512
 },
 NidUTInput {
  NID_id_tc26_mac, so::nid::Nid::ID_TC26_MAC
 },
 NidUTInput {
  NID_id_tc26_hmac_gost_3411_2012_256, so::nid::Nid::ID_TC26_HMAC_GOST_3411_2012_256
 },
 NidUTInput {
  NID_id_tc26_hmac_gost_3411_2012_512, so::nid::Nid::ID_TC26_HMAC_GOST_3411_2012_512
 },
 NidUTInput {
  NID_id_tc26_cipher, so::nid::Nid::ID_TC26_CIPHER
 },
 NidUTInput {
  NID_id_tc26_agreement, so::nid::Nid::ID_TC26_AGREEMENT
 },
 NidUTInput {
  NID_id_tc26_agreement_gost_3410_2012_256, so::nid::Nid::ID_TC26_AGREEMENT_GOST_3410_2012_256
 },
 NidUTInput {
  NID_id_tc26_agreement_gost_3410_2012_512, so::nid::Nid::ID_TC26_AGREEMENT_GOST_3410_2012_512
 },
 NidUTInput {
  NID_id_tc26_constants, so::nid::Nid::ID_TC26_CONSTANTS
 },
 NidUTInput {
  NID_id_tc26_sign_constants, so::nid::Nid::ID_TC26_SIGN_CONSTANTS
 },
 NidUTInput {
  NID_id_tc26_gost_3410_2012_512_constants, so::nid::Nid::ID_TC26_GOST_3410_2012_512_CONSTANTS
 },
 NidUTInput {
  NID_id_tc26_gost_3410_2012_512_paramSetTest, so::nid::Nid::ID_TC26_GOST_3410_2012_512_PARAMSETTEST
 },
 NidUTInput {
  NID_id_tc26_gost_3410_2012_512_paramSetA, so::nid::Nid::ID_TC26_GOST_3410_2012_512_PARAMSETA
 },
 NidUTInput {
  NID_id_tc26_gost_3410_2012_512_paramSetB, so::nid::Nid::ID_TC26_GOST_3410_2012_512_PARAMSETB
 },
 NidUTInput {
  NID_id_tc26_digest_constants, so::nid::Nid::ID_TC26_DIGEST_CONSTANTS
 },
 NidUTInput {
  NID_id_tc26_cipher_constants, so::nid::Nid::ID_TC26_CIPHER_CONSTANTS
 },
 NidUTInput {
  NID_id_tc26_gost_28147_constants, so::nid::Nid::ID_TC26_GOST_28147_CONSTANTS
 },
 NidUTInput {
  NID_id_tc26_gost_28147_param_Z, so::nid::Nid::ID_TC26_GOST_28147_PARAM_Z
 },
 NidUTInput {
  NID_INN, so::nid::Nid::INN
 },
 NidUTInput {
  NID_OGRN, so::nid::Nid::OGRN
 },
 NidUTInput {
  NID_SNILS, so::nid::Nid::SNILS
 },
 NidUTInput {
  NID_subjectSignTool, so::nid::Nid::SUBJECTSIGNTOOL
 },
 NidUTInput {
  NID_issuerSignTool, so::nid::Nid::ISSUERSIGNTOOL
 },
 NidUTInput {
  NID_grasshopper_ecb, so::nid::Nid::GRASSHOPPER_ECB
 },
 NidUTInput {
  NID_grasshopper_ctr, so::nid::Nid::GRASSHOPPER_CTR
 },
 NidUTInput {
  NID_grasshopper_ofb, so::nid::Nid::GRASSHOPPER_OFB
 },
 NidUTInput {
  NID_grasshopper_cbc, so::nid::Nid::GRASSHOPPER_CBC
 },
 NidUTInput {
  NID_grasshopper_cfb, so::nid::Nid::GRASSHOPPER_CFB
 },
 NidUTInput {
  NID_grasshopper_mac, so::nid::Nid::GRASSHOPPER_MAC
 },
 NidUTInput {
  NID_camellia_128_cbc, so::nid::Nid::CAMELLIA_128_CBC
 },
 NidUTInput {
  NID_camellia_192_cbc, so::nid::Nid::CAMELLIA_192_CBC
 },
 NidUTInput {
  NID_camellia_256_cbc, so::nid::Nid::CAMELLIA_256_CBC
 },
 NidUTInput {
  NID_id_camellia128_wrap, so::nid::Nid::ID_CAMELLIA128_WRAP
 },
 NidUTInput {
  NID_id_camellia192_wrap, so::nid::Nid::ID_CAMELLIA192_WRAP
 },
 NidUTInput {
  NID_id_camellia256_wrap, so::nid::Nid::ID_CAMELLIA256_WRAP
 },
 NidUTInput {
  NID_camellia_128_ecb, so::nid::Nid::CAMELLIA_128_ECB
 },
 NidUTInput {
  NID_camellia_128_ofb128, so::nid::Nid::CAMELLIA_128_OFB128
 },
 NidUTInput {
  NID_camellia_128_cfb128, so::nid::Nid::CAMELLIA_128_CFB128
 },
 NidUTInput {
  NID_camellia_128_gcm, so::nid::Nid::CAMELLIA_128_GCM
 },
 NidUTInput {
  NID_camellia_128_ccm, so::nid::Nid::CAMELLIA_128_CCM
 },
 NidUTInput {
  NID_camellia_128_ctr, so::nid::Nid::CAMELLIA_128_CTR
 },
 NidUTInput {
  NID_camellia_128_cmac, so::nid::Nid::CAMELLIA_128_CMAC
 },
 NidUTInput {
  NID_camellia_192_ecb, so::nid::Nid::CAMELLIA_192_ECB
 },
 NidUTInput {
  NID_camellia_192_ofb128, so::nid::Nid::CAMELLIA_192_OFB128
 },
 NidUTInput {
  NID_camellia_192_cfb128, so::nid::Nid::CAMELLIA_192_CFB128
 },
 NidUTInput {
  NID_camellia_192_gcm, so::nid::Nid::CAMELLIA_192_GCM
 },
 NidUTInput {
  NID_camellia_192_ccm, so::nid::Nid::CAMELLIA_192_CCM
 },
 NidUTInput {
  NID_camellia_192_ctr, so::nid::Nid::CAMELLIA_192_CTR
 },
 NidUTInput {
  NID_camellia_192_cmac, so::nid::Nid::CAMELLIA_192_CMAC
 },
 NidUTInput {
  NID_camellia_256_ecb, so::nid::Nid::CAMELLIA_256_ECB
 },
 NidUTInput {
  NID_camellia_256_ofb128, so::nid::Nid::CAMELLIA_256_OFB128
 },
 NidUTInput {
  NID_camellia_256_cfb128, so::nid::Nid::CAMELLIA_256_CFB128
 },
 NidUTInput {
  NID_camellia_256_gcm, so::nid::Nid::CAMELLIA_256_GCM
 },
 NidUTInput {
  NID_camellia_256_ccm, so::nid::Nid::CAMELLIA_256_CCM
 },
 NidUTInput {
  NID_camellia_256_ctr, so::nid::Nid::CAMELLIA_256_CTR
 },
 NidUTInput {
  NID_camellia_256_cmac, so::nid::Nid::CAMELLIA_256_CMAC
 },
 NidUTInput {
  NID_camellia_128_cfb1, so::nid::Nid::CAMELLIA_128_CFB1
 },
 NidUTInput {
  NID_camellia_192_cfb1, so::nid::Nid::CAMELLIA_192_CFB1
 },
 NidUTInput {
  NID_camellia_256_cfb1, so::nid::Nid::CAMELLIA_256_CFB1
 },
 NidUTInput {
  NID_camellia_128_cfb8, so::nid::Nid::CAMELLIA_128_CFB8
 },
 NidUTInput {
  NID_camellia_192_cfb8, so::nid::Nid::CAMELLIA_192_CFB8
 },
 NidUTInput {
  NID_camellia_256_cfb8, so::nid::Nid::CAMELLIA_256_CFB8
 },
 NidUTInput {
  NID_kisa, so::nid::Nid::KISA
 },
 NidUTInput {
  NID_seed_ecb, so::nid::Nid::SEED_ECB
 },
 NidUTInput {
  NID_seed_cbc, so::nid::Nid::SEED_CBC
 },
 NidUTInput {
  NID_seed_cfb128, so::nid::Nid::SEED_CFB128
 },
 NidUTInput {
  NID_seed_ofb128, so::nid::Nid::SEED_OFB128
 },
 NidUTInput {
  NID_hmac, so::nid::Nid::HMAC
 },
 NidUTInput {
  NID_cmac, so::nid::Nid::CMAC
 },
 NidUTInput {
  NID_rc4_hmac_md5, so::nid::Nid::RC4_HMAC_MD5
 },
 NidUTInput {
  NID_aes_128_cbc_hmac_sha1, so::nid::Nid::AES_128_CBC_HMAC_SHA1
 },
 NidUTInput {
  NID_aes_192_cbc_hmac_sha1, so::nid::Nid::AES_192_CBC_HMAC_SHA1
 },
 NidUTInput {
  NID_aes_256_cbc_hmac_sha1, so::nid::Nid::AES_256_CBC_HMAC_SHA1
 },
 NidUTInput {
  NID_aes_128_cbc_hmac_sha256, so::nid::Nid::AES_128_CBC_HMAC_SHA256
 },
 NidUTInput {
  NID_aes_192_cbc_hmac_sha256, so::nid::Nid::AES_192_CBC_HMAC_SHA256
 },
 NidUTInput {
  NID_aes_256_cbc_hmac_sha256, so::nid::Nid::AES_256_CBC_HMAC_SHA256
 },
 NidUTInput {
  NID_chacha20_poly1305, so::nid::Nid::CHACHA20_POLY1305
 },
 NidUTInput {
  NID_chacha20, so::nid::Nid::CHACHA20
 },
 NidUTInput {
  NID_dhpublicnumber, so::nid::Nid::DHPUBLICNUMBER
 },
 NidUTInput {
  NID_brainpoolP160r1, so::nid::Nid::BRAINPOOLP160R1
 },
 NidUTInput {
  NID_brainpoolP160t1, so::nid::Nid::BRAINPOOLP160T1
 },
 NidUTInput {
  NID_brainpoolP192r1, so::nid::Nid::BRAINPOOLP192R1
 },
 NidUTInput {
  NID_brainpoolP192t1, so::nid::Nid::BRAINPOOLP192T1
 },
 NidUTInput {
  NID_brainpoolP224r1, so::nid::Nid::BRAINPOOLP224R1
 },
 NidUTInput {
  NID_brainpoolP224t1, so::nid::Nid::BRAINPOOLP224T1
 },
 NidUTInput {
  NID_brainpoolP256r1, so::nid::Nid::BRAINPOOLP256R1
 },
 NidUTInput {
  NID_brainpoolP256t1, so::nid::Nid::BRAINPOOLP256T1
 },
 NidUTInput {
  NID_brainpoolP320r1, so::nid::Nid::BRAINPOOLP320R1
 },
 NidUTInput {
  NID_brainpoolP320t1, so::nid::Nid::BRAINPOOLP320T1
 },
 NidUTInput {
  NID_brainpoolP384r1, so::nid::Nid::BRAINPOOLP384R1
 },
 NidUTInput {
  NID_brainpoolP384t1, so::nid::Nid::BRAINPOOLP384T1
 },
 NidUTInput {
  NID_brainpoolP512r1, so::nid::Nid::BRAINPOOLP512R1
 },
 NidUTInput {
  NID_brainpoolP512t1, so::nid::Nid::BRAINPOOLP512T1
 },
 NidUTInput {
  NID_dhSinglePass_stdDH_sha1kdf_scheme, so::nid::Nid::DHSINGLEPASS_STDDH_SHA1KDF_SCHEME
 },
 NidUTInput {
  NID_dhSinglePass_stdDH_sha224kdf_scheme, so::nid::Nid::DHSINGLEPASS_STDDH_SHA224KDF_SCHEME
 },
 NidUTInput {
  NID_dhSinglePass_stdDH_sha256kdf_scheme, so::nid::Nid::DHSINGLEPASS_STDDH_SHA256KDF_SCHEME
 },
 NidUTInput {
  NID_dhSinglePass_stdDH_sha384kdf_scheme, so::nid::Nid::DHSINGLEPASS_STDDH_SHA384KDF_SCHEME
 },
 NidUTInput {
  NID_dhSinglePass_stdDH_sha512kdf_scheme, so::nid::Nid::DHSINGLEPASS_STDDH_SHA512KDF_SCHEME
 },
 NidUTInput {
  NID_dhSinglePass_cofactorDH_sha1kdf_scheme, so::nid::Nid::DHSINGLEPASS_COFACTORDH_SHA1KDF_SCHEME
 },
 NidUTInput {
  NID_dhSinglePass_cofactorDH_sha224kdf_scheme, so::nid::Nid::DHSINGLEPASS_COFACTORDH_SHA224KDF_SCHEME
 },
 NidUTInput {
  NID_dhSinglePass_cofactorDH_sha256kdf_scheme, so::nid::Nid::DHSINGLEPASS_COFACTORDH_SHA256KDF_SCHEME
 },
 NidUTInput {
  NID_dhSinglePass_cofactorDH_sha384kdf_scheme, so::nid::Nid::DHSINGLEPASS_COFACTORDH_SHA384KDF_SCHEME
 },
 NidUTInput {
  NID_dhSinglePass_cofactorDH_sha512kdf_scheme, so::nid::Nid::DHSINGLEPASS_COFACTORDH_SHA512KDF_SCHEME
 },
 NidUTInput {
  NID_dh_std_kdf, so::nid::Nid::DH_STD_KDF
 },
 NidUTInput {
  NID_dh_cofactor_kdf, so::nid::Nid::DH_COFACTOR_KDF
 },
 NidUTInput {
  NID_ct_precert_scts, so::nid::Nid::CT_PRECERT_SCTS
 },
 NidUTInput {
  NID_ct_precert_poison, so::nid::Nid::CT_PRECERT_POISON
 },
 NidUTInput {
  NID_ct_precert_signer, so::nid::Nid::CT_PRECERT_SIGNER
 },
 NidUTInput {
  NID_ct_cert_scts, so::nid::Nid::CT_CERT_SCTS
 },
 NidUTInput {
  NID_jurisdictionLocalityName, so::nid::Nid::JURISDICTIONLOCALITYNAME
 },
 NidUTInput {
  NID_jurisdictionStateOrProvinceName, so::nid::Nid::JURISDICTIONSTATEORPROVINCENAME
 },
 NidUTInput {
  NID_jurisdictionCountryName, so::nid::Nid::JURISDICTIONCOUNTRYNAME
 },
 NidUTInput {
  NID_id_scrypt, so::nid::Nid::ID_SCRYPT
 },
 NidUTInput {
  NID_tls1_prf, so::nid::Nid::TLS1_PRF
 },
 NidUTInput {
  NID_hkdf, so::nid::Nid::HKDF
 },
 NidUTInput {
  NID_id_pkinit, so::nid::Nid::ID_PKINIT
 },
 NidUTInput {
  NID_pkInitClientAuth, so::nid::Nid::PKINITCLIENTAUTH
 },
 NidUTInput {
  NID_pkInitKDC, so::nid::Nid::PKINITKDC
 },
 NidUTInput {
  NID_X25519, so::nid::Nid::X25519
 },
 NidUTInput {
  NID_X448, so::nid::Nid::X448
 },
 NidUTInput {
  NID_kx_rsa, so::nid::Nid::KX_RSA
 },
 NidUTInput {
  NID_kx_ecdhe, so::nid::Nid::KX_ECDHE
 },
 NidUTInput {
  NID_kx_dhe, so::nid::Nid::KX_DHE
 },
 NidUTInput {
  NID_kx_ecdhe_psk, so::nid::Nid::KX_ECDHE_PSK
 },
 NidUTInput {
  NID_kx_dhe_psk, so::nid::Nid::KX_DHE_PSK
 },
 NidUTInput {
  NID_kx_rsa_psk, so::nid::Nid::KX_RSA_PSK
 },
 NidUTInput {
  NID_kx_psk, so::nid::Nid::KX_PSK
 },
 NidUTInput {
  NID_kx_srp, so::nid::Nid::KX_SRP
 },
 NidUTInput {
  NID_kx_gost, so::nid::Nid::KX_GOST
 },
 NidUTInput {
  NID_auth_rsa, so::nid::Nid::AUTH_RSA
 },
 NidUTInput {
  NID_auth_ecdsa, so::nid::Nid::AUTH_ECDSA
 },
 NidUTInput {
  NID_auth_psk, so::nid::Nid::AUTH_PSK
 },
 NidUTInput {
  NID_auth_dss, so::nid::Nid::AUTH_DSS
 },
 NidUTInput {
  NID_auth_gost01, so::nid::Nid::AUTH_GOST01
 },
 NidUTInput {
  NID_auth_gost12, so::nid::Nid::AUTH_GOST12
 },
 NidUTInput {
  NID_auth_srp, so::nid::Nid::AUTH_SRP
 },
 NidUTInput {
  NID_auth_null, so::nid::Nid::AUTH_NULL
 }
};

