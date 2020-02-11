#include <simpleopenssl/simpleopenssl.h>
#include "simplelog/simplelog.h"
#include "cmdline/cmdline.h"
#include <iomanip>


using namespace so;

std::string bin2Hex(const so::Bytes &buff);

int main(int argc, char *argv[])
{
  cmdline::parser arg;
  arg.add("help", 'h', "Print help.");
  arg.add<std::string>("file", 'f', "PEM cert file to be printed.", true);
 
  if(!arg.parse(argc, const_cast<const char* const*>(argv)))
  {
    const auto fullErr = arg.error_full();
    if(!fullErr.empty())
      log << fullErr;
     
    log << arg.usage();
    return 0;
  }
  
  if(arg.exist("help"))
  {
    log << arg.usage();
    return 0;
  } 

  if(!arg.exist("file"))
  {
    log << "--file or -f argument is mandatory!";
    log << arg.usage();
    return 0;
  }
  
  const std::string file = arg.get<std::string>("file");
  auto maybeX509 = x509::convertPemFileToX509(file);
  if(!maybeX509)
  {
    log << maybeX509.msg();
    return 0;
  }

  auto cert = maybeX509.moveValue();

  auto maybeSubject = x509::getSubject(*cert);
  if(!maybeSubject)
  {
    log << maybeSubject.msg();
    return 0;
  }

  const auto subject = maybeSubject.moveValue();
  log << "Subject:";
  log << "\tCommonName: " << subject.commonName;
  log << "\tCountryName: " << subject.countryName;
  log << "\tLocalityName: " << subject.localityName;
  log << "\tOrganizationName: " << subject.organizationName;
  log << "\tStateOrProvinceName: " << subject.stateOrProvinceName;

  log << "Version: " << std::get<1>(x509::getVersion(*cert));

  auto maybeIssuer = x509::getIssuer(*cert);
  if(!maybeIssuer)
  {
    log << maybeIssuer.msg();
    return 0;
  }
  const auto issuer = maybeIssuer.moveValue();
  log << "Issuer:";
  log << "\tCommonName: " << issuer.commonName;
  log << "\tCountryName: " << issuer.countryName;
  log << "\tLocalityName: " << issuer.localityName;
  log << "\tOrganizationName: " << issuer.organizationName;
  log << "\tStateOrProvinceName: " << issuer.stateOrProvinceName;

  auto maybePubKey = x509::getPubKey(*cert);
  if(!maybePubKey)
  {
    log << maybePubKey.msg();
    return 0;
  }
  auto pubKey = maybePubKey.moveValue(); 
  const auto pubKeyBytes = evp::convertPubKeyToDer(*pubKey);
  if(!pubKeyBytes)
  {
    log << pubKeyBytes.msg();
    return 0;
  }

  log << "PublicKey: " << bin2Hex(*pubKeyBytes);

  const auto extCount = x509::getExtensionsCount(*cert);
  if(!extCount)
  {
    log << extCount.msg();
    return 0;
  }
  log << "ExtensionCount: " << *extCount;
  
  if(*extCount)
  {
    const auto extensions = x509::getExtensions(*cert);
    if(!extensions)
    {
      log << extensions.msg();
      return 0;
    }

    for(const auto &ext : extensions.value())
    {
      log << "\tname: " << ext.name << " [" << ext.oidNumerical << "]";
      log << "\t  critical: " << (ext.critical ? "true" : "false");
      log << "\t  data: " << bin2Hex(ext.data);
    }
  }
 
  const auto sig = x509::getSignature(*cert);
  if(!sig)
  {
    log << sig.msg();
    return 0;
  } 

  log << "Signature: " << bin2Hex(*sig);

  return 0;
}

std::string bin2Hex(const so::Bytes &buff)
{
  std::ostringstream oss;
  for(const auto bt : buff){
    oss << std::setfill('0') << std::setw(2) << std::hex << +bt;
  }
  return oss.str(); 
}
