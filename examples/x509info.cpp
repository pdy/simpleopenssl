#include <simpleopenssl/simpleopenssl.h>
#include "simplelog/simplelog.h"
#include "cmdline/cmdline.h"
#include <iomanip>


using namespace so;

std::string bin2Hex(const so::Bytes &buff);
std::string bin2Text(const so::Bytes &buff);
void logHex(const std::string &hexStr, size_t newLine);

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

  const auto[version, versionRaw] = x509::getVersion(*cert);
  switch(version)
  {
    case x509::Version::v1:
      log << "Version: 1 (" << versionRaw << ")";
      break;
    case x509::Version::v2:
      log << "Version: 2 (" << versionRaw << ")";
      break;
  case x509::Version::v3:
      log << "Version: 3 (" << versionRaw << ")";
      break;
  case x509::Version::vx:
      log << "Version: " << versionRaw;
      break;
  }

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

  log << "PublicKey: " << nid::getLongName(x509::getPubKeyAlgorithm(*cert)).value();
  logHex(bin2Hex(*pubKeyBytes), 30);

  const auto extensions = x509::getExtensions(*cert);
  if(!extensions)
  {
    log << extensions.msg();
    return 0;
  }
  log << "ExtensionCount: " << extensions->size();
  
  if(!extensions->empty())
  {
    for(const auto &ext : extensions.value())
    {
      if(ext.id != x509::CertExtensionId::UNDEF)
      {
        log << "\tname: " << ext.name << " [" << ext.oidNumerical << "]";
        log << "\t  critical: " << (ext.critical ? "true" : "false");
        log << "\t  data: " << bin2Text(ext.data);
      }
      else
      {
        log << "\toid: " << ext.oidNumerical;
        log << "\t  critical: " << (ext.critical ? "true" : "false");
        log << "\t  data: " << bin2Hex(ext.data);
      }
    }
  }
 
  const auto sig = x509::getSignature(*cert);
  if(!sig)
  {
    log << sig.msg();
    return 0;
  } 
  const auto sigType = x509::getSignatureAlgorithm(*cert);
  log << "Signature: " << nid::getLongName(sigType).value();
  logHex(bin2Hex(*sig), 36);

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


std::string bin2Text(const so::Bytes &buff)
{
  std::string ret;
  ret.reserve(buff.size());
  std::transform(buff.begin(), buff.end(), std::back_inserter(ret), [](uint8_t bt) { return static_cast<char>(bt);});
  return ret;
}

void logHex(const std::string &hexStr, size_t newLine)
{
  std::cout << "\t";
  for(size_t i = 1; i <= hexStr.size(); ++i)
    std::cout << hexStr[i-1] << (i%2==0 ? " ":"") << (i%newLine == 0 && i!=hexStr.size() ? "\n\t" : "");

  std::cout << "\n";
}

