#ifndef __FLUX_SIGN__
#define __FLUX_SIGN__
#include <key.h>
#include <keystore.h>

bool flux_sign_init(std::string wifKey);
bool WIFToCKey(const std::string& wif, CKey& keyOut);
std::string signTransaction(const std::string& Arg_unsigned_tx,
                            const std::map<std::string, std::pair<std::string, CAmount>>& prevouts);
#endif
