#ifndef __FLUX_SIGN__
#define __FLUX_SIGN__
#include <string>
#include <iostream>

//#include <key.h>
//#include <keystore.h>

void fluxsignStart(void);
void fluxsignStop(void);
bool fluxsignAddKey(std::string wifKey);
//bool WIFToCKey(const std::string& wif, CKey& keyOut);
std::string fluxsignTransaction(const std::string& Arg_unsigned_tx,
                            const std::map<std::string, std::pair<std::string, int64_t>>& prevouts);
#endif
