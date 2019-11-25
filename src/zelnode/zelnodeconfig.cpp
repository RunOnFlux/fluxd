// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.


#include "netbase.h"
#include "zelnodeconfig.h"
#include "util.h"
#include "ui_interface.h"
#include "chainparams.h"
#include <base58.h>

ZelnodeConfig zelnodeConfig;

void ZelnodeConfig::add(std::string alias, std::string ip, std::string privKey, std::string txHash, std::string outputIndex)
{
    ZelnodeEntry zelnodeEntry(alias, ip, privKey, txHash, outputIndex);
    entries.push_back(zelnodeEntry);
}

bool ZelnodeConfig::read(std::string& strErr)
{
    int linenumber = 1;
    boost::filesystem::path pathZelnodeConfigFile = GetZelnodeConfigFile();
    boost::filesystem::ifstream streamConfig(pathZelnodeConfigFile);

    if (!streamConfig.good()) {
        FILE* configFile = fopen(pathZelnodeConfigFile.string().c_str(), "a");
        if (configFile != NULL) {
            std::string strHeader = "# Zelnode config file\n"
                                    "# Format: alias IP:port zelnodeprivkey collateral_output_txid collateral_output_index\n"
                                    "# Example: zn1 127.0.0.2:16125 93HaYBVUCYjEMeeH1Y4sBGLALQZE1Yc1K64xiqgX37tGBDQL8Xg 2bcd3c84c84f87eaa86e4e56834c92927a07f9e18718810b92e0d0324456a67c 0\n";
            fwrite(strHeader.c_str(), std::strlen(strHeader.c_str()), 1, configFile);
            fclose(configFile);
        }
        return true; // Nothing to read, so just return
    }

    for (std::string line; std::getline(streamConfig, line); linenumber++) {
        if (line.empty()) continue;

        std::istringstream iss(line);
        std::string comment, alias, ip, privKey, txHash, outputIndex;

        if (iss >> comment) {
            if (comment.at(0) == '#') continue;
            iss.str(line);
            iss.clear();
        }

        if (!(iss >> alias >> ip >> privKey >> txHash >> outputIndex)) {
            iss.str(line);
            iss.clear();
            if (!(iss >> alias >> ip >> privKey >> txHash >> outputIndex)) {
                strErr = _("Could not parse zelnode.conf") + "\n" +
                         strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"";
                streamConfig.close();
                return false;
            }
        }

        int port = 0;
        std::string hostname = "";
        SplitHostPort(ip, port, hostname);
        if(port == 0 || hostname == "") {
            strErr = _("Failed to parse host:port string") + "\n"+
                     strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"";
            streamConfig.close();
            return false;
        }


        if (Params().NetworkID() == CBaseChainParams::MAIN) {
            if (port != 16125) {
                strErr = _("Invalid port detected in zelnode.conf") + "\n" +
                         strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"" + "\n" +
                         _("(must be 51472 for mainnet)");
                streamConfig.close();
                return false;
            }
        } else if (port == 16125) {
            strErr = _("Invalid port detected in zelnode.conf") + "\n" +
                     strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"" + "\n" +
                     _("(16125 could be used only on mainnet)");
            streamConfig.close();
            return false;
        }


        add(alias, ip, privKey, txHash, outputIndex);
    }

    streamConfig.close();
    return true;
}

bool ZelnodeConfig::ZelnodeEntry::castOutputIndex(int &n)
{
    try {
        n = std::stoi(outputIndex);
    } catch (const std::exception e) {
        LogPrintf("%s: %s on getOutputIndex\n", __func__, e.what());
        return false;
    }

    return true;
}
