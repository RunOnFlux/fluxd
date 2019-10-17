// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.




#ifndef SRC_ZELNODECONFIG_H_
#define SRC_ZELNODECONFIG_H_

#include <string>
#include <vector>

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>


class ZelnodeConfig;
extern ZelnodeConfig zelnodeConfig;


class ZelnodeConfig
{
public:
    class ZelnodeEntry
    {
    private:
        std::string alias;
        std::string ip;
        std::string privKey;
        std::string txHash;
        std::string outputIndex;

    public:
        ZelnodeEntry(std::string alias, std::string ip, std::string privKey, std::string txHash,
                     std::string outputIndex)
        {
            this->alias = alias;
            this->ip = ip;
            this->privKey = privKey;
            this->txHash = txHash;
            this->outputIndex = outputIndex;
        }

        const std::string& getAlias() const
        {
            return alias;
        }

        void setAlias(const std::string& alias)
        {
            this->alias = alias;
        }

        const std::string& getOutputIndex() const
        {
            return outputIndex;
        }

        bool castOutputIndex(int& n);

        void setOutputIndex(const std::string& outputIndex)
        {
            this->outputIndex = outputIndex;
        }

        const std::string& getPrivKey() const
        {
            return privKey;
        }

        void setPrivKey(const std::string& privKey)
        {
            this->privKey = privKey;
        }

        const std::string& getTxHash() const
        {
            return txHash;
        }

        void setTxHash(const std::string& txHash)
        {
            this->txHash = txHash;
        }

        const std::string& getIp() const
        {
            return ip;
        }

        void setIp(const std::string& ip)
        {
            this->ip = ip;
        }
    };

    ZelnodeConfig()
    {
        entries = std::vector<ZelnodeEntry>();
    }

    void clear();
    bool read(std::string& strErr);
    void add(std::string alias, std::string ip, std::string privKey, std::string txHash, std::string outputIndex);

    std::vector <ZelnodeEntry>& getEntries()
    {
        return entries;
    }

    int getCount()
    {
        int c = -1;
        for (ZelnodeEntry e : entries) {
            if (e.getAlias() != "") c++;
        }
        return c;
    }

private:
    std::vector <ZelnodeEntry> entries;

};
#endif //SRC_ZELNODECONFIG_H_