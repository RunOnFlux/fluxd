#include <key.h>
#include <keystore.h>
#include <fstream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "fluxsign.h"

using boost::property_tree::ptree;

int main(int argc, char* argv[]) {
    std::cout << "Boost thread is working\n";
    boost::mutex m;
    {
        boost::lock_guard<boost::mutex> lock(m);
        std::cout << "Mutex lock succeeded\n";
    }

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <test_data.json>" << std::endl;
        return 1;
    }

    ptree pt;
    try {
        read_json(argv[1], pt);
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse JSON: " << e.what() << std::endl;
        return 1;
    }

    fluxsignStart();
    std::vector<std::string> wif_keys;
    for (auto& key : pt.get_child("wif_keys"))
        wif_keys.push_back(key.second.get_value<std::string>());

    std::vector<std::string> unsigned_txs;
    for (auto& tx : pt.get_child("unsigned_txs"))
        unsigned_txs.push_back(tx.second.get_value<std::string>());

    std::map<std::string, std::pair<std::string, int64_t>> prevouts;
    for (auto& po : pt.get_child("prevouts")) {
        std::string key = po.first;
        std::string script = po.second.get<std::string>("script");
        int64_t amount = po.second.get<int64_t>("amount");
        prevouts[key] = {script, amount};
    }

    for (const auto& wif : wif_keys) {
        if (!fluxsignAddKey(wif)) {
            std::cerr << wif << " WIF Private key not valid!" << std::endl;
        }
    }

    for (const auto& tx : unsigned_txs) {
        try {
            std::string signedHex = fluxsignTransaction(tx, prevouts);
            std::cout << "Signed TX: " << signedHex << std::endl;
        } catch (const std::exception& ex) {
            std::cerr << "Error: " << ex.what() << std::endl;
            return 1;
        }
    }
    fluxsignStop();

    return 0;
}

