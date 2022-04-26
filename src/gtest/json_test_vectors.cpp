// Copyright (C) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "json_test_vectors.h"

UniValue
read_json(const std::string& jsondata)
{
    UniValue v;

    if (!(v.read(jsondata) && v.isArray()))
    {
        ADD_FAILURE();
        return UniValue(UniValue::VARR);
    }
    return v.get_array();
}
