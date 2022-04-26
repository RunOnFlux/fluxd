// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "Proof.hpp"

#include "crypto/common.h"

#include <boost/static_assert.hpp>
#include <mutex>

namespace libzelcash {

ProofVerifier ProofVerifier::Strict() {
    return ProofVerifier(true);
}

ProofVerifier ProofVerifier::Disabled() {
    return ProofVerifier(false);
}

}
