// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "crypto/equihash.h"
#include "primitives/block.h"
#include "streams.h"
#include "uint256.h"
#include "util.h"

#include "sodium.h"
#include "librustzcash.h"

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    const CChainParams& chainParams = Params();
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
     const arith_uint256 powLimit = UintToArith256(params.powLimit);
	
    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    // Reset the difficulty after the algo fork and keep it for 61 blocks. LWMA averaging window is 60 blocks.
    if (pindexLast->nHeight > chainParams.eh_epoch_1_end() - 1
        && pindexLast->nHeight < chainParams.eh_epoch_1_end() + 61) {
        return nProofOfWorkLimit;
    }	

    // Reset the difficulty for ZelHash fork 
     if (pindexLast->nHeight > chainParams.eh_epoch_2_end() - 1
        && pindexLast->nHeight < chainParams.eh_epoch_2_end() + 64) {

	// Get the currently calculated difficulty following LWMA3
	arith_uint256 fullTarget;
	fullTarget.SetCompact(Lwma3CalculateNextWorkRequired(pindexLast, params)); 

	// (1/32th) of the calculated diff
	arith_uint256 targetStep = fullTarget >> 5;

	// maximum: 64*(1/32)*target = 2*target
	targetStep *= (chainParams.eh_epoch_2_end() + 61 - pindexLast->nHeight);
	
	fullTarget += targetStep; 

	if (fullTarget > powLimit) { fullTarget = powLimit; }
	return fullTarget.GetCompact();
	
    }		

    {
        // Comparing to pindexLast->nHeight with >= because this function
        // returns the work required for the block after pindexLast.
        if (params.nPowAllowMinDifficultyBlocksAfterHeight != boost::none &&
            pindexLast->nHeight >= params.nPowAllowMinDifficultyBlocksAfterHeight.get())
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 6 * 2.5 minutes
            // then allow mining of a min-difficulty block.
            if (pblock && pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 6)
                return nProofOfWorkLimit;
        }
    }  

    // Find the first block in the averaging interval
    const CBlockIndex* pindexFirst = pindexLast;
    arith_uint256 bnTot {0};
    for (int i = 0; pindexFirst && i < params.nDigishieldAveragingWindow; i++) {
        arith_uint256 bnTmp;
        bnTmp.SetCompact(pindexFirst->nBits);
        bnTot += bnTmp;
        pindexFirst = pindexFirst->pprev;
    }

    // Check we have enough blocks
    if (pindexFirst == NULL)
        return nProofOfWorkLimit;

    arith_uint256 bnAvg {bnTot / params.nDigishieldAveragingWindow};

    //Difficulty algo
    int nHeight = pindexLast->nHeight + 1;
    if (nHeight < params.vUpgrades[Consensus::UPGRADE_LWMA].nActivationHeight) {
        return DigishieldCalculateNextWorkRequired(bnAvg, pindexLast->GetMedianTimePast(), pindexFirst->GetMedianTimePast(), params);
    } else if (nHeight < params.vUpgrades[Consensus::UPGRADE_ACADIA].nActivationHeight)  {
        return LWMACalculateNextWorkRequired(pindexLast, params);
    } else {
        return Lwma3CalculateNextWorkRequired(pindexLast, params);
    }
}

unsigned int DigishieldCalculateNextWorkRequired(arith_uint256 bnAvg,
                                       int64_t nLastBlockTime, int64_t nFirstBlockTime,
                                       const Consensus::Params& params)
{
    // Limit adjustment step
    // Use medians to prevent time-warp attacks
    int64_t nActualTimespan = nLastBlockTime - nFirstBlockTime;
    LogPrint("pow", "  nActualTimespan = %d  before dampening\n", nActualTimespan);
    nActualTimespan = params.DigishieldAveragingWindowTimespan() + (nActualTimespan - params.DigishieldAveragingWindowTimespan())/4;
    LogPrint("pow", "  nActualTimespan = %d  before bounds\n", nActualTimespan);

    if (nActualTimespan < params.DigishieldMinActualTimespan())
        nActualTimespan = params.DigishieldMinActualTimespan();
    if (nActualTimespan > params.DigishieldMaxActualTimespan())
        nActualTimespan = params.DigishieldMaxActualTimespan();

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew {bnAvg};
    bnNew /= params.DigishieldAveragingWindowTimespan();
    bnNew *= nActualTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    /// debug print
    LogPrint("pow", "GetNextWorkRequired RETARGET Digishield\n");
    LogPrint("pow", "params.DigishieldAveragingWindowTimespan() = %d    nActualTimespan = %d\n", params.DigishieldAveragingWindowTimespan(), nActualTimespan);
    LogPrint("pow", "Current average: %08x  %s\n", bnAvg.GetCompact(), bnAvg.ToString());
    LogPrint("pow", "After:  %08x  %s\n", bnNew.GetCompact(), bnNew.ToString());

    return bnNew.GetCompact();
}

unsigned int LWMACalculateNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    // FTL = N * T / 20
    const int64_t FTL = 360;
    const int64_t T = params.nPowTargetSpacing;
    const int64_t N = params.nZawyLWMAAveragingWindow;
    const int64_t k = N*(N+1)*T/2;
    const int height = pindexLast->nHeight;
    assert(height > N);

    arith_uint256 sum_target;
    int64_t t = 0, j = 0, solvetime;

    // Loop through N most recent blocks.
    for (int i = height - N+1; i <= height; i++) {
        const CBlockIndex* block = pindexLast->GetAncestor(i);
        const CBlockIndex* block_Prev = block->GetAncestor(i - 1);
        solvetime = block->GetBlockTime() - block_Prev->GetBlockTime();
        solvetime = std::max(-FTL, std::min(solvetime, 6*T));

        j++;
        t += solvetime * j;  // Weighted solvetime sum.

        arith_uint256 target;
        target.SetCompact(block->nBits);
        sum_target += target / (k * N);
    }
    // Keep t reasonable to >= 1/10 of expected t.
    if (t < k/10 ) {   t = k/10;  }
    arith_uint256 next_target = t * sum_target;

    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    if (next_target > bnPowLimit)
        next_target = bnPowLimit;

    /// debug print
    LogPrint("pow", "GetNextWorkRequired RETARGET LWMA\n");
    LogPrint("pow", "After:  %08x  %s\n", next_target.GetCompact(), next_target.ToString());

    return next_target.GetCompact();
}

unsigned int Lwma3CalculateNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    const int64_t T = params.nPowTargetSpacing;
    const int64_t N = params.nZawyLWMAAveragingWindow;
    const int64_t k = N * (N + 1) * T / 2;
    const int64_t height = pindexLast->nHeight;
    const arith_uint256 powLimit = UintToArith256(params.powLimit);
    
    if (height < N) { return powLimit.GetCompact(); }

    arith_uint256 sumTarget, previousDiff, nextTarget;
    int64_t thisTimestamp, previousTimestamp;
    int64_t t = 0, j = 0, solvetimeSum = 0;

    const CBlockIndex* blockPreviousTimestamp = pindexLast->GetAncestor(height - N);
    previousTimestamp = blockPreviousTimestamp->GetBlockTime();

    // Loop through N most recent blocks. 
    for (int64_t i = height - N + 1; i <= height; i++) {
        const CBlockIndex* block = pindexLast->GetAncestor(i);
        thisTimestamp = (block->GetBlockTime() > previousTimestamp) ? block->GetBlockTime() : previousTimestamp + 1;

        int64_t solvetime = std::min(6 * T, thisTimestamp - previousTimestamp);
        previousTimestamp = thisTimestamp;

        j++;
        t += solvetime * j; // Weighted solvetime sum.
        arith_uint256 target;
        target.SetCompact(block->nBits);
        sumTarget += target / (k * N);

      //  if (i > height - 3) { solvetimeSum += solvetime; } // deprecated
        if (i == height) { previousDiff = target.SetCompact(block->nBits); }
    }

    nextTarget = t * sumTarget;
    
    if (nextTarget > (previousDiff * 150) / 100) { nextTarget = (previousDiff * 150) / 100; }
    if ((previousDiff * 67) / 100 > nextTarget) { nextTarget = (previousDiff * 67)/100; }
   //  if (solvetimeSum < (8 * T) / 10) { nextTarget = previousDiff * 100 / 106; } // deprecated
    if (nextTarget > powLimit) { nextTarget = powLimit; }

    return nextTarget.GetCompact();
}

bool CheckEquihashSolution(const CBlockHeader *pblock, const Consensus::Params& params)
{
    //Set parameters N,K from solution size. Filtering of valid parameters
    //for the givenblock height will be carried out in main.cpp/ContextualCheckBlockHeader
    unsigned int n,k;
    size_t nSolSize = pblock->nSolution.size();
    switch (nSolSize){
        case 1344: n=200; k=9; break;
        case 100:  n=144; k=5; break;
        case 68:   n=96;  k=5; break;
        case 52:   n=125; k=4; break;
        case 36:   n=48;  k=5; break;
        default: return error("CheckEquihashSolution: Unsupported solution size of %d", nSolSize);
    }
    
    LogPrint("pow", "selected n,k : %d, %d \n", n,k);

    //need to put block height param switching code here

    // Hash state
    crypto_generichash_blake2b_state state;
    EhInitialiseState(n, k, state);
    // I = the block header minus nonce and solution.
    CEquihashInput I{*pblock};
    // I||V
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;
    ss << pblock->nNonce;
    // H(I||V||...
    crypto_generichash_blake2b_update(&state, (unsigned char*)&ss[0], ss.size());
    bool isValid;
    EhIsValidSolution(n, k, state, pblock->nSolution, isValid);
    if (!isValid)
        return error("CheckEquihashSolution(): invalid solution");

    return true;
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return error("CheckProofOfWork(): nBits below minimum work");

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return error("CheckProofOfWork(): hash doesn't match nBits");

    return true;
}

arith_uint256 GetBlockProof(const CBlockIndex& block)
{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for a arith_uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (nTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}

int64_t GetBlockProofEquivalentTime(const CBlockIndex& to, const CBlockIndex& from, const CBlockIndex& tip, const Consensus::Params& params)
{
    arith_uint256 r;
    int sign = 1;
    if (to.nChainWork > from.nChainWork) {
        r = to.nChainWork - from.nChainWork;
    } else {
        r = from.nChainWork - to.nChainWork;
        sign = -1;
    }
    r = r * arith_uint256(params.nPowTargetSpacing) / GetBlockProof(tip);
    if (r.bits() > 63) {
        return sign * std::numeric_limits<int64_t>::max();
    }
    return sign * r.GetLow64();
}
