// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "main.h"
#include "pon/pon-fork.h"
#include "consensus/params.h"
#include "amount.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

// Define node tiers for testing (from fluxnode/fluxnode.h)
#ifndef CUMULUS
#define CUMULUS 1
#define NIMBUS 2
#define STRATUS 3
#endif

BOOST_FIXTURE_TEST_SUITE(pon_tests, TestingSetup)

// Helper function to check if we're past PON activation for testing
// We'll use the actual activation heights from chainparams

BOOST_AUTO_TEST_CASE(pon_subsidy_initial_test)
{
    // Test that initial PON subsidy is correct
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    // Get actual activation height from params
    int ponActivationHeight = GetPONActivationHeight();
    
    // Test at PON activation height
    CAmount subsidy = GetBlockSubsidy(ponActivationHeight, consensusParams);
    BOOST_CHECK_EQUAL(subsidy, 14 * COIN);
    
    // Test one block after activation
    subsidy = GetBlockSubsidy(ponActivationHeight + 1, consensusParams);
    BOOST_CHECK_EQUAL(subsidy, 14 * COIN);
    
    // Test before first year ends (no reduction yet)
    subsidy = GetBlockSubsidy(ponActivationHeight + 1051199, consensusParams);
    BOOST_CHECK_EQUAL(subsidy, 14 * COIN);
}

BOOST_AUTO_TEST_CASE(pon_subsidy_annual_reduction_test)
{
    // Test annual 10% reduction
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    int ponActivationHeight = GetPONActivationHeight();
    CAmount expectedSubsidy = 14 * COIN;
    
    // Test subsidy after 1 year (10% reduction)
    int height = ponActivationHeight + consensusParams.nPONSubsidyReductionInterval;
    CAmount subsidy = GetBlockSubsidy(height, consensusParams);
    expectedSubsidy = (expectedSubsidy * 9) / 10;  // 90% of previous
    BOOST_CHECK_EQUAL(subsidy, expectedSubsidy);
    BOOST_CHECK_EQUAL(subsidy, (126 * COIN) / 10);  // 14 * 0.9 = 12.6
    
    // Test subsidy after 2 years (another 10% reduction)
    height = ponActivationHeight + (2 * consensusParams.nPONSubsidyReductionInterval);
    subsidy = GetBlockSubsidy(height, consensusParams);
    expectedSubsidy = (expectedSubsidy * 9) / 10;  // 90% of previous
    BOOST_CHECK_EQUAL(subsidy, expectedSubsidy);
    BOOST_CHECK_EQUAL(subsidy, (1134 * COIN) / 100);  // 12.6 * 0.9 = 11.34
    
    // Test subsidy after 3 years
    height = ponActivationHeight + (3 * consensusParams.nPONSubsidyReductionInterval);
    subsidy = GetBlockSubsidy(height, consensusParams);
    expectedSubsidy = (expectedSubsidy * 9) / 10;
    BOOST_CHECK_EQUAL(subsidy, expectedSubsidy);
    
    // Test subsidy after 5 years
    height = ponActivationHeight + (5 * consensusParams.nPONSubsidyReductionInterval);
    subsidy = GetBlockSubsidy(height, consensusParams);
    // 14 * 0.9^5 = 14 * 0.59049 = 8.26686 COIN
    CAmount expected5Years = (14 * COIN * 59049) / 100000;  // Using integer math
    BOOST_CHECK_EQUAL(subsidy, expected5Years);
}

BOOST_AUTO_TEST_CASE(pon_subsidy_max_reductions_test)
{
    // Test that reductions stop after max reductions
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    int ponActivationHeight = GetPONActivationHeight();
    
    // Log subsidy amounts for years 0-20
    printf("\n=== PON Subsidy Schedule (Years 0-20) ===\n");
    printf("Year 0 (Initial): %.8f FLUX\n", (double)(14 * COIN) / COIN);
    
    CAmount currentSubsidy = 14 * COIN;
    for (int year = 1; year <= 20; year++) {
        int height = ponActivationHeight + (year * consensusParams.nPONSubsidyReductionInterval);
        CAmount subsidy = GetBlockSubsidy(height, consensusParams);
        double subsidyInFlux = (double)subsidy / COIN;
        double percentOfInitial = (double)subsidy / (14 * COIN) * 100.0;
        printf("Year %2d: %.8f FLUX (%.2f%% of initial)\n", year, subsidyInFlux, percentOfInitial);
        
        // Verify the reduction is correct
        currentSubsidy = (currentSubsidy * 9) / 10;
        BOOST_CHECK_EQUAL(subsidy, currentSubsidy);
    }
    printf("==========================================\n\n");
    
    // Test at max reductions (20 years)
    int height = ponActivationHeight + (20 * consensusParams.nPONSubsidyReductionInterval);
    CAmount subsidy = GetBlockSubsidy(height, consensusParams);
    
    // Calculate expected: 14 * 0.9^20
    CAmount expected = 14 * COIN;
    for (int i = 0; i < 20; i++) {
        expected = (expected * 9) / 10;
    }
    BOOST_CHECK_EQUAL(subsidy, expected);
    
    // Test beyond max reductions (25 years) - should be same as 20 years
    height = ponActivationHeight + (25 * consensusParams.nPONSubsidyReductionInterval);
    CAmount subsidyAfter25 = GetBlockSubsidy(height, consensusParams);
    BOOST_CHECK_EQUAL(subsidyAfter25, expected);  // Should not reduce further
    printf("Year 25: %.8f FLUX (capped at year 20 value)\n", (double)subsidyAfter25 / COIN);
    
    // Test way beyond max reductions (30 years) - should still be same
    height = ponActivationHeight + (30 * consensusParams.nPONSubsidyReductionInterval);
    CAmount subsidyAfter30 = GetBlockSubsidy(height, consensusParams);
    BOOST_CHECK_EQUAL(subsidyAfter30, expected);  // Should not reduce further
    printf("Year 30: %.8f FLUX (capped at year 20 value)\n\n", (double)subsidyAfter30 / COIN);
}

BOOST_AUTO_TEST_CASE(pon_activation_check_test)
{
    // Test IsPONActive function
    SelectParams(CBaseChainParams::MAIN);
    int ponActivationHeight = GetPONActivationHeight();
    
    // Before activation
    BOOST_CHECK_EQUAL(IsPONActive(ponActivationHeight - 1), false);
    
    // At activation
    BOOST_CHECK_EQUAL(IsPONActive(ponActivationHeight), true);
    
    // After activation
    BOOST_CHECK_EQUAL(IsPONActive(ponActivationHeight + 1), true);
    BOOST_CHECK_EQUAL(IsPONActive(ponActivationHeight + 1000), true);
}

BOOST_AUTO_TEST_CASE(pon_vs_pow_subsidy_test)
{
    // Test that POW subsidy is used before PON activation
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    int ponActivationHeight = GetPONActivationHeight();
    
    // Test POW subsidy at height before PON
    int powHeight = ponActivationHeight - 1;
    CAmount powSubsidy = GetBlockSubsidy(powHeight, consensusParams);
    
    // This should use POW subsidy calculation (with halvings)
    // The exact value depends on halvings that have occurred
    BOOST_CHECK(powSubsidy > 0);  // Should have some subsidy
    
    // Test PON subsidy at activation
    CAmount ponSubsidy = GetBlockSubsidy(ponActivationHeight, consensusParams);
    BOOST_CHECK_EQUAL(ponSubsidy, 14 * COIN);
}

BOOST_AUTO_TEST_CASE(pon_testnet_params_test)
{
    // Test testnet parameters (faster reduction for testing)
    SelectParams(CBaseChainParams::TESTNET);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    int ponActivationHeight = GetPONActivationHeight();
    
    // Initial subsidy
    CAmount subsidy = GetBlockSubsidy(ponActivationHeight, consensusParams);
    BOOST_CHECK_EQUAL(subsidy, 14 * COIN);
    
    // After 6 months (testnet reduction interval)
    int height = ponActivationHeight + consensusParams.nPONSubsidyReductionInterval;
    subsidy = GetBlockSubsidy(height, consensusParams);
    CAmount expectedReduced = (14 * COIN * 9) / 10;  // 90% of 14 COIN
    BOOST_CHECK_EQUAL(subsidy, expectedReduced);  // 10% reduction
}

BOOST_AUTO_TEST_CASE(pon_subsidy_schedule_display)
{
    // Display the complete PON subsidy schedule
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    int ponActivationHeight = GetPONActivationHeight();
    
    printf("\n=========================================\n");
    printf("    PON Block Subsidy Schedule (FLUX)    \n");
    printf("=========================================\n");
    printf("Year  | Block Reward  | % of Initial | Total per Year\n");
    printf("------|---------------|--------------|---------------\n");
    
    for (int year = 0; year <= 20; year++) {
        int height = ponActivationHeight + (year * consensusParams.nPONSubsidyReductionInterval);
        CAmount subsidy = GetBlockSubsidy(height, consensusParams);
        double subsidyInFlux = (double)subsidy / COIN;
        double percentOfInitial = (double)subsidy / (14 * COIN) * 100.0;
        
        // Calculate approximate total FLUX per year (1,051,200 blocks per year)
        double blocksPerYear = (double)consensusParams.nPONSubsidyReductionInterval;
        double totalPerYear = subsidyInFlux * blocksPerYear;
        
        printf(" %2d   | %11.8f  |   %6.2f%%   | %14.2f\n", 
               year, subsidyInFlux, percentOfInitial, totalPerYear);
    }
    
    printf("------|---------------|--------------|---------------\n");
    printf("Note: After year 20, the subsidy remains constant at %.8f FLUX\n", 
           (double)GetBlockSubsidy(ponActivationHeight + (20 * consensusParams.nPONSubsidyReductionInterval), consensusParams) / COIN);
    printf("=========================================\n\n");
}

BOOST_AUTO_TEST_CASE(pon_regtest_params_test)
{
    // Test regtest parameters (very fast reduction for testing)
    SelectParams(CBaseChainParams::REGTEST);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    // For regtest, PON might not be activated by default
    // Just test the parameters are set correctly
    BOOST_CHECK_EQUAL(consensusParams.nPONInitialSubsidy * COIN, 14 * COIN);
    BOOST_CHECK_EQUAL(consensusParams.nPONSubsidyReductionInterval, 100);  // Quick for testing
    BOOST_CHECK_EQUAL(consensusParams.nPONMaxReductions, 10);
}

BOOST_AUTO_TEST_CASE(pon_fluxnode_subsidy_test)
{
    // Test fluxnode subsidy distribution for PON
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    int ponActivationHeight = GetPONActivationHeight();
    
    printf("\n=== PON Fluxnode Subsidy Distribution ===\n");
    
    // Test initial distribution (Year 0)
    CAmount blockSubsidy = GetBlockSubsidy(ponActivationHeight, consensusParams);
    BOOST_CHECK_EQUAL(blockSubsidy, 14 * COIN);
    
    // Node tier enums: CUMULUS=1, NIMBUS=2, STRATUS=3
    CAmount cumulusReward = GetFluxnodeSubsidy(ponActivationHeight, blockSubsidy, CUMULUS);
    CAmount nimbusReward = GetFluxnodeSubsidy(ponActivationHeight, blockSubsidy, NIMBUS);
    CAmount stratusReward = GetFluxnodeSubsidy(ponActivationHeight, blockSubsidy, STRATUS);
    
    printf("Year 0 Distribution:\n");
    printf("  Total Block Subsidy: %.8f FLUX\n", (double)blockSubsidy / COIN);
    printf("  Cumulus Node:        %.8f FLUX (%.2f%%)\n", 
           (double)cumulusReward / COIN, (double)cumulusReward / blockSubsidy * 100);
    printf("  Nimbus Node:         %.8f FLUX (%.2f%%)\n", 
           (double)nimbusReward / COIN, (double)nimbusReward / blockSubsidy * 100);
    printf("  Stratus Node:        %.8f FLUX (%.2f%%)\n", 
           (double)stratusReward / COIN, (double)stratusReward / blockSubsidy * 100);
    
    // Verify initial amounts
    BOOST_CHECK_EQUAL(cumulusReward, 1.0 * COIN);  // 1.0 FLUX
    BOOST_CHECK_EQUAL(nimbusReward, 3.5 * COIN);   // 3.5 FLUX
    BOOST_CHECK_EQUAL(stratusReward, 9.0 * COIN);  // 9.0 FLUX
    
    // Total for nodes should be 13.5 FLUX (0.5 FLUX goes to development fund)
    CAmount totalNodeRewards = cumulusReward + nimbusReward + stratusReward;
    BOOST_CHECK_EQUAL(totalNodeRewards, 13.5 * COIN);
    
    // Test after 1 year (10% reduction)
    int height1Year = ponActivationHeight + consensusParams.nPONSubsidyReductionInterval;
    blockSubsidy = GetBlockSubsidy(height1Year, consensusParams);
    cumulusReward = GetFluxnodeSubsidy(height1Year, blockSubsidy, CUMULUS);
    nimbusReward = GetFluxnodeSubsidy(height1Year, blockSubsidy, NIMBUS);
    stratusReward = GetFluxnodeSubsidy(height1Year, blockSubsidy, STRATUS);
    
    printf("\nYear 1 Distribution (after 10%% reduction):\n");
    printf("  Total Block Subsidy: %.8f FLUX\n", (double)blockSubsidy / COIN);
    printf("  Cumulus Node:        %.8f FLUX\n", (double)cumulusReward / COIN);
    printf("  Nimbus Node:         %.8f FLUX\n", (double)nimbusReward / COIN);
    printf("  Stratus Node:        %.8f FLUX\n", (double)stratusReward / COIN);
    
    // After 10% reduction, values should be 90% of original
    BOOST_CHECK_EQUAL(cumulusReward, (0.9 * 1.0 * COIN));  // 0.9 FLUX
    BOOST_CHECK_EQUAL(nimbusReward, (315 * COIN) / 100);   // 3.15 FLUX
    BOOST_CHECK_EQUAL(stratusReward, (81 * COIN) / 10);     // 8.1 FLUX
    
    // Test after 5 years
    int height5Years = ponActivationHeight + (5 * consensusParams.nPONSubsidyReductionInterval);
    blockSubsidy = GetBlockSubsidy(height5Years, consensusParams);
    cumulusReward = GetFluxnodeSubsidy(height5Years, blockSubsidy, CUMULUS);
    nimbusReward = GetFluxnodeSubsidy(height5Years, blockSubsidy, NIMBUS);
    stratusReward = GetFluxnodeSubsidy(height5Years, blockSubsidy, STRATUS);
    
    printf("\nYear 5 Distribution:\n");
    printf("  Total Block Subsidy: %.8f FLUX\n", (double)blockSubsidy / COIN);
    printf("  Cumulus Node:        %.8f FLUX\n", (double)cumulusReward / COIN);
    printf("  Nimbus Node:         %.8f FLUX\n", (double)nimbusReward / COIN);
    printf("  Stratus Node:        %.8f FLUX\n", (double)stratusReward / COIN);
    
    // Verify proportions remain constant
    // Cumulus should always be 1/14 of total
    BOOST_CHECK_EQUAL(cumulusReward, blockSubsidy / 14);
    // Nimbus should always be 3.5/14 of total
    BOOST_CHECK_EQUAL(nimbusReward, (blockSubsidy * 35) / 140);
    // Stratus should always be 9/14 of total
    BOOST_CHECK_EQUAL(stratusReward, (blockSubsidy * 9) / 14);
    
    printf("=========================================\n\n");
}

BOOST_AUTO_TEST_CASE(pon_fluxnode_subsidy_schedule)
{
    // Display complete fluxnode subsidy schedule over 20 years
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    int ponActivationHeight = GetPONActivationHeight();
    
    printf("\n========================================================\n");
    printf("         PON Fluxnode Rewards Schedule (FLUX)           \n");
    printf("========================================================\n");
    printf("Year | Total Block | Cumulus | Nimbus  | Stratus | Dev Fund\n");
    printf("-----|-------------|---------|---------|---------|----------\n");
    
    for (int year = 0; year <= 20; year++) {
        int height = ponActivationHeight + (year * consensusParams.nPONSubsidyReductionInterval);
        CAmount blockSubsidy = GetBlockSubsidy(height, consensusParams);
        CAmount cumulus = GetFluxnodeSubsidy(height, blockSubsidy, CUMULUS);
        CAmount nimbus = GetFluxnodeSubsidy(height, blockSubsidy, NIMBUS);
        CAmount stratus = GetFluxnodeSubsidy(height, blockSubsidy, STRATUS);
        CAmount devFund = blockSubsidy - cumulus - nimbus - stratus;
        
        printf(" %2d  | %11.8f | %7.5f | %7.5f | %7.5f | %8.6f\n",
               year,
               (double)blockSubsidy / COIN,
               (double)cumulus / COIN,
               (double)nimbus / COIN,
               (double)stratus / COIN,
               (double)devFund / COIN);
    }
    
    printf("-----|-------------|---------|---------|---------|----------\n");
    printf("Note: Rewards remain constant after year 20\n");
    printf("========================================================\n\n");
}

BOOST_AUTO_TEST_SUITE_END()