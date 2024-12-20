// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <txgraph.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <vector>

BOOST_AUTO_TEST_SUITE(txgraph_tests)

BOOST_AUTO_TEST_CASE(txgraph_trim_zigzag)
{
    // We will build an oversized "zigzag" or "trellis" graph.
    const unsigned int max_cluster_count = 50;
    // First we add the "bottom" transactions, which are in the mempool already.
    const unsigned int num_bottom_tx = max_cluster_count;
    // Then add the "top" transactions, which come from disconnected blocks. These are re-added to the mempool and,
    // while connecting them to the already-in-mempool transactions, we discover the resulting cluster is oversized.
    const unsigned int num_top_tx = max_cluster_count + 1;
    const unsigned int total_num_tx = num_top_tx + num_bottom_tx;
    // Set a very large cluster size limit so that only the count limit is triggered.
    const uint64_t max_cluster_size = 100'000 * 100;

    // Create a new graph for the test.
    auto graph = MakeTxGraph(max_cluster_count, max_cluster_size);

    // Add all transactions and store their Refs.
    std::vector<TxGraph::Ref> refs;
    refs.reserve(total_num_tx);
    // The ith bottom transaction is at position `i`.
    for (unsigned int i = 0; i < num_bottom_tx; ++i) {
        refs.push_back(graph->AddTransaction({(int64_t)(i), 100}));
    }
    // The ith top transaction is at position `num_bottom_tx + i`.
    for (unsigned int i = 0; i < num_top_tx; ++i) {
        refs.push_back(graph->AddTransaction({(int64_t)(100-i), 100}));
    }

    // Create the zigzag dependency structure.
    // Each transaction in the bottom row depends on two adjacent transactions from the top row.
    for (unsigned int i = 0; i < num_bottom_tx; ++i) {
        graph->AddDependency(/*parent=*/refs[num_bottom_tx + i], /*child=*/refs[i]);
        graph->AddDependency(/*parent=*/refs[num_bottom_tx + i + 1], /*child=*/refs[i]);
    }

    // Check that the graph is now oversized. This also forces the graph to
    // group clusters and compute the oversized status.
    BOOST_CHECK(graph->IsOversized(false));

    // Call Trim() to remove transactions and bring the cluster back within limits.
    auto removed_refs = graph->Trim();
    BOOST_CHECK(!graph->IsOversized(false));

    // Check that the number of removed transactions and remaining transactions matches expectations
    // for this specific graph structure and feerate distribution.
    BOOST_CHECK_EQUAL(removed_refs.size(), max_cluster_count / 2 + 1);
    BOOST_CHECK_EQUAL(graph->GetTransactionCount(false), max_cluster_count * 3 / 2);

    // Removed refs are just the first half of the bottom transactions (which are the lowest feerate ones).
    for (unsigned int i = 0; i < refs.size(); ++i) {
        BOOST_CHECK_EQUAL(graph->Exists(refs[i]), i > num_bottom_tx / 2);
    }
}

BOOST_AUTO_TEST_CASE(txgraph_trim_flower)
{
    // We will build an oversized flower-shaped graph: all transactions are spent by 1 descendant.
    const unsigned int max_cluster_count = 50;
    // First we add a single "bottom" transaction, which is in the mempool already.
    // Then add the "top" transactions, which come from disconnected blocks. These are re-added to the mempool and,
    // while connecting them to the already-in-mempool transactions, we discover the resulting cluster is oversized.
    const unsigned int num_top_tx = max_cluster_count * 2;
    const unsigned int total_num_tx = max_cluster_count * 2 + 1;

    // Set a very large cluster size limit so that only the count limit is triggered.
    const uint64_t max_cluster_size = 100'000 * 100;

    auto graph = MakeTxGraph(max_cluster_count, max_cluster_size);

    // Add all transactions and store their Refs.
    std::vector<TxGraph::Ref> refs;
    refs.reserve(total_num_tx);

    // Add all transactions. They are in individual clusters.
    refs.push_back(graph->AddTransaction({10000, 100}));
    for (unsigned int i = 0; i < num_top_tx; ++i) {
        refs.push_back(graph->AddTransaction({(int64_t)(100-i), 100}));
    }

    // The 0th transaction spends all the top transactions.
    for (unsigned int i = 1; i < total_num_tx; ++i) {
        graph->AddDependency(/*parent=*/refs[i], /*child=*/refs[0]);
    }

    // Check that the graph is now oversized. This also forces the graph to
    // group clusters and compute the oversized status.
    BOOST_CHECK(graph->IsOversized(false));

    // Call Trim() to remove transactions and bring the cluster back within limits.
    auto removed_refs = graph->Trim();
    BOOST_CHECK(!graph->IsOversized(false));

    // Check that the number of removed transactions and remaining transactions matches expectations
    // for this specific graph structure and feerate distribution.
    BOOST_CHECK_EQUAL(removed_refs.size(), 1);
    BOOST_CHECK_EQUAL(graph->GetTransactionCount(false), max_cluster_count * 2);

    BOOST_CHECK(!graph->Exists(refs[0]));
    for (unsigned int i = 1; i < refs.size(); ++i) {
        BOOST_CHECK(graph->Exists(refs[i]));
    }
}

BOOST_AUTO_TEST_SUITE_END() 