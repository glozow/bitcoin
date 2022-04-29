# Transactions with nVersion 3

A transaction with its `nVersion` field set to 3 ("V3 transactions") are allowed in mempool and
transaction relay.

The policy rules set for V3 transactions is intended to aid contract or L2 protocols in which
transactions are signed by untrusted counterparties well before broadcast time, e.g. the Lightning
Network (LN). Since these contracting transactions are shared between multiple parties and mempool
congestion is difficult to predict, mempool policy restrictions may accidentally allow a malicious
party to pin a transaction.  The goal here is create a policy for V3 transactions that retains
DoS-resistance and accepts transactions that are incentive-compatible to mine, while also avoiding
specific pinning attacks.

All existing standardness rules apply to V3. The following set of additional restrictions apply to
V3 transactions:

1. A V3 transaction can be replaced, even if it does not signal BIP125 replaceability. Other
   conditions rules apply, see [RBF rules](./mempool-replacements.md) and [Package RBF
rules][./packages.md#Package-Replace-By-Fee]. Use the (`-mempoolfullrbf`) configuration option to
allow transaction replacement without enforcement of any opt-in signaling rule.

2. Any descendant of an unconfirmed V3 transaction must also be V3.

*Rationale*: Combined with Rule 1, this gives us the property of "inherited signaling" when
descendants of unconfirmed transactions are created. Additionally, checking whether a transaction
signals replaceability this way does not require mempool traversal, and does not change based on
what transactions are mined.

*Note*: The descendant of a *confirmed* V3 transaction does not need to be V3.

3. A V3 transaction cannot have more than 1 descendant.

*Rationale*: (upper bound) the larger the descendant limit, the more transactions may need to be
replaced. This is a problematic pinning attack, i.e., a malicious counterparty prevents the
transaction from being replaced by adding many descendant transactions that aren't fee-bumping.

*Rationale*: (lower bound) at least 1 descendant is required to allow CPFP of the presigned
transaction. The contract protocol can create presigned transactions paying 0 fees and 1 output for
attaching a CPFP at broadcast time ("anchor output"). Without package RBF, multiple anchor outputs
would be required to allow each counterparty to fee-bump any presigned transaction. With package
RBF, since the presigned transactions can replace each other, 1 anchor output is sufficient.

4. A V3 transaction that has an unconfirmed V3 ancestor cannot be larger than 1000 virtual bytes.

*Rationale*: (upper bound) the larger the descendant size limit, the more vbytes may need to be
replaced. With default limits, if the child is e.g. 100,000vB, that might be an additional
100,000sats (at 1sat/vbyte) or more, depending on the feerate.

*Rationale*: (lower bound) the smaller this limit, the fewer UTXOs a child may use to fund this
fee-bump. For example, only allowing the V3 child to have 2 inputs would require L2 protocols to
manage a wallet with high-value UTXOs and make batched fee-bumping impossible. However, as the
fee-bumping child only needs to fund fees (as opposed to payments), just a few UTXOs should suffice.

*Rationale*: With a limit of 1000 virtual bytes, depending on the output types, the child can have
6-15 UTXOs, which should be enough to fund a fee-bump without requiring a carefully-managed UTXO
pool. With 1000 virtual bytes as the descendant limit, the cost to replace a V3 transaction has much
lower variance.

*Rationale*: This makes the rule very easily "tacked on" to existing logic for policy and wallets.
A transaction may be up to 100KvB on its own (`MAX_STANDARD_TX_WEIGHT`) and 101KvB with descendants
(`DEFAULT_DESCENDANT_SIZE_LIMIT_KVB`). If an existing V3 transaction in the mempool is 100KvB, its
descendant can only be 1000vB, even if the policy is 10KvB.
