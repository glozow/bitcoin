# Transactions with nVersion 3

A transaction with its `nVersion` field set to 3 ("V3 transactions") are allowed in mempool and
transaction relay.

The following set of policies apply to V3 transactions:

1. Any descendant of an unconfirmed V3 transaction must also be V3.

2. A V3 transaction can be replaced by another V3 transaction, even if it does not signal BIP125
   replaceability. Use the (`-mempoolfullrbf`) configuration option to allow transaction
   replacement without enforcement of any opt-in signaling rule.

3. A V3 transaction cannot have more than 1 descendant.

4. A V3 transaction that has a V3 ancestor cannot be larger than 4000 virtual bytes.
