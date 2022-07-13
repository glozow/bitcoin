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

*Rationale*: (FIXME exact number rationale). Combined with the limit of 1 descendant, this rule
ensures that replacing a V3 transaction never involves replacing more than 4000 virtual bytes of
descendants.

Clarifications:

- A transaction spending from a *confirmed* V3 transaction does not need to be V3.

- A V3 transaction can have both V3 and non-V3 ancestors.

## Ephemeral Dust Outputs

A transaction output is considered "uneconomical" if its value (`nValue`) is less than the
cost to spend it (i.e. the size of the input multiplied by a dust feerate). The default dust relay
feerate is 3sat/vB. Use the `-dustrelayfee` configuration option to adjust the feerate at which dust
is defined.

Uneconomical outputs are allowed in a V3 transaction if the following conditions are met:

1. The transaction only contains one uneconomical output ("the dust output").

2. The dust output `nValue` is exactly 0.

3. The transaction pays 0 fees.

4. The V3 transaction with the dust output ("parent") is spent by another V3 transaction ("child").
   These 2 transactions are expected to be relayed and submitted as a package.
