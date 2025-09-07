# Schnorr Signature (Legacy)

## Overview
This module provides a **Schnorr signature implementation** compatible with the **Smartholdem blockchain**, emulating the behavior of the **BCrypto library**. It is primarily used for **signing and verifying transactions** in legacy blockchain systems that rely on Schnorr signatures.

## Features
- Legacy Schnorr signing compatible with Smartholdem.
- Verification of signatures as accepted by the Smartholdem network.
- Emulates BCrypto library behavior for maximum compatibility.

## Signature Format
The generated signatures follow the format accepted by the Smartholdem blockchain. Ensure your public keys and message digests are compatible with the network's expectations.

## Tested With
- Smartholdem blockchain ([https://smartholdem.io/](https://smartholdem.io/))
> Branch "fixing" is giving valid signature. But there is issue, perhabs related to overlapping.