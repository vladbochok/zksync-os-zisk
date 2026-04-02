# ZiSK Solidity Verifier

On-chain verifier for ZiSK STARK→SNARK proofs of ZKsync OS batch execution.

## Contracts

- `ZiskVerifier.sol` — Main entry point. Verifies proof against a batch's public values hash
  and delegates to `PlonkVerifier` for the SNARK check.
- `PlonkVerifier.sol` — Auto-generated Plonk verifier from ZiSK's SNARK setup.
- `IZiskVerifier.sol` — Interface for integration with the ZKsync diamond proxy.

## Usage

```bash
forge build
forge test
```

## How It Works

The ZiSK prover generates a STARK proof, then wraps it in a SNARK (Plonk) for
efficient on-chain verification. The public input is:

```
publicValuesHash = keccak256(state_before || state_after || batch_hash)
```

`ZiskVerifier.hashPublicValues()` computes this from the raw 96 bytes.
`ZiskVerifier.verify()` checks the SNARK proof against this hash.
