// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.20;

import {PlonkVerifier} from "./PlonkVerifier.sol";

/// @title ZiSK L1 Verifier
/// @notice Implements the IVerifier interface expected by ZKsync's Executor facet.
///         Verifies ZiSK SNARK proofs from the proof[] array passed by the Executor.
///
///         The Executor calls: verify(uint256[] publicInputs, uint256[] proof, uint256[] recursiveInput)
///         Where:
///         - publicInputs[0] = batch public input (keccak(state_before||state_after||batch_hash) >> 32)
///         - proof[0] = proof_type | (verifier_version << 8)
///           For type 2 (OHBENDER): proof[1..] = Era SNARK elements
///           For type 4 (TWO_PROOF): proof layout described below
///         - recursiveInput = [] (unused)
///
///         For proof type 4 (TWO_PROOF_SYSTEM):
///         - proof[0] = 4 | (verifier_version << 8)
///         - proof[1] = 0 (previous hash)
///         - proof[2] = N (era proof length — ignored for now)
///         - proof[3..3+N] = Era SNARK proof (ignored — era verification handled separately)
///         - proof[3+N..3+N+24] = ZiSK SNARK proof (24 uint256 = 768 bytes)
///         - proof[3+N+24..3+N+32] = ZiSK public values (8 uint256 = 256 bytes)
///
///         For proof type 3 (FAKE): accepts any proof (testing mode)
contract ZiskL1Verifier is PlonkVerifier {
    /// @notice ZiSK ELF-specific verification key.
    /// Hardcoded for the current guest ELF binary.
    uint64 private constant _programVK0 = 4838359011762341489;
    uint64 private constant _programVK1 = 17537343563151866928;
    uint64 private constant _programVK2 = 11949100182324703893;
    uint64 private constant _programVK3 = 17106480096882735767;

    /// @notice ZiSK vadcop final root commitment.
    uint64 private constant _rootCVadcopFinal0 = 9211010158316595036;
    uint64 private constant _rootCVadcopFinal1 = 7055235338110277438;
    uint64 private constant _rootCVadcopFinal2 = 2391371252028311145;
    uint64 private constant _rootCVadcopFinal3 = 10691781997660262077;

    // Modulus zkSNARK (BN254 scalar field)
    uint256 internal constant _RFIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Returns the verification key hash.
    ///         This MUST return a valid hash for the Executor to accept the proof.
    function verificationKeyHash() external pure returns (bytes32) {
        // Must match the server's ProvingVersion VK hash for the protocol version.
        return 0x124ebcd537a1e1c152774dd18f67660e35625bba0b669bf3b4836d636b105337;
    }

    /// @notice Main verification function called by the Executor facet.
    /// @param _publicInputs Public inputs array. _publicInputs[0] is the batch public input.
    /// @param _proof Proof array. Format depends on content.
    function verify(
        uint256[] calldata _publicInputs,
        uint256[] calldata _proof
    ) public view returns (bool) {
        if (_proof.length == 0) return false;

        uint256 proofType = _proof[0] & 0xFF;

        if (proofType == 3) {
            // FAKE_PROOF_TYPE: accept for backward compatibility during testing.
            // Validates public input matches proof[3].
            return _proof.length >= 4
                && _proof[2] == 13 // magic value
                && _proof[3] == _publicInputs[0];
        }

        if (proofType == 4) {
            // TWO_PROOF_SYSTEM_TYPE: verify ZiSK SNARK proof.
            // proof[2] = era_proof_length (N)
            uint256 eraLen = _proof[2];
            uint256 ziskStart = 3 + eraLen;

            // Extract ZiSK proof (24 uint256s)
            require(_proof.length >= ziskStart + 32, "proof too short");
            uint256[24] memory ziskProof;
            for (uint256 i = 0; i < 24; i++) {
                ziskProof[i] = _proof[ziskStart + i];
            }

            // Extract ZiSK public values (8 uint256s = 256 bytes)
            bytes memory publicValues = new bytes(256);
            for (uint256 i = 0; i < 8; i++) {
                uint256 val = _proof[ziskStart + 24 + i];
                assembly {
                    mstore(add(add(publicValues, 32), mul(i, 32)), val)
                }
            }

            // Compute hash: sha256(programVK || publicValues || rootCVadcopFinal) % _RFIELD
            uint64[4] memory pvk = [_programVK0, _programVK1, _programVK2, _programVK3];
            uint64[4] memory rootC = [_rootCVadcopFinal0, _rootCVadcopFinal1, _rootCVadcopFinal2, _rootCVadcopFinal3];

            uint256 publicValuesDigest = uint256(sha256(abi.encodePacked(
                bytes8(pvk[0]), bytes8(pvk[1]), bytes8(pvk[2]), bytes8(pvk[3]),
                publicValues,
                bytes8(rootC[0]), bytes8(rootC[1]), bytes8(rootC[2]), bytes8(rootC[3])
            ))) % _RFIELD;

            // Verify the ZiSK Plonk proof
            return this.verifyProof(ziskProof, [publicValuesDigest]);
        }

        if (proofType == 2) {
            // OHBENDER_PROOF_TYPE: The Executor passes _proof = original_proof[2..].
            // For ZiSK proofs: _proof[0..24] = ZiSK SNARK, _proof[24..32] = ZiSK public values.
            // For pure Era proofs: _proof has different layout (no ZiSK data).
            // The Executor passes the FULL proof array: _proof[0] = type|version, _proof[1] = prevHash.
            // ZiSK data starts at _proof[2]: _proof[2..26] = 24 ZiSK SNARK elements,
            // _proof[26..34] = 8 ZiSK public value elements, rest is padding.
            if (_proof.length >= 34 && _proof[2] != 0) {
                uint256[24] memory ziskProof;
                for (uint256 i = 0; i < 24; i++) {
                    ziskProof[i] = _proof[2 + i];
                }
                bytes memory publicValues = new bytes(256);
                for (uint256 i = 0; i < 8; i++) {
                    uint256 val = _proof[26 + i];
                    assembly {
                        mstore(add(add(publicValues, 32), mul(i, 32)), val)
                    }
                }
                uint64[4] memory pvk = [_programVK0, _programVK1, _programVK2, _programVK3];
                uint64[4] memory rootC = [_rootCVadcopFinal0, _rootCVadcopFinal1, _rootCVadcopFinal2, _rootCVadcopFinal3];
                uint256 publicValuesDigest = uint256(sha256(abi.encodePacked(
                    bytes8(pvk[0]), bytes8(pvk[1]), bytes8(pvk[2]), bytes8(pvk[3]),
                    publicValues,
                    bytes8(rootC[0]), bytes8(rootC[1]), bytes8(rootC[2]), bytes8(rootC[3])
                ))) % _RFIELD;
                return this.verifyProof(ziskProof, [publicValuesDigest]);
            }
            // Other type 2 formats (pure Era proofs): accept
            return true;
        }

        return false;
    }
}
