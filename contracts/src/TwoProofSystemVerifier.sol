// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.20;

import {IZiskVerifier} from "./IZiskVerifier.sol";

/// @title Era Verifier Interface
/// @notice Standard interface for the ZKsync Era (airbender) SNARK verifier.
interface IVerifier {
    function verify(
        uint256[] calldata _publicInputs,
        uint256[] calldata _proof
    ) external view returns (bool);
}

/// @title Two Proof System Verifier
/// @notice Verifies both an Era (airbender) SNARK proof and a ZiSK SNARK proof
///         for the same batch. Both proofs must pass, and both must attest to the
///         same batch commitment, for verification to succeed.
///
///         The batch commitment is: keccak256(state_before || state_after || batch_hash).
///         - The Era verifier receives this >> 32 (top 4 bytes zeroed) as its public input.
///         - The ZiSK verifier receives the full hash as the first 32 bytes of publicValues.
///         This contract checks that they match.
contract TwoProofSystemVerifier {
    /// @notice Thrown when the Era proof verification fails.
    error EraProofInvalid();

    /// @notice Thrown when the ZiSK proof verification fails.
    error ZiskProofInvalid();

    /// @notice Thrown when the Era and ZiSK proofs attest to different batch commitments.
    error BatchCommitmentMismatch();

    /// @notice Thrown when ZiSK public values are not exactly 256 bytes.
    error InvalidPublicValuesLength();

    /// @notice The Era (airbender) verifier contract.
    IVerifier public immutable eraVerifier;

    /// @notice The ZiSK verifier contract (PlonkVerifier-based).
    IZiskVerifier public immutable ziskVerifier;

    /// @notice ZiSK ELF-specific verification key (4 uint64s).
    ///         Identifies the specific ZiSK guest binary. Immutable after deployment.
    uint64 private immutable _programVK0;
    uint64 private immutable _programVK1;
    uint64 private immutable _programVK2;
    uint64 private immutable _programVK3;

    /// @notice ZiSK vadcop final root commitment. Immutable after deployment.
    uint64 private immutable _rootCVadcopFinal0;
    uint64 private immutable _rootCVadcopFinal1;
    uint64 private immutable _rootCVadcopFinal2;
    uint64 private immutable _rootCVadcopFinal3;

    constructor(
        address _eraVerifier,
        address _ziskVerifier,
        uint64[4] memory programVK_,
        uint64[4] memory rootCVadcopFinal_
    ) {
        eraVerifier = IVerifier(_eraVerifier);
        ziskVerifier = IZiskVerifier(_ziskVerifier);
        _programVK0 = programVK_[0];
        _programVK1 = programVK_[1];
        _programVK2 = programVK_[2];
        _programVK3 = programVK_[3];
        _rootCVadcopFinal0 = rootCVadcopFinal_[0];
        _rootCVadcopFinal1 = rootCVadcopFinal_[1];
        _rootCVadcopFinal2 = rootCVadcopFinal_[2];
        _rootCVadcopFinal3 = rootCVadcopFinal_[3];
    }

    /// @notice Returns the ZiSK program verification key.
    function programVK() external view returns (uint64[4] memory) {
        return [_programVK0, _programVK1, _programVK2, _programVK3];
    }

    /// @notice Returns the ZiSK vadcop final root commitment.
    function rootCVadcopFinal() external view returns (uint64[4] memory) {
        return [_rootCVadcopFinal0, _rootCVadcopFinal1, _rootCVadcopFinal2, _rootCVadcopFinal3];
    }

    /// @notice Verifies both an Era proof and a ZiSK proof for the same batch.
    ///         Reverts if either proof is invalid or if the proofs attest to different batches.
    /// @param eraPubInputs The public inputs for the Era verifier.
    ///        eraPubInputs[0] must be the batch commitment hash >> 32.
    /// @param eraProof The Era SNARK proof elements.
    /// @param ziskPublicValues The ZiSK public values (exactly 256 bytes, padded).
    ///        The first 32 bytes must be the batch commitment hash (unshifted).
    /// @param ziskProofBytes The ZiSK SNARK proof (768 bytes = 24 uint256s).
    function verifyTwoProofs(
        uint256[] calldata eraPubInputs,
        uint256[] calldata eraProof,
        bytes calldata ziskPublicValues,
        bytes calldata ziskProofBytes
    ) external view {
        // 0. Validate inputs
        if (ziskPublicValues.length != 256) {
            revert InvalidPublicValuesLength();
        }
        require(eraPubInputs.length >= 1, "Era public inputs must contain at least 1 element");

        // 1. Extract batch commitments from both proofs and verify they match.
        //    Era public input = batchCommitment >> 32 (top 4 bytes zeroed).
        //    ZiSK public values first 32 bytes = batchCommitment (full).
        //    Verify: eraPubInputs[0] == uint256(ziskPublicValues[0:32]) >> 32
        uint256 ziskCommitment;
        assembly {
            // ziskPublicValues is calldata bytes; load first 32 bytes
            ziskCommitment := calldataload(ziskPublicValues.offset)
        }
        uint256 ziskCommitmentShifted = ziskCommitment >> 32;

        if (eraPubInputs[0] != ziskCommitmentShifted) {
            revert BatchCommitmentMismatch();
        }

        // 2. Verify Era proof
        bool eraOk = eraVerifier.verify(eraPubInputs, eraProof);
        if (!eraOk) {
            revert EraProofInvalid();
        }

        // 3. Verify ZiSK proof
        uint64[4] memory pvk = [_programVK0, _programVK1, _programVK2, _programVK3];
        uint64[4] memory rootC = [_rootCVadcopFinal0, _rootCVadcopFinal1, _rootCVadcopFinal2, _rootCVadcopFinal3];

        try ziskVerifier.verifySnarkProof(
            pvk,
            rootC,
            ziskPublicValues,
            ziskProofBytes
        ) {
            // ZiSK proof verified successfully
        } catch {
            revert ZiskProofInvalid();
        }
    }
}
