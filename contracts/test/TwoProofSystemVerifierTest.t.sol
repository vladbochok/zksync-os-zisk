// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/TwoProofSystemVerifier.sol";
import "../src/ZiskVerifier.sol";

/// @dev Mock Era verifier with configurable return value and recorded inputs.
contract MockEraVerifier is IVerifier {
    bool public shouldPass;
    uint256 public lastPubInput;

    constructor(bool _shouldPass) {
        shouldPass = _shouldPass;
    }

    function setShouldPass(bool _shouldPass) external {
        shouldPass = _shouldPass;
    }

    function verify(
        uint256[] calldata _publicInputs,
        uint256[] calldata
    ) external view override returns (bool) {
        // Record isn't possible in view, but we can at least validate format
        require(_publicInputs.length > 0, "no public inputs");
        return shouldPass;
    }
}

contract TwoProofSystemVerifierTest is Test {
    TwoProofSystemVerifier twoProof;
    ZiskVerifier ziskVerifier;
    MockEraVerifier mockEraVerifier;

    // Real programVK from ROM setup
    uint64[4] pvk = [
        uint64(1549616599489752631),
        uint64(6336757390536716872),
        uint64(1925050955152680221),
        uint64(18018826643453830405)
    ];

    function setUp() public {
        ziskVerifier = new ZiskVerifier();
        mockEraVerifier = new MockEraVerifier(true);

        uint64[4] memory rootC = ziskVerifier.getRootCVadcopFinal();

        twoProof = new TwoProofSystemVerifier(
            address(mockEraVerifier),
            address(ziskVerifier),
            pvk,
            rootC
        );
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    function _ziskPublicValues() internal pure returns (bytes memory) {
        return hex"aa8ce23bb15132f9f9bd720d36e1d0179855213c627e8073c3bae5c8cc369106"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000";
    }

    function _ziskProofBytes() internal pure returns (bytes memory) {
        return hex"24db945586c3f0906ee2659cdf7e329a0b2b6aef3375f957ba01198c4738d8dd"
            hex"1209bb4033a7f2218a85a350e846b26d26a6be2f7d9d058ec2a3c244bc1be21f"
            hex"17502dc2963521d876171a7293454fa10defff2d0962cbeb435398ab366acd20"
            hex"00ae7dadfb35047feb0382fca3e7b7e396864150a9b03e9b5ade7916006e7d36"
            hex"27864fb54a967a238924a0f1f0d9630b6ab8f9f2c47a89d90ad22f9bc8b34943"
            hex"0462acdcd293bc4b873432d146d3bf435dd4b7bd58af430816fb223b42467189"
            hex"2277aa910d718825341a7f612df0d0680fb4ba0e7d9aefa268686929a9f3e4ce"
            hex"0085eca306317af830565960b9cc43781ae621558361baf9c1363eaae4221a43"
            hex"2229fe035a111e7a867ce472d7e5673bf1868f1557135b22d2edac1f7eb162ba"
            hex"1133fc2cf6c4ea48c72036ba1d481b0e17b97842a0d940998c00af0fcd3f9322"
            hex"2fd63cebd5f5983e2cf396622cfb759fd4ea33e79e221e9393f9ad4adc9d56b3"
            hex"1c7a6a0133a62fe63538a39e30677182f1dd07ff732e081cbe9d27ecf63b7a3c"
            hex"2523288246802bcf6804cd1e596449d7ea828882fd30f944247d48cee946e8e2"
            hex"2801cc062c7174d256c8693783b03015db329ea68b8a8727f5987db340e67d03"
            hex"1bb7affe1c046f8715a9c16a03da0b0140e0e596f2523eaa2b9f67d3fefb8374"
            hex"1c1e7a7a3f33d58e4adbfdc0a25adb369d5cdbf94ccbef4c1226da9f534e2791"
            hex"1c5943ae20e59b6f648637ddea5309c97c7fcbd6949bfca20cf34730ae8b2955"
            hex"0f77a90b4d0df61a32f74083766e1060bc933c3a5ed8049d49f8467b48b764ed"
            hex"19e258bac255b184ef9ef07264e4ef21bd1a52044cd001a4c54a03333aa0bada"
            hex"16dea83ad0170c870e20074ae15428ce49d3ac9e6de97723971c8817894d8039"
            hex"25dcafcfbd939bd687b3f7ecb61e601d7b855fa20feb5cc4196d47b8f2580d93"
            hex"2b915e76756df81ea67d066899fa4950b0d98cd94b05e6f09329b9a0656ea806"
            hex"05d1453048fa4271301e5e5d3111165727a8ad21dbc6fb5568be539ebd62ab43"
            hex"072f918d912daa6bb68dacb6bc3c780a50ea7906e7a65ddeb4291264d2d402b6";
    }

    /// @dev Build eraPubInputs that matches the ZiSK commitment (shifted right 32 bits).
    function _matchingEraPubInputs() internal pure returns (uint256[] memory) {
        // ZiSK commitment = 0xaa8ce23bb15132f9f9bd720d36e1d0179855213c627e8073c3bae5c8cc369106
        // Shifted right 32 bits: top 4 bytes zeroed, bottom 4 bytes dropped
        // = 0x00000000aa8ce23bb15132f9f9bd720d36e1d0179855213c627e8073c3bae5c8
        uint256 commitment = 0xaa8ce23bb15132f9f9bd720d36e1d0179855213c627e8073c3bae5c8cc369106;
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = commitment >> 32;
        return inputs;
    }

    function _mismatchedEraPubInputs() internal pure returns (uint256[] memory) {
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = 0xdeadbeef; // does NOT match ZiSK commitment
        return inputs;
    }

    function _dummyEraProof() internal pure returns (uint256[] memory) {
        uint256[] memory proof = new uint256[](1);
        proof[0] = 0xabcd;
        return proof;
    }

    // ── Tests ───────────────────────────────────────────────────────────

    function test_deployment() public view {
        assertEq(address(twoProof.eraVerifier()), address(mockEraVerifier));
        assertEq(address(twoProof.ziskVerifier()), address(ziskVerifier));

        uint64[4] memory storedPVK = twoProof.programVK();
        assertEq(storedPVK[0], pvk[0]);
        assertEq(storedPVK[1], pvk[1]);
        assertEq(storedPVK[2], pvk[2]);
        assertEq(storedPVK[3], pvk[3]);

        uint64[4] memory storedRoot = twoProof.rootCVadcopFinal();
        uint64[4] memory expectedRoot = ziskVerifier.getRootCVadcopFinal();
        assertEq(storedRoot[0], expectedRoot[0]);
        assertEq(storedRoot[1], expectedRoot[1]);
        assertEq(storedRoot[2], expectedRoot[2]);
        assertEq(storedRoot[3], expectedRoot[3]);
    }

    function test_realZiskProof_withMockEra() public view {
        twoProof.verifyTwoProofs(
            _matchingEraPubInputs(),
            _dummyEraProof(),
            _ziskPublicValues(),
            _ziskProofBytes()
        );
    }

    function test_invalidEraProof_reverts() public {
        mockEraVerifier.setShouldPass(false);

        vm.expectRevert(TwoProofSystemVerifier.EraProofInvalid.selector);
        twoProof.verifyTwoProofs(
            _matchingEraPubInputs(),
            _dummyEraProof(),
            _ziskPublicValues(),
            _ziskProofBytes()
        );
    }

    function test_invalidZiskProof_reverts() public {
        bytes memory badProof = _ziskProofBytes();
        badProof[0] = 0xff;

        vm.expectRevert(TwoProofSystemVerifier.ZiskProofInvalid.selector);
        twoProof.verifyTwoProofs(
            _matchingEraPubInputs(),
            _dummyEraProof(),
            _ziskPublicValues(),
            badProof
        );
    }

    function test_invalidZiskPublicValues_reverts() public {
        bytes memory badPubVals = _ziskPublicValues();
        badPubVals[0] = 0xff;

        // Commitment changes → mismatch with Era pub input
        vm.expectRevert(TwoProofSystemVerifier.BatchCommitmentMismatch.selector);
        twoProof.verifyTwoProofs(
            _matchingEraPubInputs(),
            _dummyEraProof(),
            badPubVals,
            _ziskProofBytes()
        );
    }

    function test_batchCommitmentMismatch_reverts() public {
        // Era public input does NOT match ZiSK commitment
        vm.expectRevert(TwoProofSystemVerifier.BatchCommitmentMismatch.selector);
        twoProof.verifyTwoProofs(
            _mismatchedEraPubInputs(),
            _dummyEraProof(),
            _ziskPublicValues(),
            _ziskProofBytes()
        );
    }

    function test_wrongPublicValuesLength_reverts() public {
        bytes memory shortPubVals = hex"aa8ce23b"; // only 4 bytes

        vm.expectRevert(TwoProofSystemVerifier.InvalidPublicValuesLength.selector);
        twoProof.verifyTwoProofs(
            _matchingEraPubInputs(),
            _dummyEraProof(),
            shortPubVals,
            _ziskProofBytes()
        );
    }

    function test_bothProofsRequired() public {
        // Both pass
        twoProof.verifyTwoProofs(
            _matchingEraPubInputs(),
            _dummyEraProof(),
            _ziskPublicValues(),
            _ziskProofBytes()
        );

        // Era fails → reverts even though ZiSK would pass
        mockEraVerifier.setShouldPass(false);
        vm.expectRevert(TwoProofSystemVerifier.EraProofInvalid.selector);
        twoProof.verifyTwoProofs(
            _matchingEraPubInputs(),
            _dummyEraProof(),
            _ziskPublicValues(),
            _ziskProofBytes()
        );
    }

    function test_backwardCompat_ziskVerifierAlone() public view {
        // Standalone ZiskVerifier still works independently
        ziskVerifier.verifySnarkProof(
            pvk,
            ziskVerifier.getRootCVadcopFinal(),
            _ziskPublicValues(),
            _ziskProofBytes()
        );
    }

    function test_commitmentBindingIsCorrect() public view {
        // Verify the shift relationship manually
        uint256 fullCommitment = 0xaa8ce23bb15132f9f9bd720d36e1d0179855213c627e8073c3bae5c8cc369106;
        uint256 shifted = fullCommitment >> 32;

        uint256[] memory eraPubInputs = _matchingEraPubInputs();
        assertEq(eraPubInputs[0], shifted);

        // The bottom 4 bytes are lost in the shift
        assertEq(shifted, 0x00000000aa8ce23bb15132f9f9bd720d36e1d0179855213c627e8073c3bae5c8);
    }
}
