// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/ZiskVerifier.sol";

contract ZiskVerifierTest is Test {
    ZiskVerifier verifier;

    function setUp() public {
        verifier = new ZiskVerifier();
    }

    function test_deployment() public view {
        assertEq(keccak256(bytes(verifier.VERSION())), keccak256(bytes("v0.16.1")));
    }

    function test_rootCVadcopFinal() public view {
        uint64[4] memory root = verifier.getRootCVadcopFinal();
        assertTrue(root[0] != 0);
    }

    function test_hashPublicValues_deterministic() public view {
        uint64[4] memory programVK = [uint64(1), uint64(2), uint64(3), uint64(4)];
        uint64[4] memory rootC = verifier.getRootCVadcopFinal();
        bytes memory pubVals = hex"deadbeef";
        uint256 h1 = verifier.hashPublicValues(programVK, rootC, pubVals);
        uint256 h2 = verifier.hashPublicValues(programVK, rootC, pubVals);
        assertEq(h1, h2);
        assertTrue(h1 > 0);
    }

    function test_invalidProof_reverts() public {
        uint64[4] memory programVK = [uint64(1), uint64(2), uint64(3), uint64(4)];
        uint64[4] memory rootC = verifier.getRootCVadcopFinal();
        bytes memory pubVals = hex"deadbeef";
        uint256[24] memory zeros;
        bytes memory fakeProof = abi.encode(zeros);
        vm.expectRevert(ZiskVerifier.InvalidProof.selector);
        verifier.verifySnarkProof(programVK, rootC, pubVals, fakeProof);
    }
}
