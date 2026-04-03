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

    function test_realProof_verifies() public view {
        // programVK from ROM setup: Root hash: [1549616599489752631, 6336757390536716872, 1925050955152680221, 18018826643453830405]
        uint64[4] memory programVK = [
            uint64(1549616599489752631),
            uint64(6336757390536716872),
            uint64(1925050955152680221),
            uint64(18018826643453830405)
        ];

        // rootCVadcopFinal from ZiskVerifier.sol
        uint64[4] memory rootC = verifier.getRootCVadcopFinal();

        // Public values: 256-byte padded public values from the ZiSK proof
        bytes memory publicValues = hex"aa8ce23bb15132f9f9bd720d36e1d0179855213c627e8073c3bae5c8cc369106"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000";

        // SNARK proof bytes (24 uint256 = 768 bytes)
        bytes memory proofBytes = hex"24db945586c3f0906ee2659cdf7e329a0b2b6aef3375f957ba01198c4738d8dd"
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

        // This should not revert
        verifier.verifySnarkProof(programVK, rootC, publicValues, proofBytes);
    }

    function test_realServerBatchProof_verifies() public view {
        // programVK from ROM setup of current guest ELF (after executor fixes)
        // Root hash: [9013678481712072447, 8463721137892339782, 6219610538620145591, 3608452059388590493]
        uint64[4] memory programVK = [
            uint64(9013678481712072447),
            uint64(8463721137892339782),
            uint64(6219610538620145591),
            uint64(3608452059388590493)
        ];

        uint64[4] memory rootC = verifier.getRootCVadcopFinal();

        // Public values from real server batch (7 txs: 6 L1→L2 deposits + 1 ETH transfer)
        bytes memory publicValues = hex"854e66c3355f9c4c550912575763dae593bcdedf0f9ebfb2b11886d5eaf30c7a"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000000";

        // SNARK proof from real server batch proving (768 bytes)
        bytes memory proofBytes = hex"22f642911ad395571f2f8f8d99277efe0593834a0803da25fd0e267d62cd4675"
            hex"2f17a7c40faa6e5ae4176b75f9f38417ade5d3684280eba8b06afc82cbe43118"
            hex"12056fec12c598022a3babea2faaa16e51b835140ba9117463ca8898b77fca4d"
            hex"23f0f1a9491017891ab1bf6056e0cdad0940e02f4b3d109b72bd34ba59072368"
            hex"044e6ff7a7b16d3b6bc0da0e893785ca2f024f9b7d455d835d74e4022d81501e"
            hex"159accf74f262c4576190813b538fabf472e40d543873b2b99062aeb86ced618"
            hex"1126c7aad0c05639ac273d004949c470676589576077996b6abac790554af6f0"
            hex"187e786c4ff94590406b44d802d515f26a3504e6997865177c39915a565ad7e1"
            hex"18b51ae86910e47e6943b22497bd721e25546da2965cc37921f4fcd75aaf6d86"
            hex"04bd6205acb36cc0eb469ed6177bf0e86a9382856c315f11396a84ff5f52d8f2"
            hex"26990e2ea4c1ba262d9cc82548c0c20b920003cfe34f294bed2d52aac3038267"
            hex"1558312cf86790df2c6b3ac4251dad5c7223e606c28c074fc8ab6ebc179d16a8"
            hex"24629e4fdc45268d6eee768d311001c97453621332af338966902194c9dddb12"
            hex"15561960f4fec25316b14004afefb83dcd2eb51ffca362fe9723aabe4c626272"
            hex"1e94398f00fafda2accb619367aef1c593e204424579be64246464d9447cfb7f"
            hex"0430e92b63e655921dfe41b32687ea80003ffafde9a74bb2048c30ba214b91c3"
            hex"18beadb0f94f48bdba0f45afe9cf9b9bda6fea7a493fa5eddfccb901b1c68d62"
            hex"137784d160f03d0d7184bf0e39aa0588e7ad6845049328322a36ad0345eafa1e"
            hex"1c51eecb44e303e02fd936f12ea2718b5226353e5976434c078833abd339fbe3"
            hex"144c093b577d6665af114795a3616bbcd769b10e5924f858664ec08b9bcdd847"
            hex"1965ead15d1ba333f0425ade7e427076b975f08abb2d0788fe71c437204a78fe"
            hex"2d9cce844e4c6a9219c423708a1540660f862927515172e725819bb8f3d879d4"
            hex"2ac70e9820ae40cf4d9bf1eb849a22dc36280502caefc938dd55d4c134e6fb3f"
            hex"09a70c66bc50e7eeafe02b1d912f39a787849392abfda0a60515b945f500c9d2";

        verifier.verifySnarkProof(programVK, rootC, publicValues, proofBytes);
    }
}
