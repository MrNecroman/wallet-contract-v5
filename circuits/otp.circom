include "./mimcsponge.circom";
include "../node_modules/circomlib/circuits/mux1.circom";


template HashLeftRight() {
     signal input left;
        signal input right;
        signal output hash;

        component hasher = MiMCSponge(2, 220, 1);
        hasher.ins[0] <== left;
        hasher.ins[1] <== right;
        hasher.k <== 0;
        hash <== hasher.outs[0];
}


template OtpMerkleTreeInclusionProof(n) {
    signal input time;
    signal input root;
    signal private input otp;

    signal private input path_elements[n];
    signal private input path_index[n];

    component leafHasher = HashLeftRight();

    leafHasher.left <== time;
    leafHasher.right <== otp;

    signal leaf;
    leaf <== leafHasher.hash;

    component hashers[n];
    component mux[n];

    signal levelHashes[n + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < n; i++) {
        // Should be 0 or 1
        path_index[i] * (1 - path_index[i]) === 0;

        hashers[i] = HashLeftRight();
        mux[i] = MultiMux1(2);

        mux[i].c[0][0] <== levelHashes[i];
        mux[i].c[0][1] <== path_elements[i];

        mux[i].c[1][0] <== path_elements[i];
        mux[i].c[1][1] <== levelHashes[i];

        mux[i].s <== path_index[i];
        hashers[i].left <== mux[i].out[0];
        hashers[i].right <== mux[i].out[1];

        levelHashes[i + 1] <== hashers[i].hash;
    }
    root === levelHashes[n];

}

component main = OtpMerkleTreeInclusionProof(17); // 1 month
// component main = OtpMerkleTreeInclusionProof(17); // 1 year
