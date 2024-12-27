import { MerkleTree, mimcHash2 } from './merkleTree';
import { groth16 } from './circuit';
import path from 'path';

const wasmPath = path.join(__dirname, '../build/otp.wasm');
const zkeyPath = path.join(__dirname, '../build/otp.zkey');
const vkeyTreePath = path.join(__dirname, '../build/verification_key_otp.json');
export const vkeyOTP = require(vkeyTreePath);

export async function generateOTPProof(currentTime: number, actions_hash: bigint, tree: MerkleTree, tokens: any) {
    let currentNode = mimcHash2(BigInt(currentTime), BigInt(tokens[currentTime]));

    const index = tree.getIndex(currentNode);
    let route = tree.proof(index);

    let input = {
        time: currentTime,
        root: BigInt(tree.root()),
        actions_hash: actions_hash,
        otp: tokens[currentTime],
        path_elements: route.pathElements,
        path_index: route.pathIndices
    };

    return await groth16.fullProve(input, wasmPath, zkeyPath);
}
