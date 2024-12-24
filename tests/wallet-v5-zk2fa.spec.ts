import { Blockchain, BlockchainTransaction, SandboxContract } from '@ton/sandbox';
import { beginCell, Cell, Dictionary, Sender, toNano } from '@ton/core';
import { Opcodes, WalletId, WalletV5 } from '../wrappers/wallet-v5';
import '@ton/test-utils';
import { compile } from '@ton/blueprint';
import { getSecureRandomBytes, KeyPair, keyPairFromSeed, sign } from 'ton-crypto';
import { bufferToBigInt, createMsgInternal, validUntil } from './utils';
import {
    ActionAddExtension,
    ActionRemoveExtension,
    ActionSendMsg,
    ActionSetSignatureAuthAllowed,
    packActionsList
} from './actions';
import { TransactionDescriptionGeneric } from '@ton/core/src/types/TransactionDescription';
import { TransactionComputeVm } from '@ton/core/src/types/TransactionComputePhase';
import { buildBlockchainLibraries, LibraryDeployer } from '../wrappers/library-deployer';
import { Zk2FA } from '../wrappers/zk2fa';
import { MerkleTree, mimcHash2 } from '../utils/merkleTree';
import * as fs from 'node:fs';
import { groth16 } from '../utils/circuit';
import { randomAddress } from '@ton/test-utils';
import { TOTP } from 'totp-generator';
import { authenticator } from 'otplib';
import { generateOTPProof, vkeyOTP } from '../utils/proofGenerator';

const WALLET_ID = new WalletId({ networkGlobalId: -239, workChain: 0, subwalletNumber: 0 });

const SECRET = authenticator.generateSecret(20);
console.log('SECRET', SECRET);
const startTime = Math.floor(Date.now() / 30000 - 1) * 30000;

describe('Wallet V5 zk2fa extension auth', () => {
    let code: Cell;
    let codeZk2FA: Cell;

    beforeAll(async () => {
        code = await compile('wallet_v5');
        codeZk2FA = await compile('zk2fa');
    });
    let tree: MerkleTree;
    let time;
    let tokens: {
        [key: number]: string;
    } = {};

    let blockchain: Blockchain;
    let walletV5: SandboxContract<WalletV5>;
    let zk2fa: SandboxContract<Zk2FA>;
    let keypair: KeyPair;
    let sender: Sender;
    let seqno: number;

    let ggc: bigint = BigInt(0);
    function accountForGas(transactions: BlockchainTransaction[]) {
        transactions.forEach(tx => {
            ggc +=
                (
                    (tx?.description as TransactionDescriptionGeneric)
                        ?.computePhase as TransactionComputeVm
                )?.gasUsed ?? BigInt(0);
        });
    }

    afterAll(async () => {
        console.log('EXTENSIONS TESTS: Total gas ' + ggc);
    });

    function createBody(actionsList: Cell) {
        const payload = beginCell()
            .storeUint(Opcodes.auth_signed_internal, 32)
            .storeUint(WALLET_ID.serialized, 32)
            .storeUint(validUntil(), 32)
            .storeUint(seqno, 32) // seqno
            .storeSlice(actionsList.beginParse())
            .endCell();

        const signature = sign(payload.hash(), keypair.secretKey);
        seqno++;
        return beginCell()
            .storeSlice(payload.beginParse())
            .storeUint(bufferToBigInt(signature), 512)
            .endCell();
    }

    function signBodyForExtension(body: Cell) {
        const signature = sign(body.hash(), keypair.secretKey);
        return beginCell()
            .storeUint(bufferToBigInt(signature), 512)
            .storeSlice(body.beginParse())
            .endCell();
    }

    function createBodyFromExtension(actionsList: Cell) {
        const payload = beginCell()
            .storeUint(Opcodes.auth_extension, 32)
            .storeUint(0, 64) // query id
            .storeSlice(actionsList.beginParse())
            .endCell();

        return payload;
    }

    beforeEach(async () => {
        blockchain = await Blockchain.create();
        blockchain.libs = buildBlockchainLibraries([code]);

        keypair = keyPairFromSeed(await getSecureRandomBytes(32));

        walletV5 = blockchain.openContract(
            WalletV5.createFromConfig(
                {
                    signatureAllowed: true,
                    seqno: 0,
                    walletId: WALLET_ID.serialized,
                    publicKey: keypair.publicKey,
                    extensions: Dictionary.empty()
                },
                LibraryDeployer.exportLibCode(code)
            )
        );

        const deployer = await blockchain.treasury('deployer');
        sender = deployer.getSender();

        const deployResult = await walletV5.sendDeploy(sender, toNano('10'));

        expect(deployResult.transactions).toHaveTransaction({
            from: deployer.address,
            to: walletV5.address,
            deploy: true,
            success: true
        });
        // let list = []
        // for (var i = 0; i < 2 ** 17; i++) {
        //     time = startTime + i * 30000;
        //     let token = TOTP.generate(SECRET, { timestamp: time });
        //     tokens[time] = token.otp;
        //     list.push(mimcHash2(BigInt(time), token.otp));
        // }
        // tree = new MerkleTree(17, list, mimcHash2);
        //
        // const backup = {
        //     storage: [...tree.storage],
        //     total: tree.totalLeaves,
        //     tokens: tokens
        // }
        // // save the tree in the file
        // fs.writeFileSync('tree.json', JSON.stringify(backup));

        // load the tree from the file
        const data = fs.readFileSync('tree.json', 'utf8');
        const backup = JSON.parse(data);
        tree = new MerkleTree(17, [], mimcHash2);
        tree.storage = new Map(backup.storage);
        tree.totalLeaves = backup.total;
        tokens = backup.tokens;
        blockchain.now = Math.floor(new Date().getTime() / 1000);
        zk2fa = blockchain.openContract(
            Zk2FA.createFromConfig(
                {
                    expiration: Math.floor(new Date().getTime() / 1000) + 30 * 24 * 60 * 60,
                    publicKey: keypair.publicKey,
                    root: BigInt(tree.root()),
                    walletAddress: walletV5.address
                },
                codeZk2FA
            )
        );
        seqno = 0;

        const addExtensionResult = await walletV5.sendInternalSignedMessage(sender, {
            value: toNano(0.1),
            body: createBody(packActionsList([new ActionAddExtension(zk2fa.address!)]))
        });
        expect(addExtensionResult.transactions).toHaveTransaction({
            from: sender.address,
            to: walletV5.address,
            success: true
        });

        const deployZk2faResult = await zk2fa.sendDeploy(
            sender,
            toNano('1'),
            createBodyFromExtension(packActionsList([new ActionSetSignatureAuthAllowed(false)]))
        );
        expect(deployZk2faResult.transactions).toHaveTransaction({
            from: deployer.address,
            to: zk2fa.address,
            deploy: true,
            success: true
        });
        expect(deployZk2faResult.transactions).toHaveTransaction({
            from: zk2fa.address,
            to: walletV5.address,
            success: true
        });

        // add extension and disable signature on wallet

        const isSignatureAuthAllowed1 = await walletV5.getIsSignatureAuthAllowed();
        expect(isSignatureAuthAllowed1).toEqual(0);
    });

    it('remove the 2fa from wallet', async () => {
        if (!sender.address) {
            throw new Error('Sender address is not set');
        }
        if (!blockchain.now) {
            throw new Error('Blockchain time is not set');
        }

        blockchain.now += 1 * 24 * 60 * 60; // 1 day passed
        let currentTime = Math.floor(blockchain.now / 30) * 30000;

        const { proof, publicSignals } = await generateOTPProof(currentTime, tree, tokens);
        let verify = await groth16.verify(vkeyOTP, publicSignals, proof);

        expect(verify).toBeTruthy();

        const receipt = await zk2fa.sendExternalSignedMessage(
            signBodyForExtension(
                Zk2FA.cancel_otp_body(
                    blockchain.now + 60 * 3,
                    await zk2fa.getSeqno(),
                    {
                        timeMS: currentTime,
                        proof
                    },
                    createBodyFromExtension(
                        packActionsList([
                            new ActionSetSignatureAuthAllowed(true),
                            new ActionRemoveExtension(zk2fa.address!)
                        ])
                    )
                )
            )
        );

        expect(receipt.transactions).toHaveTransaction({
            from: zk2fa.address,
            to: walletV5.address,
            success: true
        });

        const isSignatureAuthAllowed1 = await walletV5.getIsSignatureAuthAllowed();
        expect(isSignatureAuthAllowed1).toEqual(-1);

        const extensionList = await walletV5.getExtensionsArray();
        expect(extensionList.length).toEqual(0);
    });

    it('Do a few transfers transfer with zk2fa', async () => {
        if (!sender.address) {
            throw new Error('Sender address is not set');
        }
        if (!blockchain.now) {
            throw new Error('Blockchain time is not set');
        }

        blockchain.now += 2 * 24 * 60 * 60; // 1 day passed
        let currentTime = Math.floor(blockchain.now / 30) * 30000;

        const { proof, publicSignals } = await generateOTPProof(currentTime, tree, tokens);
        let verify = await groth16.verify(vkeyOTP, publicSignals, proof);

        expect(verify).toBeTruthy();
        const receiver1 = randomAddress();
        const receiver2 = randomAddress();
        const receipt = await zk2fa.sendExternalSignedMessage(
            signBodyForExtension(
                Zk2FA.send_message_with_otp_body_ext(
                    blockchain.now + 60 * 3,
                    await zk2fa.getSeqno(),
                    {
                        timeMS: currentTime,
                        proof
                    },
                    toNano(0.02),
                    createBodyFromExtension(
                        packActionsList([
                            new ActionSendMsg(
                                1,
                                createMsgInternal({
                                    dest: receiver1,
                                    value: toNano(1)
                                })
                            ),
                            new ActionSendMsg(
                                1,
                                createMsgInternal({
                                    dest: receiver2,
                                    value: toNano(2)
                                })
                            )
                        ])
                    )
                )
            )
        );

        expect(receipt.transactions).toHaveTransaction({
            from: zk2fa.address,
            to: walletV5.address,
            success: true
        });

        expect(receipt.transactions).toHaveTransaction({
            from: walletV5.address,
            to: receiver1
        });

        expect(receipt.transactions).toHaveTransaction({
            from: walletV5.address,
            to: receiver2
        });

        expect((await blockchain.getContract(receiver2)).balance).toEqual(toNano(2));
        expect((await blockchain.getContract(receiver1)).balance).toEqual(toNano(1));
    });

    it('make 3 wrong otp attempt and lock the wallet external', async () => {
        if (!sender.address) {
            throw new Error('Sender address is not set');
        }
        if (!blockchain.now) {
            throw new Error('Blockchain time is not set');
        }

        blockchain.now += 2 * 24 * 60 * 60; // 1 day passed
        let currentTime = Math.floor(blockchain.now / 30) * 30000;

        const { proof, publicSignals } = await generateOTPProof(currentTime, tree, tokens);
        let verify = await groth16.verify(vkeyOTP, publicSignals, proof);

        expect(verify).toBeTruthy();
        const receiver1 = randomAddress();
        const receiver2 = randomAddress();
        for (let i = 0; i < 4; i++) {
            let timeStampInput = i < 3 ? currentTime + 1 : currentTime;
            const receipt = await zk2fa.sendExternalSignedMessage(
                signBodyForExtension(
                    Zk2FA.send_message_with_otp_body_ext(
                        blockchain.now + 60 * 3,
                        await zk2fa.getSeqno(),
                        {
                            timeMS: timeStampInput,
                            proof
                        },
                        toNano(0.02),
                        createBodyFromExtension(
                            packActionsList([
                                new ActionSendMsg(
                                    1,
                                    createMsgInternal({
                                        dest: receiver1,
                                        value: toNano(1)
                                    })
                                ),
                                new ActionSendMsg(
                                    1,
                                    createMsgInternal({
                                        dest: receiver2,
                                        value: toNano(2)
                                    })
                                )
                            ])
                        )
                    )
                )
            );

            expect(receipt.transactions).toHaveTransaction({
                from: undefined,
                to: zk2fa.address,
                success: true
            });
            expect(receipt.transactions.length).toEqual(1);
        }
        const mode = await zk2fa.getMode();
        expect(mode).toEqual(1);
    });

    it('make 3 wrong otp attempt and lock the wallet external and then disable the emergency', async () => {
        if (!sender.address) {
            throw new Error('Sender address is not set');
        }
        if (!blockchain.now) {
            throw new Error('Blockchain time is not set');
        }

        blockchain.now += 2 * 24 * 60 * 60; // 1 day passed
        let currentTime = Math.floor(blockchain.now / 30) * 30000;

        const { proof, publicSignals } = await generateOTPProof(currentTime, tree, tokens);
        let verify = await groth16.verify(vkeyOTP, publicSignals, proof);

        expect(verify).toBeTruthy();
        const receiver1 = randomAddress();
        const receiver2 = randomAddress();
        for (let i = 0; i < 4; i++) {
            let timeStampInput = i < 3 ? currentTime + 1 : currentTime;
            const receipt = await zk2fa.sendExternalSignedMessage(
                signBodyForExtension(
                    Zk2FA.send_message_with_otp_body_ext(
                        blockchain.now + 60 * 3,
                        await zk2fa.getSeqno(),
                        {
                            timeMS: timeStampInput,
                            proof
                        },
                        toNano(0.02),
                        createBodyFromExtension(
                            packActionsList([
                                new ActionSendMsg(
                                    1,
                                    createMsgInternal({
                                        dest: receiver1,
                                        value: toNano(1)
                                    })
                                ),
                                new ActionSendMsg(
                                    1,
                                    createMsgInternal({
                                        dest: receiver2,
                                        value: toNano(2)
                                    })
                                )
                            ])
                        )
                    )
                )
            );

            expect(receipt.transactions).toHaveTransaction({
                from: undefined,
                to: zk2fa.address,
                success: true
            });
            expect(receipt.transactions.length).toEqual(1);
        }
        const mode = await zk2fa.getMode();
        expect(mode).toEqual(1);

        currentTime = Math.floor(blockchain.now / 30) * 30000;

        const { proof: proof2, publicSignals: publicSignals2 } = await generateOTPProof(
            currentTime, tree, tokens
        );
        let verify2 = await groth16.verify(vkeyOTP, publicSignals2, proof2);
        expect(verify2).toBeTruthy();

        const result = await zk2fa.sendDisableEmergencyWithOtpInternal(
            sender,
            toNano(0.06),
            signBodyForExtension(
                Zk2FA.disable_emergency_with_otp_body({
                    timeMS: currentTime,
                    proof: proof2
                })
            )
        );
        expect(result.transactions).toHaveTransaction({
            from: sender.address,
            to: zk2fa.address,
            success: true
        });

        const mode2 = await zk2fa.getMode();
        expect(mode2).toEqual(0);
    });

    it('update code', async () => {
        if (!sender.address) {
            throw new Error('Sender address is not set');
        }
        if (!blockchain.now) {
            throw new Error('Blockchain time is not set');
        }

        blockchain.now += 2 * 24 * 60 * 60; // 1 day passed
        let currentTime = Math.floor(blockchain.now / 30) * 30000;

        const { proof, publicSignals } = await generateOTPProof(currentTime, tree, tokens);
        let verify = await groth16.verify(vkeyOTP, publicSignals, proof);

        expect(verify).toBeTruthy();

        const result = await zk2fa.sendSetCode(
            sender,
            toNano(0.06),
            signBodyForExtension(
                Zk2FA.set_code_with_otp_body(
                    {
                        timeMS: currentTime,
                        proof: proof
                    },
                    codeZk2FA
                )
            )
        );

        expect(result.transactions).toHaveTransaction({
            from: sender.address,
            to: zk2fa.address,
            success: true
        });
    });
});
