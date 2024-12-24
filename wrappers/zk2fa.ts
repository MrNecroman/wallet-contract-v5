import {
    Address,
    beginCell,
    Cell,
    Contract,
    contractAddress,
    ContractProvider,
    Sender,
    SendMode
} from '@ton/core';
import { parseG1Func, parseG2Func } from '../utils/circuit';

export type zk2faConfig = {
    root: bigint;
    expiration: number;
    publicKey: Buffer;
    walletAddress: Address;
};

export function zk2faConfigToCell(config: zk2faConfig): Cell {
    return beginCell()
        .storeUint(2, 2) // mode
        .storeUint(config.root, 256) // root
        .storeUint(0, 32) // nonce
        .storeUint(0, 64) // last_time
        .storeUint(0, 4) // failCount
        .storeUint(config.expiration, 32) // expiration time
        .storeBuffer(config.publicKey, 32)
        .storeAddress(config.walletAddress)
        .endCell();
}

export const Opcodes = {
    cancel_otp: 0x44626786,
    refresh_otp: 0x8e7757f3,
    send_msg: 0xba47ec87,
    disable_emergency: 0x80d28ffb,
    set_code: 0x9c0f3220
};

export class Zk2FA implements Contract {
    constructor(readonly address: Address, readonly init?: { code: Cell; data: Cell }) {}

    static createFromAddress(address: Address) {
        return new Zk2FA(address);
    }

    static cancel_otp_body(
        validUntil: number,
        seqno: number,
        otpProofData: {
            timeMS: number;
            proof: any;
        },
        actionlist: Cell
    ) {
        let B_x = otpProofData.proof.pi_b[0].map((num: string) => BigInt(num));
        let B_y = otpProofData.proof.pi_b[1].map((num: string) => BigInt(num));
        return beginCell()
            .storeUint(Opcodes.cancel_otp, 32)
            .storeUint(validUntil, 32)
            .storeUint(seqno, 32)
            .storeUint(otpProofData.timeMS, 64)
            .storeRef(
                beginCell()
                    .storeRef(
                        parseG1Func(
                            otpProofData.proof.pi_a.slice(0, 2).map((num: string) => BigInt(num))
                        )
                    )
                    .storeRef(parseG2Func(B_x[0], B_x[1], B_y))
                    .storeRef(
                        parseG1Func(
                            otpProofData.proof.pi_c.slice(0, 2).map((num: string) => BigInt(num))
                        )
                    )
            )
            .storeRef(actionlist)
            .endCell();
    }

    static refresh_otp_body_ext(
        validUntil: number,
        seqno: number,
        otpProofData: {
            timeMS: number;
            proof: any;
        },
        newRoot: bigint
    ) {
        let B_x = otpProofData.proof.pi_b[0].map((num: string) => BigInt(num));
        let B_y = otpProofData.proof.pi_b[1].map((num: string) => BigInt(num));
        return beginCell()
            .storeUint(Opcodes.cancel_otp, 32)
            .storeUint(validUntil, 32)
            .storeUint(seqno, 32)
            .storeUint(otpProofData.timeMS, 64)
            .storeUint(newRoot, 256)
            .storeRef(
                beginCell()
                    .storeRef(
                        parseG1Func(
                            otpProofData.proof.pi_a.slice(0, 2).map((num: string) => BigInt(num))
                        )
                    )
                    .storeRef(parseG2Func(B_x[0], B_x[1], B_y))
                    .storeRef(
                        parseG1Func(
                            otpProofData.proof.pi_c.slice(0, 2).map((num: string) => BigInt(num))
                        )
                    )
            )
            .endCell();
    }

    static send_message_with_otp_body_ext(
        validUntil: number,
        seqno: number,
        otpProofData: {
            timeMS: number;
            proof: any;
        },
        coins: bigint,
        actionlist: Cell
    ) {
        let B_x = otpProofData.proof.pi_b[0].map((num: string) => BigInt(num));
        let B_y = otpProofData.proof.pi_b[1].map((num: string) => BigInt(num));
        return beginCell()
            .storeUint(Opcodes.cancel_otp, 32)
            .storeUint(validUntil, 32)
            .storeUint(seqno, 32)
            .storeUint(otpProofData.timeMS, 64)
            .storeCoins(coins)
            .storeRef(
                beginCell()
                    .storeRef(
                        parseG1Func(
                            otpProofData.proof.pi_a.slice(0, 2).map((num: string) => BigInt(num))
                        )
                    )
                    .storeRef(parseG2Func(B_x[0], B_x[1], B_y))
                    .storeRef(
                        parseG1Func(
                            otpProofData.proof.pi_c.slice(0, 2).map((num: string) => BigInt(num))
                        )
                    )
            )
            .storeRef(actionlist)
            .endCell();
    }

    static disable_emergency_with_otp_body(otpProofData: { timeMS: number; proof: any }) {
        let B_x = otpProofData.proof.pi_b[0].map((num: string) => BigInt(num));
        let B_y = otpProofData.proof.pi_b[1].map((num: string) => BigInt(num));
        const payload = beginCell()
            .storeUint(Opcodes.disable_emergency, 32)
            .storeUint(otpProofData.timeMS, 64)
            .storeRef(
                beginCell()
                    .storeRef(
                        parseG1Func(
                            otpProofData.proof.pi_a.slice(0, 2).map((num: string) => BigInt(num))
                        )
                    )
                    .storeRef(parseG2Func(B_x[0], B_x[1], B_y))
                    .storeRef(
                        parseG1Func(
                            otpProofData.proof.pi_c.slice(0, 2).map((num: string) => BigInt(num))
                        )
                    )
            )
            .endCell();
        return payload;
    }

    static set_code_with_otp_body(otpProofData: { timeMS: number; proof: any }, code:Cell) {
        let B_x = otpProofData.proof.pi_b[0].map((num: string) => BigInt(num));
        let B_y = otpProofData.proof.pi_b[1].map((num: string) => BigInt(num));
        const payload = beginCell()
            .storeUint(Opcodes.set_code, 32)
            .storeUint(otpProofData.timeMS, 64)
            .storeRef(
                beginCell()
                    .storeRef(
                        parseG1Func(
                            otpProofData.proof.pi_a.slice(0, 2).map((num: string) => BigInt(num))
                        )
                    )
                    .storeRef(parseG2Func(B_x[0], B_x[1], B_y))
                    .storeRef(
                        parseG1Func(
                            otpProofData.proof.pi_c.slice(0, 2).map((num: string) => BigInt(num))
                        )
                    )
            )
            .storeRef(code)
            .endCell();
        return payload;
    }

    static createFromConfig(config: zk2faConfig, code: Cell, workchain = 0) {
        const data = zk2faConfigToCell(config);
        const init = { code, data };
        return new Zk2FA(contractAddress(workchain, init), init);
    }

    async sendDeploy(provider: ContractProvider, via: Sender, value: bigint, deployPayload: Cell) {
        await provider.internal(via, {
            value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body: beginCell().storeRef(deployPayload).endCell()
        });
    }

    async sendDisableEmergencyWithOtpInternal(
        provider: ContractProvider,
        via: Sender,
        value: bigint,
        payload: Cell
    ) {
        return await provider.internal(via, {
            value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body: beginCell()
                .storeUint(Opcodes.disable_emergency, 32)
                .storeUint(0, 64)
                .storeSlice(payload.beginParse())
                .endCell()
        });
    }

    async sendSetCode(
        provider: ContractProvider,
        via: Sender,
        value: bigint,
        payload: Cell
    ) {
        return await provider.internal(via, {
            value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body: beginCell()
                .storeUint(Opcodes.set_code, 32)
                .storeUint(0, 64)
                .storeSlice(payload.beginParse())
                .endCell()
        });
    }

    async sendExternalSignedMessage(provider: ContractProvider, body: Cell) {
        await provider.external(body);
    }

    async getSeqno(provider: ContractProvider) {
        const state = await provider.getState();
        if (state.state.type === 'active') {
            let res = await provider.get('seqno', []);
            return res.stack.readNumber();
        } else {
            return 0;
        }
    }

    async getMode(provider: ContractProvider) {
        let res = await provider.get('get_mode', []);
        return res.stack.readNumber();
    }

    async getFailedAttempts(provider: ContractProvider) {
        let res = await provider.get('get_failed_attempts', []);
        return res.stack.readNumber();
    }
}
