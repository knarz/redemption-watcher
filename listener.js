import fs from 'fs';
import ethers from 'ethers';

import BitcoinHelpers from '@keep-network/tbtc.js/src/BitcoinHelpers.js';
import EthereumHelpers from '@keep-network/tbtc.js/src/EthereumHelpers.js';

import TBTCSystem from "@keep-network/tbtc/artifacts/TBTCSystem.json";
import TBTCDepositToken from "@keep-network/tbtc/artifacts/TBTCDepositToken.json";
import Deposit from "@keep-network/tbtc/artifacts/Deposit.json";
import BondedECDSAKeep from "@keep-network/keep-ecdsa/artifacts/BondedECDSAKeep.json";
import DepositLog from "@keep-network/tbtc/artifacts/DepositLog.json";

if (process.argv.length < 3 || !process.argv[2]) {
	console.error('node listener.js [password]');
	process.exit(1);
}

let wallet;
let ip = new ethers.providers.InfuraProvider('homestead', process.env.INFURA_API);

const j = fs.readFileSync('wallet.json', 'utf8');
ethers.Wallet.fromEncryptedJson(j, process.argv[2]).then((w) => {
	wallet = w.connect(ip);
});

const tbtcSysContract = new ethers.Contract(TBTCSystem.networks["1"].address, TBTCSystem.abi, ip);

const states = [
	"START",
	"AWAITING_SIGNER_SETUP",
	"AWAITING_BTC_FUNDING_PROOF",
	"FAILED_SETUP",
	"ACTIVE",  // includes courtesy call
	"AWAITING_WITHDRAWAL_SIGNATURE",
	"AWAITING_WITHDRAWAL_PROOF",
	"REDEEMED",
	"COURTESY_CALL",
	"FRAUD_LIQUIDATION_IN_PROGRESS",
	"LIQUIDATION_IN_PROGRESS",
	"LIQUIDATED"
];

const fourHours = ethers.BigNumber.from((60 / 15) * 60 * 4) // ~4hours in blocks
const fiveMinutes = ethers.BigNumber.from((60 / 15) * 5) // ~5minutes in blocks
const redemptionProofTimeout = ethers.BigNumber.from(6 * 60 * 60); // 6 hours

async function filterDeposits(ev) {
	const [ dAddr, digest, r, s, ts ] = ev.args;

	const d = new ethers.Contract(dAddr, Deposit.abi, ip);
	const state = states[await d.currentState()];
	return state === 'AWAITING_WITHDRAWAL_PROOF';
}

async function broadcastSignedTx(rr, r, s) {
	const [ dAddr, requester, dgest, utxoValue, redeemerOutputScript, requestedFee, outpoint] = rr.args;
	const expectedValue = utxoValue.sub(requestedFee).toNumber();

	const d = new ethers.Contract(dAddr, Deposit.abi, ip);
	const unsignedTransaction = BitcoinHelpers.Transaction.constructOneInputOneOutputWitnessTransaction(
		outpoint.replace("0x", ""),
		0,
		expectedValue,
		EthereumHelpers.bytesToRaw(redeemerOutputScript)
	);

	const depositPks = await tbtcSysContract.queryFilter(tbtcSysContract.filters.RegisteredPubkey(d.address));
	const pk = depositPks[depositPks.length - 1].args;
	// 0. depositAddr, 1. X, 2. Y, 3. timestamp
	const signedTransaction = BitcoinHelpers.Transaction.addWitnessSignature(
		unsignedTransaction,
		0,
		r.replace("0x", ""),
		s.replace("0x", ""),
		BitcoinHelpers.publicKeyPointToPublicKeyString(
			pk[1],
			pk[2]
		)
	);

	while (true) {
		try {
			console.log(`broadcasting signedTransaction: ${signedTransaction}`);
			const bTx = await BitcoinHelpers.Transaction.broadcast(signedTransaction);
			return bTx.transactionID;
			break;
		} catch (err) {
			console.error(err.message);
		}
	}
}

async function extracFromRedemptionSig(ev) {
	const [ dAddr, digest, r, s, ts ] = ev;

	const rr = await tbtcSysContract.queryFilter(tbtcSysContract.filters.RedemptionRequested(null, null, digest))
	if (rr.length < 1) {
		console.log(`could not find redemption request for digest ${digest}`);
		return {};
	}

	const blockNumber = await ip.getBlockNumber();

	const out = {
		dAddr: dAddr,
		deadline: ts.add(redemptionProofTimeout),
		blockNum: ethers.BigNumber.from(blockNumber),
		blockTarget: ethers.BigNumber.from(blockNumber).add(fourHours),
	}

	console.log(`broadcast the bitcoin tx just in case`);
	out.transactionID = await broadcastSignedTx(rr[0], r, s);

	return out;
}

// bts is blockNum => Deposits[]
function addTarget(bts, tb, d) {
	if (bts.has(tb)) {
		bts.set(tb, bts.get(tb).concat([d]))
	} else {
		bts.set(tb, [d])
	}
}

const asyncFilter = async (arr, predicate) => 
	arr.reduce(async (memo, e) =>
		await predicate(e) ? [...await memo, e] : memo
		, []);


BitcoinHelpers.setElectrumConfig({
	server: "electrumx-server.tbtc.network",
	port: 8443,
	protocol: "wss"
});

async function main() {
	try {
		const blockTargets = new Map() // blocknum => [deposits]

		ip.on("block", async (blockNum) => {
			blockNum = blockNum.toString()
			const numTargets = blockTargets.get(blockNum) ? blockTargets.get(blockNum).length : 0;
			console.log(`[ #${blockNum.toString()} ] has ${numTargets} targets`)
			if (blockTargets.has(blockNum)) {
				for (let ds of blockTargets.get(blockNum)) {
					const d = new ethers.Contract(ds.dAddr, Deposit.abi, wallet);
					const depositState = states[await d.currentState()];
					if (depositState === 'AWAITING_WITHDRAWAL_PROOF') { // Proof was not submitted. We should do it >:[
						BitcoinHelpers.Transaction.waitForConfirmations(
							ds.transactionID,
							6,
							({transactionID, confirmations, requiredConfirmations}) => {
								console.log(`got ${confirmations} of ${requiredConfirmations} confirmations for ${ds.transactionID}`);
							}
						).then(async (conf) => {
							console.log(`got ${conf} for ${ds.transactionID}`);
							const {
								parsedTransaction,
								merkleProof,
								chainHeaders,
								txInBlockIndex
							} = await BitcoinHelpers.Transaction.getSPVProof(ds.transactionID, 6);
							const { version, txInVector, txOutVector, locktime } = parsedTransaction;
							console.log(`calling provideRedemptionProof()`);
							const proofTx = await d.provideRedemptionProof(
								Buffer.from(version, "hex"),
								Buffer.from(txInVector, "hex"),
								Buffer.from(txOutVector, "hex"),
								Buffer.from(locktime, "hex"),
								Buffer.from(merkleProof, "hex"),
								txInBlockIndex,
								Buffer.from(chainHeaders, "hex")
							);
							await proofTx.wait();
						})
					} else {
						console.log(`deposit ${ds.dAddr} was redeemed properly`)
					}
				}
			}
		})

		// Check for pending redemption requests that we might want to pick up.
		const redemptionSigs = await tbtcSysContract.queryFilter(tbtcSysContract.filters.GotRedemptionSignature());
		const waiting = await asyncFilter(redemptionSigs, filterDeposits);
		console.log(`have ${ waiting.length } deposits waiting for the withdrawal proof; adding listeners`);

		let sigsWithDeadlines = [];
		for (let w of waiting) {
			sigsWithDeadlines.push(await extracFromRedemptionSig(w.args));
		}

		for (let i in sigsWithDeadlines) {
			const target = ethers.BigNumber.from(waiting[i].blockNumber).add(fourHours).toString();
			console.log(`${sigsWithDeadlines[i].dAddr} adding listener for #${ target }`);
			addTarget(blockTargets, target, sigsWithDeadlines[i])
		}

		console.log(`Listening for GotRedemptionSignature`)
		tbtcSysContract.on(tbtcSysContract.filters.GotRedemptionSignature(), async (...ev) => {
			let sig = await extracFromRedemptionSig(ev);
			console.log(`${sig.dAddr} adding listener for #${ sig.blockTarget.toString() }`);
			addTarget(blockTargets, sig.blockTarget.toString(), sig)
		});

	} catch(err) {
		console.error(`Could not authorize: ${err}`)
		console.error(err);
		process.exit(1);
	}
}

main().catch(err => { console.error(err); })

