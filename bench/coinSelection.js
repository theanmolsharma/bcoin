'use strict';

const assert = require('bsert');
const random = require('bcrypto/lib/random');
const bench = require('./bench');
const WalletDB = require('../lib/wallet/walletdb');
const MTX = require('../lib/primitives/mtx');
const Input = require('../lib/primitives/input');
const Output = require('../lib/primitives/output');
const Script = require('../lib/script/script');
const {rimraf, testdir} = require('../test/util/common');

const ITERATIONS = 1;

(async () => {
  for (const memory of [true, false]) {
    console.log(`Memory: ${memory}`);

    const location = testdir('coinselection');

    // Create walletDB and wallet
    const wdb = new WalletDB({
      memory,
      location
    });
    await wdb.open();
    const wallet = await wdb.create();
    const addr = await wallet.receiveAddress();
    const script = Script.fromAddress(addr);

    console.log('Funding wallet...');
    {
      // Fund wallet
      const fund = new MTX();
      const input = new Input();
      // Make this a non-coinbase TX so we can spend right away
      input.prevout.hash = random.randomBytes(32);
      fund.inputs.push(input);
      for (let i = 0; i < 5000; i++) {
        const output = new Output();
        output.value = Math.floor(100000 * Math.random() + 5000);
        output.script = script;
        fund.outputs.push(output);
      }

      // Confirm
      const dummyBlock = {
        height: 0,
        hash: Buffer.alloc(32),
        time: Date.now()
      };
      await wdb.addTX(fund.toTX(), dummyBlock);
    }
    console.log('Done funding!!');

    const coins = await wallet.getSmartCoins(0);
    let balance = 0;
    for (const coin of coins)
      balance += coin.value - await coin.estimateSpendingSize() * 5;

    const values = [];
    for (let i = 1; i <= 99; i++) {
      values.push(Math.floor(i * balance / 100));
    }

    {
      const end = bench('New Selection    ');

      for (let i = 0; i < 99; i++) {
        const testMTX = new MTX();
        testMTX.addOutput(addr, values[i]);
        await testMTX.fund(coins, {
          changeAddress: addr
        });
        const [tx] = testMTX.commit();

        assert(tx.getOutputValue() >= values[i]);
      }

      end(ITERATIONS);
    }

    {
      const end = bench('Old Selection    ');

      for (let i = 0; i < 99; i++) {
        const testMTX = new MTX();
        testMTX.addOutput(addr, values[i]);
        await testMTX.fund(coins, {
          changeAddress: addr,
          useSelectEstimate: true
        });
        const [tx] = testMTX.commit();

        assert(tx.getOutputValue() >= values[i]);
      }

      end(ITERATIONS);
    }

    await rimraf(location);
  }
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
