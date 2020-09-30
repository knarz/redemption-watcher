# Redemption watchdog

This script listens for redemption requests on-chain and then makes sure that
the redemption proof is properly submitted on the Ethereum chain, so that keeps
do not end up being liquidated even though they released custodied BTC properly.

listener:

```Bash
$ INFURA_API=APIKEYGOESHERE node --experimental-json-modules listener.js WALLETPASSWORD
```

