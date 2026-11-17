# az-snp-vtpm-verifier

This is a PoC to illustrate how we can verify vTPM evidence from Azure confidential VMs without a dependency on libtss. OpenSSL is stil used for signature verification and hashing, so it's not in pure rust.

We are using fixtures from the [trustee](https://github.com/confidential-containers/trustee) project.

## Run

```bash
$ cargo r
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.06s
     Running `target/debug/az-snp-vtpm-verifier`
claims: {
    0: "f3a7e99a5f819a034386bce753a48a73cfdaa0bea0ecfc124bedbf5a8c4799be",
    1: "b851a04a29f4296fa3cfd58da742ee5192b8acaf0afb3934d9a44df61bb4f981",
    2: "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
    3: "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
    4: "1d3b1cb141906329dd8ab09584214a88dffaf839ed14c8ef677a6bcf6ea27a02",
    5: "94debde32fd2164884da055c2b06415d73591582ac7941e1c99c35eb29b34c2f",
    6: "fb9413fbc3127f236b9e3a2bbd931b743374e3b1110ca3dce4e1e2e74608f30e",
    7: "32fe42b385b47cb22c906b8a7e4f134e9f2270818f90e94072d1101ef72f1c00",
    8: "0000000000000000000000000000000000000000000000000000000000000000",
    9: "72eb9de18027746fae973c2853114928fe780807cebc932abfb0e6116d148f47",
    10: "79a9cac94ef9877851fd5bbefe7aba3905b17d8afd426012fa94b31451dac15d",
    11: "0000000000000000000000000000000000000000000000000000000000000000",
    12: "f1a142c53586e7e2223ec74e5f4d1a4942956b1fd9ac78fafcdf85117aa345da",
    13: "0000000000000000000000000000000000000000000000000000000000000000",
    14: "e3991b7ddd47be7e92726a832d6874c5349b52b789fa0db8b558c69fea29574e",
    15: "0000000000000000000000000000000000000000000000000000000000000000",
    16: "0000000000000000000000000000000000000000000000000000000000000000",
    17: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    18: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    19: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    20: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    21: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    22: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    23: "0000000000000000000000000000000000000000000000000000000000000000",
}
```
