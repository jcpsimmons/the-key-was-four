# The key was four

Companion code for Dr. Josh C. Simmons's video on the eMudhra certificate authority incident, where eight intermediate signing keys turned out to be tiny numbers. One of them, `EM OV TLS CA - G3C`, had the private key 4.

This repo rebuilds that failure with a fake certificate authority on your own machine:

1. Create a P-384 intermediate whose private key is 4.
2. Recover that key using only its public key, by trying 1, 2, 3, 4.
3. Use the recovered key to sign a new certificate for `demo.invalid`.
4. Watch OpenSSL accept the forged certificate when it trusts our lab root, and reject it when it trusts an unrelated root.

Everything is synthetic. No real CA keys are used, no network requests run, nothing is installed in your system trust store, and private keys stay in memory.

## Run it

You need Python 3 and OpenSSL on your PATH.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest -v
.venv/bin/python demo.py
```

`recording.py` walks through the same steps one at a time, pausing for Enter at each stage (this is what's on screen in the video). Add `--auto` to run it without pauses.

Installing the dependency needs internet; the demo and tests do not. Tested with cryptography 46.0.5. Captured results are in `demo-output.txt` and `test-output.txt`.

## What it does and doesn't show

The search only tries 1 through 255. Not finding a key means it's outside that range, nothing more. It does not mean the key is secure. `test_outside_search_is_not_recovered` uses 256 to make that limit visible. A 384-bit curve says nothing about how randomly the private key was chosen.

This is a certificate signature and chain check, not a browser TLS connection. It doesn't model hostname validation, Certificate Transparency, revocation, or network interception. The second check shows what changing the trusted root does; it isn't a model of how browsers distrust a CA. Each run makes fresh random roots and leaf keys, so signatures differ between runs, but the five test results and the accept/reject outcome are the same every time.

## The real incident

- [Mozilla incident bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449): key analysis, the root distrust, and the root programs' questions
- [Researcher disclosure](https://emudhra.we-have-a-problem.com/)
- [Published demonstration of the key 4](https://gist.github.com/Fluepke/9a103c7f990c3cc2fb5002f7476f2f48)
- [Google's response](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/)
- [Microsoft's response](https://www.microsoft.com/en-us/msrc/blog/2026/10/microsoft-response-to-compromised-emudhra-certificate-authority-keys)

API references: [EC keys and signatures](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/), [X.509 construction](https://cryptography.io/en/latest/x509/tutorial/). Background: [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280), [RFC 6090](https://www.rfc-editor.org/rfc/rfc6090.txt).

More from Dr. J: https://drjoshcsimmons.com/links
