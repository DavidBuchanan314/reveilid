# reveilid

Current status: Non-working, experimental

This is a pure python reimplementation of [Veilid](https://veilid.com/), written with the goal of understanding the protocol, and acting as a platform for further security research.

Ironically, this implementation is itself not very secure. There are plenty of security bugs here, from questionable cryptography, to resource exhaustion DoS vectors. Maybe one day I'll iron those out, but today is not that day. Use at your own risk!

Note: This requires installing my fork of [py-ed25519-bindings](https://github.com/DavidBuchanan314/py-ed25519-bindings) which supports blake3+ed25519ph signatures.

## Setup

Create a virtual environment and install the dependencies.

You might need to have the nightly version of Rust (`rustup default nightly`). You might also need to use Python 3.11.

```shell
python3 -m venv venv
source venv/bin/activate # .\venv\Scripts\activate on Windows
pip install -r requirements.txt
```
