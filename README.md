<p align="center">
<br><br>
➡️
<a href="http://discord.skerritt.blog">Discord</a> | 
<a href="https://broadleaf-angora-7db.notion.site/Ciphey2-32d5eea5d38b40c5b95a9442b4425710">Documentation </a>
⬅️
</p>

<p align="center">
<h1>Project Ciphey</h1>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/bee-san/ciphey/main/images/main_demo.svg" alt="ciphey demo">
</p>


`ciphey` is an automated decoding tool, written in Rust. It is designed to be the next generation of decoding tools, significantly faster and more efficient than its predecessor, [Ciphey](https://github.com/ciphey/ciphey).

✨ You can read more about ciphey here https://skerritt.blog/introducing-ciphey/ ✨

# How to Use

The simplest way to use `ciphey` is to run it via the CLI.

### Installation

```bash
cargo install ciphey
```

Or build from source:

```bash
git clone https://github.com/bee-san/ciphey
cd ciphey
cargo build --release
```

### Usage

**Basic usage:**
```bash
ciphey --text "VGhlIG1haW4gZnVuY3Rpb24gdG8gY2FsbCB3aGljaCBwZXJmb3JtcyB0aGUgY3JhY2tpbmcu"
```

**Using a file:**
```bash
ciphey --file /path/to/ciphertext.txt
```

**Common Flags:**
- `-t`, `--text`: Input ciphertext directly.
- `-f`, `--file`: Input ciphertext from a file.
- `-v`, `--verbose`: Increase verbosity level (use multiple times for more details, e.g. `-vv`).
- `--disable-human-checker`: Turn off the human verification step (useful for automation).
- `--top-results`: Show all potential plaintexts found instead of exiting after the first one.
- `--cracking-timeout`: Set a timeout for the decoding process (default is 5 seconds).
- `--wordlist`: Provide a path to a wordlist file for exact matching.
- `--regex`: Provide a regex to check against (turns off other checkers).
- `--enable-enhanced-detection`: Enable enhanced plaintext detection with BERT.

Type `ciphey --help` for a full list of options.

# Features

`ciphey` is packed with features designed for speed and flexibility.

## 🚀 Blazing Fast
`ciphey` is written in Rust and optimized for performance. It is significantly faster than the Python version of Ciphey. It uses A* search to intelligently find the best decoding path, skipping unnecessary steps.

## 📚 Library First
`ciphey` is designed as a library first, with a CLI wrapper. This means you can easily integrate `ciphey`'s powerful decoding capabilities into your own Rust projects.

## 🔓 Over 40 Decoders
`ciphey` currently supports **40+ decoders**, including:
- **Classic Ciphers:** Caesar, Atbash, Vigenère, Beaufort, Railfence, Affine, Bacon, etc.
- **Modern Encodings:** Base64, Base32, Base58 (Bitcoin, Flickr, Ripple, Monero), Base62, Base85 (Ascii85, Z85), Base91, Base65536.
- **Others:** Hexadecimal, Decimal, Binary, Octal, Morse Code, Reverse, Brainfuck, URL encoding, HTML Entities, Quoted Printable, UUEncode, and more.

## 🧵 Multithreading
`ciphey` leverages [Rayon](https://github.com/rayon-rs/rayon) for multithreading, allowing it to utilize multiple cores for parallel processing. This ensures that even with a growing number of decoders, the tool remains fast.

## 🔍 Advanced Plaintext Detection
`ciphey` uses a sophisticated system to detect plaintext:
- **LemmeKnow:** A fast Rust port of PyWhat for identifying regex patterns (IPs, emails, etc.).
- **English Checker:** Uses quadgrams, trigrams, and dictionary checks to verify if the output is English.
- **Configurable Sensitivity:** Adjust sensitivity levels for gibberish detection.
- **Enhanced Detection:** Optional BERT-based model for even higher accuracy (approx. 40% better detection).

## 🔄 Multi-level Decoding
`ciphey` can handle recursive decoding (e.g., Base64 -> Rot13 -> Base64) thanks to its fast execution and smart search algorithms.

## 💾 Database & Caching
`ciphey` includes a database to store statistics and a caching mechanism to avoid re-calculating previously solved hashes or encodings.

## 🛠️ Customization
- **Wordlists:** Supply your own wordlists for targeted cracking.
- **Regex:** Define custom regex patterns to look for specific data.
- **Themes:** Support for custom themes.

# Contributing

We welcome contributions! Whether it's adding a new decoder, improving the search algorithm, or fixing docs, your help is appreciated. Check out the issues page or join our Discord.
