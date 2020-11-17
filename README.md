<h1 align="center">Proof-carrying data (PCD)</h1>


This arkworks library describes an interface and contains an implementation for proof-carrying data (PCD).

This library is released under the MIT License and the Apache v2 License (see [License](#license)).

**WARNING:** This is an academic proof-of-concept prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.

The PCD interface is [here](src/ec_cycle_pcd/mod.rs) and relies on a cycle of elliptic curves (e.g. the MNT cycle). Separate `CircuitSpecificSetupPCD` and `UniversalSetupPCD` interfaces are included depending on the underlying SNARK type(s). Note that the underlying main SNARK and helper SNARK do not have to be the same, although both must implement either `CircuitSpecificSetupSNARK` or `UniversalSetupSNARK`.

## Build guide

The library compiles on the `stable` toolchain of the Rust compiler. To install the latest version of Rust, first install `rustup` by following the instructions [here](https://rustup.rs/), or via your platform's package manager. Once `rustup` is installed, install the Rust toolchain by invoking:
```bash
rustup install stable
```

After that, use `cargo`, the standard Rust build tool, to build the libraries:
```bash
git clone https://github.com/arkworks-rs/pcd.git
cd pcd
cargo build
```

## Tests
This library comes with comprehensive unit and integration tests. Run the tests with:
```bash
cargo test --all
```

## License

The crates in this repo are licensed under either of the following licenses, at your discretion.

 * Apache License Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution submitted for inclusion in this library by you shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.
