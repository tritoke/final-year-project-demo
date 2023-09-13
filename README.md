# final_year_project_demo
A repository to hold the code for my demo application - a flash storage based password manager for the Nucleo-F401RE.

## Dependencies
- [probe-run](https://crates.io/crates/probe-run)
- [flip-link](https://github.com/knurling-rs/flip-link)
- `thumbv7em-none-eabihf` target
- Nucleo-F401RE Dev Board

## Setting up the server
In `server/` run `DEFMT_LOG=info cargo run --profile=server`
This flashes the server to the board and allows the client to register.

## Running the client
In `client` run `cargo run --release`
This starts the GUI and allows interaction with the server.

