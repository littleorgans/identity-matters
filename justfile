default:
    @just --list

build:
    cargo build --workspace

release:
    cargo build --workspace --release

test *ARGS:
    cargo nextest run --workspace {{ARGS}}

insta *ARGS:
    cargo insta test {{ARGS}}

test-doc:
    cargo test --workspace --doc

fmt:
    cargo fmt --all

clippy:
    cargo clippy --workspace --fix --allow-dirty -- -D warnings

loc:
    scripts/check-loc-limit.sh

check: fmt clippy loc
