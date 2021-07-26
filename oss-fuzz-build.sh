#!/bin/bash -eu

export FUZZ_ROOT="github.com/celestiaorg/smt"

compile_go_fuzzer "$FUZZ_ROOT"/fuzz Fuzz fuzz_basic_op fuzz