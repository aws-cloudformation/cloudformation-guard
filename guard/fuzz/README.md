# cfn-guard-fuzz

uses [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html) to find bugs using [fuzzing](https://github.com/google/fuzzing/blob/master/docs/intro-to-fuzzing.md).

## How to use:

1. setup rustup using the steps [here](https://rustup.rs/)
2. setup a c compiler (cc needs to be available in the PATH)
3. setup cargo-fuzz using the steps [here](https://rust-fuzz.github.io/book/cargo-fuzz/setup.html)
4. locate the fuzz target of your choosing using `cargo fuzz list`
5. lastly run the fuzzer using `cargo fuzz run <name of the fuzz target>`

the following is the example of a `cargo fuzz run` output
```
$ cargo fuzz run fuzz_run_checks                                            
...
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: seed corpus: files: 69 min: 1b max: 4b total: 191b rss: 74Mb
#71	INITED cov: 3655 ft: 5587 corp: 63/171b exec/s: 0 rss: 88Mb
#74	NEW    cov: 3656 ft: 5588 corp: 64/173b lim: 4 exec/s: 0 rss: 88Mb L: 2/4 MS: 3 ChangeASCIIInt-ShuffleBytes-CopyPart-
#82	NEW    cov: 3657 ft: 5589 corp: 65/177b lim: 4 exec/s: 0 rss: 89Mb L: 4/4 MS: 3 CrossOver-CrossOver-InsertByte-
#83	NEW    cov: 3663 ft: 5596 corp: 66/181b lim: 4 exec/s: 0 rss: 89Mb L: 4/4 MS: 1 ChangeBit-
#98	NEW    cov: 3667 ft: 5600 corp: 67/184b lim: 4 exec/s: 0 rss: 90Mb L: 3/4 MS: 5 CopyPart-ChangeBinInt-ShuffleBytes-ShuffleBytes-ChangeByte-
#104	NEW    cov: 3671 ft: 5632 corp: 68/187b lim: 4 exec/s: 0 rss: 91Mb L: 3/4 MS: 1 CrossOver-
...
```
