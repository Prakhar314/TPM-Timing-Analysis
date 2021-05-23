## Instructions
1. run `make` in TSS.CPP.
2. run `make`.
3. `sudo cpulimit -l 50 -i ./bg.sh`

## Benchmarks

Both of these tests were run while limiting the cpu usage to 50% in a 6-core cpu using `cpulimit -l 50 -i`.

### Change in Time With Size
![chart](chart2.png "Time vs Bytes")

Time increases by 2.3 ms every KB.

### With and Without Background Tasks
![chart](chart1.png "Time vs Bytes")

**stress-ng** was run in the background here.

`stress-ng --cpu 4 -t 7200`
