## Instructions
1. run `make` in TSS.CPP.
2. run `make`.


## Benchmarks
### Change in Time With Size
![chart](chart2.png "Time vs Bytes")

Time increases by 1 ms every 5.61 KBs.

### With and Without Background Tasks
![chart](chart1.png "Time vs Bytes")

**stress-ng** was run in the background here.

`stress-ng --cpu 12 --cpu-method matrixprod  --metrics-brief --perf -t 1000`
