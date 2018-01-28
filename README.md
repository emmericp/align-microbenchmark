# How to run

```
# clone recursively because of the libmoon dependency!
git clone --recursive https://github.com/emmericp/align-microbenchmark
# build libmoon (the setup-hugetlbfs step requires root)
cd libmoon && ./build.sh && sudo ./setup-hugetlbfs.sh && cd -
# run it
./run_benchmark.sh <CPU name> <amount of memory to use in GB>
```

This will output a bunch of CSV files containing the throughput in Gbit/s.
CPU Name is used for the name of the output files.
