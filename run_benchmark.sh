#!/bin/bash
set -x
trap exit SIGINT

CPU=$1
size=$2
declare -a vary=("ethertype" "ip" "ip+port")
declare -a filter=("ether proto ip6" "dst host 0.0.0.0" "dst host 0.0.0.0 udp port 0")

for i in ${!vary[@]}
do
	for traffic in uniform lrz
	do
		echo "# ${CPU} ${traffic} ${vary[$i]}" >> "benchmark_${CPU}_${traffic}_${vary[$i]}.csv"
		for align in {1,2,4,8,16,32,64}
		do
			./libmoon/build/libmoon benchmark.lua -r 100 -m $size -f "${filter[$i]}" --n-aligned --alignment $align --offset 0 --traffic=$traffic --vary="${vary[$i]}" --robot >> "benchmark_${CPU}_${traffic}_${vary[$i]}.csv"
		done
		./libmoon/build/libmoon benchmark.lua -r 100 -m $size -f "${filter[$i]}" --n-aligned --alignment 4 --offset 2 --traffic=$traffic --vary="${vary[$i]}" --robot >> "benchmark_${CPU}_${traffic}_${vary[$i]}.csv"
		./libmoon/build/libmoon benchmark.lua -r 100 -m $size -f "${filter[$i]}" --n-aligned --alignment 8 --offset 2 --traffic=$traffic --vary="${vary[$i]}" --robot >> "benchmark_${CPU}_${traffic}_${vary[$i]}.csv"
		./formatResults.py "benchmark_${CPU}_${traffic}_${vary[$i]}.csv"
	done
done
