#!./libmoon/build/libmoon

local lm = require "libmoon"
local log = require "log"
local packet = require "packet"
local memory = require "memory"
local pf = require "pf"
local ffi = require "ffi"
local stats = require "stats"
local jit = require "jit"

-- we don't want dpdk
lm.config.skipInit = true

math.randomseed(0) -- deterministic, please

function configure(parser)
	parser:option("-m --memory", "Memory size in GB."):default("1"):convert(tonumber)
	parser:option("-f --filter", "pcap filter to use."):default("host 10.0.0.0")
	parser:option("--fixed-size", "Use a fixed packet size instead of a realistic distribution."):target("fixedSize"):convert(tonumber)
	parser:option("-r --runs", "Repeat the test n times."):default("1"):convert(tonumber)
	parser:option("--alignment", "Align to Nth byte."):default("1"):convert(tonumber)
	parser:flag("--null-filter", "Overwrites filter with catchall."):target("NullFilter")
	parser:mutex(
		parser:flag("--packed", "No alignment"),
		parser:flag("--l2-aligned", "Align layer 2 header on 4-byte boundaries."):target("l2Aligned"),
		parser:flag("--l3-aligned", "Align layer 3 header on 4-byte boundaries."):target("l3Aligned"),
		parser:flag("--even-aligned", "Align at 2-byte boundaries."):target("evenAligned"),
		parser:flag("--b8-aligned", "Align at 8-byte boundaries."):target("B8Aligned"),
		parser:flag("--n-aligned", "Align at N-byte boundaries."):target("NAligned")
		
	)
	args = parser:parse()
	-- TODO: argparse should be able to enforce this somehow
	if not args.packed and not args.l2Aligned and not args.l3Aligned and not args.evenAligned and not args.B8Aligned and not args.NAligned then
		parser:error("Specifiy either --packed, --l2-aligned, or --l3-aligned")
	end
	return args
end

ffi.cdef [[
	struct __attribute__((__packed__)) packet_header {
                uint64_t metadata; // combination of timestamp and vlan tag in FlowScope
                uint16_t length;
                uint8_t data[]; // packet data, we will try to align either the l2 or the l3 header here
        };
]]

local packetType = ffi.typeof("struct packet_header *")
local headerSize = ffi.sizeof("struct packet_header")

local function makeTemplate()
	local mem = { mem = memory.alloc("void*", 1518), getData = function(self) return self.mem end }
	local pkt = packet.getUdp4Packet(mem)
	pkt:fill{ ip4Src = "10.0.0.1", ip4Dst = "0.0.0.0", udpSrc = 1234, udpDst = 5678 }
	pkt:calculateIp4Checksum()
	log:info("Base packet looks like this:")
	pkt:dump()
	log:info("The destination address will use a random high byte")
	return mem:getData(), pkt
end

local ceil = math.ceil
local function noAlign(num)
	return num
end
local function alignEven(num)
	-- this only prevents odd boundaries
	--return ceil(num / 2) * 2
	return num + bit.band(num + 0ULL, 1ULL)
end
local function alignL3(num)
	-- this aligns the l3 header with the struct above, cf. figure in the paper
	--return ceil(num / 4) * 4
	return bit.band(num + 0ULL, bit.bnot(3ULL)) + 4 * bit.bor(bit.band(num, 1), bit.rshift(bit.band(num, 2), 1))
end
local function alignL2(num)
	-- packet data starts add +10 bytes
	return alignL3(num + 2) - 2
end
local function align8(num)
	-- return (num + 7) & ~7
	return bit.band(num + 7ULL, bit.bnot(7ULL))
end
local function align(num, boundary, offset)
	offset = offset or 0
	boundary = boundary or 1
	-- return (num + boundary - 1) & ~(boundary - 1)
	return bit.band(num + boundary - 1ULL, bit.bnot(boundary - 1ULL))
end

local voidPtr = ffi.typeof("void*")

local function runTest(mem, memSize, numPkts, align, filter)
	local i = 0
	local match, discard = 0, 0
	local start = getMonotonicTime() -- can't use libmoon.getTime() without initializing DPDK
	local data = 0
	for pkt = 1, numPkts do
		i = align(i)
		local pkt = packetType(voidPtr(mem + i))
		local size = pkt.length
		if filter(pkt.data, size) then
			match = match + 1
		else
			discard = discard + 1
		end
		i = i + size + headerSize
		--data = data + size
	end
	local stop = getMonotonicTime()
	local time = stop - start
	local pktRate = (match + discard) / time
	local dataRate = memSize * 8 / time
	--local dataRate = data * 8 / time
	log:info("Filtered %d packets, accepted %.2f%%.", match + discard, match / (match + discard) * 100)
	log:info("Time elapsed: %.2f milliseconds", time * 1000)
	log:info("%.2f Mpps, %.2f Gbit/s", pktRate / 10^6, dataRate / 10^9)
	return time, pktRate, dataRate
end

local function randomSize()
	return math.random(60, 124)
	--return math.random(60, 92)
end

function master(args)
	local align =
		   args.packed and noAlign
		or args.l2Aligned and alignL2
		or args.l3Aligned and alignL3
		or args.evenAligned and alignEven
		or args.B8Aligned and align8
		or args.NAligned and function(num) return align(num, args.alignment) end
		or error("no alignment specified")
	local memSize = args.memory * 2^30
	local mem = memory.allocHuge("uint8_t*", memSize)
	local template, templatePkt = makeTemplate()
	local i = 0
	local numPkts = 0
	log:info("Header size: %d", headerSize)
	for i,v in pairs({0,1,2,3,4,7,8,9,15,16}) do
		log:info("align(%d) = %d", v, tonumber(align(v)))
	end
	log:info("Generating packets in memory.")
	while true do
		local size = args.fixedSize or randomSize()
		i = align(i)
		if i + size + headerSize > memSize then
			break
		end
		templatePkt:setLength(size)
		-- random highest byte
		templatePkt.ip4.dst.uint8[0] = math.random(0, 255)
		--pkt.ip4.dst.uint8[3] = math.random(0, 255)
		-- TODO: this is slow but the partial checksum update is not yet in mainline libmoon
		--templatePkt:calculateIp4Checksum()
		local pkt = packetType(voidPtr(mem + i))
		pkt.length = size
		ffi.copy(pkt.data, template, 48) -- headers are sufficient, other stuff is zero-initialized
		i = i + size + headerSize
		numPkts = numPkts + 1
	end
	local times, pktRates, dataRates = {}, {}, {}
	--(require"jit.dump").on()
	local filter_fn = pf.compile_filter(args.filter)
	if args.NullFilter then
		log:info("Using null filter")
		filter_fn = function(data, size) return false end
	end
	for i = 1, args.runs do
		log:info("Running test run %d/%d", i, args.runs)
		local time, pktRate, dataRate = runTest(mem, memSize, numPkts, align, filter_fn)
		times[#times + 1] = time * 1000 -- ms
		pktRates[#pktRates + 1] = pktRate / 10^6 -- mpps
		dataRates[#dataRates + 1] = dataRate / 10^9 -- gbit
		print()
		jit.flush()
	end
	if args.runs > 1 then
		log:info("Averages:")
		log:info("Time: %.2f ms +/- %.2f ms", stats.average(times), stats.stdDev(times))
		log:info("Packet rate: %.2f Mpps +/- %.2f Mpps", stats.average(pktRates), stats.stdDev(pktRates))
		log:info("Data rate: %.2f Gbit/s +/- %.2f Gbit/s", stats.average(dataRates), stats.stdDev(dataRates))
	end
end

