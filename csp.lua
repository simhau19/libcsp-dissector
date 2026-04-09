local csp_prio_bits = 2
local csp_dst_bits = 14
local csp_src_bits = 14
local csp_dport_bits = 6
local csp_sport_bits = 6
local csp_flags_bits = 6

local csp_flags_offset = 0
local csp_sport_offset = csp_flags_offset + csp_flags_bits
local csp_dport_offset = csp_sport_offset + csp_sport_bits
local csp_src_offset = csp_dport_offset + csp_dport_bits
local csp_dst_offset = csp_src_offset + csp_src_bits
local csp_prio_offset = csp_dst_offset + csp_dst_bits

local csp_header_length_bytes = 6

local crc32_size_bytes = 4
local crc32_initial = 0xFFFFFFFF
local crc32_final = 0xFFFFFFFF

local csp_proto = Proto("CSP", "Cubesat Space Protocol")

local csp_priorities = {
	[0] = "Critical",
	[1] = "High",
	[2] = "Normal",
	[3] = "Low",
}

local crc_status_vals = {
	[0] = "Bad",
	[1] = "Good",
	[2] = "Unverified",
	[3] = "Not present",
	[4] = "Illegal",
}

local f_prio = ProtoField.uint8("csp.priority", "Priority", base.DEC, csp_priorities)

local f_dst = ProtoField.uint16("csp.destination", "Destination", base.DEC)
local f_src = ProtoField.uint16("csp.source", "Source", base.DEC)
local f_dport = ProtoField.uint8("csp.destination_port", "Destination port", base.DEC)
local f_sport = ProtoField.uint8("csp.source_port", "Source port", base.DEC)
local f_flags = ProtoField.uint8("csp.flags", "Flags", base.HEX)
local f_crc = ProtoField.uint32("csp.crc", "CRC32", base.HEX)
local f_crc_status = ProtoField.uint8("csp.crc.status", "CRC Status", base.DEC, crc_status_vals)

local f_frag_flag = ProtoField.bool("csp.flags.frag", "FRAG", 8, nil, 0x10)
local f_hmac_flag = ProtoField.bool("csp.flags.hmac", "HMAC", 8, nil, 0x08)
local f_rdp_flag = ProtoField.bool("csp.flags.rdp", "RDP", 8, nil, 0x02)
local f_crc_flag = ProtoField.bool("csp.flags.crc", "CRC", 8, nil, 0x01)

csp_proto.fields = {
	f_prio,
	f_dst,
	f_src,
	f_dport,
	f_sport,
	f_flags,
	f_crc,
	f_hmac_flag,
	f_frag_flag,
	f_rdp_flag,
	f_crc_flag,
	f_crc_status,
}

local source_field = Field.new("csp.source")
local source_port_field = Field.new("csp.source_port")
local destination_field = Field.new("csp.destination")
local destination_port_field = Field.new("csp.destination_port")

local f_rdp_flag_field = Field.new("csp.flags.rdp")
local f_crc_flag_field = Field.new("csp.flags.crc")

local function extract_field(raw, offset, bits)
	return (raw >> offset) & ((1 << bits) - 1)
end

local function extract_range(tvb, offset, bits)
	local start = math.floor(offset / 8)
	local bytes = math.ceil((offset + bits) / 8) - start
	return tvb(start, bytes)
end

local crc32_table = {
	0x00000000,
	0xF26B8303,
	0xE13B70F7,
	0x1350F3F4,
	0xC79A971F,
	0x35F1141C,
	0x26A1E7E8,
	0xD4CA64EB,
	0x8AD958CF,
	0x78B2DBCC,
	0x6BE22838,
	0x9989AB3B,
	0x4D43CFD0,
	0xBF284CD3,
	0xAC78BF27,
	0x5E133C24,
	0x105EC76F,
	0xE235446C,
	0xF165B798,
	0x030E349B,
	0xD7C45070,
	0x25AFD373,
	0x36FF2087,
	0xC494A384,
	0x9A879FA0,
	0x68EC1CA3,
	0x7BBCEF57,
	0x89D76C54,
	0x5D1D08BF,
	0xAF768BBC,
	0xBC267848,
	0x4E4DFB4B,
	0x20BD8EDE,
	0xD2D60DDD,
	0xC186FE29,
	0x33ED7D2A,
	0xE72719C1,
	0x154C9AC2,
	0x061C6936,
	0xF477EA35,
	0xAA64D611,
	0x580F5512,
	0x4B5FA6E6,
	0xB93425E5,
	0x6DFE410E,
	0x9F95C20D,
	0x8CC531F9,
	0x7EAEB2FA,
	0x30E349B1,
	0xC288CAB2,
	0xD1D83946,
	0x23B3BA45,
	0xF779DEAE,
	0x05125DAD,
	0x1642AE59,
	0xE4292D5A,
	0xBA3A117E,
	0x4851927D,
	0x5B016189,
	0xA96AE28A,
	0x7DA08661,
	0x8FCB0562,
	0x9C9BF696,
	0x6EF07595,
	0x417B1DBC,
	0xB3109EBF,
	0xA0406D4B,
	0x522BEE48,
	0x86E18AA3,
	0x748A09A0,
	0x67DAFA54,
	0x95B17957,
	0xCBA24573,
	0x39C9C670,
	0x2A993584,
	0xD8F2B687,
	0x0C38D26C,
	0xFE53516F,
	0xED03A29B,
	0x1F682198,
	0x5125DAD3,
	0xA34E59D0,
	0xB01EAA24,
	0x42752927,
	0x96BF4DCC,
	0x64D4CECF,
	0x77843D3B,
	0x85EFBE38,
	0xDBFC821C,
	0x2997011F,
	0x3AC7F2EB,
	0xC8AC71E8,
	0x1C661503,
	0xEE0D9600,
	0xFD5D65F4,
	0x0F36E6F7,
	0x61C69362,
	0x93AD1061,
	0x80FDE395,
	0x72966096,
	0xA65C047D,
	0x5437877E,
	0x4767748A,
	0xB50CF789,
	0xEB1FCBAD,
	0x197448AE,
	0x0A24BB5A,
	0xF84F3859,
	0x2C855CB2,
	0xDEEEDFB1,
	0xCDBE2C45,
	0x3FD5AF46,
	0x7198540D,
	0x83F3D70E,
	0x90A324FA,
	0x62C8A7F9,
	0xB602C312,
	0x44694011,
	0x5739B3E5,
	0xA55230E6,
	0xFB410CC2,
	0x092A8FC1,
	0x1A7A7C35,
	0xE811FF36,
	0x3CDB9BDD,
	0xCEB018DE,
	0xDDE0EB2A,
	0x2F8B6829,
	0x82F63B78,
	0x709DB87B,
	0x63CD4B8F,
	0x91A6C88C,
	0x456CAC67,
	0xB7072F64,
	0xA457DC90,
	0x563C5F93,
	0x082F63B7,
	0xFA44E0B4,
	0xE9141340,
	0x1B7F9043,
	0xCFB5F4A8,
	0x3DDE77AB,
	0x2E8E845F,
	0xDCE5075C,
	0x92A8FC17,
	0x60C37F14,
	0x73938CE0,
	0x81F80FE3,
	0x55326B08,
	0xA759E80B,
	0xB4091BFF,
	0x466298FC,
	0x1871A4D8,
	0xEA1A27DB,
	0xF94AD42F,
	0x0B21572C,
	0xDFEB33C7,
	0x2D80B0C4,
	0x3ED04330,
	0xCCBBC033,
	0xA24BB5A6,
	0x502036A5,
	0x4370C551,
	0xB11B4652,
	0x65D122B9,
	0x97BAA1BA,
	0x84EA524E,
	0x7681D14D,
	0x2892ED69,
	0xDAF96E6A,
	0xC9A99D9E,
	0x3BC21E9D,
	0xEF087A76,
	0x1D63F975,
	0x0E330A81,
	0xFC588982,
	0xB21572C9,
	0x407EF1CA,
	0x532E023E,
	0xA145813D,
	0x758FE5D6,
	0x87E466D5,
	0x94B49521,
	0x66DF1622,
	0x38CC2A06,
	0xCAA7A905,
	0xD9F75AF1,
	0x2B9CD9F2,
	0xFF56BD19,
	0x0D3D3E1A,
	0x1E6DCDEE,
	0xEC064EED,
	0xC38D26C4,
	0x31E6A5C7,
	0x22B65633,
	0xD0DDD530,
	0x0417B1DB,
	0xF67C32D8,
	0xE52CC12C,
	0x1747422F,
	0x49547E0B,
	0xBB3FFD08,
	0xA86F0EFC,
	0x5A048DFF,
	0x8ECEE914,
	0x7CA56A17,
	0x6FF599E3,
	0x9D9E1AE0,
	0xD3D3E1AB,
	0x21B862A8,
	0x32E8915C,
	0xC083125F,
	0x144976B4,
	0xE622F5B7,
	0xF5720643,
	0x07198540,
	0x590AB964,
	0xAB613A67,
	0xB831C993,
	0x4A5A4A90,
	0x9E902E7B,
	0x6CFBAD78,
	0x7FAB5E8C,
	0x8DC0DD8F,
	0xE330A81A,
	0x115B2B19,
	0x020BD8ED,
	0xF0605BEE,
	0x24AA3F05,
	0xD6C1BC06,
	0xC5914FF2,
	0x37FACCF1,
	0x69E9F0D5,
	0x9B8273D6,
	0x88D28022,
	0x7AB90321,
	0xAE7367CA,
	0x5C18E4C9,
	0x4F48173D,
	0xBD23943E,
	0xF36E6F75,
	0x0105EC76,
	0x12551F82,
	0xE03E9C81,
	0x34F4F86A,
	0xC69F7B69,
	0xD5CF889D,
	0x27A40B9E,
	0x79B737BA,
	0x8BDCB4B9,
	0x988C474D,
	0x6AE7C44E,
	0xBE2DA0A5,
	0x4C4623A6,
	0x5F16D052,
	0xAD7D5351,
}

local computed_crc32_cache = {}

local function crc32(tvb_range)
	local crc = crc32_initial
	for i = 0, tvb_range:len() - 1 do
		local b = tvb_range(i, 1):uint()
		local idx = (crc ~ b) & 0xFF
		crc = (crc >> 8)
		crc = crc ~ crc32_table[idx + 1] -- table is 1-indexed
	end
	return ~crc & crc32_final
end

function csp_proto.dissector(buffer, pinfo, tree)
	-- local length = buffer:reported_len()
	pinfo.cols.protocol = csp_proto.name

	local subtree = tree:add(csp_proto, buffer(), "Cubesat Space Protocol")

	local header = buffer(0, csp_header_length_bytes)

	local hi32 = buffer(0, 4):uint() -- bits 47-16
	local lo16 = buffer(4, 2):uint() -- bits 15-0

	local header_value = (hi32 << 16) + lo16

	local flags_value = extract_field(header_value, csp_flags_offset, csp_flags_bits)
	local flags_tree = subtree:add(f_flags, extract_range(header, csp_flags_offset, csp_flags_bits), flags_value)
	flags_tree:add(f_crc_flag, flags_value)
	flags_tree:add(f_rdp_flag, flags_value)
	flags_tree:add(f_hmac_flag, flags_value)
	flags_tree:add(f_frag_flag, flags_value)

	subtree:add(
		f_sport,
		extract_range(header, csp_sport_offset, csp_sport_bits),
		extract_field(header_value, csp_sport_offset, csp_sport_bits)
	)

	subtree:add(
		f_dport,
		extract_range(header, csp_dport_offset, csp_dport_bits),
		extract_field(header_value, csp_dport_offset, csp_dport_bits)
	)

	subtree:add(
		f_src,
		extract_range(header, csp_src_offset, csp_src_bits),
		extract_field(header_value, csp_src_offset, csp_src_bits)
	)

	subtree:add(
		f_dst,
		extract_range(header, csp_dst_offset, csp_dst_bits),
		extract_field(header_value, csp_dst_offset, csp_dst_bits)
	)

	subtree:add(
		f_prio,
		extract_range(header, csp_prio_offset, csp_prio_bits),
		extract_field(header_value, csp_prio_offset, csp_prio_bits)
	)

	local payload
	if f_crc_flag_field()() == true then
		payload =
			buffer(csp_header_length_bytes, buffer:reported_len() - csp_header_length_bytes - crc32_size_bytes):tvb()
		local crc_buffer = buffer(buffer:reported_len() - crc32_size_bytes, crc32_size_bytes)
		subtree:add(f_crc, crc_buffer)

		if pinfo.visited == false then
			computed_crc32_cache[pinfo.number] = crc32(payload)
		end

		local received_crc = crc_buffer:uint()

		if computed_crc32_cache[pinfo.number] == received_crc then
			subtree:add(f_crc_status, crc_buffer, 1)
		else
			subtree:add_expert_info(
				PI_CHECKSUM,
				PI_ERROR,
				string.format(
					"CRC mismatch: expected 0x%08X, got 0x%08X",
					computed_crc32_cache[pinfo.number],
					received_crc
				)
			)
			subtree:add(f_crc_status, crc_buffer, 0)
		end
	else
		payload = buffer(csp_header_length_bytes):tvb()
	end

	pinfo.cols.info = string.format(
		"%d:%d → %d:%d  Len=%d",
		source_field()(),
		source_port_field()(),
		destination_field()(),
		destination_port_field()(),
		payload:reported_len()
	)

	subtree:append_text(string.format(" (Len: %d)", payload:reported_len()))

	if f_rdp_flag_field()() == true then
		local rdp_dissector = Dissector.get("csp.rdp")
		if rdp_dissector then
			rdp_dissector:call(payload, pinfo, subtree)
		end
	else
		Dissector.get("data"):call(payload, pinfo, subtree)
	end
end
