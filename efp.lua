local csp_ethertype = 0x88B5 -- adjust if your firmware uses a different value

local efp_header_length_bytes = 8

local efp_proto = Proto("efp", "CSP Ethernet fragmentation protocol")

local f_packet_id = ProtoField.uint16("efp.packet_id", "Packet ID", base.HEX)
local f_src_addr = ProtoField.uint16("efp.src_addr", "Source Address", base.HEX)
local f_seg_size = ProtoField.uint16("efp.seg_size", "Segment Size", base.HEX)
local f_packet_length = ProtoField.uint16("efp.packet_length", "Packet Length", base.HEX)

efp_proto.fields = {
	f_packet_id,
	f_src_addr,
	f_seg_size,
	f_packet_length,
}

local f_seg_size_field = Field.new("efp.seg_size")
local f_packet_length_field = Field.new("efp.packet_length")

function efp_proto.dissector(buffer, pinfo, tree)
	-- local length = buffer:captured_len()
	pinfo.cols.protocol = efp_proto.name

	local subtree = tree:add(efp_proto, buffer(), "Ethernet Fragmentation Protocol")

	subtree:add(f_packet_id, buffer(0, 2))
	subtree:add(f_src_addr, buffer(2, 2))
	subtree:add(f_seg_size, buffer(4, 2))
	subtree:add(f_packet_length, buffer(6, 2))

	local payload = buffer(efp_header_length_bytes, f_seg_size_field()()):tvb()

	if f_seg_size_field()() == f_packet_length_field()() then
		local csp_dissector = Dissector.get("csp")
		if csp_dissector then
			csp_dissector:call(payload, pinfo, subtree)
		end
	else
		pinfo.cols.info = "Packet Fragment"
		Dissector.get("data"):call(payload, pinfo, subtree)
	end
end

DissectorTable.get("ethertype"):add(csp_ethertype, efp_proto)
