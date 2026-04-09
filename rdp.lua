local rdp_header_length_bytes = 5

local rdp_proto = Proto.new("CSP.RDP", "CSP Reliable Data Protocol")

local f_reserved = ProtoField.uint8("rdp.reserved", "Reserved bits", base.HEX, nil, 0xF0)

local f_flags = ProtoField.uint8("rdp.flags", "Flags", base.HEX)
local f_syn_flag = ProtoField.bool("rdp.flags.syn", "SYN flag", 8, nil, 0x8)
local f_ack_flag = ProtoField.bool("rdp.flags.ack", "ACK flag", 8, nil, 0x4)
local f_eak_flag = ProtoField.bool("rdp.flags.eak", "EAK flag", 8, nil, 0x2)
local f_rst_flag = ProtoField.bool("rdp.flags.rst", "RST flag", 8, nil, 0x1)

local f_seq = ProtoField.uint16("rdp.seq", "Sequence number", base.DEC, nil)
local f_ack = ProtoField.uint16("rdp.ack", "ACK number", base.DEC, nil)
local f_eak = ProtoField.uint16("rdp.eak", "EAK number", base.DEC, nil)
local f_syn_window_size = ProtoField.uint32("rdp.syn.window_size", "Window size", base.DEC, nil)
local f_syn_conn_timeout = ProtoField.uint32("rdp.syn.conn_timeout", "Connection timeout", base.DEC, nil)
local f_syn_packet_timeout = ProtoField.uint32("rdp.syn.packet_timeout", "Packet timeout", base.DEC, nil)
local f_syn_delayed_acks = ProtoField.uint32("rdp.syn.delayed_acks", "Delayed ACKs", base.DEC, nil)
local f_syn_ack_timeout = ProtoField.uint32("rdp.syn.ack_timeout", "ACK timeout", base.DEC, nil)
local f_syn_ack_delay_count = ProtoField.uint32("rdp.syn.ack_delay_count", "ACK delay count", base.DEC, nil)
local f_analysis = ProtoField.none("rdp.analysis", "RDP analysis")

rdp_proto.fields = {
	f_reserved,
	f_flags,
	f_syn_flag,
	f_ack_flag,
	f_eak_flag,
	f_rst_flag,
	f_seq,
	f_ack,
	f_eak,
	f_syn_window_size,
	f_syn_conn_timeout,
	f_syn_packet_timeout,
	f_syn_delayed_acks,
	f_syn_ack_timeout,
	f_syn_ack_delay_count,
	f_analysis,
}

local f_syn_flag_field = Field.new("rdp.flags.syn")
local f_ack_flag_field = Field.new("rdp.flags.ack")
local f_eak_flag_field = Field.new("rdp.flags.eak")
local f_rst_flag_field = Field.new("rdp.flags.rst")
local f_seq_field = Field.new("rdp.seq")
local f_ack_field = Field.new("rdp.ack")

local source_field = Field.new("csp.source")
local source_port_field = Field.new("csp.source_port")
local destination_field = Field.new("csp.destination")
local destination_port_field = Field.new("csp.destination_port")

local rdp_expected_seq = {}
local rdp_seq_analysis = {}

function rdp_proto.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = rdp_proto.name

	local subtree = tree:add(rdp_proto, buffer(), "Reliable Datagram Protocol")

	local eak_numbers = {}
	local header = buffer(buffer:reported_len() - rdp_header_length_bytes, rdp_header_length_bytes)
	local payload = buffer:range(0, buffer:reported_len() - rdp_header_length_bytes):tvb()

	subtree:add(f_reserved, header(0, 1))
	local flags_tree = subtree:add(f_flags, header(0, 1))
	flags_tree:add(f_syn_flag, header(0, 1))
	flags_tree:add(f_ack_flag, header(0, 1))
	flags_tree:add(f_eak_flag, header(0, 1))
	flags_tree:add(f_rst_flag, header(0, 1))
	subtree:add(f_seq, header(1, 2))
	subtree:add(f_ack, header(3, 2))

	if f_eak_flag_field()() == 1 then
		if payload:reported_len() > 0 then
			for offset = 0, payload:reported_len() - 2, 2 do
				subtree:add(f_eak, payload(offset, 2))
				table.insert(eak_numbers, string.format("%d", payload(offset, 2):uint64():tonumber()))
			end
			payload = payload:range(0, 0):tvb()
		end
	end

	local conv_id = string.format(
		"%d:%d-%d:%d",
		source_field()(),
		source_port_field()(),
		destination_field()(),
		destination_port_field()()
	)

	if pinfo.visited == false then
		if f_syn_flag_field()() == 1 then
			rdp_expected_seq[conv_id] = (f_seq_field()() + 1) % 65536
		else
			local expected_seq = rdp_expected_seq[conv_id]
			if f_seq_field()() == expected_seq then
				if payload:reported_len() > 0 then
					rdp_expected_seq[conv_id] = (expected_seq + 1) % 65536
				end
			elseif (expected_seq - f_seq_field()()) % 65536 < 32768 then
				rdp_seq_analysis[pinfo.number] =
					string.format("Retransmission: ACK %d expected %d", f_seq_field()(), expected_seq)
			else
				rdp_seq_analysis[pinfo.number] =
					string.format("Out of order: ACK %d expected %d", f_seq_field()(), expected_seq)
				rdp_expected_seq[conv_id] = (f_seq_field()() + 1) % 65536
			end
		end
	end

	if rdp_seq_analysis[pinfo.number] then
		local analysis = subtree:add(f_analysis)
		analysis:add_expert_info(PI_SEQUENCE, PI_NOTE, rdp_seq_analysis[pinfo.number])
	end

	if f_syn_flag_field()() == 1 and f_ack_flag_field()() == 0 and payload:reported_len() == 24 then
		subtree:add(f_syn_window_size, payload(0, 4))
		subtree:add(f_syn_conn_timeout, payload(4, 4))
		subtree:add(f_syn_packet_timeout, payload(8, 4))
		subtree:add(f_syn_delayed_acks, payload(12, 4))
		subtree:add(f_syn_ack_timeout, payload(16, 4))
		subtree:add(f_syn_ack_delay_count, payload(20, 4))
		payload = payload:range(0, 0):tvb()
	end

	subtree.text = string.format(
		"%s, Seq: %d, Ack: %d, Len: %d",
		subtree.text,
		f_seq_field()(),
		f_ack_field()(),
		payload:reported_len()
	)

	local flags = ""
	if f_syn_flag_field()() == 1 then
		flags = flags .. "SYN, "
	end
	if f_ack_flag_field()() == 1 then
		flags = flags .. "ACK, "
	end
	if f_eak_flag_field()() == 1 then
		flags = flags .. "EAK, "
	end
	if f_rst_flag_field()() == 1 then
		flags = flags .. "RST, "
	end

	local info = string.format(
		"%d:%d → %d:%d [%s] Len=%d",
		source_field()(),
		source_port_field()(),
		destination_field()(),
		destination_port_field()(),
		flags,
		payload:reported_len()
	)

	if f_eak_flag_field()() == 1 then
		info = string.format("%s Eak=%s", info, table.concat(eak_numbers, ","))
	end
	pinfo.cols.info = info

	if payload:reported_len() > 0 then
		Dissector.get("data"):call(payload:range(0):tvb(), pinfo, tree)
	end
end
