-- Copyright (C) 2022 Carnegie Mellon University
-- Copyright (C) 2025 University of Texas at Austin

tcp = Proto("uttcp", "UT TCP")

local f_identifier  = ProtoField.uint32("uttcp.identifier", "Identifier")
local f_source_port  = ProtoField.uint16("uttcp.source_port", "Source Port")
local f_destination_port  = ProtoField.uint16("uttcp.destination_port", "Destination Port")
local f_seq_num  = ProtoField.uint32("uttcp.seq_num", "Sequence Number")
local f_ack_num  = ProtoField.uint32("uttcp.ack_num", "ACK Number")
local f_hlen  = ProtoField.uint16("uttcp.hlen", "Header Length")
local f_plen  = ProtoField.uint16("uttcp.plen", "Packet Length")
local f_flags  = ProtoField.uint8("uttcp.flags", "Flags")
local f_advertised_window  = ProtoField.uint16("uttcp.advertised_window", "Advertised Window")

tcp.fields = { f_identifier, f_source_port, f_destination_port, f_seq_num, f_ack_num, f_hlen, f_plen, f_flags, f_advertised_window}

function tcp.dissector(tvb, pInfo, root) -- Tvb, Pinfo, TreeItem
   if (tvb:len() ~= tvb:reported_len()) then
      return 0 -- ignore partially captured packets
      -- this can/may be re-enabled only for unfragmented UDP packets
   end

   local t = root:add(tcp, tvb(0,25))
   t:add(f_identifier, tvb(0,4))
   t:add(f_source_port, tvb(4,2))
   t:add(f_destination_port, tvb(6,2))
   t:add(f_seq_num, tvb(8,4))
   t:add(f_ack_num, tvb(12,4))
   t:add(f_hlen, tvb(16,2))
   t:add(f_plen, tvb(18,2))
   local f = t:add(f_flags, tvb(20,1))
   t:add(f_advertised_window, tvb(21,2))
   t:add(f_extension_length, tvb(23,2))

   local flag = tvb(20,1):uint()

   if bit.band(flag, 8) ~= 0 then
      f:add(tvb(20,1), "SYN")
   end
   if bit.band(flag, 4) ~= 0 then
      f:add(tvb(20,1), "ACK")
   end
   if bit.band(flag, 2) ~= 0 then
      f:add(tvb(20,1), "FIN")
   end

   pInfo.cols.protocol = "UT TCP"
end

-- have to put the port for the server here
local udpDissectorTable = DissectorTable.get("udp.port")
udpDissectorTable:add("51085", tcp)

io.stderr:write("tcp.lua is successfully loaded\n")
