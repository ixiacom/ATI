--------------------------------------------------------------------------------
-- Minecraft.lua
-- Author: Haiyang Si
-- 
-- Works as of Wireshark v2.0.2
-- This is a Lua dissector for Minecraft 1.8.9 PC Edition validation.
-- It supports most of Minecraft actions whose 'Packet ID' are unique.
-- 
-- Notice:
-- 1. For the actions share the same 'Packet ID' It lists all the possible actions' names
-- 2. Map Chunk Bulk's length range is extraordinary, so now the disector doesn't support it well.
--
-- Setup
-- 1. Copy 'Minecraft.lua’ to somewhere in your wireshark directory. For example, C:\Program Files\Wireshark.
-- 2. Open ‘init.lua’ in your wireshark root directory. Comment the line ‘disable_lua = true’ or change it to ‘disable_lua = false’.
--------------------------------------------------------------------------------

do
    --Protocol Name: Minecraft. In Packet Details windows it is Minecraft 1.8.9 PC
    local p_Minecraft = Proto("Minecraft", "Minecraft 1.8.9 PC")

    local f_len = ProtoField.uint8("Minecraft.length","Length",base.HEX)
    local f_version = ProtoField.uint8("Minecraft.version","Version",base.HEX)
    local f_id = ProtoField.uint8("Minecraft.id","Packet ID",base.HEX,
		{ [0] = "Hand Shake / Request /Login Start / Response / Keep Alive", 
		  [1] = "Ping / Pong / Join Game",
		  [2] = "Login Success",
		  [3] = "Player / Timeupdate",
		  [4] = "Player Position",
		  [5] = "Spawn Position",
		  [8] = "Player Position And Look",
		  [9] = "Held Item Change",
		  [15] = "Spawn Mob",
		  [18] = "Entity velocity", --0x12
		  [19] = "Destroy Entities", --0x13
		  [21] = "Entity Relative Move", --0x15
		  [23] = "Entity Look And Relative Move", --0x17
		  [24] = "Entity Teleport", --0x18
		  [25] = "Entity Head Look", --0x19
		  [28] = "Entity Metadata", --0x1c
		  [32] = "Entity Properties", --0x20
		  [38] = "Map Chunk Bulk", --0x26 TODO
		  [48] = "Window Items", --0x30
		  [55] = "Statistics", --0x37
		  [56] = "Player Listitem", --0x38
		  [57] = "Player Abilities", --0x39
		  [63] = "Plugin Message",  --0x3f
		  [64] = "Disconnect", --0x40
		  [65] = "Server Difficulty", --0x41
		  [68] = "World Boardery" --0x44
		})
	local f_uuid = ProtoField.string("Minecraft.uuid","UUID")
	local f_name = ProtoField.string("Minecraft.name","Name")
	local f_x = ProtoField.double("Minecraft.x","X",base.HEX)
	local f_y = ProtoField.double("Minecraft.y","Feet Y",base.HEX)
	local f_z = ProtoField.double("Minecraft.z","Z",base.HEX)
	local f_onground = ProtoField.uint8("Minecraft.onground","On Ground",base.HEX)
	local f_position = ProtoField.uint64("Minecraft.position","Position",base.HEX)
	local f_yaw = ProtoField.float("Minecraft.yaw","Yaw",base.HEX)
	local f_pitch = ProtoField.float("Minecraft.pitch","Pitch",base.HEX)
	local f_slot = ProtoField.uint8("Minecraft.slot","Slot",base.HEX)
	local f_winid = ProtoField.uint8("Minecraft.winid","Window ID",base.HEX)
	local f_count = ProtoField.uint16("Minecraft.count","Count",base.HEX)
	local f_s_count = ProtoField.uint8("Minecraft.scount","Scount",base.HEX)
	local f_action = ProtoField.uint8("Minecraft.action","Action",base.HEX)
	local f_playernum = ProtoField.uint8("Minecraft.playernum","Player Number",base.HEX)
	local f_binary_uuid = ProtoField.bytes("Minecraft.bin_uuid","UUID",base.HEX)
	local f_flags = ProtoField.uint8("Minecraft.flags","Flags",base.HEX)
	local f_flying_speed = ProtoField.float("Minecraft.flying_speed","Flying Speed",base.HEX)
	local f_walking_speed = ProtoField.float("Minecraft.walking_speed","Walking Speed",base.HEX)
	local f_channel = ProtoField.string("Minecraft.channel","Channel")
	local f_data = ProtoField.string("Minecraft.data","Data")
	local f_difficulty = ProtoField.uint8("Minecraft.difficulty","Difficulty",base.HEX)
	
    p_Minecraft.fields = { 
	    f_len, f_id, f_version, f_uuid, f_name, f_x, f_y, f_z, 
	    f_onground, f_position, f_yaw, f_pitch, f_slot, f_winid,
	    f_count, f_s_count, f_action, f_playernum, f_binary_uuid,
	    f_flags, f_flying_speed, f_walking_speed, f_channel,
	    f_data, f_difficulty}

    local data_dis = Dissector.get("data")

    local function Minecraft_dissector(buf,pkt,root)
        -- validate packet length is adequate, otherwise quit\
        if buf:len() < 2 then return end
        pkt.cols.protocol = p_Minecraft.name
		local t = root:add(p_Minecraft,buf)
  	    --get package length. Assume it is not more than 0xff
  	    local v_len = buf(0, 1)
  	    local i_len = v_len:uint()
        t:add(f_len,v_len)
		
  	    local v_id = buf(1,1)
  	    local i_id = v_id:uint()
		t:add(f_id,v_id)
		
		if i_id == 2 then
		    t:add(f_uuid, buf(3,36))
			local name_len = buf(39, 1):uint()
			t:add(f_name, buf(40,name_len))
		elseif i_id == 4 then
		    t:add(f_x, buf(2,8))
			t:add(f_y, buf(10,8))
			t:add(f_z, buf(18,8))
			t:add(f_onground, buf(26,1))
		elseif i_id == 5 then
		    t:add(f_position, buf(2,8))
		elseif i_id == 8 then
		    t:add(f_x, buf(2,8))
			t:add(f_y, buf(10,8))
			t:add(f_z, buf(18,8))
			t:add(f_yaw, buf(26,4))
			t:add(f_pitch, buf(30,4))			
			t:add(f_onground, buf(34,1))
		elseif i_id == 9 then
		    t:add(f_slot, buf(2,1))
		elseif i_id == 48 then
		    t:add(f_winid, buf(2,1))
			t:add(f_count, buf(3,2))
	    elseif i_id == 55 then
			t:add(f_s_count, buf(2,1))
	    elseif i_id == 56 then
			t:add(f_action, buf(2,1))
			t:add(f_playernum, buf(3,1))
			t:add(f_binary_uuid, buf(4,16))
			local name_len = buf(20, 1):uint()
			t:add(f_name, buf(21,name_len))
		elseif i_id == 57 then
		    t:add(f_flags, buf(2,1))
			t:add(f_flying_speed, buf(3,4))
			t:add(f_walking_speed, buf(7,4))
		elseif i_id == 63 then
		    local channel_len = buf(2, 1):uint()
			t:add(f_channel, buf(3,channel_len))
			local data_len = buf((3 + channel_len), 1):uint()
			t:add(f_data, buf((4 + channel_len),data_len))
		elseif i_id == 65 then
		    t:add(f_difficulty, buf(2,1))
		end

        return true
    end

    function p_Minecraft.dissector(buf,pkt,root) 
        if Minecraft_dissector(buf,pkt,root) then
            --valid Minecraft diagram
        else
           -- When not Minecraft call data
            data_dis:call(buf,pkt,root)
        end
    end
    
    local tcp_encap_table = DissectorTable.get("tcp.port")
    --Just listening 25565
    tcp_encap_table:add(25565,p_Minecraft)

end
