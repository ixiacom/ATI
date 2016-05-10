--------------------------------------------------------------------------------
-- zab.lua
-- Author: Alina Lupu
-- 
-- Works as of Wireshark v2.0.2
-- This is a Lua dissector for ZAB 1.0 validation.
-- Only the messages exchanged between the client and the server are supported.
-- 
-- Notice:
-- The default port is set to 2181, but keep in mind that clients can connect to 
-- the Zookeeper server using any port configured in the configuration file.
--
-- Setup
-- 1. Copy 'zab.lua' to somewhere in your wireshark directory. For example, C:\Program Files\Wireshark.
-- 2. Open 'init.lua' in your wireshark root directory. Comment the line 'disable_lua = true' or change it to 'disable_lua = false'.
--------------------------------------------------------------------------------

local p_zab = Proto("ZAB", "ZAB 1.0")
local ZAB_PORT = 2181
local MAX_REQUEST_SIZE = 100 * 1024 * 1024
local MAX_ACLS = 10
local MAX_WATCHES = 100

local FOUR_LETTER_WORDS = {
	["conf"] = true,
	["cons"] = true,
	["crst"] = true,
	["dump"] = true,
	["envi"] = true,
	["ruok"] = true,
	["srst"] = true,
	["srvr"] = true,
	["stat"] = true,
	["wchs"] = true,
	["wchc"] = true,
	["wchp"] = true,
	["mntr"] = true
}

local NEGATIVE_XIDS = {
	[-1] = "WATCH_XID",
	[-2] = "PING_XID",
	[-4] = "AUTH_XID",
	[-8] = "SET_WATCHES_XID"
}

local opCodes = 
{	[0] = "CONNECT",
	[1] = "CREATE",
	[2] = "DELETE",
	[3] = "EXISTS",
	[4] = "GETDATA",
	[5] = "SETDATA",
	[6] = "GETACL",
	[7] = "SETACL",
	[8] = "GETCHILDREN",
	[9] = "SYNC",
	[11] = "PING",
	[12] = "GETCHILDREN2",
	[13] = "CHECK",
	[14] = "MULTI",
	[15] = "CREATE2",
	[16] = "RECONFIG",
	[-10] = "CREATESESSION",
	[-11] = "CLOSE",
	[100] = "SETAUTH",
	[101] = "SETWATCHES"
}

local watchEventTypes = {
    [-1] = "None",
    [1] = "NodeCreated",
    [2] = "NodeDeleted",
    [3] = "NodeDataChanged",
    [4] = "NodeChildrenChanged"
}

requestsXids = {}

local f_opCode = ProtoField.int64("zab.opcode", "Operation", base.INT, opCodes)
local f_data = ProtoField.string("zab.data", "Data")
local f_len = ProtoField.int64("zab.length", "Length", base.INT)
local f_xid = ProtoField.int64("zab.xid", "Transaction ID")
local f_path = ProtoField.string("zab.path", "Path")
local f_watch = ProtoField.bool("zab.watch", "Watch")
local f_protoversion = ProtoField.int64("zab.protocolversion", "Protocol Version")
local f_zxid = ProtoField.double("zab.zxid", "ZxID")
local f_zxid_epoch = ProtoField.int64("zab.zxid.epoch", "Epoch")
local f_zxid_count = ProtoField.int64("zab.zxid.count", "Count")
local f_czxid = ProtoField.double("zab.czxid", "Created ZxID")
local f_czxid_epoch = ProtoField.int64("zab.czxid.epoch", "Epoch")
local f_czxid_count = ProtoField.int64("zab.czxid.count", "Count")
local f_mzxid = ProtoField.double("zab.mzxid", "Last Modified ZxID")
local f_mzxid_epoch = ProtoField.int64("zab.mzxid.epoch", "Epoch")
local f_mzxid_count = ProtoField.int64("zab.mzxid.count", "Count")
local f_pzxid = ProtoField.double("zab.pzxid", "Last Modified Children ZxID")
local f_pzxid_epoch = ProtoField.int64("zab.pzxid.epoch", "Epoch")
local f_pzxid_count = ProtoField.int64("zab.pzxid.count", "Count")
local f_timeout = ProtoField.int64("zab.timeout", "Timeout")
local f_session = ProtoField.double("zab.session", "Session ID")
local f_authtype = ProtoField.int64("zab.authtype", "Authentication Type")
local f_perms = ProtoField.int64("zab.permissions", "Permissions")
local f_scheme = ProtoField.string("zab.scheme", "Scheme")
local f_credential = ProtoField.string("zab.credential", "Credentials")
local f_dataLength = ProtoField.int64("zab.datalength", "Data Length")
local f_ephemeral = ProtoField.bool("zab.ephemeral", "Ephemeral")
local f_sequence = ProtoField.bool("zab.sequence", "Sequence")
local f_joining = ProtoField.string("zab.joining", "Joining")
local f_leaving = ProtoField.string("zab.leaving", "Leaving")
local f_newmembers = ProtoField.string("zab.newmembers", "New Members")
local f_datawatch = ProtoField.string("zab.datawatch", "Data Watch")
local f_existwatch = ProtoField.string("zab.existwatch", "Existing Watch")
local f_childwatch = ProtoField.string("zab.childwatch", "Child Watch")
local f_firstopcode = ProtoField.int64("zab.firstopcode", "First Operation")
local f_done = ProtoField.bool("zab.done", "Done")
local f_err = ProtoField.int64("zab.err", "Error")
local f_version = ProtoField.int64("zab.version", "Version")
local f_cversion = ProtoField.int64("zab.cversion", "Child Version")
local f_aversion = ProtoField.int64("zab.aversion", "ACL Version")
local f_eventtype = ProtoField.int64("zab.eventtype", "Event Type", base.INT, watchEventTypes)
local f_state = ProtoField.int64("zab.state", "State")
local f_passwd = ProtoField.bytes("zab.passwd", "Password")
local f_readonly = ProtoField.bool("zab.readonly", "Readonly")
local f_count = ProtoField.int64("zab.count", "Count")
local f_child = ProtoField.string("zab.child", "Child")
local f_ctime = ProtoField.double("zab.ctime", "Created", base.RELATIVE_TIME)
local f_mtime = ProtoField.double("zab.mtime", "Last Modified", base.RELATIVE_TIME)
local f_ephemeralowner = ProtoField.double("zab.ephemeralowner", "Ephemeral Owner")
local f_numchildren = ProtoField.int64("zab.numchildren", "Number of Children")

p_zab.fields = { f_len, f_xid, f_data, f_opCode, f_path, f_watch, f_protoversion, 
	f_zxid, f_zxid_epoch, f_zxid_count, f_timeout, f_session, f_authtype, 
	f_perms, f_scheme, f_credential, f_dataLength, f_ephemeral, f_sequence, 
	f_joining, f_leaving, f_newmembers, f_datawatch, f_existwatch, f_childwatch,
	f_firstopcode, f_done, f_err, f_version, f_eventtype, f_state, f_passwd, f_readonly,
	f_count, f_child, f_czxid, f_czxid_epoch, f_czxid_count, f_mzxid, f_mzxid_epoch, f_mzxid_count,
	f_ctime, f_mtime, f_cversion, f_aversion, f_ephemeralowner, f_numchildren, f_pzxid,
	f_pzxid_epoch, f_pzxid_count}

function p_zab.dissector(buf, pkt, root)
	if buf:len() < 4 then return end
	pkt.cols.protocol = p_zab.name
	local tree = root:add(p_zab, buf(0))
	if pkt.dst_port == ZAB_PORT then --client_message
		local four_letter_word = buf(0, 4)
		if FOUR_LETTER_WORDS[four_letter_word:string()] then
			pkt.cols.info:set(string.format("Four letter request: %s", four_letter_word:string()))
			tree:add(f_data, four_letter_word)
		else
			dissectClient(buf, pkt, tree)
		end
		return
	elseif pkt.src_port == ZAB_PORT then --server_message
		local msg = buf(0, 9):string()
		if msg == "Zookeeper" then
			--response to the four letter message
			pkt.cols.info:set("Four letter response")
			tree:add(f_data, buf(0))
		else
			dissectServer(buf, pkt, tree)
		end
		return
	end
end

dissectClient = function (buf, pkt, tree)
	local client = string.format("%s:%s", pkt.src, pkt.src_port)
	if requestsXids[client] == nil then
		requestsXids[client] = {}
	end
	local xid = 0
	length = buf(0, 4):int()
	tree:add(f_len, buf(0, 4))
	if length >= MAX_REQUEST_SIZE or length == -2 or length == -4 or length == -8 then
		xid = length
		length = 0
	elseif length == 0 then
		if pcall(function () protoversion, zxid, zxid_epoch, zxid_count, timeout, session, passwd, readonly = dissectConnectRequest(buf, 0) end) then
			requestsXids[client]["0"] = 0
			pkt.cols.info:set("CONNECT REQUEST")
			tree:add(f_protoversion, protoversion)
			local zxidtree = tree:add(f_zxid, zxid)
			zxidtree:add(f_zxid_epoch, zxid_epoch)
			zxidtree:add(f_zxid_count, zxid_count)
			tree:add(f_timeout, timeout)
			tree:add(f_session, session)
			tree:add(f_passwd, passwd)
			tree:add(f_readonly, readonly)
		end
		return
    elseif length < 0 then
		return 0 --error: bad request length
    else
		xid = buf(4, 4):int()
        if not (xid == -2 or xid == -4 or xid == -8) and xid < 0 then
			return 0 --error: wrong xid
		elseif xid == 0 or xid == 1 then
			if pcall(function () protoversion, zxid, zxid_epoch, zxid_count, timeout, session, passwd, readonly = dissectConnectRequest(buf, 4) end) then
				requestsXids[client]["0"] = 0
				pkt.cols.info:set("CONNECT REQUEST")
				tree:add(f_protoversion, protoversion)
				local zxidtree = tree:add(f_zxid, zxid)
				zxidtree:add(f_zxid_epoch, zxid_epoch)
				zxidtree:add(f_zxid_count, zxid_count)
				tree:add(f_timeout, timeout)
				tree:add(f_session, session)
				tree:add(f_passwd, passwd)
				tree:add(f_readonly, readonly)
				return
			end
        end
	end
	
	tree:add(f_xid, buf(4, 4))
	tree:add(f_opCode, buf(8, 4))
	local offset = 12
	i_opCode = buf(8, 4):int()
	pkt.cols.info:set(string.format("%s REQUEST", opCodes[i_opCode]))
	
	if not (i_opCode == 11 or i_opCode == -11) then --any request that is not a ping or a close should be tracked
		requestsXids[client][buf(4, 4):int()] = i_opCode
	end
	
	if not (i_opCode == 0 or i_opCode == 101 or i_opCode == 11 or i_opCode == 100 or i_opCode == 14 or i_opCode == -11 or i_opCode == 16) then
		buf, tree, offset = dissectString(buf, tree, offset, f_path)
	end
	
	if (offset < buf:len() - 4) then
		if length == 0 then
			length = buf(offset, 4)
			offset = offset + 4
		end
		
		if i_opCode == 3 or i_opCode == 4 or i_opCode == 8 or i_opCode == 12 then
			tree:add(f_watch, buf(offset, 1))
			offset = offset + 1
		end
		
		if i_opCode == 1 then --CREATE request
			buf, tree, offset = dissectString(buf, tree, offset, f_data)
			buf, tree, offset = dissectAclsArray(buf, tree, offset)
			local flags = buf(offset, 4):int()
			offset = offset + 4
			local ephemeral = (bit.band(flags, 0x1) == 1)
			local sequence = (bit.band(flags, 0x2) == 2)
			tree:add(f_ephemeral, ephemeral)
			tree:add(f_sequence, sequence)
		elseif i_opCode == 2 then --DELETE request
			tree:add(f_version, buf(offset, 4))
		elseif i_opCode == 5 then --SETDATA request
			buf, tree, offset = dissectString(buf, tree, offset, f_data)
			tree:add(f_version, buf(offset, 4))
		elseif i_opCode == 7 then --SETACL request
			buf, tree, offset = dissectAclsArray(buf, tree, offset)
			tree:add(f_version, buf(offset, 4))
		elseif i_opCode == 14 then --MULTI request
			local first_opcode = buf(offset, 4):int()
			tree:add(f_firstopcode, buf(offset, 4))
			tree:add(f_done, buf(offset + 4, 1))
			tree:add(f_err, buf(offset + 5, 4))
			offset = offset + 9
			if not (first_opcode == 0 or first_opcode == 101 or first_opcode == 11 or first_opcode == 100 or first_opcode == 14 or first_opcode == -11 or first_opcode == 16) then
				buf, tree, offset = dissectString(buf, tree, offset, f_path)
			end
		elseif i_opCode == 16 then --RECONFIG request
			buf, tree, offset = dissectString(buf, tree, offset, f_joining)
			buf, tree, offset = dissectString(buf, tree, offset, f_leaving)
			buf, tree, offset = dissectString(buf, tree, offset, f_newmembers)
		elseif i_opCode == 100 then --SETAUTH request
			tree:add(f_authtype, buf(offset, 4))
			offset = offset + 4
			buf, tree, offset = dissectString(buf, tree, offset, f_scheme)
			buf, tree, offset = dissectString(buf, tree, offset, f_credential)
		elseif i_opCode == 101 then --SETWATCHES request
			local dataw_num_strs = buf(offset, 4):int()
			offset = offset + 4
			if dataw_num_strs < MAX_WATCHES then
				for i = 0, dataw_num_strs - 1 do
					buf, tree, offset = dissectString(buf, tree, offset, f_datawatch)
				end
			end
			local existw_num_strs = buf(offset, 4):int()
			offset = offset + 4
			if existw_num_strs < MAX_WATCHES then
				for i = 0, existw_num_strs - 1 do
					buf, tree, offset = dissectString(buf, tree, offset, f_existwatch)
				end
			end
			local childw_num_strs = buf(offset, 4):int()
			offset = offset + 4
			if childw_num_strs < MAX_WATCHES then
				for i = 0, childw_num_strs - 1 do
					buf, tree, offset = dissectString(buf, tree, offset, f_childwatch)
				end
			end
		end
	end
end

dissectServer = function (buf, pkt, tree)
	length = buf(0, 4):int()
	if length < 0 then
		return 0
	end
	tree:add(f_len, buf(0, 4))
	local xid = buf(4, 4):int()
	
	local client = string.format("%s:%s", pkt.dst, pkt.dst_port)
	local request_type = requestsXids[client][xid]
	if xid == 0 then
		request_type = requestsXids[client]["0"]
	end
	pkt.cols.info:set(string.format("%s REPLY", opCodes[request_type]))
	
	local offset = 4
	if request_type == 0 then --CONNECT reply
		tree:add(f_protoversion, buf(offset, 4))
		tree:add(f_timeout, buf(offset + 4, 4))
		tree:add(f_session, buf(offset + 8, 8))
		buf, tree, offset = dissectString(buf, tree, offset + 16, f_passwd)
		tree:add(f_readonly, buf(offset, 1))
		offset = offset + 17
	else
		tree:add(f_xid, buf(4, 4))
		local zxid = tree:add(f_zxid, buf(8, 8))
		zxid:add(f_zxid_epoch, buf(8, 4))
		zxid:add(f_zxid_count, buf(12, 4))
		tree:add(f_err, buf(16, 4))
		offset = 20
		
		if (xid == -1) then
			pkt.cols.info:set("WATCH EVENT")
			dissectWatchEvent(buf, tree, offset)
		elseif xid == -2 then
			pkt.cols.info:set("PING REPLY")
		end
		if request_type == 1 then --CREATE reply
			buf, tree, offset = dissectString(buf, tree, offset, f_path)
		elseif request_type == 3 then --EXISTS reply
			buf, tree, offset = dissectStat(buf, tree, offset, f_data)
		elseif request_type == 4 then --GETDATA reply
			buf, tree, offset = dissectString(buf, tree, offset, f_data)
			buf, tree, offset = dissectStat(buf, tree, offset, f_data)
		elseif request_type == 5 then --SETDATA reply
			buf, tree, offset = dissectStat(buf, tree, offset, f_data)
		elseif request_type == 6 then --GETACL reply
			buf, tree, offset = dissectAclsArray(buf, tree, offset)
			buf, tree, offset = dissectStat(buf, tree, offset, f_data)
		elseif request_type == 7 then --SETACL reply
			buf, tree, offset = dissectStat(buf, tree, offset, f_data)
		elseif request_type == 8 then --GETCHILDREN reply
			local count = buf(offset, 4)
			offset = offset + 4
			tree:add(f_count, count)
			for i = 0, count:int() - 1 do
				buf, tree, offset = dissectString(buf, tree, offset, f_child)
			end
		elseif request_type == 14 then --MULTI reply
			tree:add(f_firstopcode, buf(offset, 4))
			tree:add(f_done, buf(offset + 4, 4))
			tree:add(f_err, buf(offset + 8, 4))
		end
	end
end

dissectConnectRequest = function(buf, offset)
	protoversion = buf(offset, 4)
	offset = offset + 4
	zxid = buf(offset, 8)
	zxid_epoch = buf(offset, 4)
	zxid_count = buf(offset + 4, 4)
	offset = offset + 8
	timeout = buf(offset, 4)
	session = buf(offset + 4, 8)
	offset = offset + 12
	local pswd_length = buf(offset, 4):int()
	passwd = buf(offset + 4, pswd_length)
	offset = offset + 4 + pswd_length
	readonly = buf(offset, 1)
	return protoversion, zxid, zxid_epoch, zxid_count, timeout, session, passwd, readonly
end

dissectAclsArray = function(buf, tree, offset)
	local acls_count = buf(offset, 4):int()
	offset = offset + 4
	if acls_count < MAX_ACLS then
		for i = 0, acls_count - 1 do
			tree:add(f_perms, buf(offset, 4))
			local scheme_length = buf(offset + 4, 4):int()
			tree:add(f_scheme, buf(offset + 8, scheme_length))
			offset = offset + 8 + scheme_length
			local cred_length = buf(offset, 4):int()
			tree:add(f_credential, buf(offset + 4, cred_length))
			offset = offset + 4 + cred_length
		end
	end
	return buf, tree, offset
end

dissectString = function(buf, tree, offset, f_param)
	local data_length = buf(offset, 4):int()
	tree:add(f_param, buf(offset + 4, data_length))
	offset = offset + 4 + data_length
	return buf, tree, offset
end

dissectStat = function(buf, tree, offset, f_param)
	local zxid = tree:add(f_czxid, buf(offset, 8))
	zxid:add(f_czxid_epoch, buf(offset, 4))
	zxid:add(f_czxid_count, buf(offset + 4, 4))
	offset = offset + 8
	zxid = tree:add(f_mzxid, buf(offset, 8))
	zxid:add(f_mzxid_epoch, buf(offset, 4))
	zxid:add(f_mzxid_count, buf(offset + 4, 4))
	offset = offset + 8
	tree:add(f_ctime, buf(offset, 8))
	tree:add(f_mtime, buf(offset + 8, 8))
	offset = offset + 16
	tree:add(f_version, buf(offset, 4))
	tree:add(f_cversion, buf(offset + 4, 4))
	tree:add(f_aversion, buf(offset + 8, 4))
	offset = offset + 12
	tree:add(f_ephemeralowner, buf(offset, 8))
	tree:add(f_dataLength, buf(offset + 8, 4))
	tree:add(f_numchildren, buf(offset + 12, 4))
	offset = offset + 16
	local zxid = tree:add(f_pzxid, buf(offset, 8))
	zxid:add(f_pzxid_epoch, buf(offset, 4))
	zxid:add(f_pzxid_count, buf(offset + 4, 4))
	offset = offset + 8
	return buf, tree, offset
end

dissectWatchEvent = function(buf, tree, offset)
	tree:add(f_eventtype, buf(offset, 4))
	tree:add(f_state, buf(offset + 4, 4))
	offset = offset + 8
	buf, tree, offset = dissectString(buf, tree, offset, f_path)
end

function p_zab.init()
    local tcp_dissector_table = DissectorTable.get("tcp.port")
    tcp_dissector_table:add(ZAB_PORT, p_zab)
end