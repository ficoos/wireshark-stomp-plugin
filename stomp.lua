--
-- Copyright 2009-2012 Red Hat, Inc.
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
--
-- Refer to the README and COPYING files for full details of the license
--
local p_stomp = Proto("stomp", "STOMP")

local f_command = ProtoField.string("stomp.command", "Command", FT_STRING)
local f_body = ProtoField.string("stomp.body", "Body")
local f_header = ProtoField.string("stomp.header", "Header")
local f_header_key = ProtoField.string("stomp.header.key", "Key")
local f_header_value = ProtoField.string("stomp.header.value", "Value")

p_stomp.fields = {
    f_command,
    f_body,
    f_header,
    f_header_key,
    f_header_value,
}

p_stomp.prefs["tcp_port"] = Pref.uint(
    "TCP Port",
    54321,
    "TCP Port for STOMP communication"
)

local Headers = {
    content_length = "content-length",
}

local function _partition(buf, s)
    local buf_len = buf:len() - 1
    local s_len = s:len()
    for i=0,buf_len do
        if buf(i, s_len):string() == s then
            if (i + s_len) >= buf:len() then
                return buf(0, i), buf(i, s_len), ByteArray.new()
            else
                return buf(0, i), buf(i, s_len), buf(i + s_len)
            end
        end
    end
    return nil, nil, buf

end

local function read_line(buf)
    return _partition(buf, "\n")
end

local function read_command(buf)
    return read_line(buf)
end

local KNOWN_COMMANDS = {
    -- client commands
    ["SEND"] = true,
    ["SUBSCRIBE"] = true,
    ["UNSUBSCRIBE"] = true,
    ["BEGIN"] = true,
    ["COMMIT"] = true,
    ["ABORT"] = true,
    ["ACK"] = true,
    ["NACK"] = true,
    ["DISCONNECT"] = true,
    ["CONNECT"] = true,
    ["STOMP"] = true,

    -- server commands
    ["CONNECTED"] = true,
    ["MESSAGE"] = true,
    ["RECEIPT"] = true,
    ["ERROR"] = true,
}

function p_stomp.dissector(buf, pinfo, root)
    local offset = pinfo.desegment_offset or 0
    local command = nil
    local headers = {}
    local body = nil
    local sep = nil
    local rest = nil
    local content_length = nil
    rest = buf(offset)
    command, sep, rest = read_command(rest)
    if not sep then
        if rest:len() > 12 then
            return
        else
            pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            return
        end
    end
    offset = offset + command:len() + sep:len()
    -- This is here to fuzz out bad data that contains \n
    if not KNOWN_COMMANDS[command:string()] then
        return
    end

    do
        local header = nil
        while true do
            header, sep, rest = read_line(rest)
            if not sep then
                pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
                return
            end
            offset = offset + header:len() + sep:len()

            if header:len() == 0 then
                break
            end

            local key, sep, value = _partition(header, ":")
            if
                content_length == nil
                and key
                and key:string() == Headers.content_length
            then
                content_length = tonumber(value:string())
            end
            table.insert(headers, {header, key, value})
        end
    end
    if content_length == nil then
        body, sep, rest = _partition(rest, "\0")
        if not sep then
            pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            return
        end
        offset = offset + body:len() + sep:len()
    else
        if rest:len() < content_length then
            pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            return
        end
        body = rest(0, content_length)
        offset = offset + body:len() + 1
    end

    pinfo.cols.protocol = "STOMP"
    pinfo.cols.info = command:string()
    local subtree = root:add(p_stomp, buf(0))
    subtree:add(f_command, command)
    for _, header_info in ipairs(headers) do
        local header, key, value = unpack(header_info)
        local header_tree = subtree:add(f_header, header)
        if key then
            header_tree:add(f_header_key, key)
        end
        if value then
            header_tree:add(f_header_value, value)
        end
    end
    subtree:add(f_body, body)
    pinfo.desegment_offset = offset
end

function p_stomp.init()
    local tcp_dissector_table = DissectorTable.get("tcp.port")
    tcp_dissector_table:add(p_stomp.prefs["tcp_port"], p_stomp)
end
