-- Modified on 2015-7-4 by Hadriel to handle STOMP over HTTP/Websocket
-- Modified on 2019-8-21 by Ethan Reesor to handle STOMP over SSL/TLS
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

local settings = {
    TCP_PORT = 54321,
    SSL_PORT = 61614,
    WEBSOCKET_PORT = 9000
}

p_stomp.prefs["tcp_port"] = Pref.uint(
    "Standards-based TCP Port",
    settings.TCP_PORT,
    "TCP Port for STOMP standards-compliant communication (0 to disable)"
)

p_stomp.prefs["ssl_port"] = Pref.uint(
    "STOMP-over-SSL TCP Port",
    settings.TCP_PORT,
    "TCP Port for STOMP over SSL (0 to disable)"
)

p_stomp.prefs["websocket_port"] = Pref.uint(
    "STOMP in Websocket for HTTP server TCP port",
    settings.WEBSOCKET_PORT,
    "The TCP server port number for STOMP in Websocket payload (0 to disable)"
)

p_stomp.prefs["warning_text"] = Pref.statictext(
    "Warning: The Standards-based TCP port number must not be the "..
    "same as the Websocket TCP port number."
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

local errmsg = "Error: The STOMP preferences are invalid! The port numbers for plain STOMP, STOMP-over-SSL, and STOMP-over-Websocket must all be different!\n\nPlease correct this before continuing."

function p_stomp.prefs_changed()
    -- raw TCP and Websocket cannot use same port number
    local tcp_port = p_stomp.prefs.tcp_port
    local ssl_port = p_stomp.prefs.ssl_port
    local websocket_port = p_stomp.prefs.websocket_port

    if ((tcp_port ~= 0) and ((tcp_port == ssl_port) or (tcp_port == websocket_port))) or ((ssl_port ~= 0) and (ssl_port == websocket_port)) then
        if gui_enabled() then
            local tw = TextWindow.new("STOMP Preference Error")
            tw:set(errmsg)
        else
            print(errmsg)
        end
        return
    end

    if settings.TCP_PORT ~= tcp_port then
        -- the tcp port number preference changed
        local tcp_dissector_table = DissectorTable.get("tcp.port")
        if settings.TCP_PORT ~= 0 then
            -- remove our proto from the number it was previously dissecting
            tcp_dissector_table:remove(settings.TCP_PORT, p_stomp)
        end
        settings.TCP_PORT = tcp_port
        if settings.TCP_PORT ~= 0 then
            -- add our proto for the new port number
            tcp_dissector_table:add(settings.TCP_PORT, p_stomp)
        end
    end

    if settings.SSL_PORT ~= ssl_port then
        -- the tcp port number preference changed
        local tcp_dissector_table = DissectorTable.get("ssl.port")
        if settings.SSL_PORT ~= 0 then
            -- remove our proto from the number it was previously dissecting
            tcp_dissector_table:remove(settings.SSL_PORT, p_stomp)
        end
        settings.SSL_PORT = ssl_port
        if settings.SSL_PORT ~= 0 then
            -- add our proto for the new port number
            tcp_dissector_table:add(settings.SSL_PORT, p_stomp)
        end
    end

    if settings.WEBSOCKET_PORT ~= websocket_port then
        -- the tcp port number preference changed
        local ws_dissector_table = DissectorTable.get("ws.port")
        if settings.WEBSOCKET_PORT ~= 0 then
            -- remove our proto from the number it was previously dissecting
            ws_dissector_table:remove(settings.WEBSOCKET_PORT, p_stomp)
        end
        settings.WEBSOCKET_PORT = websocket_port
        if settings.WEBSOCKET_PORT ~= 0 then
            -- add our proto for the new port number
            ws_dissector_table:add(settings.WEBSOCKET_PORT, p_stomp)
        end
    end
end

if settings.TCP_PORT ~= 0 then
    DissectorTable.get("tcp.port"):add(settings.TCP_PORT, p_stomp)
end

if settings.SSL_PORT ~= 0 then
    DissectorTable.get("ssl.port"):add(settings.SSL_PORT, p_stomp)
end

if settings.WEBSOCKET_PORT ~= 0 then
    DissectorTable.get("ws.port"):add(settings.WEBSOCKET_PORT, p_stomp)
end
