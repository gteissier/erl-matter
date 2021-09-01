local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local bin = require "bin"
local match = require "match"

-- @usage
-- nmap -sT -p <port> <ip> --script erldp-info -sV
-- 
-- @output
-- PORT      STATE SERVICE
-- 25672/tcp open  erldp
-- | erldp-info:
-- |   version: 6e00
-- |   node: rabbit@iron
-- |_  flags: 500037f
-- 
-- Erlang daemons - couchdb, ejabberd and rabbitmq are the most common -
-- may expose a sensitive asset called Erlang distribution protocol.
-- This script actively scans for Erlang distribution protocol.
-- The portrule below asks to scan for every open TCP port.
--
-- Note that epmd-info.nse may already provide information regarding
-- named Erlang nodes.
-- 
-- Running the same command as above plus --script epmd-info gives:
-- PORT      STATE SERVICE
-- 4369/tcp  open  epmd
-- | epmd-info:
-- |   epmd_port: 4369
-- |   nodes:
-- |_    rabbit: 25672
-- 5672/tcp  open  amqp
-- 25672/tcp open  erldp
-- | erldp-info:
-- |   version: 6e00
-- |   node: rabbit@iron
-- |_  flags: 500037f
--
-- However, some security guidelines recommend to disallow access to 4369
-- while Erlang nodes might still be accessible.
--



description = [[
Identifies Erlang distribution, which provides remoting for Erlang based servers.
]]

author = "Guillaume Teissier <gteissier@gmx.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

local random = math.random
local function uuid()
    local template ='xxxxxxxx@devnull'
    return string.gsub(template, '[x]', function (c)
        local v = random(0, 0xf)
        return string.format('%x', v)
    end)
end

local function decode(conn)
  local status, data

  status, data = conn:receive_buf(match.numbytes(2), true)
  if not status then
    return
  end

  length = select(2, bin.unpack(">S", data))

  status, data = conn:receive_buf(match.numbytes(length), true)
  if not status then
    return
  end

  return data
end

local function decode_recv_challenge(data)
  local version, flags, challenge, offset
  offset, cmd, version, flags, challenge = bin.unpack(">CSII", data)
  return version, flags, challenge, data:sub(offset)
end

action = function(host, port)
  local client = nmap.new_socket()
  local status
  local data
  local send_name
  local local_name = uuid()
  local output = stdnse.output_table()

  status, data = client:connect(host, port)
  if not status then
    client:close()
    return
  end

  send_name = bin.pack('>SCSIA', 7+string.len(local_name), 110, 5, 0x7499c, local_name)

  if not client:send(send_name) then
    client:close()
    return
  end

  data = decode(client)
  if not data or data:sub(1, 1) ~= "s" or data:sub(2, 3) ~= "ok" then
    client:close()
    return
  end

  data = decode(client)
  if not data or data:sub(1, 1) ~= "n" then
    client:close()
    return
  end

  local version, flags, challenge, peer_name = decode_recv_challenge(data)

  output["version"] = stdnse.tohex(version)
  output["node"] = peer_name
  output["flags"] = stdnse.tohex(flags)

  port.version.product = "Erlang distribution protocol"
  port.version.name = "erldp"

  nmap.set_port_state(host, port, "open")
  nmap.set_port_version(host, port, "hardmatched")

  return output
end
