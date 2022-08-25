import copy
import enum
import io

from aiosmb.commons.utils.align import align
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb.protocol.smb2.headers import *
from aiosmb.protocol.smb2.commands import *
from aiosmb.protocol.smb2.command_codes import *

class SMB2Compression:
	def __init__(self, header = None, data = None):
		self.header = header
		self.data   = data
	
	@staticmethod
	def from_bytes(bbuff):
		return SMB2Compression.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = SMB2Compression()
		pos = buff.tell()
		t = buff.read(1)
		buff.seek(pos,0)
		if t == b'\xFC':
			msg.header = SMB2Header_COMPRESSION_TRANSFORM.from_buffer(buff)
		else:
			raise Exception('Unknown packet type for SMB2Compression! %s' % t)
		
		msg.data = buff.read()
		return msg

	def to_bytes(self):
		t = self.header.to_bytes()
		t += self.data
		return t

class SMB2Transform:
	def __init__(self, header = None, data = None):
		self.header = header
		self.data   = data
	
	@staticmethod
	def from_bytes(bbuff):
		return SMB2Transform.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = SMB2Transform()
		pos = buff.tell()
		t = buff.read(1)
		buff.seek(pos,0)
		if t == b'\xFD':
			msg.header = SMB2Header_TRANSFORM.from_buffer(buff)
		else:
			raise Exception('Unknown packet type for SMB2Transform! %s' % t)
		
		msg.data = buff.read()
		return msg

	def to_bytes(self):
		t = self.header.to_bytes()
		t += self.data
		return t

class SMB2Message:
	def __init__(self, header=None, command=None, next_message=None):
		self.header = header
		self.command = command
		self.next_message = next_message
		self.padder = None

	def chain_message(self, message, related=False):
		'''Chain another message to this message. Returns the chained message so that more messages can be tacked onto it.'''
		# clear any previous chained message
		if self.next_message is not None:
			self.header.NextCommand = 0
			self.next_message = None

		# only update NextCommand if unset, since chain_message is also called when parsing compound replies
		if self.header.NextCommand == 0:
			# next command location: after current command, padded to multiple of 8
			self.header.NextCommand = align(self.size(), 8)

		# set RELATED_OPERATIONS flag, if requested
		if related:
			self.header.Flags |= SMB2HeaderFlag.SMB2_FLAGS_RELATED_OPERATIONS

		# remember the next message for later
		self.next_message = message
		return message

	@staticmethod
	def from_bytes(bbuff):
		return SMB2Message.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		pos = buff.tell()

		msg = SMB2Message()
		if SMB2Message.isAsync(buff):
			msg.header = SMB2Header_ASYNC.from_buffer(buff)
		else:
			msg.header = SMB2Header_SYNC.from_buffer(buff)
			
		# maybe it's an error...
		# not sure this is the best way to check fot he error message
		if msg.header.Status != NTStatus.SUCCESS and SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR in msg.header.Flags:
			if not (msg.header.Status == NTStatus.MORE_PROCESSING_REQUIRED and msg.header.Command.name == 'SESSION_SETUP'):
				pos = buff.tell()
				structure_size = int.from_bytes(buff.read(2), byteorder='little')
				buff.seek(pos, 0)
				if structure_size == 9:
					msg.command = ERROR_REPLY.from_buffer(buff)
					return msg

		classname = msg.header.Command.name
		try:
			if SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR in msg.header.Flags:
				classname += '_REPLY'
			else:
				classname += '_REQ'
			msg.command = command2object[classname].from_buffer(buff)
		except Exception as e:

			import traceback
			traceback.print_exc()
			#print('Could not find command implementation! %s' % str(e))
			msg.command = SMB2NotImplementedCommand.from_buffer(buff)

		# if chained, parse the next command
		if msg.header.NextCommand != 0:
			buff.seek(pos + msg.header.NextCommand, io.SEEK_SET)
			next_msg = SMB2Message.from_buffer(buff)
			msg.chain_message(next_msg)

		return msg

	@staticmethod
	def isAsync(buff):
		"""
		jumping to the header flags and check if the AYSNC command flag is set
		"""
		pos = buff.tell()
		buff.seek(16, io.SEEK_SET)
		flags = SMB2HeaderFlag(int.from_bytes(buff.read(4), byteorder='little', signed = False))
		buff.seek(pos, io.SEEK_SET)
		return SMB2HeaderFlag.SMB2_FLAGS_ASYNC_COMMAND in flags

	def to_bytes(self):
		t  = self.header.to_bytes()
		t += self.command.to_bytes()

		# if not compound, we're done
		if self.next_message is None:
			return t

		# compound message: pad first
		padlen = self.header.NextCommand - len(t)
		if not callable(self.padder) or (pad := self.padder(self, padlen)) is None:
			pad = b'\x00' * padlen
		t += pad

		# then append the next message
		return t + self.next_message.to_bytes()

	def size(self):
		# since there's no available way to just compute the size of the header/command, we serialize ourselves and get the length
	    # but since serialization may alter the header/command, we operate on copies (shallow ones should be enough)
		# so this method is probably a lot more costly than it should be, meh
		clone = SMB2Message(copy.copy(self.header), copy.copy(self.command), self.next_message)
		return len(clone.to_bytes())

	def __repr__(self):
		t = "== SMBv2 Message ==\r\n"
		t += repr(self.header)
		t += repr(self.command)

		next_msg = self.next_message
		while next_msg is not None:
			t += '\r\n== (chained) ==\r\n'
			t += repr(next_msg.header)
			t += repr(next_msg.command)
			next_msg = next_msg.next_message

		return t


command2object = {
	'NEGOTIATE_REQ'       : NEGOTIATE_REQ,
	'NEGOTIATE_REPLY'     : NEGOTIATE_REPLY,
	'SESSION_SETUP_REQ'     : SESSION_SETUP_REQ,
	'SESSION_SETUP_REPLY'     : SESSION_SETUP_REPLY,
	'TREE_CONNECT_REQ'     : TREE_CONNECT_REQ,
	'TREE_CONNECT_REPLY'     : TREE_CONNECT_REPLY,
	'CREATE_REQ'     : CREATE_REQ,
	'CREATE_REPLY'     : CREATE_REPLY,
	'READ_REQ'     : READ_REQ,
	'READ_REPLY'     : READ_REPLY,
	'QUERY_INFO_REPLY' : QUERY_INFO_REPLY,
	'QUERY_INFO_REQ' : QUERY_INFO_REQ,
	'QUERY_DIRECTORY_REQ' : QUERY_DIRECTORY_REQ,
	'QUERY_DIRECTORY_REPLY' : QUERY_DIRECTORY_REPLY,
	'TREE_DISCONNECT_REPLY' : TREE_DISCONNECT_REPLY,
	'TREE_DISCONNECT_REQ' : TREE_DISCONNECT_REQ,
	'ECHO_REQ' : ECHO_REQ,
	'ECHO_REPLY' : ECHO_REPLY,
	'LOGOFF_REQ'   : LOGOFF_REQ,
	'LOGOFF_REPLY' : LOGOFF_REPLY,
	'ERROR_REPLY' : ERROR_REPLY,
	'CLOSE_REPLY' : CLOSE_REPLY,
	'WRITE_REPLY' : WRITE_REPLY,
	'WRITE_REQ' : WRITE_REQ,
	'FLUSH_REPLY' : FLUSH_REPLY,
	'FLUSH_REQ' : FLUSH_REQ,
	'IOCTL_REQ' : IOCTL_REQ,
	'IOCTL_REPLY' : IOCTL_REPLY,
}