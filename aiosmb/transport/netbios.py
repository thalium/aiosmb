import asyncio
from dataclasses import dataclass
import io

from aiosmb import logger
from aiosmb.network.tcp import TCPSocket
from aiosmb.protocol.smb.message import *
from aiosmb.protocol.smb2.message import *
from aiosmb.commons.utils.queue import CtxQueue

def netbios_prefix(length):
	return b'\x00' + length.to_bytes(3, byteorder='big', signed=False)

class NetBIOSTransport:
	"""
	Converts incoming bytestream from the network starsport to SMB messages and vice-versa.
	This layer is presented so the network transport can be changed for a TCP/UDP/whatever type of transport.
	"""
	def __init__(self, network_transport):
		self.network_transport = network_transport
		self.socket_out_queue = network_transport.out_queue
		self.socket_in_queue = network_transport.in_queue
		
		self.in_queue = asyncio.Queue()
		self.out_queue = CtxQueue()
		
		self.outgoing_task = None
		self.incoming_task = None

		self.out_task_finished = asyncio.Event()

		self.__total_size = -1
		
	async def stop(self):
		"""
		Stops the input output processing
		"""
		if self.outgoing_task is not None:
			self.outgoing_task.cancel()
		if self.incoming_task is not None:
			self.incoming_task.cancel()
		
		
	async def run(self):
		"""
		Starts the input and output processing
		"""
		try:
			if isinstance(self.network_transport, TCPSocket):
				self.incoming_task = asyncio.create_task(self.handle_incoming_noparse())
			else:
				self.incoming_task = asyncio.create_task(self.handle_incoming())
			self.outgoing_task = asyncio.create_task(self.handle_outgoing())
			return True, None
		except Exception as e:
			return False, e

	async def handle_incoming_noparse(self):
		"""
		Reads data bytes from the socket_in_queue and parses the NetBIOS messages and the SMBv1/2 messages.
		Dispatches the SMBv1/2 message objects.
		"""
		try:
			while True:
				data, err = await self.socket_in_queue.get()
				if err is not None:
					raise err
				
				await self.in_queue.put( (data, err) )

		except asyncio.CancelledError:
			#the SMB connection is terminating
			return
			
		except Exception as e:
			logger.debug('NetBIOSTransport handle_incoming error. Reason: %s' % e)
			await self.in_queue.put( (None, e) )
			await self.stop()
		
	async def handle_incoming(self):
		"""
		Reads data bytes from the socket_in_queue and parses the NetBIOS messages and the SMBv1/2 messages.
		Dispatches the SMBv1/2 message objects.
		"""
		try:
			buffer = b''
			lastcall = False
			while not lastcall:
				if self.__total_size == -1:
					if len(buffer) > 5:
						self.__total_size = int.from_bytes(buffer[1:4], byteorder='big', signed = False) + 4

				while self.__total_size > -1 and len(buffer) >= self.__total_size:
					if self.__total_size > -1 and len(buffer) >= self.__total_size:
						msg_data = buffer[:self.__total_size][4:]
						buffer = buffer[self.__total_size:]
						self.__total_size = -1
						if len(buffer) > 5:
							self.__total_size = int.from_bytes(buffer[1:4], byteorder='big', signed = False) + 4
								
						#print('%s nbmsg! ' % (self.network_transport.writer.get_extra_info('peername')[0], ))
						#print('[NetBIOS] MSG dispatched')
						await self.in_queue.put( (msg_data, None) )
				

				
				data, err = await self.socket_in_queue.get()
				if err is not None:
					raise err

				if data == b'':
					lastcall = True
					
				
				buffer += data
			
			raise Exception('Remote end terminated the connection')

		except asyncio.CancelledError:
			#the SMB connection is terminating
			return
			
		except Exception as e:
			logger.debug('NetBIOSTransport handle_incoming error. Reason: %s' % e)
			await self.in_queue.put( (None, e) )
			await self.stop()
		
	async def handle_outgoing(self):
		"""
		Reads SMBv1/2 outgoing message data bytes from out_queue, wraps them in NetBIOS object, then serializes them, then sends them to socket_out_queue
		"""
		try:
			while True:
				async with self.out_queue as smb_msg_data:
					if smb_msg_data is None:
						return
					data = netbios_prefix(len(smb_msg_data)) + smb_msg_data
					await self.socket_out_queue.put(data)
		
		except asyncio.CancelledError:
			#the SMB connection is terminating
			return
		
		except Exception as e:
			logger.exception('NetBIOSTransport handle_outgoing')
			await self.stop()
		
		finally:
			await self.stop()
			self.out_task_finished.set()
			
	def queue_outgoing(self, msg):
		self.out_queue.put_nowait(msg.to_bytes())

# dummy object to queue when stalling is required
@dataclass
class StallMarker:
	rank: int

class StallingNetBIOSTransport(NetBIOSTransport):
	'''NetBIOS transport that can send a NetBIOS prefix, stall, leaving the server waiting, then send the message data later.'''
	def __init__(self, network_transport):
		super().__init__(network_transport)
		self.auto_stall = 0  # number of subsequent messages to stall
		self.stalled = 0     # number of currently stalled messages
		self.unstalled_queue = CtxQueue()  # queue of completed stalls
		self.resume_cond = asyncio.Condition()  # synchronization primitive for the stall/unstall dance

	async def handle_outgoing(self):
		try:
			async with self.resume_cond:  # hold the lock when not stalling
				while True:
					async with self.out_queue as data:
						if data is None:
							return
						if isinstance(data, StallMarker):
							# found a stall marker, let's stall
							await self.resume_cond.wait()
							self.stalled -= 1
							self.unstalled_queue.put_nowait(data)  # give it back
							continue
						await self.socket_out_queue.put(data)

		except asyncio.CancelledError:
			#the SMB connection is terminating
			return

		except Exception as e:
			logger.exception('StallingNetBIOSTransport handle_outgoing')
			await self.stop()

		finally:
			await self.stop()
			self.out_task_finished.set()

	def queue_outgoing(self, msg):
		# queue the prefix & the message
		data = msg.to_bytes()
		self.queue_outgoing_prefix(len(data), stall=self.auto_stall > 0)
		self.queue_outgoing_data(data)
		if self.auto_stall > 0:
			self.auto_stall -= 1

	def queue_outgoing_prefix(self, len, stall=True):
		self.out_queue.put_nowait(netbios_prefix(len))
		if stall:
			self.stalled += 1
			self.out_queue.put_nowait(StallMarker(self.stalled))

	def queue_outgoing_data(self, data):
		self.out_queue.put_nowait(data)

	async def unstall_outgoing(self, count=1):
		for _ in range(count):
			async with self.resume_cond:
				self.resume_cond.notify()
			async with self.unstalled_queue:
				# nothing to do with the marker *shrug*
				pass

	async def drain_outgoing(self):
		if self.stalled:
			# the outgoing task will stall at some point, wait for this to happen, then drain the socket queue
			async with self.resume_cond:
				await self.socket_out_queue.join()
		else:
			# the outgoing task won't stall, drain its queue, then drain the socket queue
			await self.out_queue.join()
			await self.socket_out_queue.join()