import copy
from typing import List

from aiosmb.dcerpc.v5.common.connection.connectionstring import DCERPCStringBinding
from asysocks.unicomm.common.proxy import UniProxyTarget
from asysocks.unicomm.common.target import UniTarget, UniProto


class DCERPCTarget(UniTarget):
	def __init__(self, connection_string:str, ip, port, protocol, rpcprotocol, proxies = None, timeout = 1, hostname = None, domain = None, dc_ip = None, smb_connection = None, pipe=None):
		self.connection_string = connection_string
		self.rpcprotocol = rpcprotocol
		self.pipe = pipe
		self.smb_connection = smb_connection #storing the smb connection if already exists...
		UniTarget.__init__(self, ip, port, protocol, timeout, hostname = hostname, proxies = proxies, domain = domain, dc_ip = dc_ip)
		

	def get_hostname_or_ip(self):
		if self.smb_connection is not None:
			return self.smb_connection.target.get_hostname_or_ip()
		if self.hostname is None:
			return self.ip
		return self.hostname
	
	#def to_target_string(self) -> str:
	#	if self.hostname is None:
	#		raise Exception('Hostname is None!')
	#	if self.domain is None:
	#		raise Exception('Domain is None!')
	#	return 'cifs/%s@%s' % (self.hostname, self.domain)

	def to_target_string(self) -> str:
		if self.smb_connection is not None:
			return self.smb_connection.target.to_target_string()
		return 'cifs/%s@%s' % (self.hostname, self.domain)

	@staticmethod
	def from_smbconnection(smb_connection, pipe = None):
		if pipe is None:
			target = DCERPCSMBTarget(None, smb_connection.target.get_hostname_or_ip(), smb_connection=smb_connection, timeout = smb_connection.target.timeout)
		else:
			target = DCERPCSMBTarget(None, smb_connection.target.get_hostname_or_ip(), pipe, smb_connection=smb_connection, timeout = smb_connection.target.timeout)
		return target

	@staticmethod
	def from_connection_string(s, smb_connection = None, timeout = 1, proxies:List[UniProxyTarget] = None, dc_ip:str = None, domain:str = None):
		if isinstance(s, str):
			connection_string = DCERPCStringBinding(s)
		elif isinstance(s, DCERPCStringBinding):
			connection_string = s
		else:
			raise Exception('Unknown string binding type %s' % type(s))
		
		if domain is None and smb_connection is not None:
			domain = smb_connection.target.domain

		na = connection_string.get_network_address()
		ps = connection_string.get_protocol_sequence()
		if ps == 'ncadg_ip_udp':
			raise Exception('DCERPC UDP not implemented')
			port = connection_string.get_endpoint()
			target = DCERPCUDPTarget(connection_string, na, int(port), timeout = timeout)
		elif ps == 'ncacn_ip_tcp':
			port = connection_string.get_endpoint()
			target = DCERPCTCPTarget(connection_string, na, port, timeout = timeout, dc_ip=dc_ip, domain = domain)
		elif ps == 'ncacn_http':
			raise Exception('DCERPC HTTP not implemented')
			target = DCERPCHTTPTarget(connection_string, na, int(port), timeout = timeout)
		elif ps == 'ncacn_np':
			named_pipe = connection_string.get_endpoint()
			if named_pipe:
				named_pipe = named_pipe[len(r'\pipe'):]
				target = DCERPCSMBTarget(connection_string, na, pipe=named_pipe, smb_connection=smb_connection, timeout = timeout)
			else:
				target = DCERPCSMBTarget(connection_string, na, smb_connection=smb_connection, timeout = timeout)
		elif ps == 'ncalocal':
			raise Exception('DCERPC LOCAL not implemented')
			target = DCERPCLocalTarget(connection_string, na, int(port), timeout = timeout)
		
		else:
			raise Exception('Unknown DCERPC protocol %s' % ps)

		if proxies is not None:
			target.proxies = copy.deepcopy(proxies)


		if smb_connection is not None:
			if smb_connection.target.proxies is not None:
				target.proxies = copy.deepcopy(smb_connection.target.proxies)
			
		return target

	def __str__(self):
		t = '==== DCERPCTarget ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t


class DCERPCTCPTarget(DCERPCTarget):
	def __init__(self, connection_string, ip, port, timeout = 1, proxies = None, dc_ip:str = None, domain:str = None):
		DCERPCTarget.__init__(
			self, 
			connection_string, 
			ip, 
			int(port), 
			UniProto.CLIENT_TCP, 
			'ncacn_ip_tcp', 
			proxies = proxies, 
			timeout = timeout, 
			hostname = None, 
			domain = domain, 
			dc_ip = dc_ip
		)

class DCERPCUDPTarget(DCERPCTarget):
	def __init__(self, connection_string, ip, port, timeout = 1, proxies = None, dc_ip:str = None, domain:str = None):
		DCERPCTarget.__init__(
			self, 
			connection_string, 
			ip, 
			int(port), 
			UniProto.CLIENT_UDP, 
			'ncadg_ip_udp', 
			proxies = proxies, 
			timeout = timeout, 
			hostname = None, 
			domain = domain, 
			dc_ip = dc_ip
		)

class DCERPCSMBTarget(DCERPCTarget):
	def __init__(self, connection_string, ip, pipe = None, smb_connection = None, timeout = 1):
		DCERPCTarget.__init__(
			self, 
			connection_string, 
			ip, 
			None, 
			UniProto.CLIENT_TCP, 
			'ncacn_np', 
			proxies = smb_connection.target.proxies, 
			timeout = timeout, 
			hostname = None, 
			domain = smb_connection.target.domain, 
			dc_ip = smb_connection.target.dc_ip,
			smb_connection = smb_connection,
			pipe = pipe
		)

class DCERPCHTTPTarget(DCERPCTarget):
	def __init__(self, connection_string, ip, port, timeout = 1, proxies = None, domain = None, dc_ip = None):
		DCERPCTarget.__init__(
			self, 
			connection_string,
			ip,
			port, 
			UniProto.CLIENT_TCP,
			'ncacn_http',
			proxies = proxies, 
			timeout = timeout, 
			hostname = None, 
			domain = domain, 
			dc_ip = dc_ip
		)
		self.set_hostname_or_ip(ip)
		self.port = int(port)

class DCERPCLocalTarget(DCERPCTarget):
	def __init__(self, connection_string, ip, port, timeout = 1):
		raise NotImplementedError()
		DCERPCTarget.__init__(self, connection_string, DCERPCTargetType.LOCAL, timeout = timeout)
		self.set_hostname_or_ip(ip)
		self.port = int(port)
		self.rpcprotocol = 'ncalocal'



if __name__ == '__main__':
	s = ''
	target = DCERPCTarget.from_connection_string(s)
	


