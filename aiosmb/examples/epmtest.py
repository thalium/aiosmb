import traceback
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.epm import KNOWN_UUIDS
from aiosmb.dcerpc.v5.uuid import uuidtup_to_bin, generate, stringver_to_bin, bin_to_uuidtup, bin_to_string
from aiosmb.commons.connection.credential import SMBCredential, SMBAuthProtocol, SMBCredentialsSecretType
from aiosmb.commons.connection.authbuilder import AuthenticatorBuilder
from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE,\
	RPC_C_AUTHN_LEVEL_CONNECT,\
	RPC_C_AUTHN_LEVEL_CALL,\
	RPC_C_AUTHN_LEVEL_PKT,\
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,\
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY,\
	DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE
from aiosmb.dcerpc.v5.ndr import NDRCALL

class DummyOp(NDRCALL):
	opnum = 255
	structure = (
)

async def amain():
	try:
		ip = '10.10.10.2'
		epm = EPM.from_address(ip)
		_, err = await epm.connect()
		if err is not None:
			raise err

		x, err = await epm.lookup()
		if err is not None:
			raise err
		
		await epm.disconnect()
		
		#print(x)
		for entry in x[5:10]:
			version = '%s.%s' % (entry['tower']['Floors'][0]['MajorVersion'], entry['tower']['Floors'][0]['MinorVersion'])
			uuidstr = bin_to_string(entry['tower']['Floors'][0]['InterfaceUUID'])
			service_uuid = uuidtup_to_bin((uuidstr, version))
			print(entry['tower']['Floors'][0]['InterfaceUUID'])
			print(version)
			print(service_uuid)

			target, err = await EPM.create_target(ip, service_uuid)
			print(target)
			if err is not None:
				if str(err).find('ept_s_not_registered') != -1:
					continue
				raise err
			
			cred = SMBCredential(
				username = 'Administrator', 
				domain = 'TEST', 
				secret = 'Passw0rd!1', 
				secret_type = SMBCredentialsSecretType.PASSWORD, 
				authentication_type = SMBAuthProtocol.NTLM, 
				settings = None, 
				target = None
			)

			gssapi = AuthenticatorBuilder.to_spnego_cred(cred)
			auth = DCERPCAuth.from_smb_gssapi(gssapi)
			connection = DCERPC5Connection(auth, target)
			try:
				_, err = await connection.connect()
				if err is not None:
					raise err
				
				req = DummyOp()
				_, err = await connection.request(req)
				print(err)
			except Exception as e:
				traceback.print_exc()


	except Exception as e:
		traceback.print_exc()

if __name__ == '__main__':
	import asyncio
	asyncio.run(amain())