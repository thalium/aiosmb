import asyncio

class CtxQueue(asyncio.Queue):
	'''asyncio.Queue extension implementing an async context manager for get()/task_done() balance.'''
	async def __aenter__(self):
		return await self.get()

	async def __aexit__(self, exc_type, exc, traceback):
		# mark the task done whether something excepted or not, and propagate any exception
		self.task_done()
