import asyncio
import logging

from aiosmb import logger

def unwrap(ret):
    ret, err = ret
    if err is not None:
        raise err
    return ret

def unwrap_multi(ret):
    ret, err = ret[:-1], ret[-1]
    if err is not None:
        raise err
    return ret

def run(amain, args):
    if args.debug >= 1:
        logger.setLevel(logging.DEBUG)

    if args.debug > 2:
        logger.setLevel(1) #enabling deep debug
        logging.basicConfig(level=logging.DEBUG)

    asyncio.run(amain(args), debug=args.debug > 2)
