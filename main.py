from typing import Dict, Tuple, List, Self
import secrets
import asyncio
import traceback
import socket

import envelope
import cryptosystem
from cryptosystem import cryptosystems as cryptos
from proto import veilid_capnp as proto
import vld0
cryptos.register(vld0.VLD0Public, vld0.VLD0Secret)


class VeilidNode:
	secret_key: cryptosystem.CryptoSecret
	public_key: cryptosystem.CryptoPublic

	# contains known-good connections (have connected and said hi at least once)
	# node id bytes => (timestamp, hostname, tcp port)
	# TODO: populate with bootstrap results
	phonebook: Dict[bytes, Tuple[int, str, int]]

	# when we make an rpc request, it goes in here, indexed by opId
	# when the response arrives, the payload is pushed to the queue, and the
	# opId is removed from the dict
	rpc_inflight: Dict[int, asyncio.Queue] = {}

	# things we want to send to each node
	send_queues: Dict[bytes, proto.Operation] = {}

	# tasks that sit in a loop, reading from a socket
	tasks: List[asyncio.Task] = []

	def __init__(self, secret_key: cryptosystem.CryptoSecret, bootstrap_phonebook: Dict[bytes, Tuple[int, str, int]]) -> None:
		self.secret_key = secret_key
		self.public_key = self.secret_key.public()

		self.phonebook = bootstrap_phonebook

		print(f"[+] Initialised node with ID: {self.public_key}")

	async def __aenter__(self) -> Self:
		return self

	async def __aexit__(self, exc_type, exc, tb):
		# clean up readers
		for task in self.tasks:
			task.cancel()

	# may throw exceptions on timeout or other issues...
	async def rpc_query(self, target_node: cryptosystem.CryptoPublic, query: proto.Question, timeout: int=10) -> proto.Answer:
		_, host, port = self.phonebook[target_node]

		# TODO: we should have a pool of existing connections!
		if target_node not in self.send_queues:
			reader, writer = await asyncio.open_connection(host, port)
			peerinfo = writer.get_extra_info("peername")
			print(f"[+] connected to {target_node} at {peerinfo}")
			self.send_queues[target_node] = asyncio.Queue()

			# XXX: if one task dies, we kinda want to take the other down with it - does that happen?
			self.tasks.append(asyncio.create_task(self._inbound_loop(reader, target_node)))
			self.tasks.append(asyncio.create_task(self._outbound_loop(writer, target_node)))

		op = proto.Operation.new_message()
		op.opId = secrets.randbits(64)
		op.kind.question = query
		
		queue = asyncio.Queue()
		self.rpc_inflight[op.opId] = queue

		await self.send_queues[target_node].put(op)
		result = await asyncio.wait_for(queue.get(), timeout=timeout)
		del self.rpc_inflight[op.opId]
		return result

	async def _outbound_loop(self, writer: asyncio.StreamWriter, dest_node: cryptosystem.CryptoPublic):
		try:
			while True:
				op = await self.send_queues[dest_node].get()
				env = envelope.pack(self.secret_key, dest_node, op.to_bytes_packed())
				frame = b"VL" + len(env).to_bytes(2, "little") + env
				writer.write(frame)
				await writer.drain()
		except asyncio.exceptions.CancelledError:
			pass
		except KeyboardInterrupt as e:
			raise e
		except:
			traceback.print_exc()
		finally:
			writer.close()


	async def _inbound_loop(self, reader: asyncio.StreamReader, source_node: cryptosystem.CryptoPublic):
		try:
			source_ascii = str(source_node)
			while True:
				header = await reader.readexactly(4)
				if header[:2] != b"VL":
					raise Exception("bad tcp framing magic")
				body_len = int.from_bytes(header[2:], "little")
				body = await reader.readexactly(body_len)

				operation = envelope.unpack(self.secret_key, source_node, body)
				operation = proto.Operation.from_bytes_packed(operation)
				#print("INBOUND ENVELOPE:", operation)

				# TODO: do something with sender peer info!

				opkind = operation.kind.which()
				#print("opkind", opkind)
				if opkind == "question":
					q = operation.kind.question
					qkind = q.detail.which()
					print(f"[+] received '{qkind}' from {source_ascii}")
					if qkind == "statusQ":
						#peername = reader.get_extra_info()
						resop = proto.Operation.new_message()
						resop.opId = operation.opId
						answer = resop.kind.init("answer")
						statusa = answer.detail.init("statusA")
						if 0:
							sender = statusa.init("senderInfo")
							sender.socketAddress.address.ipv4.addr = int.from_bytes(socket.inet_aton("192.168.0.82"), "big")
							sender.socketAddress.port = 5150
						#print(resop)
						# TODO: not all responses are return to sender
						await self.send_queues[source_node].put(resop)
						print(f"[+] enqueued answer to {source_ascii}")
					else:
						print("dunno how to answer this question")
				elif opkind == "answer":
					queue = self.rpc_inflight.get(operation.opId)
					if queue is None:
						print("received answer to a question we don't remember asking")
					else:
						await queue.put(operation.kind.answer)
				else:
					print("dunno what to do with this operation")
		except asyncio.exceptions.CancelledError:
			pass
		except KeyboardInterrupt as e:
			raise e
		except:
			traceback.print_exc()
		finally:
			reader.close()



async def main():
	secret = cryptos.get_secret_cryptosystem(b"VLD0").generate()
	bootstrap_info = {
		#vld0_decode_pubkey('VLD0:m5OY1uhPTq2VWhpYJASmzATsKTC7eZBQmyNs6tRJMmA').public_bytes_raw():
		#	(0, 'bootstrap-1.veilid.net', 5150),

		#vld0_decode_pubkey('VLD0:6-FfH7TPb70U-JntwjHS7XqTCMK0lhVqPQ17dJuwlBM').public_bytes_raw():
		#	(0, 'bootstrap-2.veilid.net', 5150),

		cryptos.parse_public_string("VLD0:lwNHmsRwyYO6cXqPjwBN_Mhb3zhbrfNIYaDPAAbRjvw"):
			(0, "skinner", 5150),

		#cryptos.parse_public_string("VLD0:Retr02MzvOpAHAsTwEoWpdVc1W-JjTCSsGWQtL4SR-s"):
		#	(0, "208.87.102.169", 5150)
	}
	async with VeilidNode(secret, bootstrap_info) as session:
		query = proto.Question.new_message()
		query.detail.init("statusQ")
		response = await session.rpc_query(list(bootstrap_info.keys())[0], query)
		print("RPC response:", response)
		while True:
			await asyncio.sleep(10)

if __name__ == "__main__":
	asyncio.run(main())
