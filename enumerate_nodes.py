import asyncio
import cryptosystem
from node import VeilidNode, cryptos
from proto import veilid_capnp as proto
from wire_objects import TypedKey
import socket
import traceback
from util import epoch_micros_to_human


async def rpc_findNode(session: VeilidNode, node_to_ask: cryptosystem.CryptoPublic, node_to_find: cryptosystem.CryptoPublic):
	q = proto.Question.new_message()
	q.detail.init("findNodeQ")
	q.detail.findNodeQ.nodeId = TypedKey(node_to_find.CRYPTO_KIND, bytes(node_to_find)).to_proto()
	q.detail.findNodeQ.capabilities = []
	return await session.rpc_query(node_to_ask, q)

def socketAddress_to_human_string(sa: proto.SocketAddress) -> str:
	iptype = sa.address.which()
	if iptype == "ipv4":
		ipstr = socket.inet_ntoa(sa.address.ipv4.addr.to_bytes(4, "big"))
		return f"{ipstr}:{sa.port}"
	elif iptype == "ipv6":
		ipv6_bytes = \
			sa.address.ipv6.addr0.to_bytes(4, "big") + \
			sa.address.ipv6.addr1.to_bytes(4, "big") + \
			sa.address.ipv6.addr2.to_bytes(4, "big") + \
			sa.address.ipv6.addr3.to_bytes(4, "big")
		ipstr = socket.inet_ntop(socket.AF_INET6, ipv6_bytes)
		return f"{ipstr}:{sa.port}"
	else:
		raise Exception("can't stringify socketAddress")

def dialinfo_to_human_string(info: proto.DialInfo) -> str:
	proto_type = info.which()
	if proto_type == "tcp":
		return "tcp://" + socketAddress_to_human_string(info.tcp.socketAddress)
	elif proto_type == "udp":
		return "udp://" + socketAddress_to_human_string(info.udp.socketAddress)
	elif proto_type == "ws":
		# TODO: consider info.ws.request
		return "ws://" + socketAddress_to_human_string(info.ws.socketAddress)
	elif proto_type == "wss":
		# ditto
		return "wss://" + socketAddress_to_human_string(info.wss.socketAddress)
	else:
		raise Exception("can't stringify dialinfo")

async def scan_node(session: VeilidNode, target_node: cryptosystem.CryptoPublic):
	vld0_pub = cryptos.get_public_cryptosystem(b"VLD0")
	found_nodes = {} # node_id -> (timestamp, relayed/direct, connection_info)
	for i in range(0, 256, 4):
		search_key = vld0_pub(bytes([i]+[0]*31))
		res = await rpc_findNode(session, target_node, search_key)
		for peer in res.detail.findNodeA.peers:
			for nodeid in map(TypedKey.from_proto, peer.nodeIds):
				if nodeid.crypto_kind == vld0_pub.CRYPTO_KIND:
					found_node_id = vld0_pub(nodeid.key)
					break
			else:
				continue # don't bother with non-vld0 nodes
			
			dialtype = peer.signedNodeInfo.which()
			if dialtype == "direct":
				ts = peer.signedNodeInfo.direct.timestamp
				dialinfos = []
				for dial in peer.signedNodeInfo.direct.nodeInfo.dialInfoDetailList:
					dialinfos.append(dialinfo_to_human_string(dial.dialInfo))
					if dial.dialInfo.which() != "tcp":
						continue
					if dial.dialInfo.tcp.socketAddress.address.which() != "ipv4":
						continue
					v4_raw = dial.dialInfo.tcp.socketAddress.address.ipv4.addr
					port = dial.dialInfo.tcp.socketAddress.port
					ip_str = socket.inet_ntoa(v4_raw.to_bytes(4, "big"))
					prev_timestamp = session.phonebook.get(found_node_id, (0,))[0]
					if ts > prev_timestamp:
						session.phonebook[found_node_id] = (ts, ip_str, port)

				prev_timestamp = found_nodes.get(found_node_id, (0,))[0]
				if ts > prev_timestamp:
					found_nodes[found_node_id] = (ts, dialtype, dialinfos)
			else:  # relayed
				ts = peer.signedNodeInfo.relayed.timestamp
				relays = [str(vld0_pub(relay.key)) for relay in map(TypedKey.from_proto, peer.signedNodeInfo.relayed.relayIds) if relay.crypto_kind == vld0_pub.CRYPTO_KIND]
				prev_timestamp = found_nodes.get(found_node_id, (0,))[0]
				if ts > prev_timestamp:
					found_nodes[found_node_id] = (ts, dialtype, relays)
	return found_nodes


async def scan_task(queue: asyncio.Queue, queued_before: set, accumulated_found_nodes: dict, session: VeilidNode):
	while True:
		node_to_scan = await queue.get()
		try:
			found_nodes = await scan_node(session, node_to_scan)
			print(f"[+] Found {len(found_nodes)} from {node_to_scan}")
			for node, value in found_nodes.items():
				prev = accumulated_found_nodes.get(node, (0,))
				if value > prev:
					accumulated_found_nodes[node] = value
				if node not in queued_before and node in session.phonebook:
					queued_before.add(node)
					await queue.put(node)
		except KeyboardInterrupt as e:
			raise e
		except:
			traceback.print_exc()
		finally:
			await session.hangup(node_to_scan)
		queue.task_done()


async def main():
	secret = cryptos.get_secret_cryptosystem(b"VLD0").generate()
	bootstrap_info = {
		cryptos.parse_public_string("VLD0:m5OY1uhPTq2VWhpYJASmzATsKTC7eZBQmyNs6tRJMmA"):
			(0, "bootstrap-1.veilid.net", 5150)
	}
	target_node = list(bootstrap_info.keys())[0]
	found_nodes = {}
	queued_before = set()
	nodes_to_scan = asyncio.Queue()
	await nodes_to_scan.put(target_node)
	queued_before.add(target_node)
	async with VeilidNode(secret, bootstrap_info) as session:
		scan_tasks = [
			asyncio.create_task(scan_task(nodes_to_scan, queued_before, found_nodes, session))
			for _ in range(32)
		]
		await nodes_to_scan.join()
		for task in scan_tasks:
			task.cancel()
			try:
				await task
			except asyncio.CancelledError:
				pass
	
	print(f"found {len(found_nodes)} nodes total")
	found_tuples = [(str(node), info) for node, info in found_nodes.items()]
	for node, info in sorted(found_tuples):
		print(epoch_micros_to_human(info[0]), node, "->", info[1], info[2])

if __name__ == "__main__":
	asyncio.run(main())
