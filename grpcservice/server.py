import grpc
from concurrent import futures

from protobuf import rpc_pb2_grpc
from protobuf import blockchain_pb2
from protobuf import request_response_pb2

from blockchain.mempool import mempool

class NodeServiceServicer(rpc_pb2_grpc.NodeServiceServicer):
    def GetBlocks(self, request, context):
        # Stream blocks
        for i in range(request.start_height, request.end_height):
            block = blockchain_pb2.Block(
                height=i,
                hash=b"blockhash" + bytes([i % 256]),
                size=1024,
                transaction_count=0  # etc.
            )
            yield block

    def GetMempool(self, request, context):
        # Stream fake transactions
        for tx in mempool.all():
            yield tx

    def GetMempoolSize(self, request, context):
        return request_response_pb2.MempoolSizeMessage(size=mempool.len())


def grpc_serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    rpc_pb2_grpc.add_NodeServiceServicer_to_server(NodeServiceServicer(), server)
    server.add_insecure_port("[::]:50051")
    server.start()
    print("[#] gRPC server running on port 50051...")
    server.wait_for_termination()


if __name__ == "__main__":
    grpc_serve()
