import grpc
from concurrent import futures
# from google.protobuf import empty_pb2
from protobuf import rpc_pb2, rpc_pb2_grpc, message_pb2

class Node(rpc_pb2_grpc.NodeServiceServicer):
    def GetHeight(self, request, context):
        return message_pb2.HeightMessage(height=100)

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    rpc_pb2_grpc.add_NodeServiceServicer_to_server(Node(), server)
    server.add_insecure_port("[::]:50051")
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
