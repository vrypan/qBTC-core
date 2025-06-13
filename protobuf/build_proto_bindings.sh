python3 -m grpc_tools.protoc -I. --python_out=. --pyi_out=. --grpc_python_out=. *.proto
sed -I "" -e 's/^import /from \. import /g' *.py *.pyi
sed -I "" -e 's/^from . import grpc/import grpc/g' *.py *.pyi
sed -I "" -e 's/^from . import warnings//g' *.py *.pyi
