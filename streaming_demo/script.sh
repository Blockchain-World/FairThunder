#!/bin/bash
echo "Start to compile fairthunder streaming round demo..."
mvn compile
role=$1
echo "Execute different roles, e.g., ./script.sh Provider (Consumer, Deliverer)"
echo "Execute as " + $role
mvn exec:java -Dexec.mainClass=FTStreaming.$role
