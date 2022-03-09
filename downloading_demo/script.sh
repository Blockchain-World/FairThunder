#!/bin/bash
echo "Start to compile fairthunder downloading demo..."
mvn compile
role=$1
echo "Execute different roles, e.g., ./script.sh Consumer (or Deliverer)"
echo "Execute as " + $role
mvn exec:java -Dexec.mainClass=FTDownload.$role
