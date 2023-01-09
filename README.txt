how to run
---------------

compile server:
  javac src/security_server/*.java
run server:
  java -classpath src security_server.ServerMain
---
compile client
  javac src/security_client/*.java
run client (while server is running):
  java -classpath src security_client.ClientMain [args]
client arguments:
  [concurrent threads] [rounds of concurrent threads]
