# 50.005 Programming Assignment 2 Submission
#### Group members: Sean Gunawan (1004414), Claudia Chin (1004328)

## How to start

### Prerequisites for both sides (must be done first):

Compile ConnectionUtils.java using

    javac ConnectionUtils.java


### Server:

Compile both ServerShell.java and Server.java using

    javac ServerShell.java
    javac Server.java

Next, run

    java Server 4321

in the folder where Server.java is located. Usage of a different port number is currently supported by the server but not the client.

### Client:

Compile Client.java using:

    javac Client.java

Next, run

    java Client

in the folder where Client.java is located.

## How to operate:

No further steps are required for the server.

For the client, type in an integer to specify the confidentiality protocol to be used, and press enter. The protocols supported are as follows:

- 1: RSA encryption
- 2: AES encryption

Upon succesful negotiation, the client behaves as a shell where you can type in commands. Type "help" to display all available commands. The available commands are:

- put \[local filename\] \[remote filename\]: upload local file
- get \[remote filename\] \[local filename\]: download remote file
- pwd: print server working directory
- cwd \[remote directory\]: change server working directory
- ls: list server working directory's contents
- exit: disconnect from server
- shutdown: disconnect from server and shutdown server