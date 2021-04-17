import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

    private static final String ARGS_ERROR = "Usage: java <-cp classpath> Server [port number]\n";
    private static final String PORT_ERROR = "Error: could not bind to port. Perhaps the port is already bound, or you did not specify a valid value.\n";
    private static final String SOCKET_ERROR = "Error: could not listen for/accept a connection.\n";
    private static final String STREAM_ERROR = "Error: could not set up I/O streams. Aborting connection... (note that server will not exit yet).\n";
    
    private static final String LISTEN_NOTIF = "Listening for connections...";
    private static final String EXIT_NOTIF = "Server exiting...";
    private static final String CONNECT_NOTIF = "Server connected to client.";

    private static final int HANDOVER_STEP_COUNT = 8;

    // Requires arg(s): port number
    public static void main(String[] args) {
        
        // Check arg completeness
        if (args.length!=1) {
            System.out.println(ARGS_ERROR);
            return;
        }

        // Get port number
        int portNumber;
        try {
            portNumber = Integer.parseInt(args[0]);
        }
        catch (NumberFormatException e) {
            System.out.println(ARGS_ERROR);
            return;
        }

        // Get current directory
        String startingDirectory = System.getProperty("user.dir");

        // Attempt to bind to port
        ServerSocket serverSocket = null;
        try {
            serverSocket = new ServerSocket(portNumber);
        }
        catch (Exception e) {
            System.out.println(PORT_ERROR);
            return;
        }

        notifBindAddress(serverSocket);

        // Set flag for server termination - can only be set true by error and/or client
        boolean exitFlag = false;

        while (!exitFlag) {

            // Attempt to setup connection
            System.out.println(LISTEN_NOTIF);
            Socket currentConnection = null;
            try {
                currentConnection = serverSocket.accept();
            }
            catch (Exception e) {
                System.out.println(SOCKET_ERROR);
                exitFlag = true;
                continue;
            }

            System.out.println(CONNECT_NOTIF);

            // Attempt to setup data streams
            DataOutputStream serverOut = null;
            DataInputStream serverIn = null;
            try {
                serverOut = new DataOutputStream(currentConnection.getOutputStream());
                serverIn = new DataInputStream(currentConnection.getInputStream());
            }
            catch (Exception e) {
                abortConnection(serverOut,serverIn,currentConnection);
                continue;
            }

            boolean closeFlag = false;
            int handoverStep = 0;

            while (!closeFlag) {
                try {
                    // get input
                }
                catch (Exception e) {
                    // abort the connection
                }
            }

            System.out.println("Success. Exiting...");

            try {
                serverOut.close();
                serverOut = null;
                serverIn.close();
                serverIn = null;
                currentConnection.close();
                currentConnection = null;
            }
            catch (Exception e) {
                abortConnection(serverOut,serverIn,currentConnection);
            }

            exitFlag = true;


        }
        

    }

    public static void notifBindAddress(ServerSocket serverSocket) {
        System.out.println("Server bound to " + serverSocket.getInetAddress().toString() + ":" + serverSocket.getLocalPort() + ".\n");
        return;
    }

    public static void abortConnection(DataOutputStream serverOut, DataInputStream serverIn, Socket currentConnection) {

        try {if (serverOut!=null) serverOut.close();}
        catch (Exception e) {}
        try {if (serverIn!=null) serverIn.close();}
        catch (Exception e) {}
        try {currentConnection.close();}
        catch (Exception e) {}

        System.out.println(STREAM_ERROR);
        return;
    }

}