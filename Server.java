import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.Random;

public class Server {

    private static final String ARGS_ERROR = "Usage: java <-cp classpath> Server [port number]\n";
    private static final String PORT_ERROR = "Error: could not bind to port. Perhaps the port is already bound, or you did not specify a valid value.\n";
    private static final String SOCKET_ERROR = "Error: could not listen for/accept a connection.\n";
    private static final String STREAM_ERROR = "Error: could not set up I/O streams. Aborting connection... (note that server will not exit yet).\n";
    private static final String KEY_ERROR = "Error: unable to obtain server private key - is it available?\n";
    private static final String HANDSHAKE_ERROR = "Error: handshake failed! Aborting connection...\n";
    private static final String NEGOTIATION_ERROR = "Error: protocol negotiation failed! Aborting connection...\n";
    
    private static final String LISTEN_NOTIF = "Listening for connections...";
    private static final String EXIT_NOTIF = "Server exiting...";
    private static final String CONNECT_NOTIF = "Server connected to client.";

    private static final String AUTH_MESSAGE = "ACCESSING CSD SERVER - HANDSHAKE";

    private static final String PRIVATE_KEY_DIR = "./keys/csd.private_key.der";
    private static final String CERT_DIR = "./keys/csd.crt";

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

        // Attempt to get private key
        PrivateKey privateKey = null;
        try {
            privateKey = getServerPrivateKey(PRIVATE_KEY_DIR);
        }
        catch (Exception e) {
            System.out.println(KEY_ERROR);
            return;
        }

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

            // Setup connection
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

            // Setup data streams
            DataOutputStream serverOut = null;
            DataInputStream serverIn = null;
            try {
                serverOut = new DataOutputStream(currentConnection.getOutputStream());
                serverIn = new DataInputStream(currentConnection.getInputStream());
            }
            catch (Exception e) {
                abortConnection(serverOut,serverIn,currentConnection);
                System.out.println(STREAM_ERROR);
                continue;
            }

            // Handshake
            try {
                boolean handshakeResult = performHandshake(serverIn,serverOut,privateKey);
                if (!handshakeResult) throw new Exception();
            }
            catch (Exception e) {
                abortConnection(serverOut,serverIn,currentConnection);
                System.out.println(HANDSHAKE_ERROR);
                continue;
            }

            // Negotiate CP
            int cp = 0;
            Key cpKey = null;
            try {
                // TODO move this to another function
                cp = serverIn.readInt();
                switch (cp) {
                    case 1:
                        cpKey = getClientPublicKey(serverIn);
                        //TODO send
                        break;
                    case 2:
                        cpKey = getClientAESKey(serverIn);
                        //TODO send (and define this function)
                        break;
                    default:
                        throw new Exception();
                        break;
                }

            }
            catch (Exception e) {
                abortConnection(serverOut,serverIn,currentConnection);
                System.out.println(NEGOTIATION_ERROR);
                continue;
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

    public static PrivateKey getServerPrivateKey(String filename) {
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get(filename));

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePrivate(spec);
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

        return;
    }

    public static byte[] readVariableBytes(DataInputStream serverIn) throws Exception{
        int size = serverIn.readInt();
        byte[] data = new byte[size];
        serverIn.readFully(data,0,size);
        return data;
    }

    public static boolean performHandshake(
        DataOutputStream serverOut,
        DataInputStream serverIn,
        PrivateKey privateKey
    ) throws Exception {
        String in = null;
        in = serverIn.readLine();

        if (!in.equals("CONNECT")) return false;

        byte[] authMessage = processRSA(privateKey,AUTH_MESSAGE.toBytes()));
        serverOut.writeInt(authMessage.length);
        serverOut.writeBytes(authMessage,0,authMessage.length);
        in = serverIn.readLine();
        
        if (!in.equals("ACK-C1")) return false;

        sendCertificate(serverOut);
        in = serverIn.readLine();
        
        if (!in.equals("ACK-C2")) return false;
        
        int nonce = new Random().nextInt(99999999);
        serverOut.writeInt(nonce);
        byte[] receivedNonceBytes = readVariableBytes(serverIn);

        serverOut.writeChars("ACK-S1");
        PublicKey clientPublicKey = getClientPublicKey(serverIn);

        String receivedNonce = new String(processRSA(clientPublicKey,receivedNonceBytes));
        if (!receivedNonce.equals(Integer.toString(nonce))) return false;
        serverOut.writeChars("ACK-S2");

        return true;

    }

    public static void sendCertificate(DataOutputStream serverOut) throws Exception{
        String data = "";
        String line;
        BufferedReader bufferedReader = new BufferedReader( new FileReader(fileName[i]));
        while((line=bufferedReader.readLine())!=null){
            if (data.equals("")) data = line;
            else data = data + "\n" + line;
        }
        byte[] cert = data.toBytes();
        serverOut.writeInt(cert.length);
        serverOut.writeBytes(cert,0,cert.length);
        return;
    }

    public static PublicKey getClientPublicKey(DataInputStream serverIn) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(readVariableBytes(serverIn));
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePublic(spec);
    }

    public static String processRSA(Key key,byte[] message) {
        Cipher rsaEncryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaEncryptCipher.init(Cipher.ENCRYPT_MODE,key);
        return rsaEncryptCipher.doFinal(message);
    }

    public static String encryptAES(Key key,byte[] message) {
        Cipher rsaEncryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaEncryptCipher.init(Cipher.ENCRYPT_MODE,key);
        return rsaEncryptCipher.doFinal(message);
    }

}