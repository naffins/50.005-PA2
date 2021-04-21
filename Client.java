import java.io.InputStream;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.nio.file.*;


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.util.ArrayList;

public class Client {

	private static final String AUTH_MESSAGE = "ACCESSING CSD SERVER - HANDSHAKE";
	private static final String CA_CERT = "./keys/cacertificate.crt";
	private static Key serverPublicKey;
	private static int cp;
	private static Key sessionKey;
	private static Scanner inputScanner = null;
	private static final String HELP_COMMAND = "help : Prints a list of avaiable commands. \n"
			+ "put [local filename] [remote filename] : Sends file to server. \n"
			+ "exit : Close socket immediately. No response will be returned. \n"
			+ "shutdown : Server will return '0' and indicate that server is shutting down. \n"
			+ "ls : List current directory of server. \n"
			+ "pwd: Print current directory of server. \n"
			+ "cwd [directory] : Change server working directory. \n"
			+ "get [remote filename] [local filename] : Downloads file from server. \n";

	@SuppressWarnings("deprecation")
	public static void main(String[] args) throws Exception {

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		KeyPair keypair = keyGen.genKeyPair();
		Key clientPrivateKey = keypair.getPrivate();
		Key clientPublicKey = keypair.getPublic();

		String filename = "100.txt";
		if (args.length > 0)
			filename = args[0];

		String serverAddress = "localhost";
		if (args.length > 1)
			filename = args[1];

		int port = 4321;
		if (args.length > 2)
			port = Integer.parseInt(args[2]);

		int numBytes = 0;

		Socket clientSocket = null;

		DataOutputStream toServer = null;
		DataInputStream fromServer = null;

		FileInputStream fileInputStream = null;
		BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();

		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			boolean handshakeResult = performHandshake(fromServer, toServer, clientSocket, clientPublicKey,
					clientPrivateKey);
			if (!handshakeResult) {
				System.out.println("Handshake failed");
				abortConnection(fromServer, toServer, clientSocket);
				throw new Exception();
			}

			boolean negotiationResult = performNegotiation(fromServer, toServer, clientPublicKey, clientPrivateKey);
			if (!negotiationResult) {
				System.out.println("Negotiation failed");
				abortConnection(fromServer, toServer, clientSocket);
				//throw new Exception();
			}

			// Set encryptCipher, decryptCipher, and isRSA based on cp
			Cipher encryptCipher = null;
			Cipher decryptCipher = null;
			boolean isRSA = false;
			if (cp == 1) {
				encryptCipher = ConnectionUtils.getRSACipher(serverPublicKey, true); // RSA encrypt
				decryptCipher = ConnectionUtils.getRSACipher(clientPrivateKey, false); // RSA decrypt
				isRSA = true; 
			} else if (cp == 2) {
				encryptCipher = ConnectionUtils.getAESCipher(sessionKey, true); // AES encrypt
				decryptCipher = ConnectionUtils.getAESCipher(sessionKey, false); // AES decrypt
				isRSA = false;
			}

			// Keep sending commands until user decides to shutdown/exit here
			boolean exitFlag = false;

			while (!exitFlag) {
				System.out.print("Enter command (enter 'help' to see list of commands): ");
				String command = inputScanner.nextLine();

				String[] commandTokens = parseCommands(command);

				if (commandTokens[0]==null) {
					continue;
				}

				// help command
				if (commandTokens[0].equals("help")) {
					System.out.println(HELP_COMMAND);
				} 
				
				// exit command
				else if (commandTokens[0].equals("exit")) {
					//System.out.println("Exit command given. \n");
					ConnectionUtils.encryptAndIterativeWriteMessage(toServer, encryptCipher, commandTokens[0].getBytes(), isRSA); // Send command
					exitFlag = true;
				} 

				else if (commandTokens[0].equals("shutdown")) {
					//System.out.println("Shutdown command given.");
					ConnectionUtils.encryptAndIterativeWriteMessage(toServer, encryptCipher, commandTokens[0].getBytes(), isRSA);
					getResponse(fromServer,decryptCipher);
					exitFlag = true;
				}

				else if (commandTokens[0].equals("put")) {
					if (commandTokens[1]==null || commandTokens[2]==null) {
						System.out.println("put [local filename] [remote filename] : Sends file to server.\n");
						continue;
					}

					//System.out.println("Put command given.");
					
					put(fromServer,toServer,encryptCipher,decryptCipher,isRSA,commandTokens);
					System.out.print("\n");
				}

				else if (commandTokens[0].equals("ls")) {
					//System.out.println("List current directory command given.");
					ConnectionUtils.encryptAndIterativeWriteMessage(toServer, encryptCipher, commandTokens[0].getBytes(), isRSA);
					getResponse(fromServer,decryptCipher);
				}

				else if (commandTokens[0].equals("pwd")) {
					ConnectionUtils.encryptAndIterativeWriteMessage(toServer, encryptCipher, commandTokens[0].getBytes(), isRSA);
					getResponse(fromServer,decryptCipher);
					System.out.print("\n");
				}
				
				else if (commandTokens[0].equals("cwd")) {
					if (commandTokens[1]==null) {
						System.out.println("cwd [directory] : Change server working directory. \n");
						continue;
					}
					String transmitCommand = commandTokens[0] + " " + commandTokens[1];
					ConnectionUtils.encryptAndIterativeWriteMessage(toServer, encryptCipher, transmitCommand.getBytes(), isRSA);
					getResponse(fromServer,decryptCipher);
					System.out.print("\n");
				}

				else if (commandTokens[0].equals("get")) {
					if (commandTokens[1]==null || commandTokens[2]==null) {
						System.out.println("get [local filename] [remote filename] : Downloads file from server. \n");
						continue;
					}
					get(fromServer,toServer,encryptCipher,decryptCipher,isRSA,commandTokens);
					System.out.print("\n");
				}
				
				// invalid command entered
				else {
					System.out.println("Invalid command! \n");
				}
			}
			inputScanner.close();

			abortConnection(fromServer, toServer, clientSocket);

		} catch (Exception e) {
			e.printStackTrace();
		}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken / 1000000.0 + "ms to run");

	}

	private static void put(DataInputStream fromServer, DataOutputStream toServer, Cipher encryptCipher, Cipher decryptCipher, boolean isRSA, String[] commandTokens) throws Exception {
		// Send file
		FileInputStream outFile = null;
		try {
			outFile = new FileInputStream(commandTokens[1]);
		}
		catch (Exception e) {
			if (e instanceof SecurityException) System.out.println("Error: client has no read permissions");
			else System.out.println("Error: file doesn't exist");
			return;
		}
		try {
			String transmitCommand = commandTokens[0] + " " + commandTokens[2];
			ConnectionUtils.encryptAndIterativeWriteMessage(toServer, encryptCipher, transmitCommand.getBytes(), isRSA);
			int response = getResponse(fromServer,decryptCipher);
			if (response==0) ConnectionUtils.encryptAndIterativeWriteFile(toServer, encryptCipher, isRSA, outFile); 
		}
		catch (Exception e) {
			outFile.close();
			throw e;
		}
		outFile.close();
		
	}

	public static void get(DataInputStream fromServer,DataOutputStream toServer,Cipher encryptCipher,Cipher decryptCipher,boolean isRSA,String[] commandTokens) throws Exception {
		FileOutputStream inFile = null;
		
		try {
			if (Files.exists(Paths.get(commandTokens[2]))) {
				System.out.println("Error: file already exists");
				return;
			}
			inFile = new FileOutputStream(commandTokens[2]);
		}
		catch (Exception e) {
			if (e instanceof SecurityException) System.out.println("Error: client has no write permissions");
			else if (e instanceof InvalidPathException) System.out.println("Error: invalid local filename");
			else System.out.println("Error: local file cannot be created or is a directory");
			return;
		}
		try {
			String transmitCommand = commandTokens[0] + " " + commandTokens[1];
			ConnectionUtils.encryptAndIterativeWriteMessage(toServer, encryptCipher, transmitCommand.getBytes(), isRSA);
			int response = getResponse(fromServer,decryptCipher);
			if (response==0) ConnectionUtils.iterativeReadAndDecryptFile(fromServer, decryptCipher, inFile); 
		}
		catch (Exception e) {
			inFile.close();
			throw e;
		}
		inFile.close();


	}

	private static void abortConnection(DataInputStream fromServer, DataOutputStream toServer, Socket clientSocket)
			throws Exception {
		System.out.println("Closing all connections...");
		toServer.close();
		fromServer.close();
		clientSocket.close();
	}

	public static boolean performHandshake(DataInputStream fromServer, DataOutputStream toServer, Socket clientSocket,
			Key clientPublicKey, Key clientPrivateKey) throws Exception {
		// Begin handshake request
		ConnectionUtils.writeVariableBytes(toServer, "CONNECT".getBytes());

		// Receive fixed message encrypted with server private key
		byte[] authMessage = ConnectionUtils.readVariableBytes(fromServer);

		// Acknowledge
		ConnectionUtils.writeVariableBytes(toServer, "ACK-C1".getBytes());

		// Receive server certificate
		System.out.println("Requesting certificate from server...");
		byte[] encryptedCertificate = ConnectionUtils.readVariableBytes(fromServer);

		// Extract server public key from certificate
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		X509Certificate serverCertificate = (X509Certificate) certFactory
				.generateCertificate(new ByteArrayInputStream(encryptedCertificate));
		serverPublicKey = serverCertificate.getPublicKey();
		serverCertificate.checkValidity();
		
		// Verify with CA cert
		InputStream fis = new FileInputStream(CA_CERT);
		X509Certificate CAcert =(X509Certificate)certFactory.generateCertificate(fis);
		serverCertificate.verify(CAcert.getPublicKey());
		fis.close();

		// Decrypt fixed message with server public key and check if correct
		Cipher rsaDecryptCipher = ConnectionUtils.getRSACipher(serverPublicKey, false);
		boolean verified;
		if (new String(rsaDecryptCipher.doFinal(authMessage)).equals(AUTH_MESSAGE)) {
			verified = true;
		} else {
			verified = false;
		}

		// If check fails, close connection
		// If check succeeds, proceed
		if (!verified) {
			return false;
		} else {
			ConnectionUtils.writeVariableBytes(toServer, "ACK-C2".getBytes());
		}

		// Receive plaintext nonce from server
		byte[] nonce = ConnectionUtils.readVariableBytes(fromServer);

		// Encrypt plaintext nonce with client private key
		Cipher rsaClientPrivateKey = ConnectionUtils.getRSACipher(clientPrivateKey, true);
		byte[] encryptedNonce = rsaClientPrivateKey.doFinal(nonce);
		ConnectionUtils.writeVariableBytes(toServer, encryptedNonce);

		// Receive acknowledgement
		if (!new String(ConnectionUtils.readVariableBytes(fromServer)).equals("ACK-S1")) {
			return false;
		}

		// Send client public key
		ConnectionUtils.writeVariableBytes(toServer, clientPublicKey.getEncoded());

		// Receive acknowledgement
		if (!new String(ConnectionUtils.readVariableBytes(fromServer)).equals("ACK-S2")) {
			return false;
		}

		// Conclude handshake
		return true;
	}

	private static boolean performNegotiation(DataInputStream fromServer, DataOutputStream toServer,
			Key clientPublicKey, Key clientPrivateKey) throws Exception {
		// Make user choose CP1 or CP2 to send files
		String choice = "";
		inputScanner = new Scanner(System.in);
		while (!choice.equals("1") && !choice.equals("2")) {
			System.out.print("Enter CP choice [1 or 2]: ");
			choice = inputScanner.nextLine();
		}
		cp = Integer.parseInt(choice);
		toServer.writeInt(cp);

		// if CP1 chosen, send client public key as bytes
		// if CP2 chosen, encrypt AES public key with server's public key and send as
		// bytes
		// also get decryption cipher to decrypt message
		Cipher decryptCipher = null;
		if (cp == 1) {
			ConnectionUtils.writeVariableBytes(toServer, clientPublicKey.getEncoded());
			decryptCipher = ConnectionUtils.getRSACipher(clientPrivateKey,false);
		} else {
			sessionKey = KeyGenerator.getInstance("AES").generateKey();
			Cipher cipher = ConnectionUtils.getRSACipher(serverPublicKey, true);
			ConnectionUtils.encryptAndIterativeWriteMessage(toServer, cipher, sessionKey.getEncoded(), true);
			decryptCipher = ConnectionUtils.getAESCipher(sessionKey,false);
		}


		// Receive acknowledgement
		String ack = new String(ConnectionUtils.iterativeReadAndDecryptMessage(fromServer,decryptCipher));
		if (!ack.equals("ACK-S3")) {
			return false;
		}

		// Conclude negotiation
		return true;
	}

	private static String[] parseCommands(String command) {
		ArrayList<String> tokens = new ArrayList<String>();
		String regex = "\"([^\"]*)\"|(\\S+)";
        Matcher m = Pattern.compile(regex).matcher(command);
        while (m.find()) {
            if (m.group(1) != null) {
                tokens.add(m.group(1));
            } else {
                tokens.add(m.group(2));
        	}
		}
		String[] output = new String[3];
		
		switch(tokens.size()) {
			case 0:
				break;
			case 1:
				output[0] = tokens.get(0);
				break;
			case 2:
				output[0] = tokens.get(0);
				output[1] = tokens.get(1);
				break;
			case 3:
				output[0] = tokens.get(0);
				output[1] = tokens.get(1);
				output[2] = tokens.get(2);
				break;
			default:
				output[0] = tokens.get(0);
				output[1] = tokens.get(1);
				String[] lastToken = Arrays.copyOf(tokens.toArray(),tokens.toArray().length,String[].class);
				lastToken = Arrays.copyOfRange(lastToken,2,lastToken.length);
				output[2] = String.join(" ",lastToken);
				break;
		}
		return output;
	}

	public static int getResponse(DataInputStream fromServer,Cipher decryptCipher) throws Exception {
		String response = new String(ConnectionUtils.iterativeReadAndDecryptMessage(fromServer, decryptCipher));
		int responseCode = Integer.parseInt(response.substring(0,1));
		if (response.indexOf("\n")==1) System.out.println(response.substring(2));
		return responseCode; 
	}
}