import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
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

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

public class Client {

	private static final String AUTH_MESSAGE = "ACCESSING CSD SERVER - HANDSHAKE";
	private static Key serverPublicKey;
	private static int cp;
	private static Key sessionKey;
	private static Scanner inputScanner = null;
	private static final String HELP_COMMAND = "help : Prints a list of avaiable commands. \n"
			+ "put [local filename] [remote filename] : Sends file to server. \n"
			+ "exit : Close socket immediately. No response will be returned. \n"
			+ "shutdown : Server will return '0' and indicate that server is shutting down. \n";

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
				System.out.println("Enter command (enter 'help' to see list of commands): ");
				String command = inputScanner.nextLine();

				// help command
				if (command.equals("help")) {
					System.out.println(HELP_COMMAND);
				} 
				
				// exit command
				else if (command.equals("exit")) {
					System.out.println("Exit command given. \n");
					ConnectionUtils.encryptAndIterativeWriteMessage(toServer, encryptCipher, command.getBytes(), isRSA); // Send command
					exitFlag = true;
				} 
				
				// commands with responses
				else if (command.equals("shutdown") || command.split(" ")[0].equals("put")) {
					ConnectionUtils.encryptAndIterativeWriteMessage(toServer, encryptCipher, command.getBytes(), isRSA); // Send command					
					String response = new String(ConnectionUtils.iterativeReadAndDecryptMessage(fromServer, decryptCipher)); // Receive response

					// if response = 0, continue
					if (response.contains("0")) {
						switch (command.split(" ")[0]) {
						// shutdown command
						case "shutdown":
							System.out.println("Shutdown command given.");
							System.out.println(response +"\n");
							exitFlag = true;
							break;

						// put command
						case "put":
							System.out.println("Put command given.");
							put(fromServer, toServer, encryptCipher, decryptCipher, isRSA, command.split(" ")[1]);
							break;
						}
					}
					
					// if response = 1, error and if response = 2, bad request
					else if (response.contains("1") || response.contains("2")) {
						System.out.println(response +"\n");
					}
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

	private static void put(DataInputStream fromServer, DataOutputStream toServer, Cipher encryptCipher, Cipher decryptCipher, boolean isRSA, String fname) throws Exception {
		// Send file
		System.out.println(fname);
		ConnectionUtils.encryptAndIterativeWriteFile(toServer, encryptCipher, isRSA, new FileInputStream(fname)); 
		
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
		X509Certificate certificate = (X509Certificate) certFactory
				.generateCertificate(new ByteArrayInputStream(encryptedCertificate));
		serverPublicKey = certificate.getPublicKey();

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
			System.out.println("Enter CP choice [1 or 2]: ");
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

}