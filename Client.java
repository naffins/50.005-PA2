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
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

public class Client {

	private static final String AUTH_MESSAGE = "ACCESSING CSD SERVER - HANDSHAKE";
	private static Key serverPublicKey;

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
				System.out.println("Closing all connections...");
				toServer.close();
				fromServer.close();
				clientSocket.close();
				throw new Exception();
			}

			// Make user choose CP1 or CP2 to send files
			String choice = "";
			Scanner cpScanner = new Scanner(System.in);
			while (!choice.equals("1") && !choice.equals("2")) {
				System.out.println("Enter CP choice [1 or 2]: ");
				choice = cpScanner.nextLine();
			}
			cpScanner.close();
			int cp = Integer.parseInt(choice);
			toServer.writeInt(cp);

			// Do the rest of negotiation
			// Then keep sending commands until user decides to shutdown/exit here
			
			toServer.close();
			fromServer.close();
			clientSocket.close();



		} catch (Exception e) {
			e.printStackTrace();
		}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken / 1000000.0 + "ms to run");

	}

	public static boolean performHandshake(DataInputStream fromServer, DataOutputStream toServer, Socket clientSocket,
			Key clientPublicKey, Key clientPrivateKey) throws Exception {
		// Begin handshake request
		ConnectionUtils.writeVariableBytes(toServer,"CONNECT".getBytes());

		// Receive fixed message encrypted with server private key
		byte[] authMessage = ConnectionUtils.readVariableBytes(fromServer);

		// Acknowledge
		ConnectionUtils.writeVariableBytes(toServer,"ACK-C1".getBytes());

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
			ConnectionUtils.writeVariableBytes(toServer,"ACK-C2".getBytes());
		}

		// Receive plaintext nonce from server
		byte[] nonce = ConnectionUtils.readVariableBytes(fromServer);

		// Encrypt plaintext nonce with client private key
		Cipher rsaClientPrivateKey = ConnectionUtils.getRSACipher(clientPrivateKey, true);
		byte[] encryptedNonce = rsaClientPrivateKey.doFinal(nonce);
		ConnectionUtils.writeVariableBytes(toServer, encryptedNonce);

		System.out.println("test2");

		// Receive acknowledgement
		if (!new String(ConnectionUtils.readVariableBytes(fromServer)).equals("ACK-S1")) {
			return false;
		}

		// Send client public key
		System.out.println(clientPublicKey.getFormat());
		ConnectionUtils.writeVariableBytes(toServer, clientPublicKey.getEncoded());


		// Receive acknowledgement
		if (!new String(ConnectionUtils.readVariableBytes(fromServer)).equals("ACK-S2")) {
			return false;
		}

		// Conclude handshake
		return true;
	}

}
