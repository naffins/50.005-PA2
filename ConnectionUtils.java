import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;

import javax.crypto.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;

public class ConnectionUtils {

    private static int RSA_IN_BLOCK_SIZE = 100;
    private static int RSA_OUT_BLOCK_SIZE = 1024;
    private static int AES_IN_BLOCK_SIZE = 128;
    private static int AES_OUT_BLOCK_SIZE = 128;

    public static byte[] readVariableBytes(DataInputStream serverIn) throws Exception {
        int size = serverIn.readInt();
        byte[] data = new byte[size];
        serverIn.readFully(data,0,size);
        return data;
    }
    public static void writeVariableBytes(DataOutputStream serverOut, byte[] output) throws Exception {
        serverOut.writeInt(output.length);
        serverOut.write(output,0,output.length);
        return;
    }

    public static Cipher getRSACipher(Key key,boolean isEncryptCipher) throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        if (isEncryptCipher) rsaCipher.init(Cipher.ENCRYPT_MODE,key);
        else rsaCipher.init(Cipher.DECRYPT_MODE,key);
        return rsaCipher;
    }

    public static Cipher getAESCipher(Key key,boolean isEncryptCipher) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS1Padding");
        if (isEncryptCipher) aesCipher.init(Cipher.ENCRYPT_MODE,key);
        else aesCipher.init(Cipher.DECRYPT_MODE,key);
        return aesCipher;
    }

    public static byte[] performCrypto(Cipher cipher,byte[] input) throws Exception {
        return cipher.doFinal(input);
    }

    public static void encryptAndIterativeWriteMessage(DataOutputStream serverOut,Cipher cipher,byte[] input, boolean isRSA) throws Exception {
        
        int inBlockSize = isRSA? RSA_IN_BLOCK_SIZE : AES_IN_BLOCK_SIZE;
        int outBlockSize = isRSA? RSA_OUT_BLOCK_SIZE : RSA_OUT_BLOCK_SIZE;

        int blockCount = input.length/inBlockSize;
        if (input.length%inBlockSize!=0) blockCount+=1;
        int messageSize = blockCount * outBlockSize;

        serverOut.writeInt(0);

        for (int i=0;i<blockCount;i++) {
            serverOut.writeInt(outBlockSize);
            byte[] messagePortion = null;
            if (i!=blockCount-1) messagePortion = Arrays.copyOfRange(input,i*inBlockSize,(i+1)*inBlockSize);
            else messagePortion = Arrays.copyOfRange(input,i*inBlockSize,input.length);
            byte[] encryptedPortion = performCrypto(cipher,messagePortion);
            serverOut.write(encryptedPortion,0,encryptedPortion.length);
        }

        serverOut.writeInt(0);

        return;
        
    }

    public static byte[] iterativeReadAndDecryptMessage(DataInputStream serverIn,Cipher cipher) throws Exception {
        
        int startSignal = serverIn.readInt();
        if (startSignal!=0) throw new Exception();
        
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        
        while (true) {
            int size = serverIn.readInt();
            if (size==0) break;
            byte[] input = new byte[size];
            serverIn.readFully(input,0,input.length);
            byteStream.write(performCrypto(cipher,input));
        }

        return byteStream.toByteArray();

    }

    public static PrivateKey generatePrivateRSAKeyFromBytes(byte[] input) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(input);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePrivate(spec);
    }

    public static SecretKey generateSecretAESKeyFromBytes(byte[] input) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(input);
        SecretKeyFactory kf = SecretKeyFactory.getInstance("AES");
        return kf.generateSecret(spec);
    }


}