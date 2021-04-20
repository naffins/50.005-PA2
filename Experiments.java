import java.io.File;
import java.io.FilenameFilter;

import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class Experiments {
    /*public static void listFilesForFolder(final File folder) {
    for (String a : folder.list(new FilenameFilter (){
        public boolean accept(File dir, String name) {
            
            return new File(dir,name).isFile();
            }
        })) {
            System.out.println(a);
        }
    }*/

    public static void main(String[] args) throws Exception {
        System.out.println(args[0]);
        if (args[0].equals("0")) {
            ServerSocket s = new ServerSocket(54321);
            Socket s1 = s.accept();
            DataOutputStream d = new DataOutputStream(s1.getOutputStream());
            d.writeChars("test");
            while(true);
        }
        else {
            Socket clientSocket = new Socket("localhost", 54321);
			DataInputStream fromServer = new DataInputStream(clientSocket.getInputStream());
            System.out.println(fromServer.readLine());
            fromServer.close();
            clientSocket.close();
        }
    }


}