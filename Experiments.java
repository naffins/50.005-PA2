import java.io.File;
import java.io.FilenameFilter;

import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import javax.crypto.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Experiments {

    public static void main(String[] args) throws Exception {
        String text = "aasdfasdfasdfasdfa \"sdfasdfasdfa sdfa  sdfadf\"  sdfsdfsdfs";
        String regex = "\"([^\"]*)\"|(\\S+)";
        Matcher m = Pattern.compile(regex).matcher(text);
        while (m.find()) {
            if (m.group(1) != null) {
                System.out.println(m.group(1));
            } else {
                System.out.println(m.group(2));
        }
    }
    }


}