import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.FileInputStream;

import java.nio.file.*;
import java.io.File;
import java.io.FilenameFilter;

import javax.crypto.*;

import java.lang.SecurityException;

public class ServerShell {

    private static String[] AVAILABLE_COMMANDS = {
        "exit",
        "shutdown",
        "put",
        "ls",
        "cwd",
        "pwd",
        "get"
    };
    private static String SHUTDOWN_RESPONSE = "0\nServer shutting down...";
    private static String INVALID_COMMAND_ERROR = "2\nError: invalid command";

    public static boolean launchShell(
        DataInputStream serverIn,
        DataOutputStream serverOut,
        Cipher[] commCiphers,
        String startingDirectory,
        int cp
    ) throws Exception {
        
        String[] currentDirectory = {startingDirectory};

        while (true) {
            
            // Read command from client
            String command = new String(ConnectionUtils.iterativeReadAndDecryptMessage(serverIn,commCiphers[1]));

            // Parse command into function and parameters
            String[] parsedCommand = parseCommand(command);

            // Execute command, getting 1 of 3 return values:
            // 0: continue, 1: close connection, 2: shutdown server
            switch (executeCommand(parsedCommand,serverIn,serverOut,commCiphers,currentDirectory,cp)) {
                case 1:
                    return false;
                case 2:
                    return true;
                default:
                    break;
            }

        }

    }

    public static String[] parseCommand(String command) {
        
        String[] returnValues = new String[2];
        int spaceIndex = command.indexOf(" ");
        if (spaceIndex==-1) {
            returnValues[0] = command;
            returnValues[1] = null;
        }
        else if (spaceIndex==command.length()-1) {
            returnValues[0] = command.substring(0,command.length()-1);
            returnValues[1] = null;
        }
        else {
            returnValues[0] = command.substring(0,spaceIndex);
            returnValues[1] = command.substring(spaceIndex+1);
        }

        return returnValues;

    }

    public static int executeCommand(
        String[] parsedCommand,
        DataInputStream serverIn,
        DataOutputStream serverOut,
        Cipher[] commCiphers,
        String[] currentDirectory,
        int cp
    ) throws Exception {
        
        int commandIndex = -1;
        for (int i=0;i<AVAILABLE_COMMANDS.length;i++) {
            if (AVAILABLE_COMMANDS[i].equals(parsedCommand[0])) {
                commandIndex = i;
                break;
            }
        }
        boolean isRSA = cp == 1;

        switch (commandIndex) {
            case 0:
                return 1;
            case 1:
                ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],SHUTDOWN_RESPONSE.getBytes(),isRSA);
                return 2;
            case 2:
                receiveFile(parsedCommand[1],serverIn,serverOut,commCiphers,isRSA,currentDirectory[0]);
                break;
            case 3:
                listCurrentDirectory(serverOut,commCiphers,isRSA,currentDirectory[0]);
                break;
            case 4:
                changeCurrentDirectory(parsedCommand[1],serverOut,commCiphers,isRSA,currentDirectory);
                break;
            case 5:
                displayCurrentDirectory(serverOut,commCiphers,isRSA,currentDirectory[0]);
                break;
            case 6:
                sendFile(parsedCommand[1],serverOut,commCiphers,isRSA,currentDirectory[0]);
                break;
            default:
                ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],INVALID_COMMAND_ERROR.getBytes(),isRSA);
                break;
        }

        return 0;

    }

    private static String RECEIVEFILE_INVALID_PATH_ERROR = "1\nError: target path/filename is invalid.";
    private static String RECEIVEFILE_FILE_EXISTS_ERROR = "1\nError: target file already exists.";
    private static String RECEIVEFILE_WRITE_ERROR = "1\nError: server has no write permissions for target file.";

    private static String RECEIVEFILE_SUCCESS_RESPONSE = "0";

    public static void receiveFile(
        String targetFilename,
        DataInputStream serverIn,
        DataOutputStream serverOut,
        Cipher[] commCiphers,
        boolean isRSA,
        String currentDirectory
    ) throws Exception {

        if (targetFilename==null) {
            ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],RECEIVEFILE_INVALID_PATH_ERROR.getBytes(),isRSA);
            return;
        }

        Path targetPath = Paths.get(currentDirectory);
        try {
            targetPath = targetPath.resolve(targetFilename);
        }
        catch (InvalidPathException e) {
            ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],RECEIVEFILE_INVALID_PATH_ERROR.getBytes(),isRSA);
            return;
        }

        try {
            targetPath = Files.createFile(targetPath);
        }
        catch (Exception e) {
            String error = null;
            if (e instanceof FileAlreadyExistsException) error = RECEIVEFILE_FILE_EXISTS_ERROR;
            else if (e instanceof SecurityException) error = RECEIVEFILE_WRITE_ERROR;
            else error = RECEIVEFILE_INVALID_PATH_ERROR;
            ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],error.getBytes(),isRSA);
            return;
        }

        ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],RECEIVEFILE_SUCCESS_RESPONSE.getBytes(),isRSA);
        FileOutputStream inFile = null;
        try {
            inFile = new FileOutputStream(targetPath.toString());
        }
        catch (SecurityException e) {
            ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],RECEIVEFILE_WRITE_ERROR.getBytes(),isRSA);
            return;
        }
        
        ConnectionUtils.iterativeReadAndDecryptFile(serverIn,commCiphers[1],inFile);
        inFile.close();
        return;

    }

    private static String LISTCURRENTDIRECTORY_READ_ERROR = "1\nError: server unable to read current directory";

    private static String LISTCURRENTDIRECTORY_SUCCESS_PREFIX = "0\n";

    public static void listCurrentDirectory(
        DataOutputStream serverOut,
        Cipher[] commCiphers,
        boolean isRSA,
        String currentDirectory
    ) throws Exception {
        File targetDirectory = new File(currentDirectory);
        String dirList = LISTCURRENTDIRECTORY_SUCCESS_PREFIX;
        try {
            String[] directoryList = targetDirectory.list(new FilenameFilter() {
                public boolean accept(File dir, String name) {
                    return new File(dir,name).isDirectory();
                }
            });
            String[] fileList = targetDirectory.list(new FilenameFilter() {
                public boolean accept(File dir, String name) {
                    return new File(dir,name).isFile();
                }
            });
            for (int i=0;i<directoryList.length;i++) {
                dirList += "/" + directoryList[i] + "\n";
            }
            for (int i=0;i<fileList.length;i++) {
                dirList += fileList[i] + "\n";
            }
        }
        catch (SecurityException e) {
            ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],LISTCURRENTDIRECTORY_READ_ERROR.getBytes(),isRSA);
            return;
        }
        ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],dirList.getBytes(),isRSA);
        return;
    }

    public static void displayCurrentDirectory(
        DataOutputStream serverOut,
        Cipher[] commCiphers,
        boolean isRSA,
        String currentDirectory
    ) throws Exception {
        String response = "0\n" + currentDirectory;
        ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],response.getBytes(),isRSA);
        return;
    }

    private static String CHANGECURRENTDIRECTORY_INVALID_PATH_ERROR = "1\nError: target path/filename is invalid.";
    private static String CHANGECURRENTDIRECTORY_OTHER_ERROR = "1\nError: either the directory to move to doesn't exist, or the server has no permission to read it.";

    private static String CHANGECURRENTDIRECTORY_SUCCESS_RESPONSE = "0\nSuccessfully changed directory.";

    public static void changeCurrentDirectory(
        String targetDirectory,
        DataOutputStream serverOut,
        Cipher[] commCiphers,
        boolean isRSA,
        String[] currentDirectory
    ) throws Exception {

        if (targetDirectory==null) {
            ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],CHANGECURRENTDIRECTORY_INVALID_PATH_ERROR.getBytes(),isRSA);
            return;
        }
        
        Path startDir = Paths.get(currentDirectory[0]);
        Path targetDir = null;
        try {
            targetDir = startDir.resolve(targetDirectory).toRealPath();
        }
        catch (Exception e) {
            if (e instanceof InvalidPathException) ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],CHANGECURRENTDIRECTORY_INVALID_PATH_ERROR.getBytes(),isRSA);
            else ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],CHANGECURRENTDIRECTORY_OTHER_ERROR.getBytes(),isRSA);
            return;
        }

        try {
            if (Files.exists(targetDir)&&Files.isDirectory(targetDir)) {
                currentDirectory[0] = targetDir.toString();
                ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],CHANGECURRENTDIRECTORY_SUCCESS_RESPONSE.getBytes(),isRSA);
                return;
            }
            ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],CHANGECURRENTDIRECTORY_OTHER_ERROR.getBytes(),isRSA);
            return;
        }
        catch (SecurityException e) {
            ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],CHANGECURRENTDIRECTORY_OTHER_ERROR.getBytes(),isRSA);
            return;
        }
    }

    private static String SENDFILE_INVALID_PATH_ERROR = "1\nError: source path/filename is invalid.";
    private static String SENDFILE_FILE_NOT_EXIST_ERROR = "1\nError: source file doesn't exist.";
    private static String SENDFILE_READ_ERROR = "1\nError: server has no read permissions for target file.";

    private static String SENDFILE_SUCCESS_RESPONSE = "0";

    public static void sendFile(
        String sourceFilename,
        DataOutputStream serverOut,
        Cipher[] commCiphers,
        boolean isRSA,
        String currentDirectory
    ) throws Exception {
        
        if (sourceFilename==null) {
            ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],SENDFILE_INVALID_PATH_ERROR.getBytes(),isRSA);
            return;
        }
        
        Path sourcePath = Paths.get(currentDirectory);
        try {
            sourcePath = sourcePath.resolve(sourceFilename);
        }
        catch (InvalidPathException e) {
            ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],SENDFILE_INVALID_PATH_ERROR.getBytes(),isRSA);
            return;
        }

        try {
            if (!Files.exists(sourcePath)) {
                ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],SENDFILE_FILE_NOT_EXIST_ERROR.getBytes(),isRSA);
                return;
            }
        }
        catch (SecurityException e) {
            ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],SENDFILE_READ_ERROR.getBytes(),isRSA);
            return;
        }

        ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],SENDFILE_SUCCESS_RESPONSE.getBytes(),isRSA);
        
        FileInputStream outFile = null;

        try{
            outFile = new FileInputStream(sourcePath.toString());
        }
        catch (SecurityException e) {
            ConnectionUtils.encryptAndIterativeWriteMessage(serverOut,commCiphers[0],SENDFILE_READ_ERROR.getBytes(),isRSA);
            return;
        }
        try {
            ConnectionUtils.encryptAndIterativeWriteFile(serverOut,commCiphers[0],isRSA,outFile);
        }
        catch (Exception e) {
            outFile.close();
            throw e;
        }
        outFile.close();
        return;

    }
}