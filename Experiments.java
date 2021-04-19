import java.io.File;
import java.io.FilenameFilter;

public class Experiments {
    public static void listFilesForFolder(final File folder) {
    for (String a : folder.list(new FilenameFilter (){
        public boolean accept(File dir, String name) {
            
            return new File(dir,name).isFile();
        }
    })) {
        System.out.println(a);
    }
}

    public static void main(String[] args) {
        final File folder = new File(".");
        listFilesForFolder(folder);
    }


}