import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class StringObfuscator {

    public static void main(String[] args) throws URISyntaxException, IOException {

        String sourceFolder = null;
        String targetFolder = null;
        if (args.length > 1) {
            sourceFolder = args[0];
            targetFolder = args[1];
        }

        if (targetFolder == null) {
            System.out.println("Source and target folder missing: " + sourceFolder);
            return;
        }

        Path targetFolderFile = Paths.get(targetFolder);
        if (!Files.exists(targetFolderFile)) {
            Files.createDirectories(targetFolderFile);
        }

        List<Path> javaFiles = findAllFilesNio(sourceFolder, ".*\\.java");

        HashMap<String, String> stringToUuid = new HashMap<>();
        HashMap<String, String> uuidToString = new HashMap<>();


        // Regex to find string literals
        String regex = "\"([^\"\\\\]|\\\\.)*\"";
        Pattern pattern = Pattern.compile(regex);

        StringBuffer mapperClassSourceCode = new StringBuffer("package org.kx;\n");
        mapperClassSourceCode.append("public class zqw {\n");
        for (int i = 0; i < 256; i++) {
            mapperClassSourceCode.append(
                    "    public static String p" + encode(i) + "(byte[] z) {\n" +
                            "        byte q = (byte)" + i + "; int x = q; int p = z[1];\n" +
                            "        byte [] t = new byte[z.length - 2];\n" +
                            "        for (int i  = 2; i < z.length; i++) {\n" +
                            "            t[i - 2] = (byte)(z[i] ^ (byte)p);\n" +
                            "            p += x;\n" +
                            "            p = (byte)p;\n" +
                            "        }\n" +
                            "        return new String(t);\n" +
                            "    }\n");
        }

        if (true == false) {
            mapperClassSourceCode.append("    public static void main(String [] args) {\n");
            for (Path file : javaFiles) {
                processFile(file, pattern, sourceFolder, targetFolder, mapperClassSourceCode);
            }
            mapperClassSourceCode.append("}");
        }
        else {
            for (Path file : javaFiles) {
                processFile(file, pattern, sourceFolder, targetFolder, null);
            }
        }
        mapperClassSourceCode.append("}");
        Files.writeString(Paths.get( targetFolder + "\\org\\kx\\zqw.java"), mapperClassSourceCode.toString());
    }

    private static void processFile(Path file, Pattern pattern, String sourceFolder, String targetFolder, StringBuffer mapperClassSourceCode) throws IOException {
        //String javaSourceCode = Files.readString(file);
        String javaSourceCode = "";
        List<String> javaSourceLines = Files.readAllLines(file);
        StringBuffer encryptedSourceCode = new StringBuffer();
        //String encryptedSourceCode = javaSourceCode;
        //Matcher matcher = pattern.matcher(javaSourceCode);

        System.out.println("File: " + file);
        System.out.println("Found strings:");
        boolean changed = false;
        for (String line : javaSourceLines) {
            //System.out.println(line);
            String xline = line;
            if (!line.trim().startsWith("//") && !line.trim().startsWith("@")) {
                Matcher matcher = pattern.matcher(line);
                while (matcher.find()) {
                    //encryptedSourceCode = processStrings(matcher, encryptedSourceCode, mapperClassSourceCode);
                    xline = processStrings(matcher, xline, mapperClassSourceCode);
                    changed = true;
                }
            }
            encryptedSourceCode.append(xline);
            encryptedSourceCode.append("\n");
        }


        Path targetPath = Paths.get(file.toString().replace(sourceFolder, targetFolder));
        System.out.println("    " + targetPath);
        if (!Files.exists(targetPath.getParent())) {
            Files.createDirectories(targetPath.getParent());
        }

        if (changed) {
            Files.writeString(targetPath, encryptedSourceCode);
        }
        else {
            Files.copy(file, targetPath, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static int linesTested = 0;
    private static String processStrings(Matcher matcher, String javaSourceCode, StringBuffer mapperClassSourceCode) {
        String sourceString = matcher.group();

        String str = sourceString.substring(1).substring(0, sourceString.length() - 2);
        int increaseBy = random.nextInt(256);
        String methodName = "zqw.p" + encode(increaseBy);
        String [] coded =  stringToArray((byte)increaseBy, str);
        System.out.println(str);
        String stringCoded = String.join(",", coded);
        System.out.println(stringCoded);
        String methodCall = methodName + "(new byte[] {" + stringCoded + "})";
        String encryptedSourceCode = javaSourceCode.replace(sourceString, methodCall);
        if (mapperClassSourceCode != null && (linesTested++ > 250 &&  linesTested < 400)) {
            mapperClassSourceCode.append("System.out.println(" + methodCall + ");\n");
        }
        return encryptedSourceCode;
    }

    public static List<Path> findAllFilesNio(String directoryPath, String pattern) {
        Path startPath = Paths.get(directoryPath);
        List<Path> fileList = new ArrayList<>();

        try (Stream<Path> walk = Files.walk(startPath)) {
            fileList = walk
                    .filter(Files::isRegularFile) // Filter for regular files
                    .filter(p -> p.getFileName().toString().matches(pattern))
                    .collect(Collectors.toList());
        } catch (IOException e) {
            System.err.println("Error walking directory: " + e.getMessage());
        }
        return fileList;
    }

    private static String p(byte[] z) {
        int x = z[0]; int p = z[1];
        byte [] t = new byte[z.length - 2];
        for (int i  = 2; i < z.length; i++) {
            t[i - 2] = (byte)(z[i] ^ (byte)p);
            p += x;
            p = (byte)p;
        }
        return new String(t, StandardCharsets.UTF_8);
    }


    private static String[] stringToArray(byte increaseBy, String str) {
        if (str.contains("\\")) {
            String test = str
                    .replace("\\\\", "")
                    .replace("\\r", "")
                    .replace("\\\"", "")
                    .replace("\\/", "")
                    .replace("\\n", "")
                    .replace("\\t", "");
            if (test.contains("\\")) throw new RuntimeException("Error in string: " + str);
        }
        byte [] arr = str
                .replace("\\\\", "\\")
                .replace("\\r", "\r")
                .replace("\\\"", "\"")
                .replace("\\n", "\n")
                .replace("\\t", "\t")
                .getBytes(StandardCharsets.UTF_8);
        byte [] ret = new byte[arr.length + 2];
        ret[0] = (byte)random.nextInt();
        ret[1] = (byte)random.nextInt();
        if (ret[1] == 0 || ret[1] == 255) ret[1] = (byte)178;
        int p = ret[1];
        int x = increaseBy;
        for (int i = 0; i < arr.length; i++) {
            ret[i + 2] = (byte)(arr[i] ^ (byte)p);
            p += x;
            p = (byte)p;
        }
        String []strArr = new String[ret.length];
        for (int i = 0; i < ret.length; i++) {
            strArr[i] = "(byte)" + ret[i];
        }
        return strArr;
    }

    private static final Random random = new Random();

    private static final String ALPHABET = "PQRtuvwxyzSTUV3456WXYZabcdefghijkABCDEFGH789IJKLMNOlmnopqrs";

    public static String encode(int number) {
        if (number < 0 || number > 255) {
            throw new IllegalArgumentException("Number must be between 0 and 255.");
        }

        StringBuilder encodedString = new StringBuilder();
        int base = ALPHABET.length();

        // Handle the case of 0 separately
        if (number == 0) {
            return String.valueOf(ALPHABET.charAt(0));
        }

        while (number > 0) {
            encodedString.insert(0, ALPHABET.charAt(number % base));
            number /= base;
        }
        return encodedString.toString();
    }

    public static String generateRandomString(int length) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int index = random.nextInt(alphabet.length());
            sb.append(alphabet.charAt(index));
        }
        return sb.toString();
    }
}