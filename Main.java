import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.util.*;
import java.nio.file.*;
import org.json.JSONArray;
import org.json.JSONObject;




public class Main{
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int KEY_LENGTH_BITS = 256;
    private static final int PBKDF2_ITERS = 500_000;
    private static final int TAG_LEN_BITS = 128;


    public static char[] masterPass;
    public static void setKey() throws Exception{
        Console console = System.console();
        if(console != null){
            masterPass = console.readPassword("Enter master password: ");
        } else{
            System.out.print("Enter master password: ");
            masterPass = new Scanner(System.in).nextLine().toCharArray();
        }
    }


    private static byte[] deriveKeyPBKDF2(char[] password, byte[] salt, int iterations, int keyLenBits) throws Exception{
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLenBits);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = skf.generateSecret(spec).getEncoded();
        spec.clearPassword();
        return key;
    }


    private static byte[] aesGcmEncrypt(byte[] keyBytes, byte[] iv, byte[] plaintext, byte[] aad) throws Exception{
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LEN_BITS, iv);
        c.init(Cipher.ENCRYPT_MODE, key, spec);
        if (aad != null) c.updateAAD(aad);
        return c.doFinal(plaintext);
    }


    private static byte[] aesGcmDecrypt(byte[] keyBytes, byte[] iv, byte[] ciphertextAndTag, byte[] aad) throws Exception{
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LEN_BITS, iv);
        c.init(Cipher.DECRYPT_MODE, key, spec);
        if (aad != null) c.updateAAD(aad);
        return c.doFinal(ciphertextAndTag);
    }


    public static Path vaultFile = Paths.get("vault");


    public static class Credential{
        private String website;
        private String username;
        private String password;
        public Credential(String website, String username, String password){
            this.website = website;
            this.username = username;
            this.password = password; }
        public String getWebsite() { return website; }
        public String getUsername() { return username; }
        public String getPassword() { return password; }
    }


    public static void vaultHelp(){
        System.out.println("Helping you now...");
    }


    public static byte[] jsonBytes;
    public static void gatherCredentials(){
        Scanner in = new Scanner(System.in);
        List<Credential> creds = new ArrayList<>();
        System.out.println("Password Vault Input");
        System.out.print("Enter website: ");
        String site = in.nextLine();
        System.out.print("Enter username: ");
        String user = in.nextLine();
        System.out.print("Enter password: ");
        String pass = in.nextLine();
        creds.add(new Credential(site, user, pass));
        JSONArray jsonArray = new JSONArray();
        for (Credential c : creds) {
            JSONObject obj = new JSONObject();
            obj.put("website", c.getWebsite());
            obj.put("username", c.getUsername());
            obj.put("password", c.getPassword());
            jsonArray.put(obj);
        }
        String jsonString = jsonArray.toString(2);
        jsonBytes = jsonString.getBytes(StandardCharsets.UTF_8);
        System.out.println("\nJSON OUTPUT");
        System.out.println(jsonString);

    }


    public static void addCredential() throws Exception{
        Scanner in = new Scanner(System.in);
        System.out.println("Adding credential...");
        while(true)
        {
            gatherCredentials();
            System.out.println("Add these credentials? (y/n)");
            String answer = in.nextLine().trim().toLowerCase();
            if(answer.equals("y")){
                try{
                    SecureRandom rnd = new SecureRandom();
                    byte[] salt = new byte[SALT_LENGTH];
                    rnd.nextBytes(salt);
                    byte[] iv = new byte[IV_LENGTH];
                    rnd.nextBytes(iv);
                    byte[] key = deriveKeyPBKDF2(masterPass, salt, PBKDF2_ITERS, KEY_LENGTH_BITS);
                    byte[] ctWithTag = aesGcmEncrypt(key, iv, jsonBytes, null);
                    byte[] blob = new byte[salt.length + iv.length + ctWithTag.length];
                    System.arraycopy(salt, 0, blob, 0, salt.length);
                    System.arraycopy(iv,   0, blob, salt.length, iv.length);
                    System.arraycopy(ctWithTag, 0, blob, salt.length + iv.length, ctWithTag.length);
                    String b64 = Base64.getEncoder().encodeToString(blob) + "\n";
                    Files.write(vaultFile, b64.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                    System.out.println("Saved.");
                } catch (IOException e) {
                    System.err.println("Error writing to file");
                }
                break;
            }
            else if(answer.equals("n")) continue;
            else{
                System.out.println("Invalid input.");
                break;
            }
        }



    }


    public static void removeCredential() throws Exception{
        System.out.println("Removing credential...");
    }


    public static void viewCredentials(){
        if (!Files.exists(vaultFile)){
            System.out.println("Vault is empty");
            return;
        }
        List<String> lines;
        try {
            lines = Files.readAllLines(vaultFile, StandardCharsets.UTF_8);
        } catch (IOException e){
            System.err.println("Error reading vault: " + e.getMessage());
            return;
        }
        for (String line : lines){
            if (line.isBlank()) continue;
            try{
                byte[] blob = Base64.getDecoder().decode(line);
                byte[] salt = Arrays.copyOfRange(blob, 0, SALT_LENGTH);
                byte[] iv   = Arrays.copyOfRange(blob, SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
                byte[] ct   = Arrays.copyOfRange(blob, SALT_LENGTH + IV_LENGTH, blob.length);
                byte[] key = deriveKeyPBKDF2(masterPass, salt, PBKDF2_ITERS, KEY_LENGTH_BITS);
                byte[] pt = aesGcmDecrypt(key, iv, ct, null);
                String json = new String(pt, StandardCharsets.UTF_8);
                System.out.println(json);
            } catch (Exception e){
                System.out.println("Error decrypting entry: " + e.getMessage());
            }
        }
    }


    public static void initVault(Path vaultFile) throws Exception{
        try {
            Files.createFile(vaultFile);
            setKey();
        } catch(IOException e){
            System.err.println("Error initiating vault");
        }
    }


    public static void vaultCheck(String[] args) throws Exception{
        if(args.length < 1){ System.out.println("Incorrect usage.\n");
            System.exit(0);
        }
        if(!Files.exists(vaultFile)){
            initVault(vaultFile);
        }else{
            setKey();
        }
    }


    public static void main(String[] args) throws Exception{

        for(int i = 0; i < args.length; i++){
            switch (args[i]) {
                case "--help":
                case "-h":
                    vaultHelp();
                    break;
                case "--add-credential":
                case "-ac":
                    vaultCheck(args);
                    addCredential();
                    break;
                case "--remove-credential":
                case "-rc":
                    break;
                case "--view-credentials":
                case "-vc":
                    vaultCheck(args);
                    viewCredentials();
                    break;
                default:
                    System.out.println("Incorrect usage. try --help or -h.");
            }
        }
    }
}
