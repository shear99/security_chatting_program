import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

public class Client {
    private static SecretKey aesKey;
    private static final int AES_KEY_SIZE = 256;
    private static final String AES = "AES";
    private static final String RSA = "RSA";
    private static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";

    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("localhost", 8000);
        System.out.println("Server connected.");

        // AES key generation
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(AES_KEY_SIZE);
        aesKey = keyGenerator.generateKey();
        byte[] iv = generateIV();

        // Receive server's public key
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        PublicKey publicKey = (PublicKey) ois.readObject();
        System.out.println("Received server's public key.");

        // Encrypt AES key and IV with server's public key
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAesKey = cipher.doFinal(aesKey.getEncoded());
        byte[] encryptedIv = cipher.doFinal(iv);

        // Send encrypted AES key and IV to server
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        oos.writeObject(encryptedAesKey);
        oos.writeObject(encryptedIv);
        System.out.println("Encrypted AES key and IV sent to server.");

        // Print RSA public key and AES key information
        System.out.println("RSA public key received:");
        System.out.println("Public key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.println("AES key and IV generated:");
        System.out.println("AES key: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));
        System.out.println("IV: " + Base64.getEncoder().encodeToString(iv));

        // Start message sending and receiving loop
        Scanner scanner = new Scanner(System.in);
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        String message;
        try {
        while (true) {
            System.out.print("\n> Enter message : ");
            message = scanner.nextLine();
            // Exit if user types "exit"
            if (message.equalsIgnoreCase("exit")) {
                oos.writeObject(encrypt("exit", aesKey, new IvParameterSpec(iv)));
                break;
            }
            String encryptedMessage = encrypt(message, aesKey, new IvParameterSpec(iv));
            oos.writeObject(encryptedMessage);
            // Receive encrypted reply
            String encryptedReply = (String) ois.readObject();
            String decryptedReply = decrypt(encryptedReply, aesKey, new IvParameterSpec(iv));

            // Exit if either side types "exit"
            if (decryptedReply.equalsIgnoreCase("exit")) {
                System.out.println("\n> Received : " + decryptedReply + "  [" + dateFormat.format(new Date()) + "]");
                System.out.println("Encrypted message: " + encryptedMessage);
                break;
            }
            System.out.println("\n> Received : " + decryptedReply + "  [" + dateFormat.format(new Date()) + "]");
            System.out.println("Encrypted message: " + encryptedMessage);
        }
        } catch (Exception e) {
            System.out.println("Connection closed.");
        }
        ois.close();
        oos.close();
        socket.close();
    }

    private static byte[] generateIV() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        return iv;
    }

    public static String encrypt(String strToEncrypt, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encryptedBytes = cipher.doFinal(strToEncrypt.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String strToDecrypt, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decodedBytes = Base64.getDecoder().decode(strToDecrypt);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, "UTF-8");
    }
}
