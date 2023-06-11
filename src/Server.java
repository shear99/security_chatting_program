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

public class Server {
    private static SecretKey aesKey;
    private static final int RSA_KEY_SIZE = 2048;
    private static final int AES_KEY_SIZE = 256;
    private static final String AES = "AES";
    private static final String RSA = "RSA";
    private static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";

    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(8000);
        System.out.println("Waiting for client connection...");

        // Wait for client connection
        Socket socket = serverSocket.accept();
        System.out.println("Client connected.");

        // RSA key pair generation
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(RSA_KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Send public key to client
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        oos.writeObject(publicKey);
        System.out.println("Server: Public key sent to client.");

        // Receive encrypted AES key and IV from client
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        byte[] encryptedAesKey = (byte[]) ois.readObject();
        byte[] encryptedIv = (byte[]) ois.readObject();

        // Decrypt AES key and IV
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedAesKey = cipher.doFinal(encryptedAesKey);
        byte[] decryptedIv = cipher.doFinal(encryptedIv);

        // Create AES key and IV
        aesKey = new SecretKeySpec(decryptedAesKey, 0, decryptedAesKey.length, AES);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(decryptedIv);

        // Print RSA key pair and AES key information
        System.out.println("RSA key pair generated:");
        System.out.println("Private key: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println("Public key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.println("AES key and IV received and decrypted:");
        System.out.println("AES key: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));
        System.out.println("IV: " + Base64.getEncoder().encodeToString(ivParameterSpec.getIV()));

        // Start message sending and receiving loop
        Scanner scanner = new Scanner(System.in);
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        String message;
        try {
            while (true) {
                // Receive encrypted message
                String encryptedMessage = (String) ois.readObject();
                String decryptedMessage = decrypt(encryptedMessage, aesKey, ivParameterSpec);

                // Exit if either side types "exit"
                if (decryptedMessage.equalsIgnoreCase("exit")) {
                    System.out.println("\n> Received : " + decryptedMessage + "  [" + dateFormat.format(new Date()) + "]");
                    System.out.println("Encrypted message: " + encryptedMessage);
                    break;
                }
                System.out.println("\n> Received : " + decryptedMessage + "  [" + dateFormat.format(new Date()) + "]");
                System.out.println("Encrypted message: " + encryptedMessage);

                System.out.print("\n> Enter message : ");
                message = scanner.nextLine();
                // Exit if user types "exit"
                if (message.equalsIgnoreCase("exit")) {
                    oos.writeObject(encrypt("exit", aesKey, ivParameterSpec));
                    break;
                }
                String encryptedReply = encrypt(message, aesKey, ivParameterSpec);
                oos.writeObject(encryptedReply);
            }
        } catch (Exception e) {
            System.out.println("Connection closed.");
        }
        ois.close();
        oos.close();
        socket.close();
        serverSocket.close();
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
