import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;

public class Client {

    public static void main(String[] args) {
        String host = "localhost";
        int port = 5555;
        String filePath = "archivo.txt";  // Cambia a tu archivo

        try (Socket socket = new Socket(host, port)) {
            System.out.println("Conectado al servidor.");

            DataInputStream dis = new DataInputStream(socket.getInputStream());
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

            // 1. Recibir clave pública RSA
            String publicKeyBase64 = dis.readUTF();
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            System.out.println("Clave pública recibida.");

            // 2. Generar clave AES y cifrarla con RSA
            SecretKey aesKey = CryptoUtils.generateAESKey();
            byte[] encryptedAESKey = CryptoUtils.encryptRSA(aesKey.getEncoded(), publicKey);
            dos.writeInt(encryptedAESKey.length);
            dos.write(encryptedAESKey);
            dos.flush();
            System.out.println("Clave AES enviada.");

            // 3. Leer archivo
            File file = new File(filePath);
            byte[] fileBytes = new FileInputStream(file).readAllBytes();

            // 4. Generar IV para AES
            byte[] iv = new byte[16];
            new Random().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            dos.write(iv);  // Enviar IV

            // 5. Cifrar archivo con AES
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
            byte[] encryptedFile = aesCipher.doFinal(fileBytes);

            // 6. Enviar archivo cifrado
            dos.writeInt(encryptedFile.length);
            dos.write(encryptedFile);
            dos.flush();
            System.out.println("Archivo cifrado enviado.");

            // 7. Calcular y enviar hash SHA-256
            byte[] hash = CryptoUtils.sha256(fileBytes);
            dos.writeInt(hash.length);
            dos.write(hash);
            dos.flush();
            System.out.println("Hash enviado.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
