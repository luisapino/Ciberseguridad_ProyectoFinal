import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.Base64;

public class Server {

    public static void main(String[] args) {
        int port = 5555;
        String outputFile = "archivo_recibido.txt";

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Servidor esperando conexión en puerto " + port + "...");
            Socket clientSocket = serverSocket.accept();
            System.out.println("Cliente conectado.");

            DataInputStream dis = new DataInputStream(clientSocket.getInputStream());
            DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream());

            // 1. Generar claves RSA
            KeyPair keyPair = CryptoUtils.generateRSAKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            String publicKeyEncoded = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            dos.writeUTF(publicKeyEncoded);
            dos.flush();
            System.out.println("Clave pública enviada.");

            // 2. Recibir y descifrar clave AES
            int keyLength = dis.readInt();
            byte[] encryptedKey = dis.readNBytes(keyLength);
            byte[] aesKeyBytes = CryptoUtils.decryptRSA(encryptedKey, privateKey);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, 0, aesKeyBytes.length, "AES");
            System.out.println("Clave AES recibida y descifrada.");

            // 3. Recibir IV
            byte[] iv = dis.readNBytes(16);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // 4. Recibir archivo cifrado
            int fileLength = dis.readInt();
            byte[] encryptedFile = dis.readNBytes(fileLength);

            // 5. Descifrar archivo
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
            byte[] decryptedFile = aesCipher.doFinal(encryptedFile);

            // 6. Guardar archivo descifrado
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                fos.write(decryptedFile);
            }
            System.out.println("Archivo recibido y descifrado guardado como: " + outputFile);

            // 7. Recibir hash del cliente
            int hashLength = dis.readInt();
            byte[] clientHash = dis.readNBytes(hashLength);

            // 8. Calcular hash local y comparar
            byte[] serverHash = CryptoUtils.sha256(decryptedFile);
            boolean matches = MessageDigest.isEqual(clientHash, serverHash);

            System.out.println(matches
                    ? "✅ Integridad verificada: archivo transferido correctamente."
                    : "❌ Error de integridad: los hashes no coinciden.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
