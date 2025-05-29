import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class Client {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Uso: java Client <archivo_a_enviar>");
            return;
        }

        String filename = args[0];
        new File("client_files").mkdir();

        Socket socket = new Socket("localhost", 5555);
        System.out.println("[Cliente] Conectado al servidor.");

        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
        DataInputStream dis = new DataInputStream(socket.getInputStream());

        int pubKeyLen = dis.readInt();
        byte[] publicKeyBytes = dis.readNBytes(pubKeyLen);
        PublicKey publicKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        CryptoUtils.saveKey("client_files/public_key_recibida.pem", publicKey);
        System.out.println("[Cliente] Clave pública recibida.");

        SecretKey aesKey = CryptoUtils.generateAESKey();
        byte[] aesBytes = aesKey.getEncoded();
        CryptoUtils.saveToFile("client_files/aes_key.hex", aesBytes);
        byte[] encryptedAES = CryptoUtils.encryptRSA(aesBytes, publicKey);

        dos.writeInt(encryptedAES.length);
        dos.write(encryptedAES);
        dos.flush();
        System.out.println("[Cliente] Clave AES enviada.");

        byte[] fileData = Files.readAllBytes(new File(filename).toPath());
        CryptoUtils.saveToFile("client_files/archivo_original.txt", fileData);
        byte[] encryptedFile = CryptoUtils.encryptAES(fileData, aesKey);
        CryptoUtils.saveToFile("client_files/archivo_cifrado_client.bin", encryptedFile);

        dos.writeInt(encryptedFile.length);
        dos.write(encryptedFile);
        dos.flush();
        System.out.println("[Cliente] Archivo cifrado enviado.");

        byte[] fileHash = CryptoUtils.sha256(fileData);
        CryptoUtils.saveToFile("client_files/hash_cliente.hex", fileHash);
        dos.writeInt(fileHash.length);
        dos.write(fileHash);
        dos.flush();

        dis.close();
        dos.close();
        socket.close();
        System.out.println("[Cliente] Hash enviado. Proceso completado.");
    }
}