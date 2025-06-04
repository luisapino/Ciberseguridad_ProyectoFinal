package client;

import crypto.CryptoUtils;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class Client {
    public static void runClient(String filePath) throws Exception {
        File clientDir = new File("client_files");
        if (!clientDir.exists()) clientDir.mkdirs();

        Socket socket = new Socket("localhost", 5555);
        System.out.println("[Cliente] Conectado al servidor.");

        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
        DataInputStream dis = new DataInputStream(socket.getInputStream());

        int pubKeyLen = dis.readInt();
        byte[] publicKeyBytes = dis.readNBytes(pubKeyLen);
        PublicKey publicKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        CryptoUtils.saveKey("client_files/public_key_recibida.pem", publicKey);

        SecretKey aesKey = CryptoUtils.generateAESKey();
        byte[] aesBytes = aesKey.getEncoded();
        CryptoUtils.saveToFile("client_files/aes_key.hex", aesBytes);
        byte[] encryptedAES = CryptoUtils.encryptRSA(aesBytes, publicKey);

        dos.writeInt(encryptedAES.length);
        dos.write(encryptedAES);
        dos.flush();

        byte[] fileData = Files.readAllBytes(new File(filePath).toPath());
        CryptoUtils.saveToFile("client_files/archivo_original.txt", fileData);
        byte[] encryptedFile = CryptoUtils.encryptAES(fileData, aesKey);
        CryptoUtils.saveToFile("client_files/archivo_cifrado_client.bin", encryptedFile);

        dos.writeInt(encryptedFile.length);
        dos.write(encryptedFile);
        dos.flush();

        byte[] fileHash = CryptoUtils.sha256(fileData);
        CryptoUtils.saveToFile("client_files/hash_cliente.hex", fileHash);
        dos.writeInt(fileHash.length);
        dos.write(fileHash);
        dos.flush();

        dis.close();
        dos.close();
        socket.close();
    }
}