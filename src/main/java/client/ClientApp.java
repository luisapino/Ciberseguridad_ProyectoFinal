package client;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;

import java.io.File;

public class ClientApp extends Application {
    private TextArea logArea;
    private ProgressBar progressBar;
    private Label statusLabel;
    private Label fileInfoLabel;
    private Button selectButton;
    private Button sendButton;
    private TextField fileField;
    private File selectedFile;

    @Override
    public void start(Stage stage) {
        stage.setTitle("🔐 Cliente - Transferencia Segura de Archivos");

        Label titleLabel = new Label("Cliente de Transferencia Segura");
        titleLabel.setFont(Font.font("Arial", FontWeight.BOLD, 18));
        titleLabel.setTextFill(Color.web("#251605"));

        VBox fileSection = createFileSelectionSection();

        VBox progressSection = createProgressSection();

        VBox logSection = createLogSection();

        VBox root = new VBox(15);
        root.setPadding(new Insets(20));
        root.setStyle("-fx-background-color: #D9DCE7;");

        root.getChildren().addAll(
                titleLabel,
                createSeparator(),
                fileSection,
                createSeparator(),
                progressSection,
                createSeparator(),
                logSection
        );

        Scene scene = new Scene(new ScrollPane(root), 485, 600);
        stage.setScene(scene);
        stage.show();
    }

    private VBox createFileSelectionSection() {
        VBox section = new VBox(10);
        section.setStyle("-fx-background-color: white; -fx-padding: 15; -fx-background-radius: 5;");

        Label sectionTitle = new Label("📁 Selección de Archivo");
        sectionTitle.setFont(Font.font("Arial", FontWeight.BOLD, 14));

        fileField = new TextField();
        fileField.setEditable(false);
        fileField.setPromptText("Ningún archivo seleccionado");

        fileInfoLabel = new Label("Información del archivo aparecerá aquí");
        fileInfoLabel.setTextFill(Color.GRAY);

        selectButton = new Button("🔍 Seleccionar Archivo");
        selectButton.setStyle("-fx-background-color: #8AEDC9; -fx-text-fill: white; -fx-font-weight: bold;");
        selectButton.setOnAction(e -> selectFile());

        sendButton = new Button("🚀 Enviar Archivo Seguro");
        sendButton.setStyle("-fx-background-color:rgb(22, 145, 245); -fx-text-fill: white; -fx-font-weight: bold;");
        sendButton.setDisable(true);
        sendButton.setOnAction(e -> sendFile());

        HBox buttonBox = new HBox(10, selectButton, sendButton);

        section.getChildren().addAll(sectionTitle, fileField, fileInfoLabel, buttonBox);
        return section;
    }

    private VBox createProgressSection() {
        VBox section = new VBox(10);
        section.setStyle("-fx-background-color: white; -fx-padding: 15; -fx-background-radius: 5;");

        Label sectionTitle = new Label("📊 Progreso de Transferencia");
        sectionTitle.setFont(Font.font("Arial", FontWeight.BOLD, 14));

        progressBar = new ProgressBar(0);
        progressBar.setPrefWidth(400);
        progressBar.setStyle("-fx-accent: #8AEDC9;");

        statusLabel = new Label("Esperando archivo...");
        statusLabel.setTextFill(Color.GRAY);

        section.getChildren().addAll(sectionTitle, progressBar, statusLabel);
        return section;
    }

    private VBox createLogSection() {
        VBox section = new VBox(10);
        section.setStyle("-fx-background-color: white; -fx-padding: 15; -fx-background-radius: 5;");

        Label sectionTitle = new Label("📋 Log de Operaciones Criptográficas");
        sectionTitle.setFont(Font.font("Arial", FontWeight.BOLD, 14));

        logArea = new TextArea();
        logArea.setEditable(false);
        logArea.setPrefRowCount(12);
        logArea.setStyle("-fx-font-family: 'Courier New'; -fx-font-size: 11px;");
        logArea.appendText("=== CLIENTE DE TRANSFERENCIA SEGURA ===\n");
        logArea.appendText("🔐 Protocolo: RSA + AES-256 + SHA-256\n");
        logArea.appendText("📡 Puerto: 5555\n");
        logArea.appendText("Esperando selección de archivo...\n\n");

        section.getChildren().addAll(sectionTitle, logArea);
        return section;
    }

    private Separator createSeparator() {
        Separator sep = new Separator();
        sep.setStyle("-fx-background-color: #AB2247;");
        return sep;
    }

    private void selectFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Seleccionar archivo para transferencia segura");
        selectedFile = fileChooser.showOpenDialog(null);

        if (selectedFile != null) {
            fileField.setText(selectedFile.getAbsolutePath());

            // Show file information
            long sizeBytes = selectedFile.length();
            String sizeInfo = formatFileSize(sizeBytes);
            fileInfoLabel.setText(String.format("📄 %s | 📏 %s | 📅 %s",
                    selectedFile.getName(),
                    sizeInfo,
                    new java.util.Date(selectedFile.lastModified()).toString()));
            fileInfoLabel.setTextFill(Color.DARKGREEN);

            sendButton.setDisable(false);
            logArea.appendText("✅ Archivo seleccionado: " + selectedFile.getName() + "\n");
            logArea.appendText("📏 Tamaño: " + sizeInfo + "\n\n");
        }
    }

    private String formatFileSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024));
    }

    private void sendFile() {
        if (selectedFile == null) return;

        sendButton.setDisable(true);
        selectButton.setDisable(true);

        new Thread(() -> {
            try {
                Platform.runLater(() -> {
                    statusLabel.setText("🔄 Iniciando transferencia segura...");
                    statusLabel.setTextFill(Color.BLUE);
                    progressBar.setProgress(0.1);
                    logArea.appendText("🚀 INICIANDO TRANSFERENCIA SEGURA\n");
                    logArea.appendText("=" + "=".repeat(40) + "\n");
                });

                ClientWithProgress.runClient(selectedFile.getAbsolutePath(), new ProgressCallback() {
                    @Override
                    public void onProgress(String message, double progress) {
                        Platform.runLater(() -> {
                            logArea.appendText(message + "\n");
                            progressBar.setProgress(progress);
                            if (progress < 1.0) {
                                statusLabel.setText("🔄 " + message);
                                statusLabel.setTextFill(Color.BLUE);
                            }
                        });
                    }

                    @Override
                    public void onComplete(boolean success, String message) {
                        Platform.runLater(() -> {
                            if (success) {
                                statusLabel.setText("✅ " + message);
                                statusLabel.setTextFill(Color.GREEN);
                                progressBar.setProgress(1.0);
                                logArea.appendText("\n🎉 " + message + "\n");
                                showAlert("Éxito", "Archivo transferido correctamente con verificación de integridad.");
                            } else {
                                statusLabel.setText("❌ " + message);
                                statusLabel.setTextFill(Color.RED);
                                logArea.appendText("\n❌ " + message + "\n");
                                showAlert("Error", message);
                            }

                            sendButton.setDisable(false);
                            selectButton.setDisable(false);
                        });
                    }
                });

            } catch (Exception ex) {
                Platform.runLater(() -> {
                    statusLabel.setText("❌ Error en transferencia");
                    statusLabel.setTextFill(Color.RED);
                    logArea.appendText("❌ ERROR: " + ex.getMessage() + "\n");
                    showAlert("Error", "Error al enviar archivo: " + ex.getMessage());
                    sendButton.setDisable(false);
                    selectButton.setDisable(false);
                });
            }
        }).start();
    }

    private void showAlert(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    public static void main(String[] args) {
        launch(args);
    }
}

interface ProgressCallback {
    void onProgress(String message, double progress);
    void onComplete(boolean success, String message);
}

class ClientWithProgress {
    public static void runClient(String filePath, ProgressCallback callback) throws Exception {
        File clientDir = new File("client_files");
        if (!clientDir.exists()) clientDir.mkdirs();

        callback.onProgress("📡 Conectando al servidor (localhost:5555)...", 0.1);
        Thread.sleep(500);

        java.net.Socket socket = new java.net.Socket("localhost", 5555);
        callback.onProgress("✅ Conectado al servidor", 0.2);

        java.io.DataOutputStream dos = new java.io.DataOutputStream(socket.getOutputStream());
        java.io.DataInputStream dis = new java.io.DataInputStream(socket.getInputStream());

        callback.onProgress("📥 Recibiendo clave pública RSA del servidor...", 0.3);
        int pubKeyLen = dis.readInt();
        byte[] publicKeyBytes = dis.readNBytes(pubKeyLen);
        java.security.PublicKey publicKey = java.security.KeyFactory.getInstance("RSA")
                .generatePublic(new java.security.spec.X509EncodedKeySpec(publicKeyBytes));
        crypto.CryptoUtils.saveKey("client_files/public_key_recibida.pem", publicKey);
        callback.onProgress("🔑 Clave pública RSA recibida y guardada (2048 bits)", 0.4);

        callback.onProgress("🔐 Generando clave AES-256...", 0.5);
        javax.crypto.SecretKey aesKey = crypto.CryptoUtils.generateAESKey();
        byte[] aesBytes = aesKey.getEncoded();
        crypto.CryptoUtils.saveToFile("client_files/aes_key.hex", aesBytes);
        callback.onProgress("🔑 Clave AES-256 generada", 0.55);

        callback.onProgress("🔒 Cifrando clave AES con RSA...", 0.6);
        byte[] encryptedAES = crypto.CryptoUtils.encryptRSA(aesBytes, publicKey);
        dos.writeInt(encryptedAES.length);
        dos.write(encryptedAES);
        dos.flush();
        callback.onProgress("📤 Clave AES enviada cifrada al servidor", 0.65);

        callback.onProgress("📖 Leyendo archivo...", 0.7);
        byte[] fileData = java.nio.file.Files.readAllBytes(new File(filePath).toPath());
        crypto.CryptoUtils.saveToFile("client_files/archivo_original.txt", fileData);
        callback.onProgress("🔐 Cifrando archivo con AES-256...", 0.75);

        byte[] encryptedFile = crypto.CryptoUtils.encryptAES(fileData, aesKey);
        crypto.CryptoUtils.saveToFile("client_files/archivo_cifrado_client.bin", encryptedFile);
        callback.onProgress("📤 Enviando archivo cifrado...", 0.8);

        dos.writeInt(encryptedFile.length);
        dos.write(encryptedFile);
        dos.flush();
        callback.onProgress("✅ Archivo cifrado enviado", 0.85);

        callback.onProgress("🧮 Calculando hash SHA-256 para verificación...", 0.9);
        byte[] fileHash = crypto.CryptoUtils.sha256(fileData);
        crypto.CryptoUtils.saveToFile("client_files/hash_cliente.hex", fileHash);

        dos.writeInt(fileHash.length);
        dos.write(fileHash);
        dos.flush();
        callback.onProgress("📤 Hash SHA-256 enviado para verificación", 0.95);

        dis.close();
        dos.close();
        socket.close();

        callback.onComplete(true, "Transferencia completada exitosamente");
    }
}