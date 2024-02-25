import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import java.awt.*;
import java.awt.event.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EncryptionApp extends JFrame {
    private JComboBox<String> encryptionMethodComboBox;
    private JTextArea inputTextArea, outputTextArea;
    private JButton encryptButton, decryptButton;

    public EncryptionApp() {
        setTitle("CipherGaurd");
        setSize(300, 200);
        setDefaultCloseOperation(EXIT_ON_CLOSE);

        String[] encryptionMethods = { "AES", "RSA" };
        encryptionMethodComboBox = new JComboBox<>(encryptionMethods);
        inputTextArea = new JTextArea(5, 20);
        outputTextArea = new JTextArea(5, 20);
        outputTextArea.setEditable(false);
        encryptButton = new JButton("Encrypt");
        decryptButton = new JButton("Decrypt");

        encryptButton.addActionListener(e -> encrypt());
        decryptButton.addActionListener(e -> decrypt());

        JPanel panel = new JPanel(new GridLayout(3, 2));
        panel.add(new JLabel("Encryption Method:"));
        panel.add(encryptionMethodComboBox);
        panel.add(new JLabel("Input:"));
        panel.add(new JScrollPane(inputTextArea));
        panel.add(new JLabel("Output:"));
        panel.add(new JScrollPane(outputTextArea));

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);

        add(panel, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void encrypt() {
        String method = (String) encryptionMethodComboBox.getSelectedItem();
        String input = inputTextArea.getText();
        String output;

        if (method.equals("AES")) {
            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                byte[] keyBytes = "1234567890123456".getBytes();
                SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
                IvParameterSpec ivParameterSpec = new IvParameterSpec(keyBytes);
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
                byte[] encrypted = cipher.doFinal(input.getBytes());
                output = Base64.getEncoder().encodeToString(encrypted);
            } catch (Exception e) {
                output = "Error: " + e.getMessage();
            }
        } else if (method.equals("RSA")) {
            try {
                KeyPair keyPair = generateRSAKeyPair();
                PublicKey publicKey = keyPair.getPublic();
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                byte[] encrypted = cipher.doFinal(input.getBytes());
                output = Base64.getEncoder().encodeToString(encrypted);
            } catch (Exception e) {
                output = "Error: " + e.getMessage();
            }
        } else {
            output = "Invalid encryption method!";
        }

        outputTextArea.setText(output);
    }

    private void decrypt() {
        String method = (String) encryptionMethodComboBox.getSelectedItem();
        String input = inputTextArea.getText();
        String output;

        if (method.equals("AES")) {
            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                byte[] keyBytes = "1234567890123456".getBytes();
                SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
                IvParameterSpec ivParameterSpec = new IvParameterSpec(keyBytes);
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
                byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(input));
                output = new String(decrypted);
            } catch (Exception e) {
                output = "Error: " + e.getMessage();
            }
        } else if (method.equals("RSA")) {
            try {
                KeyPair keyPair = generateRSAKeyPair();
                PrivateKey privateKey = keyPair.getPrivate();
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(input));
                output = new String(decrypted);
            } catch (Exception e) {
                output = "Error: " + e.getMessage();
            }
        } else {
            output = "Invalid encryption method!";
        }

        outputTextArea.setText(output);
    }

    private KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // You can adjust the key size
        return keyPairGenerator.genKeyPair();
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new EncryptionApp().setVisible(true);
        });
    }
}
