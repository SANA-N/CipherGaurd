import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.Base64;

public class EncryptionApp extends JFrame {
    private JComboBox<String> encryptionMethodComboBox;
    private JTextArea inputTextArea, outputTextArea;
    private JButton encryptButton, decryptButton;

    public EncryptionApp() {
        setTitle("Encryption Decryption Tool");
        setSize(400, 300);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

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
            // Implement RSA encryption
            output = "RSA encryption not implemented yet!";
        } else {
            output = "Invalid encryption method!";
        }
        outputTextArea.setText(output);
    }

    private void decrypt() {
        // Implement decryption
        outputTextArea.setText("Decryption not implemented yet!");
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new EncryptionApp().setVisible(true);
        });
    }
}