import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.*;
import java.util.Base64;

public class EncryptionApp extends JFrame {
    private JComboBox<String> encryptionMethodComboBox;
    private JTextArea inputTextArea, outputTextArea;
    private JButton encryptButton, decryptButton;
    private KeyPair rsaKeyPair;

    public EncryptionApp() {
        setTitle("CipherGuard");
        setSize(400, 300);
        setDefaultCloseOperation(EXIT_ON_CLOSE);

        String[] encryptionMethods = { "AES", "RSA" };
        encryptionMethodComboBox = new JComboBox<>(encryptionMethods);
        inputTextArea = new JTextArea(5, 20);
        outputTextArea = new JTextArea(5, 20);
        outputTextArea.setEditable(false);
        encryptButton = new JButton("Encrypt");
        decryptButton = new JButton("Decrypt");

        // Set fonts and colors
        Font labelFont = new Font("Arial", Font.BOLD, 14);
        Font textAreaFont = new Font("TimesNow", Font.PLAIN, 14);
        Color panelColor = new Color(240, 235, 171);
        Color buttonColor = new Color(0, 150, 0);
        Color comboBoxColor = new Color(199, 227, 141);
        Color buttonTextColor = Color.BLACK;

        encryptionMethodComboBox.setFont(textAreaFont);
        encryptionMethodComboBox.setBackground(comboBoxColor);

        inputTextArea.setFont(textAreaFont);
        outputTextArea.setFont(textAreaFont);

        encryptButton.setFont(labelFont);
        encryptButton.setBackground(buttonColor);
        encryptButton.setForeground(buttonTextColor);

        decryptButton.setFont(labelFont);
        decryptButton.setBackground(buttonColor);
        decryptButton.setForeground(buttonTextColor);

        encryptButton.addActionListener(e -> encrypt());
        decryptButton.addActionListener(e -> decrypt());

        JPanel panel = new JPanel(new GridLayout(3, 2));
        panel.setBackground(panelColor);
        panel.add(new JLabel("Encryption Method:")).setFont(labelFont);
        panel.add(encryptionMethodComboBox);
        panel.add(new JLabel("Input:")).setFont(labelFont);
        panel.add(new JScrollPane(inputTextArea));
        panel.add(new JLabel("Output:")).setFont(labelFont);
        panel.add(new JScrollPane(outputTextArea));

        JPanel buttonPanel = new JPanel();
        buttonPanel.setBackground(panelColor);
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);

        add(panel, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        // Generate RSA key pair once during application initialization
        try {
            rsaKeyPair = generateRSAKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
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
                PublicKey publicKey = rsaKeyPair.getPublic();
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
                PrivateKey privateKey = rsaKeyPair.getPrivate();
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
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                e.printStackTrace();
            }
            new EncryptionApp().setVisible(true);
        });
    }
}
