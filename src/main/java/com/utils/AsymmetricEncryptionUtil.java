package com.utils;

import com.constant.CryptoConstant;
import com.model.EncryptionRequest;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;

public class AsymmetricEncryptionUtil {

    public static String[] encrypt(String jsonRequest,PublicKey publicKey) throws NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, CertificateException, IOException {
        byte[] jsonRequestBytes = jsonRequest.getBytes(StandardCharsets.UTF_8);

        // Generate AES Key 256
        KeyGenerator keyGen = KeyGenerator.getInstance(CryptoConstant.AES_ALGORITHM);
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        // Generate 12 bytes IV
        // NEVER REUSE THIS IV WITH SAME KEY
        byte[] iv = new byte[12];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);

        // Encrypt Message with AES Key with "AES/GCM/NoPadding" algorithm
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        Cipher aesCipher = Cipher.getInstance(CryptoConstant.AES_GCM_NO_PADDING_ALGORITHM);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, parameterSpec);
        byte[] encryptedJSONRequest = aesCipher.doFinal(jsonRequestBytes);

        /*// create PublicKey from X.509 certificate
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        byte[] certificateBytes = x509Cert.getBytes(StandardCharsets.UTF_8);
        PublicKey publicKey;
        try (InputStream in = new ByteArrayInputStream(certificateBytes)) {
            java.security.cert.Certificate cer = fact.generateCertificate(in);
            publicKey = cer.getPublicKey();
        }*/

        // Encrypt AES Key with "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" algorithm
        Cipher rsaCipher = Cipher.getInstance(CryptoConstant.RSA_ECB_ALGORITHM);
        rsaCipher.init(Cipher.WRAP_MODE, publicKey);
        byte[] encryptedKey = rsaCipher.wrap(aesKey);

        // Generate base64 encoded array of EncryptedMessage, EncryptedKey, IV
        String[] encodeMessageKeyIV = new String[3];
        encodeMessageKeyIV[0] = Base64.getEncoder().encodeToString(encryptedJSONRequest);
        encodeMessageKeyIV[1] = Base64.getEncoder().encodeToString(encryptedKey);
        encodeMessageKeyIV[2] = Base64.getEncoder().encodeToString(iv);
        return encodeMessageKeyIV;
    }

    public static String decrypt(EncryptionRequest encryptionRequest, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        // Base64 Decode Message, Key, IV
        byte[] decodedEncryptedMessage = Base64.getDecoder().decode(encryptionRequest.getEncodedEncryptedMessage());
        byte[] decodedEncryptedKey = Base64.getDecoder().decode(encryptionRequest.getEncodedEncryptedKey());
        byte[] decodedIV = Base64.getDecoder().decode(encryptionRequest.getEncodeEncryptedIV());

        // Decrypt AES Key with "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" algorithm
        Cipher rsaCipher = Cipher.getInstance(CryptoConstant.RSA_ECB_ALGORITHM);
        rsaCipher.init(Cipher.UNWRAP_MODE, privateKey);
        SecretKey aesKey = (SecretKey) rsaCipher.unwrap(decodedEncryptedKey, CryptoConstant.AES_ALGORITHM, Cipher.SECRET_KEY);

        // Decrypt Message with "AES/GCM/NoPadding" algorithm
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, decodedIV);
        Cipher aesCipher = Cipher.getInstance(CryptoConstant.AES_GCM_NO_PADDING_ALGORITHM);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, parameterSpec);
        byte[] decryptedMessageBytes = aesCipher.doFinal(decodedEncryptedMessage);

        // Return Decrypted String
        return new String(decryptedMessageBytes);
    }
}
