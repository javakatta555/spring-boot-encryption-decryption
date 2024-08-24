package com.utils;

import com.constant.CryptoConstant;
import com.model.EncryptionRequest;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionUtil {

    public static String[] encrypt(String jsonRequest) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

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

        // Generate base64 encoded array of EncryptedMessage, EncryptedKey, IV
        String[] encodeMessageKeyIV = new String[3];
        encodeMessageKeyIV[0] = Base64.getEncoder().encodeToString(encryptedJSONRequest);
        encodeMessageKeyIV[1] = Base64.getEncoder().encodeToString(aesKey.getEncoded());
        encodeMessageKeyIV[2] = Base64.getEncoder().encodeToString(iv);
        return encodeMessageKeyIV;
    }

    public static String decrypt(EncryptionRequest encryptionRequest) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {

        // Base64 Decode Message, Key, IV
        byte[] decodedEncryptedMessage = Base64.getDecoder().decode(encryptionRequest.getEncodedEncryptedMessage());
        byte[] decodedEncryptedKey = Base64.getDecoder().decode(encryptionRequest.getEncodedEncryptedKey());
        byte[] decodedIV = Base64.getDecoder().decode(encryptionRequest.getEncodeEncryptedIV());

        // Convert the byte array to a SecretKey
        SecretKey aesKey = new SecretKeySpec(decodedEncryptedKey, CryptoConstant.AES_ALGORITHM);

        // Decrypt Message with "AES/GCM/NoPadding" algorithm
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, decodedIV);
        Cipher aesCipher = Cipher.getInstance(CryptoConstant.AES_GCM_NO_PADDING_ALGORITHM);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, parameterSpec);
        byte[] decryptedMessageBytes = aesCipher.doFinal(decodedEncryptedMessage);

        // Return Decrypted String
        return new String(decryptedMessageBytes, StandardCharsets.UTF_8);
    }
}
