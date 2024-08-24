package com.controller;

import com.model.EncryptionRequest;
import com.model.ProductEncryptRequest;
import com.utils.AsymmetricEncryptionUtil;
import com.utils.JsonUtil;
import com.utils.SymmetricEncryptionUtil;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

@RestController
@RequestMapping("/api/v1")
public class EncryptionController {

    @GetMapping("/symmetric")
    public String symmetric() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        ProductEncryptRequest productEncryptRequest = ProductEncryptRequest.builder()
                .id("1")
                .productName("TextBook")
                .build();
        String[] encryptionArray = SymmetricEncryptionUtil.encrypt(JsonUtil.asJsonString(productEncryptRequest));
        EncryptionRequest encryptionRequest = EncryptionRequest.builder()
                .encodedEncryptedMessage(encryptionArray[0])
                .encodedEncryptedKey(encryptionArray[1])
                .encodeEncryptedIV(encryptionArray[2])
                .build();
        SymmetricEncryptionUtil.decrypt(encryptionRequest);
        return "SUCCESS";
    }

    @GetMapping("/asymmetric")
    public String asymmetric() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, UnrecoverableKeyException {
        ProductEncryptRequest productEncryptRequest = ProductEncryptRequest.builder()
                .id("1")
                .productName("TextBook")
                .build();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream("/Users/admin/Documents/POC/spring-boot-encryption-decryption/src/main/resources/security/keystore.p12")) {
            keyStore.load(fis, "Swap@123".toCharArray());
        }
        java.security.cert.Certificate cert = keyStore.getCertificate("1");
        X509Certificate x509Cert = (X509Certificate) cert;
        // Retrieve and print the public key
        PublicKey publicKey = x509Cert.getPublicKey();
        System.out.println("Public Key: " + publicKey);

        String[] encryptionArray = AsymmetricEncryptionUtil.encrypt(JsonUtil.asJsonString(productEncryptRequest),publicKey);
        EncryptionRequest encryptionRequest = EncryptionRequest.builder()
                .encodedEncryptedMessage(encryptionArray[0])
                .encodedEncryptedKey(encryptionArray[1])
                .encodeEncryptedIV(encryptionArray[2])
                .build();

        PrivateKey privateKey = (PrivateKey) keyStore.getKey("1", "Swap@123".toCharArray());
        String message = AsymmetricEncryptionUtil.decrypt(encryptionRequest,privateKey);
        return "SUCCESS";
    }

    @GetMapping("/alias")
    public String alias() throws KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream("/Users/admin/Documents/POC/spring-boot-encryption-decryption/src/main/resources/security/keystore.p12")) {
            keyStore.load(fis, "Swap@123".toCharArray());
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        // List all aliases
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Alias: " + alias);
        }
        return "SUCCESS";
    }



}
