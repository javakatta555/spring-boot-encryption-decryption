package com.controller;

import com.model.EncryptionRequest;
import com.model.ProductEncryptRequest;
import com.utils.JsonUtil;
import com.utils.SymmetricEncryptionUtil;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

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
        System.out.println(encryptionRequest);
        String product = SymmetricEncryptionUtil.decrypt(encryptionRequest);
        System.out.println(JsonUtil.parse(product));
        return "SUCCESS";
    }

    @GetMapping("/asymmetric")
    public String asymmetric(){

        return "SUCCESS";
    }

}
