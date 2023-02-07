package com.controller;

import com.model.ProductEncryptRequest;
import com.utils.EncryptionDecryptionUtility;
import com.utils.JsonUtil;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ProductController {

    @GetMapping("/health")
    public String healthCheck(){
        ProductEncryptRequest productEncryptRequest = new ProductEncryptRequest("1","NoteBook");
        String encrypt = EncryptionDecryptionUtility.encrypt(JsonUtil.toJson(productEncryptRequest).toPrettyString(),"key");
        System.out.println("Encrypted product is"+encrypt);
        System.out.println("Decrypted String is"+ JsonUtil.fromJson(JsonUtil.parse(EncryptionDecryptionUtility.decrypt(encrypt,"key")), ProductEncryptRequest.class));

        return "I am Healthy !";
    }

}
