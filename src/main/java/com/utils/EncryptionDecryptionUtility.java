package com.utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public final class EncryptionDecryptionUtility {

    public static String encrypt(String input, String secretKey) {
        try {
            if(input == null) return null;
            IvParameterSpec iv = new IvParameterSpec("RandomIn".getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(secretKey.getBytes("UTF-8"), "Blowfish");
            Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            byte[] cipherText = cipher.doFinal(input.getBytes());
            return Base64.getEncoder()
                    .encodeToString(cipherText);
        }
        catch (Exception var7) {
            System.out.println("Crypto Service : Encrpytion error : " + var7);
            return null;
        }
    }

    public static String decrypt(String input,String secretKey) {
        try {
            IvParameterSpec iv = new IvParameterSpec("RandomIn".getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(secretKey.getBytes("UTF-8"), "Blowfish");
            Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5PADDING");
            cipher.init(2, skeySpec, iv);
            byte[] original = cipher.doFinal(Base64.getDecoder().decode(input));
            return new String(original);
        }
        catch (Exception var7) {
            System.out.println("Crypto Service : Decrpytion error : " + var7);
            return null;
        }
    }
}
