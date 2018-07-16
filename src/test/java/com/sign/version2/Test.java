package com.sign.version2;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

public class Test {


    public static void main(String[] args) throws Exception {

        Map<String, Object> map = RSAUtils.initKey();
        String publicKey = RSAUtils.getPublicKey(map);
        String privateKey = RSAUtils.getPrivateKey(map);
        String data = "ABC";

        byte[] en = RSAUtils.encryptByPublicKey(data.getBytes(), publicKey);
        System.out.println("密文：" + RSAUtils.toHexString(en));
        byte[] de = RSAUtils.decryptByPrivateKey(en, privateKey);
        System.out.println("解密结果：" + new String(de));

        byte[] enc = RSAUtils.encryptByPrivateKey(data.getBytes(), privateKey);
        byte[] dec = RSAUtils.decryptByPublicKey(enc, publicKey);
        System.out.println("私钥加密：" + RSAUtils.toHexString(enc));
        System.out.println("公钥解密：" + new String(dec));
        byte[] md5 = MD5Utils.getMD5String(data);
        System.out.println("md5:" + md5);
        String sign = RSAUtils.sign(md5, privateKey);
        boolean flag = RSAUtils.verify(md5, publicKey, sign);
        System.out.println("sign签名：" + sign);
        System.out.println("校验签名：" + flag);

        // AES 加密解密
        // 1. 随机生成 key/iv
        SecretKey secretKey = AESUtil.getSecretKey();
        IvParameterSpec ivParameterSpec = AESUtil.getIv();
        // 2. AES 加密
        byte[] aes_en = AESUtil.encrypt(data, secretKey, ivParameterSpec);
        String aes_de = AESUtil.decrypt(Base64Utils.encode(aes_en), secretKey, ivParameterSpec);
        System.out.println("AES原文：" + data);
        System.out.println("AES密文(16进制)：" + RSAUtils.toHexString(aes_en));
        System.out.println("AES解密：" + aes_de);
        // 3. key/iv 二进制转十六进制
        String key = RSAUtils.toHexString(secretKey.getEncoded());
        String iv = RSAUtils.toHexString(ivParameterSpec.getIV());
//		System.out.println("AES key length:" + secretKey.getEncoded().length);
//		System.out.println("AES iv length:" + ivParameterSpec.getIV().length);
        System.out.println("AES key(16进制):" + key);
        // 4. RSA加密十六进制的key和iv
        System.out.println("AES key(RSA密文):" + RSAUtils.toHexString(RSAUtils.encryptByPublicKey(key.getBytes(), publicKey)));
//		System.out.println("AES byte key:" + new String(secretKey.getEncoded()));
        System.out.println("AES iv(16进制):" + iv);
        System.out.println("AES iv(RSA密文):" + RSAUtils.toHexString(RSAUtils.encryptByPublicKey(iv.getBytes(), publicKey)));
//		System.out.println("AES byte iv:" + new String(ivParameterSpec.getIV()));

    }


    @org.junit.Test
    public void test() throws IOException {
        InputStream in = Test.class.getResourceAsStream("/private_key.pem");

        BufferedReader bufr = new BufferedReader(new InputStreamReader(in));
        String line;
        while ((line = bufr.readLine()) != null) {
            System.out.println(line);
        }
    }
}
