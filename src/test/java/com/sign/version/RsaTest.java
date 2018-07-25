package com.sign.version;

import org.junit.Test;

/**
 *
 */
public class RsaTest {

    public final static String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCGcljLtTSxWqo5x8/FBnDxEEBBCkW1SdLwsNinM10MlCCcD2foBfia2GKCE3F40D5UdCgW8JBW9f+uvEKq+Mp5QXEHvKvrVwl3dyDlBJcyomyRIqQLfBissouTagDQ5WWdEP27Ebi09+mo13rYaFIo/gQehQh8/U2XMPAtIDSNiwIDAQAB";

    final static String privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAIZyWMu1NLFaqjnHz8UGcPEQQEEKRbVJ0vCw2KczXQyUIJwPZ+gF+JrYYoITcXjQPlR0KBbwkFb1/668Qqr4ynlBcQe8q+tXCXd3IOUElzKibJEipAt8GKyyi5NqANDlZZ0Q/bsRuLT36ajXethoUij+BB6FCHz9TZcw8C0gNI2LAgMBAAECgYAdLQdT/ZjXvAMg0tmlugYcahhnhOEnvEOIc/gwIJdauXJyK22zDkiq4bZO4AVJ4HcGQMbKY54PIQdBVh1pmN/nKc0wCDpvh6jLA4Vzre4XqkwpSfXN5JAjfUucwTW/jVAR0vsW/cLnQYVxIvYA6b/omAUQlwh2WT7ILT8++GqL4QJBAOjtvXpLfBN3i1hp/ctMrs312mtud3zXzs3d8OAWqWkprr6fscR61N4ksLAHsIxuQpzNWnoL8AVMU1vI362RT3MCQQCTw3IxxaL1g9WBhxKmzxOJg4BaRaxKdT8kF2dWyOl5JRYMJlgOPhvtC0132sSAeFL1bzQlm6X1W0bbLQ8HZpOJAkEAlhpGhV3Jil36LTK4e19iMpWheKPKWmhT+7RvemkAKSXUV0Ff9GbXcIQiXH3IFucjBBsNmCLDPRbPjRFom1hN4wJAITBE9ejuMTbrPayZA95/BOQEcEI18INlKzYWf+egiRVLXm8+V/SbUSK4w7Lfb/uWponTrJ7JJ9LYl2IHfiIMAQJBAL2LU44y0N7jIK7gNx2RGlXRsfVCDrnzKubao04VFeD9LWKjoby84PxktPxQ32zrnxxT6U+UvYhzAlblvhpadEw=";

    public static void main(String[] args) throws Exception {

//        String m = System.getProperty("user.dir");
//        String path = m + "\\src\\main\\resources";
//        GenerateKeyByRSA.genKeyPair(path);

//        test();

//        test2();
//
//        test3();
//
//        test4();


    }

    @Test
    public void test() throws Exception {
        System.out.println("--------------公钥加密私钥解密过程-------------------");
//        String plainText = "{\"userid\": \"123\",\"mobileno\": \"18567232758\"}";
        String plainText = "{\"userId\": \"2\",\"walletAddress\": \"ystjkelwriofjdsjiowrjewo\"}";

        //公钥加密过程
        byte[] cipherData = RSA.encryptByPub(RSA.loadPublicKeyByStr(publicKey), plainText.getBytes());
        String cipher = Base64.encode(cipherData);
        //私钥解密过程
        byte[] res = RSA.decryptByPri(RSA.loadPrivateKeyByStr(privateKey), Base64.decode(cipher));
        String restr = new String(res);
        System.out.println("原文：" + plainText);
        System.out.println("加密：" + cipher);
        System.out.println("解密：" + restr);
    }


    @Test
    public void test2() throws Exception {
        System.out.println("--------------私钥加密公钥解密过程-------------------");

        String plainText = "helloworld_私钥加密公钥解密";
        //私钥加密过程
        byte[] cipherData = RSA.encryptByPri(RSA.loadPrivateKeyByStr(privateKey), plainText.getBytes());
        String cipher = Base64.encode(cipherData);
        //公钥解密过程
        byte[] res = RSA.decryptByPub(RSA.loadPublicKeyByStr(publicKey), Base64.decode(cipher));
        String restr = new String(res);
        System.out.println("原文：" + plainText);
        System.out.println("加密：" + cipher);
        System.out.println("解密：" + restr);
        System.out.println();
    }

    @Test
    public void test3() {
        System.out.println("---------------私钥签名过程------------------");
//        String content = "helloworld_这是用于签名的原始数据";
        String content = "{\"userid\": \"123\",\"mobileno\": \"18567232758\"}";
        String signstr = RSASignature.sign(content, privateKey, "UTF-8");
        System.out.println("签名原串：" + content);
        System.out.println("签名串：" + signstr);
    }

    @Test
    public void test4() throws Exception {
        System.out.println("---------------公钥校验签名------------------");
//        String content = "helloworld_这是用于签名的原始数据";
        String content = "{\"userid\": \"123\",\"mobileno\": \"18567232758\"}";
        System.out.println("签名原串：" + content);
        String signstr = RSASignature.sign(content, privateKey, "UTF-8");

        System.out.println("签名串：" + signstr);

        System.out.println("验签结果：" + RSASignature.doCheck(content, signstr, publicKey, "UTF-8"));
    }


    @Test
    public void test5() {
        String filePath = new StringBuilder(System.getProperty("user.dir")).append("/src/main/resources/").toString();
        GenerateKeyByRSA.genKeyPair(filePath);
    }

}
