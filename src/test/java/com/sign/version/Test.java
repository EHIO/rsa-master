package com.sign.version;

/**
 *
 */
public class Test {

    public final static String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDTeNQ0SIDrt2/1jSjvO+4m7LL5flZjnw5k+WHS\n" +
            "Y2xMepNqJshdl2GJ/TahcVdRnNk+xE+SDqCuM4VXgEaM8URMucFyz8KD6840W34xD1HZeEjhg5hf\n" +
            "xXxYAae7qJhvvxt4VhGI11DEF08XCXZoFkQs92osWItcue4IcMnXLvlE8wIDAQAB";

    final static String privateKey = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANN41DRIgOu3b/WNKO877ibssvl+\n" +
            "VmOfDmT5YdJjbEx6k2omyF2XYYn9NqFxV1Gc2T7ET5IOoK4zhVeARozxREy5wXLPwoPrzjRbfjEP\n" +
            "Udl4SOGDmF/FfFgBp7uomG+/G3hWEYjXUMQXTxcJdmgWRCz3aixYi1y57ghwydcu+UTzAgMBAAEC\n" +
            "gYEAkzynkxeAG56Gp1L3U0pI0HUxT6D1CTuvTAKOZ2ut9bnKdbg2/WLvGKJirRk7EKnCYH9SX4Er\n" +
            "wt5AUuIPPQam4/iTYC2pMhU4ECPhcaCTwoKH/hyloj2aHeF6GZOoGbIKoGDr9buKU57NbkOM/6J/\n" +
            "bc5La+gLfC7VUSvAGh/xFFECQQDyaj3UZ6MX0FawoJdLicSqPJwb+XZ6SNPmz8uw0k+IFfGybbZW\n" +
            "iV69LLNdNe6O4YOdU6Q7UEegv6NUS8qMMknXAkEA31KraRAsHdhtEXKO269g4SdpDJ9VLHobuJhj\n" +
            "gjdye/WuEj2H42Wt/Q2GK8SUmJHMRbFxgerdS8zxeeLhEM/SRQJBAMkpQIWyOrTYPhf0K5iTio96\n" +
            "HFFageaX6L/wT6c73qOfEiJuyJCnDecN4QnIZ15J5V34uqA9zjKm1HJvMnWEhaECQQDZh7A5xawD\n" +
            "YlZTQXBQIxPOHVJhHi6cBVFNTPrY02OrxVLKp67e3KNOs8a2iWRo/NOqKz6yWvE2LaolnM64Toa1\n" +
            "AkARewxgq+WjepPfVEYmS7XmyQmBemLAYq5BBQ9HCR9kMssj2+joC/t+XvrcGFvLJPGPAY+0P+/5\n" +
            "VO/A7lEhmd3j";

    public static void main(String[] args) throws Exception {

//        String m = System.getProperty("user.dir");
//        String path = m + "\\src\\main\\resources";
//        GenerateKeyByRSA.genKeyPair(path);

        test();

        test2();

        test3();

        test4();


    }

    private static void test() throws Exception {
        System.out.println("--------------公钥加密私钥解密过程-------------------");
        String plainText = "helloworld_公钥加密私钥解密";

        //公钥加密过程
        byte[] cipherData = RSA.encryptByPub(RSA.loadPublicKeyByStr(publicKey), plainText.getBytes());
        String cipher = Base64.encode(cipherData);
        //私钥解密过程
        byte[] res = RSA.decryptByPri(RSA.loadPrivateKeyByStr(privateKey), Base64.decode(cipher));
        String restr = new String(res);
        System.out.println("原文：" + plainText);
        System.out.println("加密：" + cipher);
        System.out.println("解密：" + restr);
        System.out.println();
    }

    public static void test2() throws Exception {
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

    public static void test3() {
        System.out.println("---------------私钥签名过程------------------");
        String content = "helloworld_这是用于签名的原始数据";
        String signstr = RSASignature.sign(content, privateKey, "UTF-8");
        System.out.println("签名原串：" + content);
        System.out.println("签名串：" + signstr);
    }

    public static void test4() throws Exception {
        System.out.println("---------------公钥校验签名------------------");
        String content = "helloworld_这是用于签名的原始数据";
        System.out.println("签名原串：" + content);
        String signstr = RSASignature.sign(content, privateKey, "UTF-8");

        System.out.println("签名串：" + signstr);

        System.out.println("验签结果：" + RSASignature.doCheck(content, signstr, publicKey, "UTF-8"));
    }

}
