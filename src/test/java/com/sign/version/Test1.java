package com.sign.version;

import com.sign.version2.Coder;
import sun.misc.BASE64Decoder;



public class Test1 {

    public static void main(String[] args) throws Exception {

        String key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCykSDJVdCUPb4keZXIR3p9koT2BrTza6KE7MCOeqwUn6QCNEwS3nIvAu08Qn6c1Lb0jDGnwK0IBlCLzARqnURxfi90scUOiBed6qv6cvfrOYUGwFEsEgFq/eh+leIg7e8P9thawmkvjXmrnn40N6qQR74k3qJLjvY9KlC5rTVx5QIDAQAB";
        System.out.println(new BASE64Decoder().decodeBuffer(key));
        System.out.println(Coder.decryptBASE64(key));
    }
}
