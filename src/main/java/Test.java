import java.util.Map;

/**
 * @author heh
 * @date 2021/12/29
 */
public class Test {
    /**
     * 待加密的明文
     */
    public final static String DATA = "haha";

    public static void main(String[] args) throws Exception {
        /* Test DH */
        // 张三公钥
        byte[] publicKeyA;
        // 张三私钥
        byte[] privateKeyA;
        // 张三本地密钥
        byte[] secretKeyA;
        // 李四公钥
        byte[] publicKeyB;
        // 李四私钥
        byte[] privateKeyB;
        // 李四本地密钥
        byte[] secretKeyB;

        // 初始化密钥 并生成张三密钥对
        Map<String, Object> keyMap1 = DHUtil.initKey();
        publicKeyA = DHUtil.getPublicKey(keyMap1);
        privateKeyA = DHUtil.getPrivateKey(keyMap1);
        System.out.println("DH 张三公钥 : " + BytesToHex.fromBytesToHex(publicKeyA));
        System.out.println("DH 张三私钥 : " + BytesToHex.fromBytesToHex(privateKeyA));

        // 李四根据张三公钥产生李四密钥对
        Map<String, Object> keyMap2 = DHUtil.initKey(publicKeyA);
        publicKeyB = DHUtil.getPublicKey(keyMap2);
        privateKeyB = DHUtil.getPrivateKey(keyMap2);
        System.out.println("DH 李四公钥 : " + BytesToHex.fromBytesToHex(publicKeyB));
        System.out.println("DH 李四私钥 : " + BytesToHex.fromBytesToHex(privateKeyB));

        // 对于张三， 根据其私钥和李四发过来的公钥， 生成其本地密钥secretKeyA
        secretKeyA = DHUtil.getSecretKeyBytes(publicKeyB, privateKeyA);
        System.out.println("DH 张三 本地密钥 : " + BytesToHex.fromBytesToHex(secretKeyA));

        // 对于李四， 根据其私钥和张三发过来的公钥， 生成其本地密钥secretKeyB
        secretKeyB = DHUtil.getSecretKeyBytes(publicKeyA, privateKeyB);
        System.out.println("DH 李四 本地密钥 : " + BytesToHex.fromBytesToHex(secretKeyB));
        // ---------------------------
        // 测试数据加密和解密
        System.out.println("加密前的数据：【" + DATA.concat("】"));
        // 张三进行数据的加密
        // 用的是张三的私钥和李四的公钥
        byte[] encryptDH = DHUtil.encryptDH(DATA.getBytes(), publicKeyB, privateKeyA);
        System.out.println("加密后的数据 字节数组转16进制显示：" + BytesToHex.fromBytesToHex(encryptDH));
        // 李四进行数据的解密
        // 用的是李四的私钥和张三的公钥
        byte[] decryptDH = DHUtil.decryptDH(encryptDH, publicKeyA, privateKeyB);
        System.out.println("解密后数据:【" + new String(decryptDH).concat("】"));
    }
}

