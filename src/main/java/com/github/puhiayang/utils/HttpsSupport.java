package com.github.puhiayang.utils;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * https支持工具类
 *
 * @author puhaiyang
 * created on 2019/10/25 22:27
 */
public class HttpsSupport {
    /**
     * 证书
     */
    private SslContext clientSslCtx;
    /**
     * 证书使用者
     */
    private String issuer;
    /**
     * 证书开始时间
     */
    private Date caNotBefore;
    /**
     * 证书结束时间
     */
    private Date caNotAfter;
    /**
     * ca私钥
     */
    private PrivateKey caPriKey;
    /**
     * 服务端私钥
     */
    private PrivateKey serverPriKey;
    /**
     * 服务端公钥
     */
    private PublicKey serverPubKey;

    /**
     * 证书cahce
     */
    private Map<String, X509Certificate> certCache = new HashMap<>();
    /**
     *
     */
    private KeyFactory keyFactory = null;

    private static Logger logger = LoggerFactory.getLogger(HttpsSupport.class);

    private HttpsSupport() {
        initHttpsConfig();
    }

    private static HttpsSupport httpsSupport;

    public static HttpsSupport getInstance() {
        logger.debug("进入证书方法getInstance第1个");
        if (httpsSupport == null) {
            httpsSupport = new HttpsSupport();
        }
        return httpsSupport;
    }

    private void initHttpsConfig() {
        logger.debug("进入证书方法initHttpsConfig第2个");
        try {
            keyFactory = KeyFactory.getInstance("RSA");
            //信任客户端的所有证书,不进行校验
            setClientSslCtx(SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build());
            //加载证书
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            //从项目目录加入ca根证书
            X509Certificate caCert = loadCert(classLoader.getResourceAsStream("ca.crt"));
            //从项目目录加入ca私钥
            //PrivateKey caPriKey = loadPriKey(classLoader.getResourceAsStream("ca_private.der"));
            PrivateKey caPriKey = getPrivateKey();
            setCaPriKey(caPriKey);
            //从证书中获取使用者信息
            setIssuer(getSubjectByCert(caCert));
            //设置ca证书有效期
            setCaNotBefore(caCert.getNotBefore());
            setCaNotAfter(caCert.getNotAfter());
            //生产一对随机公私钥用于网站SSL证书动态创建
            KeyPair keyPair = genKeyPair();
            //server端私钥
            setServerPriKey(keyPair.getPrivate());
            //server端公钥
            setServerPubKey(keyPair.getPublic());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成RSA公私密钥对,长度为2048
     */
    private KeyPair genKeyPair() throws Exception {
        logger.debug("进入证书方法genKeyPair第3个");
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyPairGenerator caKeyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
        caKeyPairGen.initialize(2048, new SecureRandom());
        return caKeyPairGen.genKeyPair();
    }

    /**
     * 获取证书中的subject信息
     */
    private String getSubjectByCert(X509Certificate certificate) {
        logger.debug("进入证书方法getSubjectByCert第4个");
        //读出来顺序是反的需要反转下
        List<String> tempList = Arrays.asList(certificate.getIssuerDN().toString().split(", "));
        return IntStream.rangeClosed(0, tempList.size() - 1)
                .mapToObj(i -> tempList.get(tempList.size() - i - 1)).collect(Collectors.joining(", "));
    }

    /**
     * 加载ca的私钥
     *
     * @param inputStream ca私钥文件流
     */
    private PrivateKey loadPriKey(InputStream inputStream) throws Exception {
        logger.debug("进入证书方法loadPriKey第5个");
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] bts = new byte[1024];
        int len;
        while ((len = inputStream.read(bts)) != -1) {
            outputStream.write(bts, 0, len);
        }
        inputStream.close();
        outputStream.close();
        return loadPriKey(outputStream.toByteArray());
    }

    /**
     * 从文件加载RSA私钥 openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in ca.key -out
     * ca_private.der
     */
    private PrivateKey loadPriKey(byte[] bts)
            throws Exception {
        logger.debug("进入证书方法loadPriKey第6个");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bts);
        return keyFactory.generatePrivate(privateKeySpec);
    }

    /**
     * 加载ca根证书
     *
     * @param inputStream 证书文件流
     */
    private X509Certificate loadCert(InputStream inputStream) throws Exception {
        logger.debug("进入证书方法loadCert第7个");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(inputStream);
    }

    public SslContext getClientSslCtx() {
        return clientSslCtx;
    }

    public void setClientSslCtx(SslContext clientSslCtx) {
        this.clientSslCtx = clientSslCtx;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public Date getCaNotBefore() {
        return caNotBefore;
    }

    public void setCaNotBefore(Date caNotBefore) {
        this.caNotBefore = caNotBefore;
    }

    public Date getCaNotAfter() {
        return caNotAfter;
    }

    public void setCaNotAfter(Date caNotAfter) {
        this.caNotAfter = caNotAfter;
    }

    public PrivateKey getCaPriKey() {
        return caPriKey;
    }

    public void setCaPriKey(PrivateKey caPriKey) {
        this.caPriKey = caPriKey;
    }

    public PrivateKey getServerPriKey() {
        return serverPriKey;
    }

    public void setServerPriKey(PrivateKey serverPriKey) {
        this.serverPriKey = serverPriKey;
    }

    public PublicKey getServerPubKey() {
        return serverPubKey;
    }

    public void setServerPubKey(PublicKey serverPubKey) {
        this.serverPubKey = serverPubKey;
    }


    /**
     * 获取证书
     *
     * @param host host
     * @return host对应的证书
     */
    public X509Certificate getCert(String host) throws Exception {
        logger.debug("进入证书方法getCert第8个");
        if (StringUtils.isBlank(host)) {
            return null;
        }
        X509Certificate cacheCert = certCache.get(host);
        if (cacheCert != null) {
            //将缓存的证书返回
            return cacheCert;
        }
        //生成新的证书，并将它放到缓存中去
        host = host.trim().toLowerCase();
        String hostLowerCase = host.trim().toLowerCase();
        X509Certificate cert = genCert(getIssuer(), getCaPriKey(), getCaNotBefore(), getCaNotAfter(), getServerPubKey(), hostLowerCase);
        //添加到缓存
        certCache.put(host, cert);
        return certCache.get(host);
    }

    /**
     * 动态生成服务器证书,并进行CA签授
     *
     * @param issuer 颁发机构
     */
    /**
     * @param issuer        颁发机构
     * @param caPriKey      ca私钥
     * @param certStartTime 证书开始时间
     * @param certEndTime   证书结束时间
     * @param serverPubKey  server证书的公钥
     * @param hosts         host，支持同时生成多个host
     * @return 证书
     * @throws Exception Exception
     */
    public static X509Certificate genCert(String issuer, PrivateKey caPriKey, Date certStartTime,
                                          Date certEndTime, PublicKey serverPubKey,
                                          String... hosts) throws Exception {
        logger.debug("进入证书方法genCert第9个");
        //根据CA证书subject来动态生成目标服务器证书的issuer和subject
        String subject = "C=CN, ST=SC, L=CD, O=hai, OU=study, CN=" + hosts[0];
        JcaX509v3CertificateBuilder jv3Builder = new JcaX509v3CertificateBuilder(new X500Name(issuer),
                //序列号，需要唯一;ElementaryOS上证书不安全问题(serialNumber为1时证书会提示不安全)，避免serialNumber冲突，采用时间戳+4位随机数生成
                BigInteger.valueOf(System.currentTimeMillis() + (long) (Math.random() * 10000) + 1000),
                certStartTime,
                certEndTime,
                new X500Name(subject),
                serverPubKey);
        //SAN扩展证书支持的域名，否则浏览器提示证书不安全
        GeneralName[] generalNames = new GeneralName[hosts.length];
        for (int i = 0; i < hosts.length; i++) {
            generalNames[i] = new GeneralName(GeneralName.dNSName, hosts[i]);
        }
        GeneralNames subjectAltName = new GeneralNames(generalNames);
        //添加多域名支持
        jv3Builder.addExtension(Extension.subjectAlternativeName, false, subjectAltName);
        //SHA256 用SHA1浏览器可能会提示证书不安全
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(caPriKey);
        return new JcaX509CertificateConverter().getCertificate(jv3Builder.build(signer));
    }

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        String ss = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "Proc-Type: 4,ENCRYPTED\n" +
                "DEK-Info: DES-EDE3-CBC,21A39AFB00E0058C\n" +
                "\n" +
                "ztzsjlb0LR9r5kxejXqfcx0C8IQjBUfRxBnTbAtFzjYsfSfBhYR4VS7TxsjQ6gnU\n" +
                "iwPz0qeJO3PDmHY9C3qDAv3VDfMuvh+HLS6gCMtYNGICkstA/8JjImzhnE/DWf8l\n" +
                "ecPfgPfQVSLD6BhHN2daPQucIJ5eWoty76S+bSULb2HPsYSfW9qfsHlIEE+/XsPW\n" +
                "CssG/8Adh2SvZrg7qeIaD4WP0piC/277C+qZwbvGvvBBv4llOmAWfLci0OmW3v1f\n" +
                "jYwmvedGZAj0kbZJevjstD544Qz72q3TPep8+8ZzSKl1QixTquaoYLJCNATCJjXE\n" +
                "/J0qMuV4PTTpG7PYJhgSU6qDi2nzGeJOyXLHjlpBXd1lrkNCY+GQOesBbH5PQtxQ\n" +
                "kyCFFyomxsTjScrt8FoocBOi6jbKjW7gRr8IuHuK4WhGqT59cgQnbq+CoxJBDUCq\n" +
                "NQn0NHoz55h3wiwxLcZ6vkwBOYjQ9OsWAM5B6kr3bepytxdmDdHjxw48+M3b+DPs\n" +
                "H3zY4CtS2QUi1Icch+QVh6/QCvFJiJy4ns7Ju3fdQtCm3VW0MfntieN8H+GQA9Qp\n" +
                "+PcO7v/fDEMuelZY+rA5yeMFGiM5/4NHf7qhfZEcNGagzCvZLVkttCU9znOgFAtp\n" +
                "wcL1nOEIWaX2parO58J2f4B1yXHL9rWpo7XN6fFVbpEwIY3yDs+pLKBwzvjA04fu\n" +
                "bOQhQkH991JpPGHi55fCf0KyA5ikTqijM1ZRUUmYb1VvZ//XxJ28A2Rc1od2JZ5E\n" +
                "Ql8mhwS09iFGoE7ApzeZP2P1wn7lAfeuAeqDh/dvIk4HCTJDlwLvwBFccOXVe1sl\n" +
                "7B4vqYJArl1sdV6rVbhb6kWwmAl9ES+AtRFblGykeZptvaVOzjnDp8FL0XQt2/No\n" +
                "cAff50/oup4YXt4fR/mnNd5ub8NfypgBcW0BX+1Si2c32vyeqJ6Mm/aXyJynN6if\n" +
                "34tUcROA41V8g68mPSx1FAjasENoz6J6+nTHnukJjL5m0X2rtzWbi+CrQBEY3Ec4\n" +
                "Le5a/PGnJypCPsaqfgGGcsawRClQ1TFptRuBklKsW497JkHY4zvaumK1DfTlWNS1\n" +
                "76KhwKVF3Rx4TpInFbDWeVA1NDcOA+PNc30KoWuOP2jD+zDA5tIfYn9MZZDN31gh\n" +
                "YmC7cxWzXppZZ+M69k0I3VgqRvZuLx59cGZ5hYy/Ih8TXsHOdN6S1SWtSn9n79d5\n" +
                "wNdyWsaKXujo2yfdfmOCv+1KLbdCBOSW92MtUjuaPXYfR9WMZtKetYO6PvhOTxTP\n" +
                "rDIlbjnrxUdveZ4VR0tVOqgDQwM7ynZ7AnXfl6a/8EGUhsmahBGhsvLmVVB/psDj\n" +
                "H8WQazAVmur8q/+Y1127Q163R+edrfH9Ug8Qp1VaDdgRMzeR+hbeSWOtZYExGE6U\n" +
                "siJ2Jr/vFrr6QkZt9iAhXEwJVG3W+RKTpAMgnBA/hqcAo6d2ev+5+Me4thjU0BEC\n" +
                "2IRs1wvLIlJ3wYjFlUwsph4KMh3zvIx5MmK1os37mmyge2sl8/9fcGMZksVQ1PRb\n" +
                "lG6bBhq0XMAAqiWlXjxBhtPfqPoNdimfqNJhBGKwFPuljoieG/mS4A==\n" +
                "-----END RSA PRIVATE KEY-----";
        getPrivateKey();
    }
    public static PrivateKey getPrivateKey(String base64PrivateKey) {
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public static PrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        String ss = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "Proc-Type: 4,ENCRYPTED\n" +
                "DEK-Info: DES-EDE3-CBC,21A39AFB00E0058C\n" +
                "\n" +
                "ztzsjlb0LR9r5kxejXqfcx0C8IQjBUfRxBnTbAtFzjYsfSfBhYR4VS7TxsjQ6gnU\n" +
                "iwPz0qeJO3PDmHY9C3qDAv3VDfMuvh+HLS6gCMtYNGICkstA/8JjImzhnE/DWf8l\n" +
                "ecPfgPfQVSLD6BhHN2daPQucIJ5eWoty76S+bSULb2HPsYSfW9qfsHlIEE+/XsPW\n" +
                "CssG/8Adh2SvZrg7qeIaD4WP0piC/277C+qZwbvGvvBBv4llOmAWfLci0OmW3v1f\n" +
                "jYwmvedGZAj0kbZJevjstD544Qz72q3TPep8+8ZzSKl1QixTquaoYLJCNATCJjXE\n" +
                "/J0qMuV4PTTpG7PYJhgSU6qDi2nzGeJOyXLHjlpBXd1lrkNCY+GQOesBbH5PQtxQ\n" +
                "kyCFFyomxsTjScrt8FoocBOi6jbKjW7gRr8IuHuK4WhGqT59cgQnbq+CoxJBDUCq\n" +
                "NQn0NHoz55h3wiwxLcZ6vkwBOYjQ9OsWAM5B6kr3bepytxdmDdHjxw48+M3b+DPs\n" +
                "H3zY4CtS2QUi1Icch+QVh6/QCvFJiJy4ns7Ju3fdQtCm3VW0MfntieN8H+GQA9Qp\n" +
                "+PcO7v/fDEMuelZY+rA5yeMFGiM5/4NHf7qhfZEcNGagzCvZLVkttCU9znOgFAtp\n" +
                "wcL1nOEIWaX2parO58J2f4B1yXHL9rWpo7XN6fFVbpEwIY3yDs+pLKBwzvjA04fu\n" +
                "bOQhQkH991JpPGHi55fCf0KyA5ikTqijM1ZRUUmYb1VvZ//XxJ28A2Rc1od2JZ5E\n" +
                "Ql8mhwS09iFGoE7ApzeZP2P1wn7lAfeuAeqDh/dvIk4HCTJDlwLvwBFccOXVe1sl\n" +
                "7B4vqYJArl1sdV6rVbhb6kWwmAl9ES+AtRFblGykeZptvaVOzjnDp8FL0XQt2/No\n" +
                "cAff50/oup4YXt4fR/mnNd5ub8NfypgBcW0BX+1Si2c32vyeqJ6Mm/aXyJynN6if\n" +
                "34tUcROA41V8g68mPSx1FAjasENoz6J6+nTHnukJjL5m0X2rtzWbi+CrQBEY3Ec4\n" +
                "Le5a/PGnJypCPsaqfgGGcsawRClQ1TFptRuBklKsW497JkHY4zvaumK1DfTlWNS1\n" +
                "76KhwKVF3Rx4TpInFbDWeVA1NDcOA+PNc30KoWuOP2jD+zDA5tIfYn9MZZDN31gh\n" +
                "YmC7cxWzXppZZ+M69k0I3VgqRvZuLx59cGZ5hYy/Ih8TXsHOdN6S1SWtSn9n79d5\n" +
                "wNdyWsaKXujo2yfdfmOCv+1KLbdCBOSW92MtUjuaPXYfR9WMZtKetYO6PvhOTxTP\n" +
                "rDIlbjnrxUdveZ4VR0tVOqgDQwM7ynZ7AnXfl6a/8EGUhsmahBGhsvLmVVB/psDj\n" +
                "H8WQazAVmur8q/+Y1127Q163R+edrfH9Ug8Qp1VaDdgRMzeR+hbeSWOtZYExGE6U\n" +
                "siJ2Jr/vFrr6QkZt9iAhXEwJVG3W+RKTpAMgnBA/hqcAo6d2ev+5+Me4thjU0BEC\n" +
                "2IRs1wvLIlJ3wYjFlUwsph4KMh3zvIx5MmK1os37mmyge2sl8/9fcGMZksVQ1PRb\n" +
                "lG6bBhq0XMAAqiWlXjxBhtPfqPoNdimfqNJhBGKwFPuljoieG/mS4A==\n" +
                "-----END RSA PRIVATE KEY-----";
        // reads your key file
        Reader privateKeyReader = new StringReader(ss);
        PEMParser privatePemParser = new PEMParser(privateKeyReader);
        PEMParser pemParser = new PEMParser(new FileReader("E:\\nettycode\\easyHttpProxy\\src\\main\\resources\\ca.key"));

        Object object = privatePemParser.readObject();

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

        KeyPair kp = null;

        if (object instanceof PEMEncryptedKeyPair) {

// Encrypted key - we will use provided password

            PEMEncryptedKeyPair ckp = (PEMEncryptedKeyPair) object;

// uses the password to decrypt the key
//
            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build("snetty".toCharArray());

            kp = converter.getKeyPair(ckp.decryptKeyPair(decProv));

        } else {

// Unencrypted key - no password needed

            PEMKeyPair ukp = (PEMKeyPair) object;

            kp = converter.getKeyPair(ukp);

        }

// RSA

        KeyFactory keyFac = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kp.getPrivate();

        System.out.println(privateKey);

        return privateKey;

    }
}
