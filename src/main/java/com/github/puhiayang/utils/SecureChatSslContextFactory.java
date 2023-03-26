package com.github.puhiayang.utils;



import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public final class SecureChatSslContextFactory {

    private static final String PROTOCOL = "TLS";

    private static SSLContext SERVER_CONTEXT;//服务器安全套接字协议

    private static SSLContext CLIENT_CONTEXT;//客户端安全套接字协议

    //服务端使用
    public static SSLContext getServerContext(String pkPath){
        if(SERVER_CONTEXT!=null) return SERVER_CONTEXT;
        InputStream in =null;

        try{
            //密钥管理器
            KeyManagerFactory kmf = null;
            if(pkPath!=null){
                //密钥库KeyStore
                // KeyStore.getDefaultType()
                KeyStore ks = KeyStore.getInstance("JKS");
                //加载服务端证书
                in = new FileInputStream(pkPath);
                //加载服务端的KeyStore  ；sNetty是生成仓库时设置的密码，用于检查密钥库完整性的密码
                ks.load(in, "sNetty".toCharArray());

                kmf = KeyManagerFactory.getInstance("SunX509");
                //初始化密钥管理器
                kmf.init(ks, "sNetty".toCharArray());
            }
            //获取安全套接字协议（TLS协议）的对象
            SERVER_CONTEXT= SSLContext.getInstance(PROTOCOL);
            //初始化此上下文
            //参数一：认证的密钥（服务端的私钥）
            // 参数二：对等信任认证 （客户端的公约，已导入到sChat.jks证书仓库中了）
            // 参数三：伪随机数生成器 。 ，

            //1、客户端认证服务端的 单认证模式(服务端不用验证客户端，所以第二个参数为null)
            SERVER_CONTEXT.init(kmf.getKeyManagers(), null, null);

            //2、如果要服务端的单认证或双认证模式，使用如下代码,(服务端需要验证客户端，所以第二个参数不能为null))
            //SERVER_CONTEXT.init(kmf.getKeyManagers(),  tf.getTrustManagers(), null);

            //tf.getTrustManagers()的获取如下:
            /*
            TrustManagerFactory tf = null;
            if (pkPath!= null) {
                //密钥库KeyStore
                KeyStore tks = KeyStore.getInstance("JKS");
                //加载客户端证书
                tIN = new FileInputStream(pkPath);    //（客户端的公约，已导入到sChat.jks证书仓库中了）
                tks.load(tIN, "sNetty".toCharArray());
                tf = TrustManagerFactory.getInstance("SunX509");
                // 初始化信任库
                tf.init(tks);
            }
            */
            //SERVER_CONTEXT.init(参数1，参数2，参数3)
            //说明： 参数1 主要是https交换密钥的 加密的私钥信息，
            //       参数2 主要是验证信息，即用参数1的私钥加密后，用参数2的公钥解密，能解开 即验证成功了（秘钥验证成功了）
            //       参数3  生成的密钥随机数
        }catch(Exception e){
            throw new Error("Failed to initialize the server-side SSLContext", e);
        }finally{
            if(in !=null){
                try {
                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

        }
        return SERVER_CONTEXT;
    }

    //客户端使用
    public static SSLContext getClientContext(String caPath){
        if(CLIENT_CONTEXT!=null) return CLIENT_CONTEXT;

        InputStream tIN = null;
        try{
            //信任库
            TrustManagerFactory tf = null;
            if (caPath != null) {
                //密钥库KeyStore
                KeyStore tks = KeyStore.getInstance("JKS");
                //加载客户端证书
                tIN = new FileInputStream(caPath);
                tks.load(tIN, "sNetty".toCharArray());
                tf = TrustManagerFactory.getInstance("SunX509");
                // 初始化信任库
                tf.init(tks);
            }

            CLIENT_CONTEXT = SSLContext.getInstance(PROTOCOL);
            //1、设置信任证书，这个原理同服务端的介绍，下面的是单认证模式，为客户端的单认证模式，客户端认证服务端的证书是否正确，cChat.jks 中有服务端的公约了，即可以认证了
            CLIENT_CONTEXT.init(null, tf.getTrustManagers(), null);

            //2、如何需要服务端的单认证模式，即服务端认证客户端的证书的正确性（第一个参数不能为null），单客户端不需要认证服务端的正确性，那第二个参数就可以为null
            //CLIENT_CONTEXT.init(kmf.getKeyManagers(),  null, null);
            //其中kmf.getKeyManagers() 获取如下：
//            InputStream in =null;
//            KeyManagerFactory kmf = null;
//			if(caPath !=null){
//                //密钥库KeyStore
//               // KeyStore.getDefaultType()
//                KeyStore ks = KeyStore.getInstance("JKS");
//                //加载服务端证书
//                in = new FileInputStream(caPath );
//                //加载服务端的KeyStore  ；sNetty是生成仓库时设置的密码，用于检查密钥库完整性的密码
//                ks.load(in, "sNetty".toCharArray());
//
//                kmf = KeyManagerFactory.getInstance("SunX509");
//                //初始化密钥管理器
//                kmf.init(ks, "sNetty".toCharArray());
//            }


            //3、如果需要双认证模式，代码如下
            //CLIENT_CONTEXT.init(kmf.getKeyManagers(),  tf.getTrustManagers(), null);


        }catch(Exception e){
            e.printStackTrace();
            throw new Error("Failed to initialize the client-side SSLContext");
        }finally{
            if(tIN !=null){
                try {
                    tIN.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return CLIENT_CONTEXT;
    }

}
