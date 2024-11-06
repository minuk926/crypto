package kr.xit.crypto.config;

import org.jasypt.encryption.*;
import org.jasypt.encryption.pbe.*;
import org.jasypt.encryption.pbe.config.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.context.annotation.*;

/**
 * <pre>
 * description : properties 암호화 설정
 * packageName : kr.xit.crypto.config
 * fileName    : JasyptConfig
 * author      : julim
 * date        : 2024-11-06
 * ======================================================================
 * 변경일         변경자        변경 내용
 * ----------------------------------------------------------------------
 * 2024-11-06    julim       최초 생성
 *
 * </pre>
 */

@Configuration
public class JasyptConfig {
    @Value("${app.jasypt.secretKey:none}")
    private String secretKey;

    @Value("${app.jasypt.alg:none}")
    private String secretAlg;

    @Value("${app.jasypt.type:none}")
    private String secretType;

    @Bean(name = "jasyptStringEncryptor")
    public StringEncryptor jasyptStringEncryptor() {
        SimpleStringPBEConfig config = new SimpleStringPBEConfig();
        // 암/복호화 키
        config.setPassword(secretKey);
        // 암/복호화 알고리즘
        config.setAlgorithm(secretAlg);
        // 반복할 해싱 회수
        config.setKeyObtentionIterations("1000");
        config.setProviderName("SunJCE");
        // salt 생성 클래스
        config.setSaltGeneratorClassName("org.jasypt.salt.RandomSaltGenerator");
        // 암/복호화 인스턴스 : 0보다 커야
        config.setPoolSize("1");
        config.setStringOutputType(secretType);

        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
        encryptor.setConfig(config);
        return encryptor;
    }
    
    public static void main(String[] args) {
        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setAlgorithm("PBEWithMD5AndDES");
        encryptor.setPassword("xit5811807!@");

        String key = encryptor.encrypt("123456789012345678901234");
        String iv = encryptor.encrypt("1234567890123456");

        System.out.println(key);
        System.out.println(iv);
        System.out.println(encryptor.decrypt(key));
        System.out.println(encryptor.decrypt(iv));
    }

}
