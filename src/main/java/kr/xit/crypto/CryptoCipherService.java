package kr.xit.crypto;

import java.nio.charset.*;
import java.util.*;

import org.springframework.beans.factory.annotation.*;
import org.springframework.stereotype.*;

/**
 * <pre>
 * description : 
 * packageName : kr.xit.crypto
 * fileName    : CryptoCipherService
 * author      : limju
 * date        : 2024 11월 06
 * ======================================================================
 * 변경일         변경자        변경 내용
 * ----------------------------------------------------------------------
 * 2024 11월 06   limju       최초 생성
 *
 * </pre>
 */
@Service
public class CryptoCipherService {
    @Value("${app.crypto.alg:ARIA}")
    private String crypto;

    @Value("${app.crypto.mode:GCM}")
    private String cryptoMode;

    @Value("${app.crypto.key:}")
    private String secretKey;

    @Value("${app.crypto.iv:}")
    private String iv;
    
    private final byte[] add = "0123456789012345".getBytes();

    // @Deprecated
    // public String encrypt(String plainText) throws Exception {
    //     byte[] encStr = AriaCryptoCipher.encryptGCM(secretKey.getBytes(StandardCharsets.UTF_8), iv.getBytes(StandardCharsets.UTF_8), plainText.getBytes(StandardCharsets.UTF_8), add);
    //     return new String(encStr, StandardCharsets.UTF_8);
    // }
    //
    // @Deprecated
    // public String decrypt(String plainText) throws Exception {
    //     byte[] decStr = AriaCryptoCipher.decryptGCM(secretKey.getBytes(StandardCharsets.UTF_8), iv.getBytes(StandardCharsets.UTF_8), plainText.getBytes(StandardCharsets.UTF_8), add);
    //     return new String(decStr, StandardCharsets.UTF_8);
    // }

    /**
     * 반드시 Base64로 encoding 하여야만 한다
     * 
     * @param plainText
     * @return
     * @throws Exception
     */
    public String encryptBase64(String plainText) throws Exception {
        if (plainText == null) {
            throw new Exception("Input text cannot be null");
        }
        byte[] encStr = AriaCryptoCipher.encryptGCM(secretKey.getBytes(), iv.getBytes(), plainText.getBytes(), add);
        return Base64.getEncoder().encodeToString(encStr);
    }
    
    public String decryptBase64(String base64Text) throws Exception {
        if (base64Text == null) {
            throw new Exception("Input text cannot be null");
        }
        byte[] decBytes = Base64.getDecoder().decode(base64Text);
        byte[] decStr = AriaCryptoCipher.decryptGCM(secretKey.getBytes(), iv.getBytes(), decBytes, add);
        return new String(decStr, StandardCharsets.UTF_8);
    }
}
