package kr.xit.crypto.service;

import java.nio.charset.*;
import java.util.*;

import org.springframework.beans.factory.annotation.*;
import org.springframework.stereotype.*;

import kr.xit.crypto.config.*;
import kr.xit.crypto.util.*;

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

    /**
     * <pre>
     * 데이타 유실 방지를 위해 반드시 Base64로 encoding 하여야만 한다
     * properties에서 정의한 key, iv 값은 Base64로 encoding되어 있어 decoding 하여 사용
     * 
     * @param plainText
     * @return 암호화후 Base64로 encoding
     * </pre>
     */
    public String encryptBase64(String plainText) {
        if (plainText == null) {
            throw BizRuntimeException.create("암호화할 대상이 null 입니다");
        }
        byte[] encStr = AriaCryptoCipher.encryptGCM(Base64.getDecoder().decode(secretKey), Base64.getDecoder().decode(iv), plainText.getBytes(), null);
        return Base64.getEncoder().encodeToString(encStr);
    }

    /**
     * <pre>
     * Base64로 encoding된 암호화된 값 -> decoding후 처리
     * properties에서 정의한 key, iv 값은 Base64로 encoding되어 있어 decoding 하여 사용
     * 
     * @param base64Text
     * @return 
     * </pre>
     */
    public String decryptBase64(String base64Text) {
        if (base64Text == null) {
            throw BizRuntimeException.create("복호화할 대상이 null 입니다");
        }
        
        byte[] decBytes = validBase64(base64Text);
        byte[] decStr = AriaCryptoCipher.decryptGCM(Base64.getDecoder().decode(secretKey), Base64.getDecoder().decode(iv), decBytes, null);
        return new String(decStr, StandardCharsets.UTF_8);
    }

    private byte[] validBase64(String value) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw BizRuntimeException.create("복호화할 문자열은 Base64로 encode된 데이타여야 합니다");
        }
    }
}
