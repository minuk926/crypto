package kr.xit.crypto.exam;

import java.security.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * <pre>
 * 암호화 모드 - CCM (Counter with CBC-MAC) 데이터의 기밀성과 무결성을 동시에 제공하는 암호화 모드
 * CTR (Counter) 모드와 CBC-MAC (Cipher Block Chaining Message Authentication Code)를 결합하여 인증된 암호화를 구현
 * CCM 모드의 핵심은 mac 값을 검증하는 것 
 * -> mac 값이 서로 다르면 암호화 된 데이터가 위조 혹은 변조된 것
 *
 * 특징
 * 1. 인증된 암호화:
 *   - CCM 모드는 암호화와 데이터 무결성 검증을 동시에 수행
 *   - 메시지 인증 코드를 사용하여 데이터가 변조되지 않았음을 보장
 * 2. CTR + CBC-MAC:
 *   - CTR 모드로 데이터를 암호화하고, CBC-MAC을 사용하여 데이터의 무결성을 확인
 *   - 두 가지 모드를 결합하여 보안성을 강화
 * 3. 초기 벡터(IV) 사용:
 *   - 보안을 위해 초기 벡터(IV)를 사용
 *   - IV는 고유하고 예측 불가능해야 한다
 *
 * CCM 모드의 장점
 * 1. 보안성 강화:
 *    - 데이터의 기밀성과 무결성을 동시에 보장하여 높은 보안성을 제공
 * 2. 단일 패스 처리:
 *    - 암호화와 인증을 단일 패스로 처리하여 효율성을 증가
 * 3. 변형 방지:
 *    - 데이터를 암호화하고 인증하므로 위변조를 방지
 *
 * CCM 모드의 단점
 * 1. 복잡성 증가:
 *   - 암호화와 인증을 동시에 처리로 구현이 복잡
 * 2. 추가적인 인증 태그:
 *   - 데이터 무결성을 확인하기 위해 추가적인 태그 정보가 필요
 *
 * 동작 방식
 * 1. 암호화:
 *    - CTR 모드로 평문을 암호화하여 암호문을 생성
 *    - CBC-MAC으로 인증 태그를 생성 -> 데이터의 무결성 보장
 * 2. 복호화:
 *    - 암호문에서 인증 태그를 분리 -> 태그를 검증 -> 데이터 무결성을 확인
 *    - CTR 모드로 암호문을 복호화 -> 평문을 복구
 *
 * 결론
 *    CCM 모드는 데이터의 기밀성과 무결성을 동시에 제공하는 강력한 암호화 모드 
 *    CTR 모드와 CBC-MAC을 결합하여 데이터를 안전하게 암호화하고 인증 
 *    -> 높은 보안성 및 데이터 무결성 요구 사항이 있는 애플리케이션에서 특히 유용
 *    그러나 구현의 복잡성과 추가적인 인증 태그 관리는 신중하게 고려해야 함.
 *</pre>
 */
public class CCMExample {
    public static void main(String[] args) throws Exception {
        // 키 및 IV 생성
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        byte[] iv = new byte[12]; // GCM을 위해 권장되는 IV 길이는 12바이트입니다.
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // 초기화 벡터 (IV) 설정
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // 128비트 인증 태그 사용

        // 암호화 설정
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        byte[] plainText = "Hello, World! This is a test for CCM mode.".getBytes("UTF-8");
        byte[] encryptedText = cipher.doFinal(plainText);

        // 복호화 설정
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        byte[] decryptedText = cipher.doFinal(encryptedText);

        // 결과 출력
        System.out.println("암호화된 텍스트: " + Arrays.toString(encryptedText));
        System.out.println("복호화된 텍스트: " + new String(decryptedText, "UTF-8"));
    }
}