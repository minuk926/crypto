package kr.xit.crypto.exam;

import java.security.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.*;

/**
 * <pre>
 * 암호화 모드 - CFB (Cipher Feedback)
 * 스트림 암호와 유사한 동작을 가지며, 블록 암호를 스트림 암호처럼 사용할 수 있게 한다
 * -> 블록 암호 방식을 조금 더 유연하게 사용할 수 있다.
 * 특징
 * 1. 블록 체이닝
 *   - 초기 벡터(IV)를 사용하여 첫 번째 블록을 암호화
 *   - 암호화된 블록의 일부를 평문 블록과 XOR 연산하여 암호문을 생성
 *   - 생성된 암호문 블록의 일부와 다음 평문 블록을 XOR 연산하여 다음 암호문 블록을 생성
 * 2. 초기 벡터(IV)
 *   - 보안을 위해 초기 벡터 사용
 *   - IV는 고유하고 임의의 값이어야 하며, 예측 불가능 해야 한다
 * 3. 스트림 암호화
 *   - 블록 암호를 블록 단위로 처리하는 대신 바이트 단위로 처리
 * 장점
 *  - 스트림 암호 유사
 *    - 입력 데이터가 블록 크기보다 작아도 암호화가 가능하여, 가변 길이의 데이터를 효율적으로 처리할 수 있다.
 *  - 강화된 보안
 *    - IV와 이전 암호문이 다음 블록으로 전달되기 때문에 보안성이 높아진다.
 *  - 병렬 복호화 가능 
 *    - 복호화 과정은 병렬로 수행할 수 있어 성능을 어느 정도 보장할 수 있다
 * 단점
 *  - 순차적 암호화
 *    -> 암호문 생성이 이전 블록의 결과에 의존하기 때문에 암호화는 순차적으로 이루어져야 한다
 *    -> 암호화의 병렬 처리에는 제한
 *
 * 결론
 *   CFB 모드는 블록 암호를 스트림 암호처럼 사용할 수 있게 하며, 
 *   특히 데이터의 길이가 가변적인 경우 유용. 
 *   보안성과 유연성 측면에서 장점이 많지만, 암호화 과정의 순차 처리가 필요하므로 특정 상황에서는 제한될 수 있다.
 * </pre>
 */
public class CFBExample {
    public static void main(String[] args) throws Exception {
        // BouncyCastle 프로바이더 추가
        Security.addProvider(new BouncyCastleProvider());
        
        // 키 및 IV 생성
        KeyGenerator keyGen = KeyGenerator.getInstance("ARIA");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // 초기화 벡터 (IV) 설정
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // 암호화
        Cipher cipher = Cipher.getInstance("ARIA/CFB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] plainText = "Hello, World ARIA/CFB TEST!".getBytes("UTF-8");
        byte[] encryptedText = cipher.doFinal(plainText);

        // 암호문을 Base64으로 인코딩 (출력 전시용)
        String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedText);
        System.out.println("암호화된 텍스트 (Base64 인코딩): " + encryptedBase64);

        // 복호화
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decryptedText = cipher.doFinal(encryptedText);

        // 결과 출력
        System.out.println("암호화된 텍스트: " + new String(encryptedText, "UTF-8"));
        System.out.println("복호화된 텍스트: " + new String(decryptedText, "UTF-8"));
    }
}