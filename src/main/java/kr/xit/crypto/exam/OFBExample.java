package kr.xit.crypto.exam;

import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * <pre>
 * 암호화 모드 - OFB (Output Feedback)
 * 스트림 암호처럼 동작하여 블록 암호를 연속된 스트림으로 변환하는 방식
 * 특징
 * 1. 스트림 암호화
 *   - 암호를 스트림 암호처럼 사용할 수 있도록 한다
 *     -> 고정된 블록 크기를 넘는 가변 길이 데이터 처리할 수 있다.
 * 2. 초기 벡터(IV)
 *   - 보안을 위해 초기 벡터 사용
 *   - IV는 고유하고 임의의 값이어야 하며, 예측 불가능 해야 한다
 * 3. 독립적인 블록
 *   - 이전 암호문 블록의 출력에 의존하지 않아 블록이 독립적으로 처리
 *     -> 결과적으로 에러 전파가 발생하지 않습니다
 * 4. 동일한 키 스트림
 *   - 동일한 키와 IV를 사용하면 동일한 키 스트림이 생성
 *     -> 따라서 다른 메시지를 암호화할 때 동일한 키와 IV를 사용하면 보안 문제가 발생할 수 있다.
 * 장점
 *  - 스트림 암호화
 *    - 데이터가 블록 크기보다 작아도 암호화가 가능하여 유연하게 데이터를 처리
 *  - 에러 전파 없음
 *    - 이전 암호문 블록에 의존하지 않기 때문에, 하나의 비트가 변경되더라도 그 영향이 최소화
 *  - 병렬 암복호화 가능 
 *    - 암호화와 복호화에서 병렬 처리가 가능
 * 단점
 *  - 동기화 문제
 *    -> 암호화 및 복호화 양쪽이 같은 블록을 유지해야 하며, 순서가 중요
 *  - 키 스트림 재사용 방지  
 *    -> 동일한 키와 IV 조합은 재사용하면 안 됩
 *
 * 결론
 *    OFB 모드는 스트림 암호 방식으로 데이터를 암호화하고 처리할 때 유용 
 *    블록 별 암호화 방식이 독립적이기 때문에 에러 전파를 방지하며, 보안성을 높여준다. 
 *    그러나 동일한 키와 IV 조합을 재사용하면 안 되는 중요한 원칙을 따라야 한다. 
 *    OFB 모드는 효율성과 보안성을 모두 고려해야 하는 다양한 시나리오에서 적합한 선택일 수 있다.
 * </pre>
 */
public class OFBExample {
    public static void main(String[] args) throws Exception {
        // 키 및 IV 생성
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // 초기화 벡터 (IV) 설정
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // 암호화
        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] plainText = "Hello, World!".getBytes("UTF-8");
        byte[] encryptedText = cipher.doFinal(plainText);

        // 복호화
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decryptedText = cipher.doFinal(encryptedText);

        // 결과 출력
        System.out.println(new String(decryptedText, "UTF-8"));
    }
}