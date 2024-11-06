package kr.xit.crypto.exam;

import java.security.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.*;

/**
 * <pre>
 * 암호화 모드 - CTR (Counter) 
 * 블록 암호를 스트림 암호처럼 사용할 수 있게 합니다. CTR 모드는 매우 효율적이고 병렬 처리가 가능하며, 
 * 다양한 응용 프로그램에서 널리 사용
 *
 * 특징
 * 1.카운터 사용:
 *   - CTR 모드는 초기 벡터(IV)와 카운터 값을 결합하여 블록 암호 알고리즘을 적용
 *   - 각 블록마다 카운터가 증가하며, 이를 통해 서로 다른 값을 입력으로 사용
 * 2. 동일한 길이 유지:
 *   - 평문과 암호문이 동일한 길이를 유지 -> 패딩 불필요
 * 3. 병렬 처리 가능:
 *   - 각 블록이 독립적으로 처리되므로 병렬 처리가 가능
 *     -> 성능 향상
 * 4. 독립적인 처리:
 *   - 이전 암호문 블록에 의존하지 않으므로 에러 전파가 발생하지 않는다
 *
 * CTR 모드의 장점
 * 1. 효율성:
 *   - 병렬 처리로 암호화와 복호화 속도가 빠르다.
 * 2. 간단한 구현:
 *   - 패딩을 사용할 필요가 없어 구현이 간단하고 직관적
 * 3. 에러 전파 없음:
 *   - 각 블록이 독립적으로 처리되므로, 한 블록에서 발생한 에러가 다른 블록에 영향을 미치지 않는다
 *
 * CTR 모드의 단점
 * 1. 카운터 관리 필요:
 *   - 카운터 값이 중복되지 않도록 주의 필요
 * 2. 초기 벡터(IV) 중요성:
 *   - 초기 벡터가 예측 불가능하고 고유해야 한다. 동일한 IV와 키 조합을 재사용하면 안된다.
 *
 *결론
 *   CTR 모드는 효율적이고 간단하게 구현할 수 있는 암호화 모드로, 병렬 처리의 장점과 데이터 길이 유지의 장점을 모두 갖추고 있다. 
 *   데이터의 블록 처리를 독립적으로 수행할 수 있어 다양한 보안 시나리오에서 유용하게 사용될 수 있다. 
 *   다만, 카운터 값의 중복을 피하고 고유한 초기 벡터를 사용하는 데 주의
 * </pre>
 */
public class CTRExample {
    public static void main(String[] args) throws Exception {
        // BouncyCastle 프로바이더 추가
        Security.addProvider(new BouncyCastleProvider());
        
        // 키 및 IV 생성
        KeyGenerator keyGen = KeyGenerator.getInstance("ARIA", "BC");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // 초기화 벡터 (IV) 설정
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // 암호화 설정
        Cipher cipher = Cipher.getInstance("ARIA/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] plainText = "Hello, World! This is a test for ARIA/CTR mode.".getBytes("UTF-8");
        byte[] encryptedText = cipher.doFinal(plainText);

        // 암호문을 Base64으로 인코딩 (출력 전시용)
        String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedText);
        System.out.println("암호화된 텍스트 (Base64 인코딩): " + encryptedBase64);

        // 복호화 설정
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decryptedText = cipher.doFinal(encryptedText);

        // 결과 출력
        System.out.println("암호화된 텍스트: " + new String(encryptedText, "UTF-8"));
        System.out.println("복호화된 텍스트: " + new String(decryptedText, "UTF-8"));
    }
}