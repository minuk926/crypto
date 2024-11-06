package kr.xit.crypto.exam;

import java.security.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.*;

/**
 * <pre>
 * 암호화 모드 - CBC (Cipher Block Chaining)
 * 이전 블록의 암호문을 현재 블록의 입력에 혼합하여 보안을 강화
 * 특징
 * 1. 블록 체이닝
 *   - 평문 블록은 암호화되기 전에 이전 암호문 블록과 XOR 연산을 수행
 *   - 첫 번째 블록의 경우, 초기 벡터(IV, Initialization Vector)가 사용
 *     -> 동일한 평문 블록도 서로 다른 이전 블록의 암호문에 종속되어 서로 다른 암호문 블록으로 암호화
 * 2. 초기 벡터(IV)
 *   - 보안성을 위해 초기 벡터가 매우 중요
 *   - IV는 암호문 블록의 계산에 사용되며, 고유하고 임의의 값이어야 한다.
 *   - IV를 공개할 수 있지만, 안전한 난수 생성기를 사용해 예측 불가능하게 만들어야 한다.
 * 3. 사전 처리 필요  
 *   - 하나의 블록을 암호화하려면 이전 블록의 암호화 결과가 필요
 *     -> 평문을 암호화할 때 평문 블록의 순서에 따라 순차적으로 처리해야 합니다.
 * 장점
 *  - 강화된 보안
 *    - 동일한 평문 블록이어도 다른 위치에 있으면 다른 암호문을 생성
 *    - 이전 블록이 암호화된 정보를 혼합되어 보안성이 크게 향상
 *  - 일부 오류 전파
 *    - 하나의 블록이 손상되면 해당 블록과 다음 블록만 영향을 받는다. 
 *      -> 오류 검출에 유리
 * 단점
 *  - 순차처리 및 동시성 제한(암호문 전체를 처리해야 하므로)
 *  - IV 관리 중요성
 *
 * 결론
 *    CFB 모드는 블록 암호를 스트림 암호처럼 사용할 수 있게 하며, 
 *    특히 데이터의 길이가 가변적인 경우 유용 
 *    보안성과 유연성 측면에서 장점이 많지만, 암호화 과정의 순차 처리가 필요하므로 특정 상황에서는 제한될 수 있다
 *
 * </pre>
 */
public class CBCExample {
    public static void main(String[] args) throws Exception {
        // BouncyCastle 프로바이더 추가
        Security.addProvider(new BouncyCastleProvider());
        
        // 키 및 IV 생성
        // KeyGenerator keyGen = KeyGenerator.getInstance("ARIA", "BC");
        // keyGen.init(128);
        // SecretKey secretKey = keyGen.generateKey();
        byte[] key = "0123456789012345".getBytes();
        SecretKey secretKey = new SecretKeySpec(key, "ARIA");
        
        // byte[] iv = new byte[16];
        // SecureRandom random = new SecureRandom();
        // random.nextBytes(iv);
        byte[] iv = "0123456789012345".getBytes();

        // 초기화 벡터 (IV) 설정
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // 암호화
        Cipher cipher = Cipher.getInstance("ARIA/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] plainText = "Hello, World ARIA/CBC TEST".getBytes("UTF-8");
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