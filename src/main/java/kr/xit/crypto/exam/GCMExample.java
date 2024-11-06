package kr.xit.crypto.exam;

import java.security.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * <pre>
 * 암호화 모드 - GCM (Galois/Counter Mode) 데이터의 기밀성과 무결성을 동시에 제공하는 암호화 모드
 * GCM은 성능이 뛰어날 뿐만 아니라 높은 보안성을 제공하기 때문에 여러 분야에서 널리 사용
 * -> GCM 모드는 CCM 모드와 달리 개발자가 직접 mac 값을 검증할 필요가 없다.
 *
 * 특징
 * 1. CTR (Counter) 모드 기반:
 *    - GCM은 CTR 모드를 기반으로 하여, 암호화와 복호화 모두 병렬 처리가 가능하며 빠른 성능을 제공
 * 2. Galois Message Authentication Code (GMAC):
 *    - 데이터의 무결성을 보장하기 위해 Galois 필드에서 메시지 인증 코드를 생성
 *      -> 이 인증 과정은 추가적인 보안성을 제공
 * 3. 초기 벡터(IV) 사용:
 *    - GCM은 보안을 위해 초기 벡터 (IV)를 사용
 *    - IV는 고유하고 예측 불가능해야 하며, GCM에서는 일반적으로 12바이트의 IV가 권장
 * 4. 인증 태그:
 *    - 암호화 과정에서 생성된 인증 태그는 데이터가 변조되지 않았음을 확인하는 데 사용
 *
 * GCM 모드의 장점
 * 1. 고성능:
 *    - 병렬 처리가 가능하여 암복호화 성능이 뛰어나다.
 * 2. 보안성:
 *    - 데이터 무결성과 기밀성을 동시에 보장하므로 높은 보안성을 제공
 * 3. 패딩 불필요:
 *    - CTR 모드를 기반으로 하여 데이터의 길이가 블록 크기의 배수가 아니어도 패딩이 필요 없다.
 *
 * GCM 모드의 단점
 * 1. IV 관리 필요:
 *    - 초기 벡터가 고유해야 하므로, IV를 관리하고 재사용을 방지해야 한다
 * 2. 복잡성:
 *    - 암호화와 인증이 결합되어 있어 구현 복잡
 *
 * 동작 방식
 * 1. 암호화:
 *    - CTR 모드로 평문을 암호화하여 암호문을 생성
 *    - GMAC을 사용하여 암호문과 추가 데이터의 인증 태그를 생성
 * 2. 복호화:
 *    - 암호문의 인증 태그를 검증하여 데이터 무결성을 확인
 *    - CTR 모드로 암호문을 복호화하여 평문을 복구
 *
 * 결론
 *    - GCM 모드는 성능과 보안을 모두 제공하는 강력한 암호화 모드 
 *    - CTR 모드의 빠른 성능과 Galois Message Authentication Code (GMAC)의 강력한 무결성 보장을 결합하여, 
 *      데이터의 기밀성과 무결성을 동시에 보장
 *    - 다양한 응용 프로그램에서 널리 사용되며, 특히 고성능, 고보안 요구사항이 있는 상황에 적합
 *    - 초기 벡터(IV)의 관리와 인증 태그 처리에 주의하여야 한다.
 * </pre>
 */
public class GCMExample {
    public static void main(String[] args) throws Exception {
        // 키 및 IV 생성
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        byte[] iv = new byte[12];  // GCM을 위해 권장되는 IV 길이는 12바이트입니다.
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // 초기화 벡터 (IV) 설정
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);  // 128비트 인증 태그 사용

        // 평문 설정
        byte[] plainText = "Hello, World! This is a test for GCM mode.".getBytes("UTF-8");

        // 암호화 설정
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        byte[] encryptedText = cipher.doFinal(plainText);

        // 암호문을 Base64으로 인코딩 (출력 전시용)
        String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedText);
        System.out.println("암호화된 텍스트 (Base64 인코딩): " + encryptedBase64);

        // 복호화 설정
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        byte[] decryptedText = cipher.doFinal(encryptedText);

        // 결과 출력
        System.out.println("복호화된 텍스트: " + new String(decryptedText, "UTF-8"));
    }
}