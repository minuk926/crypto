package kr.xit.crypto.exam;

import java.security.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.*;

/**
 * <pre>
 * 암호화 모드 - CTS (Cipher Text Stealing)
 * 가변 길이의 데이터를 처리할 때 사용되는 암호화 모드 중 하나
 * -> 데이터 길이가 블록 크기의 배수가 아닌 경우 발생하는 문제를 해결하기 위해 사용
 * 특징
 * 1. 변경된 패딩 방식
 *   - 블록 암호화 알고리즘은 보통 고정된 크기의 블록을 처리
 *     -> 입력 데이터 길이가 블록 크기의 배수가 아닐 경우 패딩을 추가
 *   - 반면에 CTS 모드는 
 *     -> 패딩 대신, 마지막 두 블록의 암호문을 조정하여 전체 암호문이 평문과 동일한 길이를 갖도록 한다.  
 * 2. 블록 크기와 관계없는 길이
 *   - 입력 데이터의 길이가 블록 크기의 배수가 아니더라도 암호문과 평문이 동일한 길이를 유지
 *     -> 패딩을 추가하지 않아도 되는 장점
 * 3. CBC 모드와 결합
 *   - 주로 CBC (Cipher Block Chaining) 모드와 결합하여 사용
 *     -> 데이터의 독립적 처리 대신 체이닝된 방식으로 암호화가 처리
 * 장점
 *  - 동일한 길이 유지
 *    - 암호화된 데이터의 길이가 평문 데이터의 길이와 동일
 *      -> 패딩으로 인한 데이터 길이 증가를 방지
 *  - 변형된 패딩 없음
 *    - 패딩 알고리즘 대신 마지막 두 블록의 조정을 통해 길이 문제를 해결
 * 단점
 *  - 복잡한 처리
 *    -> 암호화 및 복호화 과정이 다른 모드에 비해 복잡
 *  - 저장 공간 절약이 미미 
 *    -> 패딩 대신 조정을 사용하지만, 실제 저장 공간 절약은 매우 미미
 *
 * 결론
 *     CTS 모드는 데이터 길이가 블록 크기의 배수가 아닌 경우 사용할 수 있는 유용한 암호화 모드
 *     암호화된 데이터와 원래 데이터의 길이를 동일하게 유지할 수 있다.
 * </pre>
 */
public class CTSExample {
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

        // 평문 설정 (가변 길이)
        byte[] plainText = "Hello, World! This is a test for ARIA/CTS.".getBytes("UTF-8");

        // 암호화
        Cipher cipher = Cipher.getInstance("ARIA/CTS/NoPadding");
        int blockSize = cipher.getBlockSize();
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        // 패딩 없이 암호화할 경우, 입력 데이터 길이가 블록 크기의 배수가 되어야 함
        int paddedLength = ((plainText.length + blockSize - 1) / blockSize) * blockSize;
        byte[] paddedText = Arrays.copyOf(plainText, paddedLength);

        // 암호화 수행
        byte[] encryptedText = cipher.doFinal(paddedText);

        // 암호문을 Base64으로 인코딩 (출력 전시용)
        String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedText);
        System.out.println("암호화된 텍스트 (Base64 인코딩): " + encryptedBase64);

        // CTS 방식으로 마지막 블록 조정
        int lastBlockStart = encryptedText.length - blockSize;
        byte[] lastBlock = Arrays.copyOfRange(encryptedText, lastBlockStart, encryptedText.length);
        byte[] secondLastBlock = Arrays.copyOfRange(encryptedText, lastBlockStart - blockSize, lastBlockStart);

        // 마지막 두 블록 교환 및 길이 조정
        System.arraycopy(secondLastBlock, 0, encryptedText, lastBlockStart, lastBlock.length);
        System.arraycopy(lastBlock, 0, encryptedText, lastBlockStart - blockSize, secondLastBlock.length);

        // 복호화
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decryptedText = cipher.doFinal(encryptedText);

        // 복호화된 평문에서 패딩 제거
        decryptedText = Arrays.copyOf(decryptedText, plainText.length);

        // 결과 출력
        System.out.println("암호화된 텍스트: " + new String(encryptedText, "UTF-8"));
        System.out.println("복호화된 텍스트: " + new String(decryptedText, "UTF-8"));
    }
}