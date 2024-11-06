package kr.xit.crypto;

import java.util.*;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.paddings.*;
import org.bouncycastle.crypto.params.*;

/**
 * <pre>
 * ARIA (Academy Research Institute Algorithm)
 *    - ARIA는 ETRI, KISA 및 학계의 연구자들에 의해 개발된 블록 암호 알고리즘
 *    - 주로 금융 및 정부 기관에서의 사용을 고려하여 설계
 *    
 * 특징
 * 1. 보안성:
 *    - AES(Advanced Encryption Standard) 기반 설계로 높은 보안성을 제공
 *    - 한국 국가 표준 암호 알고리즘으로 채택
 * 2. 블록 크기 및 키 크기:
 *    - ARIA는 128비트 블록 크기를 사용하며, 128비트, 192비트, 256비트 키 길이를 지원
 * 3. 라운드 구조:
 *    - 키 크기에 따라 12, 14, 16라운드의 암호화 라운드를 가진다.
 * 4. 효율성:
 *    - 소프트웨어와 하드웨어 모두에서 동작
 *    
 * --> GCM, CCM 모드 확인    
 *    
 * description : 
 * packageName : kr.xit.crypto
 * fileName    : AriaCryptoCipher
 * author      : limju
 * date        : 2024 11월 06
 * ======================================================================
 * 변경일         변경자        변경 내용
 * ----------------------------------------------------------------------
 * 2024 11월 06   limju       최초 생성
 *
 * </pre>
 */
public class AriaCryptoCipher {

    /**
     * <pre>
     * 암호화 모드 : ECB(Electronic Codebook) 대칭 키 암호화 알고리즘 
     * - 입력 데이터(평문)를 일정 크기의 블록으로 분할하여 독립적으로 암호화
     * - 동일한 평문 블록은 항상 동일한 암호문 블록으로 암호화
     * - 장점
     *   -> 빠르고 병렬처리 가능
     * - 취약점 
     *   -> 동일한 평문 블록은 항상 동일한 암호문 블록 -> 구조나 패턴을 식별 가능
     * - 보안성이 높은 CBC (Cipher Block Chaining), CFB (Cipher Feedback), OFB (Output Feedback) 사용 권장  
     * @param key 16, 24, 32bytes 길이의 key를 사용
     * @param plainText
     * @return
     * @throws Exception
     * </pre>
     */
    public static byte[] encryptECB(byte[] key, byte[] plainText) throws Exception {

        // block size가 16의 배수가 아닐경우, 암호화가 안될수 있으므로 항상 데이터를 패딩한다
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new ARIAEngine());
        cipher.init(true, new KeyParameter(key));

        byte[] outputData = new byte[cipher.getOutputSize(plainText.length)];
        int tam = cipher.processBytes(plainText, 0, plainText.length, outputData, 0);
        cipher.doFinal(outputData, tam);

        return outputData;
    }

    /**
     * <pre>
     * 암호화 모드 : ECB
     * @param key
     * @param cipherText
     * @return
     * @throws Exception
     * </pre>
     */
    public static byte[] decryptECB(byte[] key, byte[] cipherText) throws Exception {
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new ARIAEngine());
        cipher.init(false, new KeyParameter(key));

        byte[] outputData = new byte[cipher.getOutputSize(cipherText.length)];
        int tam = cipher.processBytes(cipherText, 0, cipherText.length, outputData, 0);
        int finalLen = cipher.doFinal(outputData, tam);

        return Arrays.copyOfRange(outputData, 0, finalLen + tam);
    }

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
     * @param key
     * @param iv
     * @param plainText
     * @return
     * @throws Exception
     * </pre>
     */
    public static byte[] encryptCBC(byte[] key, byte[] iv, byte[] plainText) throws Exception {
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(new ARIAEngine()));
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] outputData = new byte[cipher.getOutputSize(plainText.length)];
        int tam = cipher.processBytes(plainText, 0, plainText.length, outputData, 0);
        cipher.doFinal(outputData, tam);

        return outputData;
    }

    public static byte[] decryptCBC(byte[] key, byte[] iv, byte[] cipherText) throws Exception {
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(new ARIAEngine()));
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] outputData = new byte[cipher.getOutputSize(cipherText.length)];
        int tam = cipher.processBytes(cipherText, 0, cipherText.length, outputData, 0);
        int finalLen = cipher.doFinal(outputData, tam);

        return Arrays.copyOfRange(outputData, 0, finalLen + tam);
    }
    
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
     *   
     * @param key
     * @param iv
     * @param plainText
     * @return
     * </pre>
     */
    public static byte[] encryptCFB(byte[] key, byte[] iv, byte[] plainText) {

        // blockSize는 64 혹은 128만 입력 가능 (128 권장)
        CFBModeCipher cipher = CFBBlockCipher.newInstance(new ARIAEngine(), 128);
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] outputData = new byte[plainText.length];
        cipher.processBytes(plainText, 0, plainText.length, outputData, 0);

        return outputData;
    }

    public static byte[] decryptCFB(byte[] key, byte[] iv, byte[] cipherText) {
        CFBModeCipher cipher = CFBBlockCipher.newInstance(new ARIAEngine(), 128);
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] result = new byte[cipherText.length];
        cipher.processBytes(cipherText, 0, cipherText.length, result, 0);

        return result;
    }

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
     *    
     * @param key
     * @param iv
     * @param plainText
     * @return
     * </pre>
     */
    public static byte[] encryptOFB(byte[] key, byte[] iv, byte[] plainText) {

        // blockSize는 8 혹은 16만 입력 가능 (16 권장)
        // OFBBlockCipher는 newInstance() 메소드가 없다
        OFBBlockCipher cipher = new OFBBlockCipher(new ARIAEngine(), 16);
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] outputData = new byte[plainText.length];
        cipher.processBytes(plainText, 0, plainText.length, outputData, 0);

        return outputData;
    }

    public static byte[] decryptOFB(byte[] key, byte[] iv, byte[] cipherText) {
        OFBBlockCipher cipher = new OFBBlockCipher(new ARIAEngine(), 16);
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] result = new byte[cipherText.length];
        cipher.processBytes(cipherText, 0, cipherText.length, result, 0);

        return result;
    }

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
     * 
     * @param key
     * @param plainText
     * @return
     * @throws Exception
     * </pre>
     */
    public static byte[] encryptCTS(byte[] key, byte[] plainText) throws Exception {
        CTSBlockCipher cipher = new CTSBlockCipher(new ARIAEngine());
        cipher.init(true, new KeyParameter(key));

        byte[] outputData = new byte[plainText.length];
        int tam = cipher.processBytes(plainText, 0, plainText.length, outputData, 0);
        cipher.doFinal(outputData, tam);

        return outputData;
    }

    public static byte[] decryptCTS(byte[] key, byte[] cipherText) throws Exception {
        CTSBlockCipher cipher = new CTSBlockCipher(new ARIAEngine());
        cipher.init(false, new KeyParameter(key));

        byte[] result = new byte[cipherText.length];
        int finalLen = cipher.processBytes(cipherText, 0, cipherText.length, result, 0);
        cipher.doFinal(result, finalLen);

        return result;
    }

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
     *   
     * @param key
     * @param iv
     * @param plainText
     * @return
     * </pre>
     */
    public static byte[] encryptCTR(byte[] key, byte[] iv, byte[] plainText) {
        CTRModeCipher cipher = SICBlockCipher.newInstance(new ARIAEngine());
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] outputData = new byte[plainText.length];
        cipher.processBytes(plainText, 0, plainText.length, outputData, 0);

        return outputData;
    }

    public static byte[] decryptCTR(byte[] key, byte[] iv, byte[] cipherText) {
        CTRModeCipher cipher = SICBlockCipher.newInstance(new ARIAEngine());
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] result = new byte[cipherText.length];
        cipher.processBytes(cipherText, 0, cipherText.length, result, 0);

        return result;
    }

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
     * 
     * @param key
     * @param iv 7~13bytes 길이의 값이다 (12bytes 길이 권장)
     * @param plainText
     * @param aad aad 값은 필수는 아니며, 길이는 2^64 bit보다 작아야 한다
     * @return
     * @throws InvalidCipherTextException
     * </pre>
     */
    public static List<byte[]> encryptCCM(byte[] key, byte[] iv, byte[] plainText, byte[] aad) throws
        InvalidCipherTextException {
        int macSize = 128;
        CCMModeCipher cipher = CCMBlockCipher.newInstance(new ARIAEngine());
        cipher.init(true, new AEADParameters(new KeyParameter(key), macSize, iv, aad));

        byte[] outputData = new byte[cipher.getOutputSize(plainText.length)];
        int tam = cipher.processBytes(plainText, 0, plainText.length, outputData, 0);
        cipher.doFinal(outputData, tam);

        List<byte[]> arr = new ArrayList<>();
        arr.add(outputData);
        arr.add(cipher.getMac());

        return arr;
    }

    /**
     * 
     * @param key
     * @param iv 7~13bytes 길이의 값이다 (12bytes 길이 권장)
     * @param cipherText
     * @param aad aad 값은 필수는 아니며, 길이는 2^64 bit보다 작아야 한다
     * @param mac
     * @return
     * @throws Exception
     */
    public static byte[] decryptCCM(byte[] key, byte[] iv, byte[] cipherText, byte[] aad, byte[] mac) throws Exception {
        int macSize = 128;
        CCMModeCipher cipher = CCMBlockCipher.newInstance(new ARIAEngine());
        cipher.init(false, new AEADParameters(new KeyParameter(key), macSize, iv, aad));

        byte[] result = new byte[cipher.getOutputSize(cipherText.length)];
        int tam = cipher.processBytes(cipherText, 0, cipherText.length, result, 0);
        cipher.doFinal(result, tam);

        // encrypt의 cipher.mac 값과 decrypt의 cipher.mac 값이 다르면 암호화 된 데이터가 위조 혹은 변조된 것이다
        if (!Arrays.equals(mac, cipher.getMac())) {
            throw new Exception("데이터가 위변조되었습니다.");
        }

        return result;
    }

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
     *    
     * @param key 16, 24, 32bytes 길이의 key를 사용할 수 있다
     * @param iv
     * @param plainText
     * @param aad aad 값은 필수는 아니며, 길이는 2^64 bit보다 작아야 한다
     * @return
     * @throws Exception
     * </pre>
     */
    public static byte[] encryptGCM(byte[] key, byte[] iv, byte[] plainText, byte[] aad) throws Exception {
        int macSize = 128;
        GCMModeCipher cipher = GCMBlockCipher.newInstance(new ARIAEngine());
        cipher.init(true, new AEADParameters(new KeyParameter(key), macSize, iv, aad));

        byte[] encryptedData = new byte[cipher.getOutputSize(plainText.length)];
        int tam = cipher.processBytes(plainText, 0, plainText.length, encryptedData, 0);

        try {
            cipher.doFinal(encryptedData, tam);
        } catch (InvalidCipherTextException e) {
            throw new Exception("GCM authentication tag generation failed: " + e.getMessage(), e);
        }

        return encryptedData;
    }

    public static byte[] decryptGCM(byte[] key, byte[] iv, byte[] cipherText, byte[] aad) throws Exception {
        int macSize = 128;
        GCMModeCipher cipher = GCMBlockCipher.newInstance(new ARIAEngine());
        cipher.init(false, new AEADParameters(new KeyParameter(key), macSize, iv, aad));

        byte[] outputData = new byte[cipher.getOutputSize(cipherText.length)];
        int tam = cipher.processBytes(cipherText, 0, cipherText.length, outputData, 0);

        try {
            cipher.doFinal(outputData, tam);
        } catch (InvalidCipherTextException e) {
            throw new Exception("GCM authentication tag generation failed: " + e.getMessage()
                + ". Possible causes may include key mismatch, IV mismatch, corrupted cipherText or AAD.", e);
        }

        return outputData;
    }
    
    public static void main(String[] args) {
        byte[] messageBytes = "암호화 모듈별 암복호화 테스트!".getBytes();


        try {
            // 16, 24, 32bytes 길이의 key를 사용할 수 있다
            byte[] key = "123456789012345678901234".getBytes();

            // CCM 모드에서 iv는 7~13bytes 길이의 값이다 (12bytes 길이 권장)
            byte[] iv = "0123456789012345".getBytes();
            
            // aad 값은 필수는 아니며, 길이는 2^64 bit보다 작아야 한다
            byte[] add = "0123456789012345".getBytes();

            byte[] encryptedData = encryptECB(key, messageBytes);
            byte[] originalMessage = decryptECB(key, encryptedData);
            System.out.println("ECB => "+new String(originalMessage));


            
            byte[] encryptedDataCBC = encryptCBC(key, iv, messageBytes);
            byte[] originalMessageCBC = decryptCBC(key, iv, encryptedDataCBC);
            System.out.println("CBC => "+new String(originalMessageCBC));

            byte[] encryptedDataCFB = encryptCFB(key, iv, messageBytes);
            byte[] originalMessageCFB = decryptCFB(key, iv, encryptedDataCFB);
            System.out.println("CFB => "+new String(originalMessageCFB));

            byte[] encryptedDataOFB = encryptCFB(key, iv, messageBytes);
            byte[] originalMessageOFB = decryptCFB(key, iv, encryptedDataOFB);
            System.out.println("OFB => "+new String(originalMessageOFB));

            byte[] encryptedDataCTS = encryptCTS(key, messageBytes);
            byte[] originalMessageCTS = decryptCTS(key, encryptedDataCTS);
            System.out.println("CTS => "+new String(originalMessageCTS));

            byte[] encryptedDataCTR = encryptCTR(key, iv, messageBytes);
            byte[] originalMessageCTR = decryptCTR(key, iv, encryptedDataCTR);
            System.out.println("CTR => "+new String(originalMessageCTR));

            // CCM 모드에서 iv는 7~13bytes 길이의 값이다 (12bytes 길이 권장)
            iv = "012345678901".getBytes();
            List<byte[]> encryptedDataAndMac = encryptCCM(key, iv, messageBytes, add);
            byte[] encryptedDataCCM = encryptedDataAndMac.get(0);
            byte[] mac = encryptedDataAndMac.get(1);
            byte[] originalMessageCCM = decryptCCM(key, iv, encryptedDataCCM, add, mac);
            System.out.println("CCM => "+new String(originalMessageCCM));

            iv = "0123456789012345".getBytes();
            byte[] encryptedDataGCM = encryptGCM(key, iv, messageBytes, add);
            byte[] originalMessageGCM = decryptGCM(key, iv, encryptedDataGCM, add);
            System.out.println("GCM => "+new String(originalMessageGCM));
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
