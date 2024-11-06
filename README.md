# crypto
LEA / ARIA 암호화 모듈
> jdk1.8 over

### LEA / ARIA Engine Algorithms
> bouncycastle 라이브러리 사용시 ARIAEngine or LEAEngine 으로만 변경하면 됨

### java, javax의 암호화 모듈 사용 직접 구현시
> bouncycastle 라이브러리의 jce.provider 를 사용
> Security.addProvider(new BouncyCastleProvider())
```java
public static void main(String[] args) throws Exception {
        // BouncyCastle 프로바이더 추가
        Security.addProvider(new BouncyCastleProvider());
        
        // 키 및 IV 생성
        // KeyGenerator keyGen = KeyGenerator.getInstance("ARIA", "BC");
        // keyGen.init(128);
        // SecretKey secretKey = keyGen.generateKey();
        byte[] key = "0123456789012345".getBytes();
        SecretKey secretKey = new SecretKeySpec(key, "ARIA");

        // 초기화 벡터 (IV) 생성
        // byte[] iv = new byte[16];  // GCM을 위해 권장되는 IV 길이는 16바이트입니다.
        // SecureRandom random = new SecureRandom();
        // random.nextBytes(iv);
        byte[] iv = "0123456789012345".getBytes();
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // 초기화 벡터 (IV) 설정
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);  // 128비트 인증 태그 사용

        // 평문 설정
        byte[] plainText = "Hello, World! This is a test for ARIA/GCM mode.".getBytes("UTF-8");

        // 암호화 설정
        Cipher cipher = Cipher.getInstance("ARIA/GCM/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        byte[] encryptedText = cipher.doFinal(plainText);

        // 암호문을 Base64으로 인코딩 (출력 전시용)
        String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedText);
        System.out.println("암호화된 텍스트 (Base64 인코딩): " + encryptedBase64);

        // 복호화 설정
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        byte[] decryptedText = cipher.doFinal(encryptedText);

        // 결과 출력
        System.out.println("암호화된 텍스트: " + new String(encryptedText, "UTF-8"));
        System.out.println("복호화된 텍스트: " + new String(decryptedText, "UTF-8"));
    }
```
