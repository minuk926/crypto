package kr.xit.crypto;

import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestPropertySource(properties = {
    "app.crypto.alg=ARIA",
    "app.crypto.mode=GCM",
    "app.crypto.key=123456789012345678901234",
    "app.crypto.iv=1234567890123456"
})
public class CryptoCipherServiceTest {

    @Autowired
    private CryptoCipherService cryptoCipherService;

    @Test
    @DisplayName("암호화 대상이 정상인 경우 성공")
    public void testEncrypt_ValidInput_CorrectEncryption() throws Exception {
        // arrange
        String plainText = "hello world";

        // act
        String base64Str = cryptoCipherService.encryptBase64(plainText);
        System.out.println(base64Str);
        
        // assert
        assertEquals(plainText, cryptoCipherService.decryptBase64(base64Str));

        // String encStr = cryptoCipherService.encrypt(plainText);
        // System.out.println(encStr);
        //
        // // assert
        // assertEquals(plainText, cryptoCipherService.decrypt(encStr));
    }


    @Test
    @DisplayName("암호화 대상이 Empty 인경우 성공")
    public void testEncrypt_EmptyInput_EmptyEncryption() throws Exception {
        // arrange
        String plainText = "";

        // act
        String base64Str = cryptoCipherService.encryptBase64(plainText);
        System.out.println(base64Str);

        // assert
        assertEquals(plainText, cryptoCipherService.decryptBase64(base64Str));
    }
    
    @Test
    @DisplayName("암호화 대상이 null 인경우 Exeption")
    public void testEncrypt_NullInput_ThrowsException() {
        // arrange
        String plainText = null;

        // act and assert
        assertThrows(Exception.class, () -> cryptoCipherService.encryptBase64(plainText));
    }

    @Test
    @DisplayName("암호화 대상 길이가 overflow 인경우 성공")
    public void testEncrypt_LargeInput_CorrectEncryption() throws Exception {
        // arrange
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            stringBuilder.append("a");
        }
        String plainText = stringBuilder.toString();

        // act
        String base64Str = cryptoCipherService.encryptBase64(plainText);
        System.out.println(base64Str);

        // assert
        //Assertions.assertNotNull(base64Str);
        assertEquals(plainText, cryptoCipherService.decryptBase64(base64Str));
    }
}