package kr.xit.crypto.web;

import org.springframework.web.bind.annotation.*;

import io.swagger.v3.oas.annotations.*;
import io.swagger.v3.oas.annotations.tags.*;
import kr.xit.crypto.config.*;
import kr.xit.crypto.model.*;
import kr.xit.crypto.service.*;
import lombok.*;

/**
 * <pre>
 * description : 
 * packageName : kr.xit.crypto.web
 * fileName    : CryptoCipherController
 * author      : limju
 * date        : 2024 11월 07
 * ======================================================================
 * 변경일         변경자        변경 내용
 * ----------------------------------------------------------------------
 * 2024 11월 07   limju       최초 생성
 *
 * </pre>
 */
@Tag(name = "CryptoCipherController", description = "ARIA 암복호화")
@RestController
@RequiredArgsConstructor
public class CryptoCipherController {
    private final CryptoCipherService cryptoCipherService;

    @Operation(summary = "암호화" , description = "암호화 - 암호화후 Base64로 encoding 하여 return")
    @GetMapping(value = "/crypto/encode")
    public ApiResponse<?> encode(final String plainText) {
        return ApiResponse.of(cryptoCipherService.encryptBase64(plainText));
    }

    @Operation(summary = "복호화" , description = "복호화 - Base64 encoding된 암호화된 데이타 대상")
    @GetMapping(value = "/crypto/decode")
    public ApiResponse<?> decode(final String base64Text) {
        return ApiResponse.of(cryptoCipherService.decryptBase64(base64Text));
    }
}
