package kr.xit.crypto.model;

import org.apache.commons.lang3.*;
import org.springframework.http.*;

import com.fasterxml.jackson.annotation.*;

import io.swagger.v3.oas.annotations.media.*;
import lombok.*;

/**
 * <pre>
 * description : 
 * packageName : kr.xit.crypto.config
 * fileName    : ApiResponse
 * author      : limju
 * date        : 2024 11월 07
 * ======================================================================
 * 변경일         변경자        변경 내용
 * ----------------------------------------------------------------------
 * 2024 11월 07   limju       최초 생성
 *
 * </pre>
 */
@Schema(name = "ApiResponse", description = "Restful API 결과")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@JsonRootName("result")
@Data
public class ApiResponse<T> {
    private boolean success;
    private String code;
    private String message;
    private T data;
    
    public static ApiResponse<Void> success() {
        return new ApiResponse<>(true, HttpStatus.OK.name(), StringUtils.EMPTY, null);
    }
    
    public static <T> ApiResponse of(T data) {
        return new ApiResponse<>(true, HttpStatus.OK.name(), StringUtils.EMPTY, data);
    }
    
    public static ApiResponse<Void> error(String message) {
        return new ApiResponse<>(false, HttpStatus.BAD_REQUEST.name(), message, null);
    }
    
    public static ApiResponse<Void> error(String code, String message) {
        return new ApiResponse<>(false, code, message, null);
    }

    private ApiResponse(final boolean success, final String code, final String message, final T data) {
        this.success = success;
        this.code = code;
        this.message = message;
        this.data = data;
    }
}
