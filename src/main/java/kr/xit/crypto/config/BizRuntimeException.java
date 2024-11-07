package kr.xit.crypto.config;

import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import lombok.*;
import lombok.extern.slf4j.*;

@Getter
@Setter
@Slf4j
@ResponseStatus(code = HttpStatus.BAD_REQUEST, reason = "Invalid parameter")
public class BizRuntimeException extends RuntimeException{
    private String code;
    private String message;


    private BizRuntimeException(String message) {
        super(message);
        this.message = message;
    }
    
    public static BizRuntimeException create(String message) {
        return new BizRuntimeException(message);
    }
    
    public static BizRuntimeException create(String code, String message) {
        BizRuntimeException e = new BizRuntimeException(message);
        e.setCode(code);
        return e;
    }

    public static BizRuntimeException create(Throwable e) {
        return new BizRuntimeException(
            e.getCause() != null ? e.getCause().getMessage() : e.getMessage()
        );
    }
}
