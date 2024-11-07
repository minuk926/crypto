package kr.xit.crypto.config;

import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import kr.xit.crypto.model.*;
import lombok.extern.slf4j.*;

@Slf4j
@RestControllerAdvice
public class CustomRestExceptionHandler {
    
    @ExceptionHandler(value = {BizRuntimeException.class})
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    protected ApiResponse<Void> handleBizRutimeException(BizRuntimeException e) {
        log.error("==== throw BizRutimeException====\n{}", e.getMessage());
        return sendError(e);
    }

    @ExceptionHandler(value = {RuntimeException.class})
    @ResponseStatus(value = HttpStatus.INTERNAL_SERVER_ERROR)
    protected ApiResponse<Void> handleRuntimeException(RuntimeException e) {
        log.error("==== throw RuntimeException ====================\n{}", e.getMessage());
        return sendError(e);
    }

    /**
     * Exception
     *
     * @param e Exception
     * @return ErrorResponse
     */
    @ExceptionHandler(value = {Exception.class})
    @ResponseStatus(value = HttpStatus.INTERNAL_SERVER_ERROR)
    protected ApiResponse<Void> handleException(Exception e) {
        log.error("==== throw Exception ====================\n{}", e.getMessage());
        return sendError(e);
    }


    private ApiResponse<Void> sendError(Throwable e) {
        return ApiResponse.error(HttpStatus.BAD_REQUEST.toString(), e.getMessage());
    }
}
