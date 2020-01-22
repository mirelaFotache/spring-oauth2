package oauth2.exception;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.Objects;

@ControllerAdvice
public class RestResponseEntityExceptionHandler extends ResponseEntityExceptionHandler {

    @Autowired
    private MessageSource messageSource;

    @ExceptionHandler(value = {OAuth2Exception.class})
    protected ResponseEntity<Object> handleErrors(RuntimeException ex, WebRequest request) {
        String msg = messageSource.getMessage(ex.getMessage(), null, LocaleContextHolder.getLocale());
        return handleExceptionInternal(ex, msg, new HttpHeaders(), HttpStatus.BAD_REQUEST, request);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
        final DefaultMessageSourceResolvable argument = (DefaultMessageSourceResolvable) Objects.requireNonNull(ex.getBindingResult().getAllErrors().get(0).getArguments())[0];
        String msg = "";
        String code = ex.getBindingResult().getAllErrors().get(0).getCode();
        final String[] codes = argument.getCodes();
        String objectName = ex.getBindingResult().getAllErrors().get(0).getObjectName();
        if (code != null && codes != null) {
            msg = messageSource.getMessage(objectName.toLowerCase() + "." + code.toLowerCase() + "." + codes[1].toLowerCase(), null, LocaleContextHolder.getLocale());
        }
        OAuth2Exception error = new OAuth2Exception(msg);
        return handleExceptionInternal(error, msg, new HttpHeaders(), HttpStatus.BAD_REQUEST, request);
    }
}
