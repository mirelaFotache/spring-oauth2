package oauth2.exception;

public class OAuth2Exception extends RuntimeException {


    private String message;

    public OAuth2Exception(String message) {
        super(message);
        this.message = message;
    }

    @Override
    public String getMessage() {
        return message;
    }
}