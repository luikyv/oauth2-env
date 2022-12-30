package oauthserver.configuration;

public class Constant {
    public static final String ISSUER_NAME = "OAuth Server";

    public static final String AUTHORIZATION_HEADER = "Authorization";

    public static final String BEARER_PREFIX = "Bearer";

    public static final String FLOW_ID_COOKIE = "flow_id";

    public static final Integer FLOW_ID_COOKIE_EXPIRE_TIME_SECONDS = 300;

    public static final Integer AUTH_CODE_LENGTH = 30;

    public static final Integer ACCESS_TOKEN_EXPIRE_TIME_SECONDS = 600;

    public static final Integer ID_TOKEN_EXPIRE_TIME_SECONDS = 600;
}
