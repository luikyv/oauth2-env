package oauthserver.service;

import oauthserver.domain.payload.AccessTokenResponse;
import org.springframework.stereotype.Service;

@Service
public class TokenService {
    // TODO
    public AccessTokenResponse buildAccessTokenResponse() {
        return new AccessTokenResponse();
    }
}
