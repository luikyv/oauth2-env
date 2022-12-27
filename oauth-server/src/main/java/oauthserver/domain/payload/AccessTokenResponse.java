package oauthserver.domain.payload;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;
import oauthserver.enumerations.TokenType;

@AllArgsConstructor
@NoArgsConstructor
@Setter
@Getter
@Builder
public class AccessTokenResponse {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("token_type")
    private TokenType tokenType;

    @JsonProperty("expires_in")
    private Integer expiresIn;

//    @JsonProperty("refresh_token")
//    private String refreshToken;

    private String scope;
}
