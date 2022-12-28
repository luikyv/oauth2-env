package oauthserver.domain.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
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

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("id_token")
    private String idToken;

    @JsonProperty("token_type")
    private TokenType tokenType;

    @JsonProperty("expires_in")
    private Integer expiresIn;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("refresh_token")
    private String refreshToken;

    private String scope;
}
