package oauthserver.domain.payload;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import oauthserver.constants.TokenType;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Setter
@Getter
public class AccessTokenResponse {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("token_type")
    private TokenType tokenType;

    @JsonProperty("expires_in")
    private Long expiresIn;

    @JsonProperty("refresh_token")
    private String refreshToken;

    private List<String> scopes;
}
