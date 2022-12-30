package oauthserver.domain.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

/**
 * Response to the introspection endpoint.
 */
@Builder
@AllArgsConstructor
@Setter
@Getter
public class AccessTokenIntrospectionResponse {
    private boolean active;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String scope;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("client_id")
    private String clientId;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String username;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Long exp;

}
