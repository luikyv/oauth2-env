package oauthserver.domain.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

/**
 * User information to be return in the <code>/user_info</code> endpoint.
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class UserInfoResponse {
    private String username;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String email;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String name;
}
