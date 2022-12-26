package oauthserver.domain.payload;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.io.Serializable;

@Getter
@Setter
public class UserCredentials implements Serializable {
    @NotBlank
    @NotNull
    private String username;
    @NotBlank
    @NotNull
    private String password;
}
