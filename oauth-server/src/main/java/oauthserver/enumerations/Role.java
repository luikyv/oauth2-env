package oauthserver.enumerations;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum Role {
    CLIENT("ROLE_CLIENT"),
    USER("ROLE_USER");

    private String roleName;
}
