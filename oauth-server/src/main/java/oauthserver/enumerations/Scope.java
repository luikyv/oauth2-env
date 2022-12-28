package oauthserver.enumerations;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum Scope {
    read,
    write,
    openid,
    email,
    name;
}
