package oauthserver.enumerations;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum ViewPage {
    LOGIN_PAGE("login"),
    SIGNUP_PAGE("signup"),
    ERROR_PAGE("error");

    private String name;
}
