package oauthserver.domain.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;


@AllArgsConstructor
@Getter
@Setter
public class ClientDTO {
    @JsonProperty("client_id")
    @NotBlank
    @NotNull
    private String clientId;

    @NotBlank
    @NotNull
    private String secret;

    @NotBlank
    @NotNull
    private String name;

    @NotBlank
    @NotNull
    private String description;

    @JsonProperty("redirect_uri")
    @NotBlank
    @NotNull
    private String redirectUri;
}
