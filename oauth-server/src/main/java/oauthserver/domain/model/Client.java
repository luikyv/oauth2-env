package oauthserver.domain.model;

import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import java.util.Set;

@Entity
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Client {
    @Id
    private String id;

    @Column(name = "hashed_secret", nullable = false)
    private String hashedSecret;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description", nullable = false)
    private String description;

    @Column(name = "redirect_uri", nullable = false)
    private String redirectUri;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    private Set<OAuthFlowCache> oauthFlows;
}
