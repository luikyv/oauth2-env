package oauthserver.domain.model;

import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import java.util.Set;

@Entity
@Table(name = "app_user")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class User {
    @Id
    @GeneratedValue
    private Long id;

    @Column(name = "username", nullable = false)
    private String username;

    @NotBlank
    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "hashed_password", nullable = false)
    private String hashedPassword;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    private Set<OAuthFlowSession> oauthFlows;
}
