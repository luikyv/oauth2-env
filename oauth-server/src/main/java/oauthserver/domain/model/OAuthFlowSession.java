package oauthserver.domain.model;

import lombok.*;
import oauthserver.enumerations.CodeChallengeMethod;
import oauthserver.enumerations.Scope;

import javax.persistence.*;
import java.util.List;

@Entity
@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class OAuthFlowSession {
    @Id
    @GeneratedValue
    private Long id;

    @Column(name = "flow_cookie", nullable = false)
    private String flowCookie;

    @ManyToOne(fetch = FetchType.EAGER,  cascade=CascadeType.ALL, optional = true)
    @JoinColumn(name="user_id")
    private User user;

    @ManyToOne(fetch = FetchType.EAGER,  cascade=CascadeType.ALL)
    @JoinColumn(name="client_id")
    private Client client;

    @Column(name = "auth_code", nullable = false)
    private String authCode;

    @Column(name = "code_already_used", nullable = false)
    private boolean codeAlreadyUsed;

    @Column(name = "scopes", nullable = false)
    @ElementCollection
    private List<Scope> scopes;

    @Column(name = "state")
    private String state;

    @Column(name = "code_challenge")
    private String codeChallenge;

    @Column(name = "code_challenge_method")
    private CodeChallengeMethod codeChallengeMethod;

}
