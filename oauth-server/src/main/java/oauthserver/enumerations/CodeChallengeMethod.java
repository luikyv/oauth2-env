package oauthserver.enumerations;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum CodeChallengeMethod {
    sha256("sha256", Hashing.sha256());

    private String hashFunctionName;
    private HashFunction hashFunction;
}
