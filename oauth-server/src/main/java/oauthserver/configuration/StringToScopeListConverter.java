package oauthserver.configuration;

import lombok.extern.slf4j.Slf4j;
import oauthserver.enumerations.Scope;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Component
@Slf4j
public class StringToScopeListConverter implements Converter<String, List<Scope>>  {
    @Override
    public List<Scope> convert(String source) {
        return Arrays
                .stream(source.split(" "))
                .map(s -> Scope.valueOf(s.toLowerCase()))
                .collect(Collectors.toList());
    }
}
