package server.jwt.example.manager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import server.jwt.example.security.PrincipalDetails;
import server.jwt.example.service.UserService;
import server.jwt.example.service.UserServiceImpl;

@Component
public class CustomAuthenticationManager implements AuthenticationManager {


    private final UserServiceImpl useServiceImpl;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    public CustomAuthenticationManager(UserServiceImpl useServiceImpl, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.useServiceImpl = useServiceImpl;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        // authentication에는 파라미터로 UsernamePasswordAuthenticationToken 이 들어온다.
        // UsernamePasswordAuthenticationToken 의 첫번째 파라미터에는 pricipal이 들어간다.
        // authentication.getName()은 UsernamePasswordAuthenticationToken의 첫번째 파라미터값을 가져온다.

        final PrincipalDetails principalDetails = (PrincipalDetails) useServiceImpl.loadUserByUsername(authentication.getName()); // getUsername , token 첫번째 파라미터
        // 사용자가 로그인 시점에서 입력 한 비밀번호랑, DB에서 username으로 조회한 사용자의 비밀번호랑 일치하는지 확인한다.
        if (!bCryptPasswordEncoder.matches(authentication.getCredentials().toString(), principalDetails.getPassword())) {
            throw new BadCredentialsException("Wrong password");
        }

        // 해당 UsernamePasswordAuthenticationToken 을 가지고 successAuthentication을 처리한다.
        return new UsernamePasswordAuthenticationToken(principalDetails, principalDetails.getPassword(), principalDetails.getAuthorities());
    }
}

