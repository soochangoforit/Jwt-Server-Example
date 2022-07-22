package server.jwt.example.filter;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
// this filter is going to intercept every request that comes into the application
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    // all to login we're going to put to filter the request coming in and determine if the user has access to the application or not
    // intercept every request the comes into the application
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // the first thing is to check to see if this is not the login path , don't try to do anything here
        // just want to let it go through // todo : permit all 해야하는 url에 대해서 해당 if문에 추가하고 있다. URL 경로에 대해서 정확히 명시해야 한다 "/**" 허용X
        if(request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")) {
            filterChain.doFilter(request, response); // not going to do anything , it's just to make this filter pass thre request to the next filter and filter chain

        }
        // if it's not that case, need to start checking to see , this had an authorizatioin and then set the user as the logged in user and the security context
        // try to access the authorizatioin header.
        else{
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            // when client get tokes, client need to send the request with token, we're going to put the word "Bearer" in front of the token
            if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){

                try{

                    String token = authorizationHeader.substring("Bearer ".length()); // just need token without "Bearer"
                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes()); // use same secret here when we made token

                    // we need the alogrithm , the same secre key that we use to edcode the token and then pass that algorithm to the verifier
                    JWTVerifier verifier = JWT.require(algorithm).build(); // this is the verifier that we need to use to verify the token

                    // and then now, we can do the decoded token
                    DecodedJWT decodedJWT = verifier.verify(token); // this is the decoded token

                    // can grab user information from the decoded token
                    String username = decodedJWT.getSubject(); // this is the username that we stored in the token
                    // we don't need the password, because at this point, the user has been authenticated, and there JSON web token or their access token is valid .
                    // we just need to set them in the authentication context
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);  // todo : refresh token 만들때 role 안넣었다. if refresh token으로 요청시 role를 가져오지 못한다.

                    // we need to get those roles and convert them into something that extends GrantedAuthority
                    // Spring Security is expecting as the rules of the user, like something that extends GrantedAuthority
                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    stream(roles).forEach(role -> authorities.add(new SimpleGrantedAuthority(role))); // role is consisted with "ROLE_USER"

                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities); // 이미 인증된 사용자 이기 때문ㅇ pw는 필요 X

                    // todo : 아직까지 이러한 과정으로 토큰을 뜯어서 보아도, 사용자가 어떤 권한을 가지는지만 알지
                    //  해당 사용자가 자신 권한에게 맞는 url을 요청했는지 확인하지는 못한다.

                    // need to set this user the security context holder
                    // hey, security !! this is the user here's , their username , roles , there what that can do in the application
                    // so Spring is going to look at the user , look at their role , and determine what resources they can access
                    // and what they can access, depending on the roles.
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    filterChain.doFilter(request, response); // 계속해서 진행한다. todo : 꼭 필요하다. 다음단계로 넘어가기 위해서는

                }catch(Exception exception){

                    // need to handle exception that occured , token not valid, if it expires or somehting like that
                    // we need to send back to the user so that they know what happenns
                    log.error("Error logging in: {}" , exception.getMessage());
                    response.setHeader("error", exception.getMessage());
                    response.setStatus(FORBIDDEN.value());

                    //response.sendError(FORBIDDEN.value());

                    Map<String , String> error = new HashMap<>();
                    error.put("error_message" , exception.getMessage());
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), error); // that's going to return everything in the body

                }

            }else{
                // still need to let the request continued course, and then we pass in the request and then response
                filterChain.doFilter(request, response);
            }
        }


    }
}
