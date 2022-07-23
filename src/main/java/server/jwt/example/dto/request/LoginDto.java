package server.jwt.example.dto.request;

import lombok.Getter;

@Getter
public class LoginDto {

    private String username;
    private String password;
}
