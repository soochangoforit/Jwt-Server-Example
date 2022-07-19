package server.jwt.example.service;

import server.jwt.example.domain.AppUser;
import server.jwt.example.domain.Role;

import java.util.List;

public interface UserServoce {

    AppUser saveUser(AppUser user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    AppUser getUser(String username);
    List<AppUser> getUsers();


}
