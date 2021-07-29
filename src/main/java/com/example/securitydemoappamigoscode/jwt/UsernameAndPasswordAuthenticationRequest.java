package com.example.securitydemoappamigoscode.jwt;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@NoArgsConstructor
@Data
@ToString
public class UsernameAndPasswordAuthenticationRequest {

    private String username;
    private String password;



//    public UsernameAndPasswordAuthenticationRequest() {
//    }

//    public String getUsername() {
//        return username;
//    }
//
//    public void setUsername(String username) {
//        this.username = username;
//    }
//
//    public String getPassword() {
//        return password;
//    }
//
//    public void setPassword(String password) {
//        this.password = password;
//    }
}
