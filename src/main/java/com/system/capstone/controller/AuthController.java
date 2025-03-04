package com.system.capstone.controller;


import com.system.capstone.dto.ResponseDTO;
import com.system.capstone.exceptions.UserNotFoundException;
import com.system.capstone.model.User;
import com.system.capstone.security.JwtFilter;
import com.system.capstone.security.JwtUtil;
import com.system.capstone.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);
    private final UserService userService;
    private final JwtUtil jwtUtil;


    public AuthController(UserService userService, JwtUtil jwtUtil){
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/auth/register")
    public ResponseEntity<?> register(@Valid @RequestBody User user){
        try{
            User registeredUser = userService.registerUser(user);

            return ResponseEntity.ok(
                    new ResponseDTO<User>("Registered User!",HttpStatus.CREATED,registeredUser)
            );
        }catch (UserNotFoundException e){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                    new ResponseDTO<>(e.getMessage(), HttpStatus.NOT_FOUND,null)
            );
        }
        catch (RuntimeException e){
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/auth/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        try{
            User loggedInUser = this.userService.loginUser(user);

            if(loggedInUser == null){
                throw new UserNotFoundException("Invalid Credentials");
            }

            String role = loggedInUser.getRole();
            String token = jwtUtil.generateToken(loggedInUser.getUsername(), role);

            Map<String, String> response = new HashMap<>();
            response.put("token", token);

            return ResponseEntity.status(HttpStatus.OK)
                    .body(new ResponseDTO<Map<String,String>>("User Logged In Successfully",HttpStatus.OK,response));

        }catch (UserNotFoundException e){
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ResponseDTO<>(e.getMessage(),HttpStatus.NOT_FOUND,null));
        }catch (RuntimeException e){
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }


    @GetMapping("/api/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getAllUsersADMIN(){
        try{
            List<User> userList = this.userService.getAllUsers();
            return ResponseEntity.status(HttpStatus.OK)
                    .body(new ResponseDTO<List<User>>(
                            "Successfully fetched list of users",
                            HttpStatus.OK,
                            userList
                    ));
        }catch (RuntimeException e){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ResponseDTO<>(e.getMessage(),HttpStatus.BAD_REQUEST,null));
        }
    }

    @GetMapping("/api/user/users")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> getAllUsersUSER(){
        try{
            List<User> userList = this.userService.getAllUsers();
            return ResponseEntity.status(HttpStatus.OK)
                    .body(new ResponseDTO<List<User>>(
                            "Successfully fetched list of users",
                            HttpStatus.OK,
                            userList
                    ));
        }
        catch (RuntimeException e){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ResponseDTO<>(e.getMessage(),HttpStatus.BAD_REQUEST,null));
        }
    }
}