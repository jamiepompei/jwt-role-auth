package com.example.demo.service;

import com.example.demo.model.User;
import com.example.demo.model.UserDto;

import java.util.List;

public interface UserService {
    User save(UserDto user);
    List<User> findAll();
    User findOne(String username);
}
