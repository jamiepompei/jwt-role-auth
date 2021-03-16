package com.example.demo.dao;

import com.example.demo.model.Role;
import org.springframework.data.repository.CrudRepository;

public interface RoleDao extends CrudRepository<Role, Long> {
    Role findRoleByName(String name);

}
