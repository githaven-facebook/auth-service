package com.facebook.auth.service;

import com.facebook.auth.exception.AuthException;
import com.facebook.auth.exception.ErrorCode;
import com.facebook.auth.model.entity.Permission;
import com.facebook.auth.model.entity.Role;
import com.facebook.auth.model.entity.User;
import com.facebook.auth.repository.RoleRepository;
import com.facebook.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class RbacService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Transactional(readOnly = true)
    public boolean hasPermission(UUID userId, String permissionName) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));

        return user.getRoles().stream()
            .flatMap(role -> role.getPermissions().stream())
            .anyMatch(permission -> permission.getName().equals(permissionName));
    }

    @Transactional(readOnly = true)
    public boolean hasRole(UUID userId, String roleName) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));

        return user.getRoles().stream()
            .anyMatch(role -> role.getName().equals(roleName));
    }

    @Transactional(readOnly = true)
    public Set<String> getEffectivePermissions(UUID userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));

        return user.getRoles().stream()
            .flatMap(role -> role.getPermissions().stream())
            .map(Permission::getName)
            .collect(Collectors.toSet());
    }

    @Transactional(readOnly = true)
    public Set<String> getUserRoles(UUID userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));

        return user.getRoles().stream()
            .map(Role::getName)
            .collect(Collectors.toSet());
    }

    @Transactional
    public void assignRole(UUID userId, String roleName) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));

        Role role = roleRepository.findByName(roleName)
            .orElseThrow(() -> new AuthException(ErrorCode.ROLE_NOT_FOUND));

        user.getRoles().add(role);
        userRepository.save(user);
        log.info("Assigned role {} to user {}", roleName, userId);
    }

    @Transactional
    public void revokeRole(UUID userId, String roleName) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));

        Role role = roleRepository.findByName(roleName)
            .orElseThrow(() -> new AuthException(ErrorCode.ROLE_NOT_FOUND));

        user.getRoles().remove(role);
        userRepository.save(user);
        log.info("Revoked role {} from user {}", roleName, userId);
    }
}
