package com.facebook.auth.repository;

import com.facebook.auth.model.entity.OAuthClient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OAuthClientRepository extends JpaRepository<OAuthClient, String> {

    Optional<OAuthClient> findByClientIdAndActiveTrue(String clientId);
}
