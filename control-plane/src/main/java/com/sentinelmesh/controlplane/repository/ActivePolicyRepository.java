package com.sentinelmesh.controlplane.repository;
import com.sentinelmesh.controlplane.model.ActivePolicy;
import org.springframework.data.jpa.repository.JpaRepository;
public interface ActivePolicyRepository extends JpaRepository<ActivePolicy,String> {}
