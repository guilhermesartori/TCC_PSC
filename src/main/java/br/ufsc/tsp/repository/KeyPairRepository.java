package br.ufsc.tsp.repository;

import java.util.Optional;

import org.springframework.context.annotation.Lazy;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import br.ufsc.tsp.entity.AppUser;
import br.ufsc.tsp.entity.KeyPair;

// TODO make find by username and identifier
@Lazy
@Repository
public interface KeyPairRepository extends JpaRepository<KeyPair, Long> {

	public Optional<KeyPair> findKeyPairByUniqueIdentifier(String uniqueIdentifier);

	public Optional<KeyPair> findKeyPairByOwnerAndUniqueIdentifier(AppUser owner, String uniqueIdentifier);

	public void deleteKeyPairByOwnerAndUniqueIdentifier(AppUser owner, String uniqueIdentifier);

	public void deleteKeyPairByUniqueIdentifier(String uniqueIdentifier);

	public boolean existsKeyPairByOwnerAndUniqueIdentifier(AppUser owner, String uniqueIdentifier);

	public boolean existsKeyPairByKeyName(String keyName);

	public boolean existsKeyPairByUniqueIdentifier(String uniqueIdentifier);

}
