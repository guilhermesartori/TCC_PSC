package br.ufsc.tsp.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import br.ufsc.tsp.domain.AppUser;
import br.ufsc.tsp.domain.KeyPair;

@Repository
public interface KeyPairRepository extends JpaRepository<KeyPair, Long> {

//	@Query("SELECT kp from KeyPaur kp WHERE s.uniqueIdentifier = ?1")
	public Optional<KeyPair> findKeyPairByUniqueIdentifier(String uniqueIdentifier);

	public Optional<KeyPair> findKeyPairByOwnerAndUniqueIdentifier(AppUser owner, String uniqueIdentifier);

	public void deleteKeyPairByOwnerAndUniqueIdentifier(AppUser owner, String uniqueIdentifier);

	public void deleteKeyPairByUniqueIdentifier(String uniqueIdentifier);

	public boolean existsKeyPairByOwnerAndUniqueIdentifier(AppUser owner, String uniqueIdentifier);

	public boolean existsKeyPairByKeyName(String keyName);

	public boolean existsKeyPairByUniqueIdentifier(String uniqueIdentifier);

}
