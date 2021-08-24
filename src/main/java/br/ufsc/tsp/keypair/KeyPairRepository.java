package br.ufsc.tsp.keypair;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface KeyPairRepository extends JpaRepository<KeyPair, Long> {

//	@Query("SELECT kp from KeyPaur kp WHERE s.uniqueIdentifier = ?1")
	public Optional<KeyPair> findKeyPairByUniqueIdentifier(String uniqueIdentifier);

	public void deleteKeyPairByUniqueIdentifier(String uniqueIdentifier);

	public boolean existsKeyPairByUniqueIdentifier(String uniqueIdentifier);

}
