package br.ufsc.labsec.openpsc.repository;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import br.ufsc.labsec.openpsc.entity.AppUser;
import br.ufsc.labsec.openpsc.entity.KeyPair;

@Repository
public interface KeyPairRepository extends JpaRepository<KeyPair, Long> {

  public Optional<KeyPair> findKeyPairByUniqueIdentifier(String uniqueIdentifier);

  public Optional<KeyPair> findKeyPairByOwnerAndUniqueIdentifier(AppUser owner,
      String uniqueIdentifier);

  @Query("select k from KeyPair k join k.owner u where u.username = :username and k.uniqueIdentifier = :uniqueIdentifier")
  public Optional<KeyPair> findKeyPairByOwnerUsernameAndUniqueIdentifier(String username,
      String uniqueIdentifier);

  @Query("select k from KeyPair k join k.owner u where u.username = :username and k.keyName = :keyName")
  public Optional<KeyPair> findKeyPairByOwnerUsernameAndKeyName(String username, String keyName);

  public void deleteKeyPairByOwnerAndUniqueIdentifier(AppUser owner, String uniqueIdentifier);

  public void deleteKeyPairByUniqueIdentifier(String uniqueIdentifier);

  public boolean existsKeyPairByOwnerAndUniqueIdentifier(AppUser owner, String uniqueIdentifier);

  public boolean existsKeyPairByKeyName(String keyName);

  public boolean existsKeyPairByUniqueIdentifier(String uniqueIdentifier);

  @Query("select k from KeyPair k join k.owner u where u.username = :username")
  public List<KeyPair> findKeyPairByOwnerUsername(String username);

}
