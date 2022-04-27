package br.ufsc.labsec.openpsc.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import br.ufsc.labsec.openpsc.entity.KnetConfiguration;

@Repository
public interface KnetConfigurationRepository extends JpaRepository<KnetConfiguration, Long> {

}
