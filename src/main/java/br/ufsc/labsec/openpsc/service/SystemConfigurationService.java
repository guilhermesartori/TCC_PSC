package br.ufsc.labsec.openpsc.service;

import java.util.Map;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.ufsc.labsec.openpsc.entity.AppUser;
import br.ufsc.labsec.openpsc.entity.KnetConfiguration;
import br.ufsc.labsec.openpsc.entity.enums.Authority;
import br.ufsc.labsec.openpsc.repository.KnetConfigurationRepository;
import br.ufsc.labsec.openpsc.service.exception.KNetCommunicationServiceException;
import br.ufsc.labsec.openpsc.service.exception.SystemServiceException;
import br.ufsc.labsec.openpsc.service.exception.SystemServiceException.ExceptionType;
import br.ufsc.labsec.valueobject.exception.KNetException;

@Service
@Transactional
public class SystemConfigurationService {

  @Autowired
  private AppUserService appUserService;

  @Autowired
  private KNetCommunicationService kNetCommunicationService;

  @Autowired
  private KnetConfigurationRepository knetConfigurationRepository;

  @Autowired
  private ParameterEncryptor parameterEncryptor;

  private boolean systemIsConfigured = false;

  public AppUser createAdministratorUser(String username, String password)
      throws SystemServiceException {
    if (appUserService.getAdministrator().isPresent()) {
      throw new SystemServiceException();
    }
    final var user = new AppUser(null, username, password, Authority.ADMINISTRATOR);
    final var savedUser = appUserService.saveAppUser(user);
    updateSystemConfiguredState();
    return savedUser;
  }

  public KnetConfiguration setKnetConfiguration(Map<String, String> knetParameters,
      String encryptedAccessKey) throws SystemServiceException {
    final var knetConfigurations = knetConfigurationRepository.findAll();
    KnetConfiguration knetConfiguration;
    if (knetConfigurations.size() == 0)
      knetConfiguration = new KnetConfiguration();
    else
      knetConfiguration = knetConfigurations.get(0);
    final var encryptedParameters =
        parameterEncryptor.encryptKnetParameters(knetParameters, encryptedAccessKey);
    try {
      kNetCommunicationService.setKnetConfiguration(knetParameters);
    } catch (KNetException e) {
      throw new SystemServiceException(ExceptionType.INVALID_KNET_CONFIG);
    }
    knetConfiguration.setEncryptedParameters(encryptedParameters);
    final var savedKnetConfiguration = knetConfigurationRepository.save(knetConfiguration);
    updateSystemConfiguredState();
    return savedKnetConfiguration;
  }

  public void loadKnetConfiguration(String encryptedAccessKey) throws SystemServiceException {
    try {
      kNetCommunicationService.loadKnetConfiguration(encryptedAccessKey);
    } catch (KNetException e1) {
      throw new SystemServiceException(ExceptionType.INVALID_KNET_CONFIG);
    } catch (KNetCommunicationServiceException e1) {
      throw new SystemServiceException(e1.getMessage());
    }
    updateSystemConfiguredState();
  }

  public void refreshSystemKey() {
    SystemKey.refreshKey();
  }

  public boolean isSystemConfigured() {
    return this.systemIsConfigured;
  }

  public void updateSystemConfiguredState() {
    var temp = true;
    temp = temp && appUserService.getAdministrator().isPresent();
    temp = temp && kNetCommunicationService.isKnetConfigurationLoaded();
    systemIsConfigured = temp;
  }

  public void deleteKnetConfiguration(KnetConfiguration savedKnetConfiguration) {
    knetConfigurationRepository.delete(savedKnetConfiguration);
  }

}
