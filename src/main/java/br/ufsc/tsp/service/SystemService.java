package br.ufsc.tsp.service;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.tsp.exception.SystemServiceException;
import br.ufsc.tsp.service.utility.KeyManager;

@Service
public class SystemService {

	@Autowired
	private KeyManager keyManager;

	public void createKnetConfiguration(Map<String, String> knetParameters) throws SystemServiceException {
		try {
			keyManager.setKnetConfiguration(knetParameters);
		} catch (KNetException e) {
			throw new SystemServiceException();
		}
	}

}
