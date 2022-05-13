package br.ufsc.labsec.openpsc.service.exception;

public class KNetCommunicationServiceException extends Exception {

  /**
   * 
   */
  private static final long serialVersionUID = 8164927720607350111L;

  public enum ExceptionType {
    DEFAULT("KNet configuration not initialized."), MULTIPLE_CONFIGURATIONS(
        "Multiple KNet configurations registered.");

    private String message;

    /**
     * @param message
     */
    private ExceptionType(String message) {
      this.message = message;
    }

  }

  /**
   * 
   */
  public KNetCommunicationServiceException() {
    super(ExceptionType.DEFAULT.message);
  }

  public KNetCommunicationServiceException(ExceptionType exceptionType) {
    super(exceptionType.message);
  }

}
