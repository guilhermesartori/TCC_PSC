package br.ufsc.labsec.openpsc.service.exception;

public class AppUserServiceException extends Exception {

  /**
   * 
   */
  private static final long serialVersionUID = -6414506226923184398L;

  public enum ExceptionType {
    DEFAULT("Error during user operation."), USERNAME_NOT_EXIST(
        "Username does not exist."), USERNAME_IN_USE("Username already in use.");

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
  public AppUserServiceException() {
    super(ExceptionType.DEFAULT.message);
  }

  public AppUserServiceException(ExceptionType exceptionType) {
    super(exceptionType.message);
  }

}
