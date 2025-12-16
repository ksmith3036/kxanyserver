package org.kx;

import java.io.Serial;

public class KxDataEncryptException extends Exception {
   @Serial
   private static final long serialVersionUID = -1312345678901234567L;

   public KxDataEncryptException() {
   }

   public KxDataEncryptException(String message) {
      super(message);
   }

   public KxDataEncryptException(Exception cause) {
      super(cause);
   }

   public KxDataEncryptException(String message, Exception cause) {
      super(message, cause);
   }
}
