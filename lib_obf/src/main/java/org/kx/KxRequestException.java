package org.kx;

import java.io.Serial;

public class KxRequestException extends Exception {
   @Serial
   private static final long serialVersionUID = 1272374821L;

   public KxRequestException(String message) {
      super(message);
   }
}
