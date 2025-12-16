package org.kx;

import java.io.Serial;

public class KxRequestEntityTooLargeException extends Exception {
   @Serial
   private static final long serialVersionUID = 571342L;

   public KxRequestEntityTooLargeException(String message) {
      super(message);
   }
}
