package org.kx;

// Fixed

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

public class KxByteArrayResponseWrapper extends HttpServletResponseWrapper {
   KxByteArrayResponseWrapper.ServletOutputStreamImpl sosi = null;
   PrintWriter printWriter = null;
   private ByteArrayOutputStream baos;

   public KxByteArrayResponseWrapper(HttpServletResponse response) {
      super(response);
      this.baos = new ByteArrayOutputStream();
   }

   public byte[] getOutputBytes() {
      if (this.printWriter != null) {
         this.printWriter.flush();
      }

      return this.baos.toByteArray();
   }

   public PrintWriter getWriter() {
      if (this.printWriter == null) {
         this.printWriter = new PrintWriter(this.baos, true);
      }

      return this.printWriter;
   }

   class ServletOutputStreamImpl extends ServletOutputStream {
      private final OutputStream out;

      public ServletOutputStreamImpl(OutputStream out) {
         this.out = out;
      }

      public void write(int b) throws IOException {
         this.out.write(b);
      }

      public void flush() throws IOException {
         this.out.flush();
      }

      public boolean isReady() {
         return false;
      }

      public void setWriteListener(WriteListener writeListener) {
      }
   }

   public ServletOutputStream getOutputStream() {
      if (this.sosi == null) {
         this.sosi = new ServletOutputStreamImpl(this.baos);
      }

      return this.sosi;
   }

}
