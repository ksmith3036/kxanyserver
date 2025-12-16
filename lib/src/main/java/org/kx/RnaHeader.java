package org.kx;

public enum RnaHeader {
   XSS("X-SS"),
   XSK("X-SK"),
   XSN("X-SN"),
   XED("X-ED"),
   TIMESTAMP("client_request_time_stamp"),
   XDCC_VERIFIED("x-dcc-verified"),
   CONTENT_TYPE("Content-Type");

   private String value;

   private RnaHeader(String value) {
      this.value = value;
   }

   public String getValue() {
      return this.value;
   }
}
