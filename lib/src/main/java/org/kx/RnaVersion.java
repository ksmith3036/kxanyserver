package org.kx;

public enum RnaVersion {
   V0("rna1.0"),
   V1("rna1.1"),
   V2("rna1.2"),
   V3("rna1.3"),
   V4A("rna1.4a"),
   V4B("rna1.4b");

   private String value;

   private RnaVersion(String value) {
      this.value = value;
   }

   public String getValue() {
      return this.value;
   }
}
