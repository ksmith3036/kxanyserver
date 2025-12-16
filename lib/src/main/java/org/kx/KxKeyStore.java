package org.kx;

// Fixed

public class KxKeyStore {

   public KxKeyStore(String key, String encoder, String alias) {

       this.key = key;
       this.encoder = encoder;
       this.alias = alias;
   }

   private String key;
   private String encoder;
   private String alias;

   public String getKey() {
      return this.key;
   }

   public String getEncder() {
      return this.encoder;
   }

   public String getAlias() {
      return this.alias;
   }

}
