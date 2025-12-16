package org.kx;

public enum RnaVersion {
   V0(zqw.pQG(new byte[] {(byte)52,(byte)-16,(byte)-126,(byte)60,(byte)-43,(byte)39,(byte)86,(byte)-22})),
   V1(zqw.puU(new byte[] {(byte)70,(byte)-86,(byte)-40,(byte)-52,(byte)-5,(byte)-93,(byte)-92,(byte)-77})),
   V2(zqw.pRY(new byte[] {(byte)5,(byte)-20,(byte)-98,(byte)24,(byte)97,(byte)-69,(byte)58,(byte)-84})),
   V3(zqw.puz(new byte[] {(byte)-17,(byte)56,(byte)74,(byte)67,(byte)67,(byte)38,(byte)34,(byte)50})),
   V4A(zqw.pRy(new byte[] {(byte)-69,(byte)-53,(byte)-71,(byte)39,(byte)-90,(byte)116,(byte)-19,(byte)117,(byte)-34})),
   V4B(zqw.pRu(new byte[] {(byte)-41,(byte)68,(byte)54,(byte)-48,(byte)89,(byte)-125,(byte)2,(byte)-110,(byte)66}));

   private String value;

   private RnaVersion(String value) {
      this.value = value;
   }

   public String getValue() {
      return this.value;
   }
}
