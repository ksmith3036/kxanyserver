package org.kx;

public enum RnaHeader {
   XSS(zqw.pQx(new byte[] {(byte)-64,(byte)-30,(byte)-70,(byte)9,(byte)53,(byte)-5})),
   XSK(zqw.ptk(new byte[] {(byte)-102,(byte)98,(byte)58,(byte)30,(byte)87,(byte)-98})),
   XSN(zqw.pQ3(new byte[] {(byte)85,(byte)122,(byte)34,(byte)-18,(byte)95,(byte)27})),
   XED(zqw.pRp(new byte[] {(byte)74,(byte)41,(byte)113,(byte)-5,(byte)-58,(byte)116})),
   TIMESTAMP(zqw.pN(new byte[] {(byte)-59,(byte)2,(byte)97,(byte)95,(byte)13,(byte)-16,(byte)-88,(byte)-125,(byte)119,(byte)43,(byte)-17,(byte)-54,(byte)-103,(byte)120,(byte)61,(byte)11,(byte)-17,(byte)-107,(byte)123,(byte)46,(byte)17,(byte)-6,(byte)-91,(byte)115,(byte)89,(byte)4,(byte)-22})),
   XDCC_VERIFIED(zqw.pRx(new byte[] {(byte)-7,(byte)53,(byte)77,(byte)-97,(byte)75,(byte)-49,(byte)74,(byte)-117,(byte)85,(byte)-59,(byte)111,(byte)-13,(byte)113,(byte)-3,(byte)116,(byte)-22})),
   CONTENT_TYPE(zqw.pQn(new byte[] {(byte)-68,(byte)15,(byte)76,(byte)16,(byte)-127,(byte)43,(byte)-86,(byte)81,(byte)-37,(byte)50,(byte)-37,(byte)-122,(byte)31,(byte)-70}));

   private String value;

   private RnaHeader(String value) {
      this.value = value;
   }

   public String getValue() {
      return this.value;
   }
}
