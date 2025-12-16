package org.kx;

// Fixed

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;

public class KxKeyData {
   private static final Logger _logger = LoggerFactory.getLogger(KxKeyData.class);
   private int bits;
   private PrivateKey privateKey;
   private BigInteger qinv;
   private BigInteger d;
   private BigInteger dp;
   private BigInteger dq;
   private BigInteger e;
   private BigInteger n;
   private BigInteger p;
   private BigInteger q;

   public KxKeyData(int bits, BigInteger n, BigInteger e, BigInteger d, BigInteger p, BigInteger q, BigInteger dp, BigInteger dq, BigInteger qinv) {
      this.bits = bits;
      this.n = n;
      this.e = e;
      this.d = d;
      this.p = p;
      this.q = q;
      this.dp = dp;
      this.dq = dq;
      this.qinv = qinv;

      try {
         KeyFactory factory = KeyFactory.getInstance(zqw.pQg(new byte[] {(byte)39,(byte)118,(byte)36,(byte)-98,(byte)101}), zqw.pi(new byte[] {(byte)114,(byte)-95,(byte)-29,(byte)-4}));
         RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qinv);
         this.privateKey = factory.generatePrivate(privKeySpec);
      } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException var12) {
         _logger.error(zqw.pRO(new byte[] {(byte)99,(byte)37,(byte)117,(byte)-65,(byte)28,(byte)107,(byte)-92,(byte)25,(byte)112,(byte)-99,(byte)14,(byte)104,(byte)-52,(byte)125,(byte)96,(byte)-33,(byte)39,(byte)-110,(byte)-41}), var12);
      }
   }

   public BigInteger getN() {
      return this.n;
   }

   public void setN(BigInteger n) {
      this.n = n;
   }

   public BigInteger getDq() {
      return this.dq;
   }

   public void setDq(BigInteger dq) {
      this.dq = dq;
   }

   public BigInteger getE() {
      return this.e;
   }

   public void setE(BigInteger e) {
      this.e = e;
   }

   public BigInteger getP() {
      return this.p;
   }

   public void setP(BigInteger p) {
      this.p = p;
   }

   public BigInteger getQ() {
      return this.q;
   }

   public void setQ(BigInteger q) {
      this.q = q;
   }

   public BigInteger getDp() {
      return this.dp;
   }

   public void setDp(BigInteger dp) {
      this.dp = dp;
   }

   public BigInteger getQinv() {
      return this.qinv;
   }

   @Override
   public int hashCode() {
      int prime = 31;
      int result = 1;
      result = 31 * result + this.bits;
      result = 31 * result + (this.dp == null ? 0 : this.dp.hashCode());
      result = 31 * result + (this.dq == null ? 0 : this.dq.hashCode());
      result = 31 * result + (this.e == null ? 0 : this.e.hashCode());
      result = 31 * result + (this.n == null ? 0 : this.n.hashCode());
      result = 31 * result + (this.p == null ? 0 : this.p.hashCode());
      result = 31 * result + (this.q == null ? 0 : this.q.hashCode());
      return 31 * result + (this.qinv == null ? 0 : this.qinv.hashCode());
   }

   public int getBits() {
      return this.bits;
   }

   public void setBits(int bits) {
      this.bits = bits;
   }

   @Override
   public String toString() {
      return zqw.pRb(new byte[] {(byte)-64,(byte)76,(byte)7,(byte)-68,(byte)31,(byte)-73,(byte)-31,(byte)121,(byte)-5,(byte)7,(byte)-17,(byte)35,(byte)-89,(byte)47,(byte)-101,(byte)72})
              + this.bits
              + zqw.ptg(new byte[] {(byte)77,(byte)73,(byte)101,(byte)54,(byte)-115,(byte)-115})
              + this.n
              + zqw.pux(new byte[] {(byte)33,(byte)60,(byte)16,(byte)15,(byte)83,(byte)40})
              + this.q
              + zqw.puT(new byte[] {(byte)120,(byte)108,(byte)64,(byte)67,(byte)63,(byte)108})
              + this.e
              + zqw.pQc(new byte[] {(byte)94,(byte)-46,(byte)-2,(byte)5,(byte)9,(byte)-94,(byte)112,(byte)7,(byte)-7})
              + this.qinv
              + zqw.ptz(new byte[] {(byte)-37,(byte)22,(byte)58,(byte)-16,(byte)-6,(byte)121})
              + this.p
              + zqw.pQe(new byte[] {(byte)24,(byte)38,(byte)10,(byte)91,(byte)-76,(byte)85,(byte)71})
              + this.dp
              + zqw.puT(new byte[] {(byte)-51,(byte)-127,(byte)-83,(byte)88,(byte)11,(byte)23,(byte)96})
              + this.dq
              + zqw.pRV(new byte[] {(byte)-73,(byte)105,(byte)52});
   }

   public void setQinv(BigInteger qinv) {
      this.qinv = qinv;
   }

   public BigInteger getD() {
      return this.d;
   }

   public void setD(BigInteger d) {
      this.d = d;
   }

   public PrivateKey getPrivateKey() {
      return this.privateKey;
   }

   public void setPrivateKey(PrivateKey privateKey) {
      this.privateKey = privateKey;
   }

   @Override
   public boolean equals(Object obj) {
      if (obj == null) {
         return false;
      } else if (this == obj) {
         return true;
      } else if (this.getClass() != obj.getClass()) {
         return false;
      } else {
         KxKeyData other = (KxKeyData)obj;
         if (this.bits != other.bits) {
            return false;
         } else {
            if (this.dq == null) {
               if (other.dq != null) {
                  return false;
               }
            } else if (!this.dq.equals(other.dq)) {
               return false;
            }

            if (this.dp == null) {
               if (other.dp != null) {
                  return false;
               }
            } else if (!this.dp.equals(other.dp)) {
               return false;
            }

            if (this.e == null) {
               if (other.e != null) {
                  return false;
               }
            } else if (!this.e.equals(other.e)) {
               return false;
            }

            if (this.n == null) {
               if (other.n != null) {
                  return false;
               }
            } else if (!this.n.equals(other.n)) {
               return false;
            }

            if (this.p == null) {
               if (other.p != null) {
                  return false;
               }
            } else if (!this.p.equals(other.p)) {
               return false;
            }

            if (this.q == null) {
               if (other.q != null) {
                  return false;
               }
            } else if (!this.q.equals(other.q)) {
               return false;
            }

            if (this.qinv == null) {
               if (other.qinv != null) {
                  return false;
               }
            } else if (!this.qinv.equals(other.qinv)) {
               return false;
            }

            return true;
         }
      }
   }

}
