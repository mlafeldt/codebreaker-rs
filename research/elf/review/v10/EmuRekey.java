import java.math.BigInteger;
public class EmuRekey extends EmuP {
 @Override public void run() throws Exception {
  long[] im=IMAGES.get("v10");
  RESET=im[0];DECRYPT=im[1];MEMSET=im[2];MEMCPY=im[3];INV=im[4];MUL=im[5];RSA=im[6];RSA_N=im[7];MODE=im[8];LINES=im[9];V1=im[10];BF=im[11];OPT=im[12];KEY=im[13];KC=im[14];SEEDS=im[15];
  for(long val:new long[]{0L,0x01020304L}) {
   reset();where="rekey-"+val;call(RESET);
   emu.writeMemory(addr(BUF),le(0xb4336fa9L,0x4dfefb79L));emu.writeRegister("a0",BigInteger.valueOf(BUF));emu.writeRegister("a1",BigInteger.valueOf(BUF+4));call(DECRYPT);
   emu.writeRegister("a0",BigInteger.ZERO);emu.writeRegister("a1",BigInteger.valueOf(val));call(0x104660L);
   println(String.format("REKEY val=%08X %s",val,state()));
  }
  emu.dispose();
 }
}
