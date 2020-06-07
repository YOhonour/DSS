package DSS;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class DSSMain {
    private Pub_Key pub_key = new Pub_Key();

    public Pub_Key getPub_key() {
        return pub_key;
    }

    public Signature getSignature() {
        return signature;
    }

    private Signature signature = new Signature();
    static final int pSizeInBits = 512;
    static final int qSizeInBits = 160;
    BigInteger x = new BigInteger("6b2cd935d0192d54e2c942b574c80102c8f8ef67",16);
    protected class Pub_Key{
        BigInteger p = new BigInteger("d411a4a0e393f6aab0f08b14d18458665b3e4dbdce2544543fe365cf71c8622412db6e7dd02bbe13d88c58d7263e90236af17ac8a9fe5f249cc81f427fc543f7",16);
        BigInteger q = new BigInteger("b20db0b101df0c6624fc1392ba55f77d577481e5",16);
        BigInteger g = new BigInteger("b3085510021f999049a9e7cd3872ce9958186b5007e7adaf25248b58a3dc4f71781d21f2df89b71747bd54b323bbecc443ec1d3e020dadabbf7822578255c104",16);
        BigInteger y = new BigInteger("b32fbec03175791df08c3f861c81df7de7e0cba7f1c4f7269bb12d6c628784fb742e66ed315754dfe38b5984e94d372537f655cb3ea4767c878cbd2d783ee662",16);

        public Pub_Key(BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
            this.p = p;
            this.q = q;
            this.g = g;
            this.y = y;
        }

        Pub_Key(){

        }
    }
    class Signature{
        public String  M;
        public BigInteger r;
        public BigInteger s;

        public Signature() {
        }

        public Signature(String  m, BigInteger r, BigInteger s) {
            M = m;
            this.r = r;
            this.s = s;
        }

        @Override
        public String toString() {
            return "Signature{\n\r" +
                    "\tM=" + M + "\n\r" +
                    "\tr=" + r.toString() + "\n\r" +
                    "\ts=" + s.toString() + "\n\r" +
                    '}';
        }
    }

    DSSMain(){
        DSSInit(this);
    }

    public DSSMain(Pub_Key pub_key, Signature signature, BigInteger x) {
        this.pub_key = pub_key;
        this.signature = signature;
        this.x = x;
    }

    public static void main(String[] args) {
        //powModCompere();
        DSSMain dssMain = new DSSMain();
        String M = "签名测试";
        Pub_Key pub_key = dssMain.getPub_key();
        Signature signature1 = dssMain.generateSignature(M);
        System.out.println("获得签名：");
        System.out.println(signature1);
        System.out.println("开始签名验证");
        dssMain.testSign(M,signature1,pub_key);

        M = M+"1";
        System.out.println();
        System.out.println("信息修改后对原签名测试，M="+M);
        dssMain.testSign(M,signature1,pub_key);

    }
    public void testSign(String M,Signature signature1,Pub_Key pub_key){
        boolean b = verifySignature(M, signature1, pub_key);
        System.out.println("待检验消息为："+M);
        System.out.println("验证结果为:"+b);
        if (b == true){
            System.out.println("接受该签名");
        }else {
            System.out.println("拒绝该签名");
        }
    }
    public Signature generateSignature(String  M){
        signature.M = M;
        BigInteger k = new BigInteger(new Random().nextInt(qSizeInBits), new SecureRandom());
        while (k.compareTo(pub_key.q) >= 0 || k.compareTo(BigInteger.ZERO) <= 0){ //保证 0 < k < q
            k = new BigInteger(new Random().nextInt(pSizeInBits), new SecureRandom());
        }
        System.out.println("K = "+k.toString(16));
        BigInteger r,s,HM = new BigInteger(SHA1(M),16);
        r = pub_key.g.modPow(k,pub_key.p).mod(pub_key.q);
        BigInteger k_reverse = modReverse(k,pub_key.q);
        s = (x.multiply(r).add(HM)).multiply(k_reverse).mod(pub_key.q);
        Signature signature = new Signature(M,r,s);
        return signature;
    }
    public boolean verifySignature(String  M,Signature signature,Pub_Key pub_key){
        BigInteger HM =  new BigInteger(SHA1(M),16);
        BigInteger w = modReverse(signature.s,pub_key.q).mod(pub_key.q);
//        System.out.println(w.toString(16));

        BigInteger u1 =HM.multiply(w).mod(pub_key.q);
//        System.out.println(u1.toString(16));

        BigInteger u2 = signature.r.multiply(w).mod(pub_key.q);
//        System.out.println(u2.toString(16));

        BigInteger gu1modp = pub_key.g.modPow(u1,pub_key.p);
//        System.out.println(gu1modp.toString(16));

        BigInteger yu2modp = pub_key.y.modPow(u2,pub_key.p);
//        System.out.println("yu2modp:"+yu2modp.toString(16));

        BigInteger v = gu1modp.multiply(yu2modp).mod(pub_key.p).mod(pub_key.q);
//        System.out.println("当前q:"+pub_key.q.toString(16));
//        System.out.println(v.toString(16));
        return signature.r.equals(v);
    }

    /**
     * 初始化 DSS初始变量
     */
    private static void DSSInit(DSSMain dssMain){
        System.out.println("开始初始化DSS系统");
        BigInteger[] q_p = generatePAndQ();
        dssMain.pub_key.q = q_p[0];
        dssMain.pub_key.p = q_p[1];
        System.out.println("p % q = "+dssMain.pub_key.p.mod(dssMain.pub_key.q));
        //生成随机h
        BigInteger h = new BigInteger(new Random().nextInt(pSizeInBits), new SecureRandom());
        //BigInteger h = new BigInteger("12");
        while (h.compareTo(dssMain.pub_key.p) >= 0 || h.compareTo(BigInteger.ONE) <= 0){ //保证 0 < h < p-1
            h = new BigInteger(new Random().nextInt(pSizeInBits), new SecureRandom());
        }
        //计算 g=h^((p-1)/q) mod p
        dssMain.pub_key.g = DSSMain.expMod(h,(dssMain.pub_key.p.subtract(BigInteger.ONE)).divide(dssMain.pub_key.q),dssMain.pub_key.p);
        //生成私钥 x
        dssMain.x = new BigInteger(new Random().nextInt(qSizeInBits), new SecureRandom());
//        dssMain.x = new BigInteger("10");
        while (dssMain.x.compareTo(dssMain.pub_key.q) >= 0 || h.compareTo(BigInteger.ONE) <= 0){ //保证 0 < h < p-1
            dssMain.x = new BigInteger(new Random().nextInt(qSizeInBits), new SecureRandom());
        }
        //计算y= g^x mod p
        dssMain.pub_key.y = dssMain.pub_key.g.modPow(dssMain.x,dssMain.pub_key.p);
        System.out.println("初始化完成！\n公钥为：");
        System.out.println("\tp="+dssMain.pub_key.p.toString(16));
        System.out.println("\tq="+dssMain.pub_key.q.toString(16));
        System.out.println("\tg="+dssMain.pub_key.g.toString(16));
        System.out.println("\ty="+dssMain.pub_key.y.toString(16));
        System.out.println("私钥为:\n\tx = "+dssMain.x);
    }
    /**
     * 使用扩展欧几里得算法求最大公因子与最后一组 a,b,x,y
     * @param a
     * @param b
     * @param ops
     * @return
     */
    private static BigInteger e_gcd(BigInteger[] a,BigInteger[] b,BigInteger ops[]){
        if (b[0].equals(BigInteger.ZERO)){
            ops[0] = new BigInteger("1");
            ops[1] = new BigInteger("0");
            return a[0];
        }
        BigInteger ans = e_gcd(b,new BigInteger[]{a[0].mod(b[0])},ops);
        BigInteger temp = ops[0];
        ops[0] = ops[1];
        ops[1] = temp.subtract(a[0].divide(b[0]).multiply(ops[1]));
        return ans;
    }

    /**
     * 根据扩展欧几里得算法计算a mod m 上的乘法逆元
     * @param a
     * @param m
     * @return
     */
    public static BigInteger modReverse(BigInteger a,BigInteger m){
        BigInteger[] ops = {BigInteger.ONE,BigInteger.ONE};
        BigInteger[] aa = {a};
        BigInteger[] mm = {m};
        BigInteger gcd = e_gcd(aa,mm,ops);
        ops[0] = ops[0].divide(gcd);
        mm[0] = mm[0].abs();
        if (ops[0].compareTo(BigInteger.ZERO) < 0){//如果小于零
            ops[0] = ops[0].add(mm[0]);
        }
        return ops[0].mod(mm[0]);
    }


    /**
     *  使用快速模幂算法求模幂值
     * @param base
     * @param exp
     * @param n
     * @return
     */
    public static BigInteger expMod(BigInteger base, BigInteger exp, BigInteger n){
        BigInteger result = new BigInteger("1");
        result = powMod(base,exp,n,result);
        return result;
    }
    private static BigInteger powMod(BigInteger base, BigInteger exp, BigInteger n, BigInteger result) {
        if (exp.equals(new BigInteger("2"))){
            int sss = 1;
        }
        if (exp.equals(BigInteger.ZERO)) {
            return BigInteger.ONE;
        }
        if (exp.equals(BigInteger.ONE)){
            return (result.multiply(base)).mod(n);
        }
        if (!exp.testBit(0)) {//如果为偶数
            return powMod((base.multiply(base)).mod(n), exp.divide(BigInteger.valueOf(2)), n,result);
        } else {//奇数
            return powMod(base, exp.subtract(BigInteger.ONE), n,(result.multiply(base)).mod(n));
        }
    }

    /**
     * 生成 p q
     * @return
     */
    private static BigInteger[] generatePAndQ() {
        SecureRandom random = new SecureRandom();


        BigInteger q = BigInteger.probablePrime(qSizeInBits, random);
        BigInteger k = BigInteger.ONE.shiftLeft(pSizeInBits - qSizeInBits); // k = 2^(pSizeInBits - qSizeInBits);

        BigInteger probablyPrime = q.multiply(k).add(BigInteger.ONE); // probablyPrime = q * k + 1
        while (!probablyPrime.isProbablePrime(5)) {
            q = BigInteger.probablePrime(qSizeInBits, random);
            probablyPrime = q.multiply(k).add(BigInteger.ONE);
        }

        BigInteger[] qAndP = new BigInteger[2];
        qAndP[0] = q;
        qAndP[1] = probablyPrime;

        return qAndP;
    }

    /*
     *对比模幂运算计算速度
     */
    public static void powModCompere(){
        System.out.println("测试模幂运算计算速度");
        BigInteger a = new BigInteger(512,5,new Random());
        BigInteger b = new BigInteger(512,5,new Random());
        BigInteger n = new BigInteger(512,5,new Random());
        long start = System.nanoTime();
        for (int i = 0; i < 10000; i++) {
            expMod(a,b,n);
        }
        double elapsed = (System.nanoTime() - start) / 1e9;
        System.out.println("a="+a);
        System.out.println("b="+b);
        System.out.println("n="+n);
        System.out.println("计算10000次模幂用时: "+elapsed+"s\n");
        long start2 = System.nanoTime();
        for (int i = 0; i < 10000; i++) {
            BigInteger result2 = a.modPow(b,n);
        }
        double elapsed2= (System.nanoTime() - start2) / 1e9;
        System.out.println("JDK用时: "+elapsed2+"s");

//////////////////////////////////////////////////////////////////
        System.out.println("测试乘法逆元计算速度");
        a = new BigInteger(160,50,new Random());
        BigInteger m = new BigInteger(512,50,new Random());
        start2 = System.nanoTime();
        BigInteger integer = BigInteger.ONE;
        BigInteger integer2 = BigInteger.ONE;
        for (int i = 0; i < 10000; i++) {
            integer = modReverse(a, m);
        }
        elapsed2= (System.nanoTime() - start2) / 1e9;
        System.out.println("a="+a);
        System.out.println("m="+m);
        System.out.println("10000次逆元运算用时: "+elapsed2+"s\n");
        System.out.println("a="+a);
        System.out.println("m="+m);
        System.out.println("逆元为"+integer);
        start2 = System.nanoTime();
        integer = BigInteger.ONE;
        for (int i = 0; i < 10000; i++) {
            integer = a.modInverse(m);
        }
        elapsed2= (System.nanoTime() - start2) / 1e9;
        System.out.println("JDK用时: "+elapsed2+"s");
    }
    private static String SHA1(String decript) {
        try {
            MessageDigest digest = java.security.MessageDigest
                    .getInstance("SHA-1");
            digest.update(decript.getBytes());
            byte messageDigest[] = digest.digest();
            // Create Hex String
            StringBuffer hexString = new StringBuffer();
            // 字节数组转换为 十六进制 数
            for (int i = 0; i < messageDigest.length; i++) {
                String shaHex = Integer.toHexString(messageDigest[i] & 0xFF);
                if (shaHex.length() < 2) {
                    hexString.append(0);
                }
                hexString.append(shaHex);
            }
            return hexString.toString();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "";
    }
}
