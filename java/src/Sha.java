import utils.SHA1;

public class Sha {
    public static void main(String[] args) throws Exception {
        String signature = SHA1.getSHA1("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG","1569293758","5Ehivc","2RxnU1A7lrsmK8YgOgFIUEJ4swj/rJ+M5K1qGYlVK4kkcaXBYNXok2fhv9SRRNZcFKc400Yv6mALeOQDurKVjg==");
        System.out.println(signature);
    }
}
