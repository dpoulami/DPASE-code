/*
 * inspiration from
 * https://www.javacodegeeks.com/2016/12/adding-microbenchmarking-build-process.html
 * and
 * https://www.mkyong.com/java/java-jmh-benchmark-tutorial/
 */

package benchmark;

import java.util.*;
import java.util.concurrent.TimeUnit;

import org.apache.milagro.amcl.BLS461.*;
import client.DPASEClient;
import client.interfaces.UserClient;
import org.apache.milagro.amcl.RAND;
import server.DPASESP;
import server.interfaces.Storage;
import server.storage.InMemoryDPASEDatabase;


public class Benchmark {


    private static final int ITERATIONS = 100;
    private static final int WARMUP = 20;
    private static int SERVERCOUNT = 10;

    private static String user = "username";
    private static String password = "password";
    private static UserClient client;


    public static void main(String[] args) throws Exception {

        List<DPASESP> dpasesps = new ArrayList<>();
        setup(dpasesps);
        ArrayList<List> times;

        System.out.println("Executing " + ITERATIONS + " time each with " + WARMUP + " warmups");

        times = benchmarkCreateUser();
        System.out.println("Creating user time: client took " + TimeUnit.NANOSECONDS.toMillis(avg(times.get(0))) + " ms, server took:" + TimeUnit.NANOSECONDS.toMillis(avg(times.get(1))) + " ms");

        times= benchmarkEncDecRequest();
        System.out.println("User authenticate + Enc/Dec time: client took " + TimeUnit.NANOSECONDS.toMillis(avg(times.get(0))) + " ms, server took:" + TimeUnit.NANOSECONDS.toMillis(avg(times.get(1))) + " ms");
    }


    private static void setup(List<DPASESP> dpasesps) throws Exception {
        int serverCount = SERVERCOUNT;
        long startTime = System.currentTimeMillis();
        BIG[] serversecrets = new BIG[serverCount];
        RAND rng = new RAND();

        for (int i = 0; i < serverCount; i++) {
            serversecrets[i] = BIG.random(rng);
            Storage storage = InMemoryDPASEDatabase.getInstance();
            DPASESP dp = new DPASESP(storage, i);
            dpasesps.add(i, dp);
        }

        for (int i = 0; i < serverCount; i++) {
            try {
                System.out.println("setting up server " + i);
                long s1 = System.currentTimeMillis();
                DPASESP dpasesp = dpasesps.get(i);
                dpasesp.setup(serversecrets[i]);


                System.out.println("finished with server " + i + "(" + (System.currentTimeMillis() - s1) + ")");
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Failed to start IdP");
            }

        }
        client = new DPASEClient(dpasesps);
        System.out.println("setup took " + (System.currentTimeMillis() - startTime) + " ms");
    }

    private static long avg(List<Long> times) {
        long sum = 0;
        for (int i = 0; i < times.size(); i++) {
            sum += times.get(i);
        }
        return sum / times.size();
    }

    private static double std(List<Long> times) {
        double avg = avg(times);
        double squaredDiff = 0.0;
        double sum = 0;
        for (int i = 0; i < times.size(); i++) {
            squaredDiff += (avg - times.get(i).doubleValue()) * (avg - times.get(i).doubleValue());
        }
        return Math.sqrt(squaredDiff / times.size());
    }

    private static ArrayList<List> benchmarkCreateUser() throws Exception {

        int Servercount = SERVERCOUNT;
        List<Long> clientTime = new ArrayList<>(ITERATIONS);
        List<Long> serverTime = new ArrayList<>(ITERATIONS);
        ArrayList<List> timeTupleList = new ArrayList<>();
        for (int i = 0; i <= ITERATIONS + WARMUP; i++)
        {
            long start_time = java.lang.System.nanoTime();
            RAND rng = new RAND();
            BIG r_1 = BIG.random(rng);
            long time = client.createUserAccount(user + i, password, r_1);
            long end_time = java.lang.System.nanoTime();
            Thread.sleep(20);
            if (i > WARMUP) {
                clientTime.add(end_time - start_time - SERVERCOUNT*time);
                serverTime.add(time);
            }

        }
        timeTupleList.add(clientTime);
        timeTupleList.add(serverTime);
        return timeTupleList;

    }

    private static ArrayList<List> benchmarkEncDecRequest() throws Exception {

        boolean flag=true;
        int length = 1600;
        int Servercount = SERVERCOUNT;
        byte[] message = new byte[length];
        for(int len=0;len<length;len++)
            message[len]=(byte)len;

        List<Long> clientTime = new ArrayList<>(ITERATIONS);
        List<Long> serverTime = new ArrayList<>(ITERATIONS);
        ArrayList<List> timeTupleList = new ArrayList<>();
        for (int i = 0; i <= ITERATIONS + WARMUP; i++)
        {
            RAND rng = new RAND();
            BIG r_1 = BIG.random(rng);
            long start_time = java.lang.System.nanoTime();
            rng = new RAND();
            BIG r_2 = BIG.random(rng);
            long time = client.EncDecRequest(user + i, password, message,flag,r_1, r_2);
            long end_time = java.lang.System.nanoTime();
            Thread.sleep(20);
            if (i > WARMUP) {
                clientTime.add(end_time - start_time - SERVERCOUNT*time);
                serverTime.add(time);
            }
        }
        timeTupleList.add(clientTime);
        timeTupleList.add(serverTime);
        return timeTupleList;

    }
}
