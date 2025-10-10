package org.bloxbeantest;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.cip.cip30.CIP30DataSigner;
import com.bloxbean.cardano.client.cip.cip30.DataSignature;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.crypto.bip39.MnemonicCode;
import com.bloxbean.cardano.client.util.HexUtil;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.List;
import java.util.concurrent.*;

public class TestBloxBean {
  private static final byte[] PAYLOAD = ("I agree to abide by the terms and conditions as described in version 1-0 of the Midnight scavenger mining process: 281ba5f69f4b943e3fb8a20390878a232787a04e4be22177f2472b63df01c200"
  ).getBytes(StandardCharsets.UTF_8);

  public static void main(String[] args) throws Exception {
    // Defaults
    long count = 1_000_000L;
    int threads = Math.max(1, Runtime.getRuntime().availableProcessors());
    Path out = Paths.get("runs.csv");

    // Parse CLI flags: --count N --threads N --out path.csv
    for (int i = 0; i < args.length; i++) {
      switch (args[i]) {
        case "--count":   count = Long.parseLong(args[++i]); break;
        case "--threads": threads = Integer.parseInt(args[++i]); break;
        case "--out":     out = Paths.get(args[++i]); break;
        default:          throw new IllegalArgumentException("Unknown arg: " + args[i]);
      }
    }

    // Writer (single file, synchronized writes)
    try (BufferedWriter bw = Files.newBufferedWriter(out, StandardCharsets.UTF_8,
            StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
      bw.write("Address, sig, pubkey");
      bw.newLine();

      final Object lock = new Object();
      final ThreadLocal<SecureRandom> rng = ThreadLocal.withInitial(SecureRandom::new);

      ExecutorService pool = Executors.newFixedThreadPool(threads);
      CompletionService<String> cs = new ExecutorCompletionService<>(pool);

      for (long i = 0; i < count; i++) {
        cs.submit(() -> {
          // 256-bit entropy -> 24-word mnemonic
          byte[] entropy = new byte[32];
          rng.get().nextBytes(entropy);
          List<String> words = MnemonicCode.INSTANCE.toMnemonic(entropy);
          String mnemonic = String.join(" ", words);

          Account account = new Account(Networks.testnet(), mnemonic);

          // pubkey (payment key), base address, CIP-30 signature
          byte[] pub = account.publicKeyBytes();
          String pubHex = HexUtil.encodeHexString(pub);

          Address baseAddrObj = new Address(account.baseAddress());
          byte[] addressBytesBase = baseAddrObj.getBytes();

          DataSignature ds = CIP30DataSigner.INSTANCE.signData(addressBytesBase, PAYLOAD, account, false);

          // CSV line
          return baseAddrObj.toBech32() + "," + ds.signature() + "," + pubHex;
        });
      }

      // Drain results and write as they complete
      for (long i = 0; i < count; i++) {
        try {
          Future<String> f = cs.take();
          String line = f.get(); // propagate exceptions if any
          if (line != null && !line.isEmpty()) {
            synchronized (lock) {
              bw.write(line);
              bw.newLine();
            }
          }
        } catch (ExecutionException ee) {
          // Skip failed run but keep going
          // You can log ee.getCause() if you want to debug.
        }
      }

      pool.shutdown();
      pool.awaitTermination(7, TimeUnit.DAYS);
    }
    System.out.println("Done -> " + out.toAbsolutePath());
  }
}
