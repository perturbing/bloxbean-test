package org.bloxbeantest;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.cip.cip30.CIP30DataSigner;
import com.bloxbean.cardano.client.cip.cip30.DataSignature;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.util.HexUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

public class TestBloxBean {
  public static void main(String[] args) throws Exception {
    // 1) Make an account
    String mnemonic =
        "fiction sample couple hockey demise mean riot cricket garlic lady cabin fury "
            + "valve rice divorce alter stem chest vote pill favorite office tiny sand";
    Account account = new Account(Networks.testnet(), mnemonic);

    // 2) Address bytes (what CIP-30 expects in the protected header)
    byte[] addressBytes = new Address(account.baseAddress()).getBytes();

    // 3) Payload to sign (raw bytes). If you need hashed mode, set hashPayload=true below.
    byte[] payload = "Hello World".getBytes(StandardCharsets.UTF_8);

    // 4) CIP-30 signature (hashPayload=false -> embed raw payload in COSE_Sign1)
    DataSignature ds = CIP30DataSigner.INSTANCE.signData(addressBytes, payload, account, false);

    // 5) Log everything to copy it in https://verifycardanomessage.cardanofoundation.org/
    System.out.println("CIP-0030 .signData() key: " + ds.key());
    System.out.println("CIP-0030 .signData() sig: " + ds.signature());
    // The message that was signed is embedded in COSE_Sign1 when hashPayload=false
    byte[] embeddedPayload = ds.coseSign1().payload();
    System.out.println("CIP-0030 .signData() msg: " + HexUtil.encodeHexString(embeddedPayload));

    // 6) Verify locally (signature + address binding)
    boolean ok = CIP30DataSigner.INSTANCE.verify(ds);
    System.out.println("Signature valid? " + ok);

    // now we do a little round trip

    // 7) Serialize to JSON (wire format: {"signature":"<hex>","key":"<hex>"})
    ObjectMapper mapper = new ObjectMapper();
    String json = mapper.writeValueAsString(ds);
    System.out.println("DataSignature JSON: " + json);

    // 8) Deserialize on the other side and verify again
    DataSignature received = DataSignature.from(json);
    received.signature(received.signature()).key(received.key());

    boolean ok2 = CIP30DataSigner.INSTANCE.verify(received);
    System.out.println("Signature valid after round-trip? " + ok2);

    // Given a received digitaal signature as the above json file, we check that
    // the encoded pubkey hash in the addres below matched that of the hash derived
    // from the pubkey in the signature

    // ---- Extract pubkey from the received signature's COSE_Key (-2 'x' header)
    byte[] pubFromSig = received.x();
    System.out.println("pub (hex) from signature: " + HexUtil.encodeHexString(pubFromSig));

    // ---- Compare pubkey hash (blake2b-224) with payment credential from a known address
    String hardcodedEnterprise = "addr_test1vz68yh5lf6whh8lm394sfh0v4ex0whdqec2h9e2gry39wjqa3u3j7";
    Address parsed = new Address(hardcodedEnterprise);

    // 1) hash(pubkey) -> 28 bytes
    byte[] pubHash = com.bloxbean.cardano.client.crypto.Blake2bUtil.blake2bHash224(pubFromSig);
    // you can verify this hash also by dropping the address in https://cardanoscan.io/ (it will
    // show the hex value)
    System.out.println("pubkey blake2b-224 (hex): " + HexUtil.encodeHexString(pubHash));

    // 2) extract payment credential hash from the address
    Optional<byte[]> payCredHashOpt = AddressProvider.getPaymentCredentialHash(parsed);
    if (payCredHashOpt.isEmpty()) {
      System.out.println("Address has no payment credential (unexpected for enterprise/base).");
      return;
    }
    byte[] paymentCredHash = payCredHashOpt.get();
    System.out.println(
        "payment credential from address (hex): " + HexUtil.encodeHexString(paymentCredHash));

    // 3) compare
    boolean matches = Arrays.equals(pubHash, paymentCredHash);
    System.out.println("Does pubkey hash match address payment credential? " + matches);
  }
}
