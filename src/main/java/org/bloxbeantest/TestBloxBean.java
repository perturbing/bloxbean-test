package org.bloxbeantest;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.cip.cip30.CIP30DataSigner;
import com.bloxbean.cardano.client.cip.cip30.DataSignature;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.util.HexUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;

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
  }
}
