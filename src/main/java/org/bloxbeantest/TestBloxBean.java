package org.bloxbeantest;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.cip.cip30.CIP30DataSigner;
import com.bloxbean.cardano.client.cip.cip30.DataSignature;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.util.HexUtil;
import java.nio.charset.StandardCharsets;

public class TestBloxBean {
  public static void main(String[] args) throws Exception {
    // 1) Make an account
    String mnemonic =
        "fiction sample couple hockey demise mean riot cricket garlic lady cabin fury "
            + "valve rice divorce alter stem chest vote pill favorite office tiny sand";
    Account account = new Account(Networks.testnet(), mnemonic);

    // 2) Payload to sign
    byte[] payload =
        "I agree to abide by the terms and conditions as described in version 1-0 of the Midnight scavenger mining process: fefe36bf8e5fb4616cc568a8d7ba20ab70cabf2e87b8f86aecb96b02d83ed48f"
            .getBytes(StandardCharsets.UTF_8);

    // 3) The pubkey of the address (that is used for signing)
    // this is encode in the first part of the address (the payment credential)
    byte[] pub = account.publicKeyBytes();
    System.out.println("Pubkey: " + HexUtil.encodeHexString(pub));

    // 4a) Address bytes of the base address with a staking key in it
    Address baseAddrObj = new Address(account.baseAddress());
    byte[] addressBytesBase = baseAddrObj.getBytes();

    // 5a) CIP-30 signature for the base address (with staking key)
    DataSignature ds = CIP30DataSigner.INSTANCE.signData(addressBytesBase, payload, account, false);

    // 6a) Log everything of the base address
    System.out.println("\n--- Base address signing ---");
    System.out.println("Base address: " + baseAddrObj.toBech32());
    System.out.println("CIP-0030 .signData() sig: " + ds.signature());

    //////////////////////////////////// enterprise address example
    // ////////////////////////////////////

    // 4b) Address bytes of the enterprise address (without staking key in it)
    Address enterpriseAddrObj = new Address(account.enterpriseAddress());
    byte[] addressBytesEnterprise = enterpriseAddrObj.getBytes();

    // 5b) CIP-30 signature for the enterprise address (without staking key)
    DataSignature dsEnt =
        CIP30DataSigner.INSTANCE.signData(addressBytesEnterprise, payload, account, false);

    // 6b) Log everything of the enterprise address signing
    System.out.println("\n--- Enterprise address signing ---");
    System.out.println("Enterprise address: " + enterpriseAddrObj.toBech32());
    System.out.println("CIP-0030 .signData() sig: " + dsEnt.signature());
  }
}
