package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	bp "server/bulletproof/src"
	"server/util"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"

	"github.com/ZZMarquis/gm/sm2"
)

type Electricity struct {
	ID string `json:"id"`
	// Owner  string `json:"owner"`
	Price  int64 `json:"price"`
	Amount int   `json:"amount"`
}
type Asset struct {
	Name   string `json:"name"`
	Wallet string `json:"wallet"`
}
type Wallet struct {
	Balance string `json:"balance"`
}
type CiperBalance struct {
	Initiator string `json:"initiator"`
	Recipient string `json:"recipient"`
	Price     string `json:"price"`
}

/*
Initiator: Initiator pub
Recipient: Recipient pub
OrderNum: ordernum
VerifySign: verifysign
*/
type Identity struct {
	Initiator  string `json:"initiator"`
	Recipient  string `json:"recipient"`
	OrderNum   string `json:"ordernum"`
	VerifySign string `json:"verifysign"`
}
type Transaction struct {
	ID          string `json:"id"`
	Ciper_Price string `json:"ciper_price"`
	Amount      int    `json:"amount"`
}
type Bill struct {
	ID         string `json:"id"`
	Transferor string `json:"transferor"`
	Collector  string `json:"collector"`
}

func main() {
	log.Println("============ application-golang starts ============")

	err := os.Setenv("DISCOVERY_AS_LOCALHOST", "true")
	if err != nil {
		log.Fatalf("Error setting DISCOVERY_AS_LOCALHOST environemnt variable: %v", err)
	}

	wallet, err := gateway.NewFileSystemWallet("wallet")
	if err != nil {
		log.Fatalf("Failed to create wallet: %v", err)
	}

	if !wallet.Exists("appUser") {
		err = populateWallet(wallet)
		if err != nil {
			log.Fatalf("Failed to populate wallet contents: %v", err)
		}
	}

	ccpPath := filepath.Join(
		"..",
		"..",
		"go",
		"src",
		"github.com",
		"hyperledger",
		"fabric-samples",
		"test-network",
		"organizations",
		"peerOrganizations",
		"org1.example.com",
		"connection-org1.yaml",
	)

	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromFile(filepath.Clean(ccpPath))),
		gateway.WithIdentity(wallet, "appUser"),
	)
	if err != nil {
		log.Fatalf("Failed to connect to gateway: %v", err)
	}
	defer gw.Close()

	network, err := gw.GetNetwork("mychannel")
	if err != nil {
		log.Fatalf("Failed to get network: %v", err)
	}

	contract := network.GetContract("basic")

	log.Println("---初始化账本---")
	log.Println("--> Submit Transaction: InitLedger, function creates the initial set of user on the ledger")
	result, err := contract.SubmitTransaction("InitLedger")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))
	log.Println()

	log.Println("---测试Hello函数---")
	log.Println("--> Submit Transaction: Hello, function return hello")
	result, err = contract.SubmitTransaction("Hello")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))

	log.Println("---测试SetAsset函数--Alice---")
	log.Println("--> Submit Transaction: SetAsset, creates new publickey with alice_pub_str for Alice")
	log.Println("将密钥上链保存...")
	alice_pri_str, alice_pub_str, err := util.MyGenerateKey()
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	result, err = contract.SubmitTransaction("SetAsset", "Alice", alice_pub_str)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println("SetAsset Alice result", string(result))

	log.Println("---测试SetAsset函数--Bob---")
	log.Println("--> Submit Transaction: SetAsset, creates new publickey with bob_pub_str for Bob")
	bob_pri_str, bob_pub_str, err := util.MyGenerateKey()
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	result, err = contract.SubmitTransaction("SetAsset", "Bob", bob_pub_str)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println("SetAsset Bob result", string(result))

	log.Println("---测试SetAsset函数--Monitor---")
	log.Println("--> Submit Transaction: SetAsset, creates new publickey with bob_pub_str for Bob")
	monitor_pri_str, monitor_pub_str, err := util.MyGenerateKey()
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	result, err = contract.SubmitTransaction("SetAsset", "Monitor", monitor_pub_str)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println("SetAsset Monitor result", string(result))

	log.Println("---测试GetAsset函数--Alice---")
	log.Println("--> Submit Transaction: GetAsset, function return Alice")
	log.Println("获取转账方公钥...")
	alice_result, err := contract.EvaluateTransaction("GetAsset", "Alice")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println("alice-pub:", string(alice_result))

	var alice Asset
	if err := json.Unmarshal(alice_result, &alice); err != nil {
		log.Fatalf("Failed to Unmarshal alice_result: %v", err)
	}

	log.Println("---测试GetAsset函数--Bob---")
	log.Println("--> Submit Transaction: GetAsset, function return Bob")
	log.Println("获取接收方公钥...")
	bob_result, err := contract.EvaluateTransaction("GetAsset", "Bob")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println("bob-pub:", string(bob_result))

	var bob Asset
	if err := json.Unmarshal(bob_result, &bob); err != nil {
		log.Fatalf("Failed to Unmarshal bob_result: %v", err)
	}

	log.Println("获取监管中心公钥...")
	monitor_result, err := contract.EvaluateTransaction("GetAsset", "Bob")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println("monitor-pub:", string(bob_result))

	var monitor Asset
	if err := json.Unmarshal(monitor_result, &monitor); err != nil {
		log.Fatalf("Failed to Unmarshal monitor_result: %v", err)
	}

	log.Println("---测试获取所有Electricity---")
	log.Println("--> Submit Transaction: GetAllElectricity, function return []*Electricity")
	result, err = contract.EvaluateTransaction("GetAllElectricity")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))

	log.Println("---测试获取Electricity---")
	log.Println("--> Submit Transaction: GetElectricity, function return *Electricity")
	result, err = contract.EvaluateTransaction("GetElectricity", "10000")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	var electricity Electricity
	if err := json.Unmarshal(result, &electricity); err != nil {
		log.Fatalf("Failed to unmarshal electricity data: %v", err)
	}
	log.Println(string(result))

	log.Println("---Decode Alice private_key---")
	alice_pri_bytes := base64ToPrivateKey(alice_pri_str)
	var alice_pri *sm2.PrivateKey
	if err := json.Unmarshal(alice_pri_bytes, &alice_pri); err != nil {
		log.Fatalf("Failed to decode private_key: %v", err)
	}
	log.Println("alice-private-key:", alice_pri)

	log.Println("---Decode Alice public_key---")
	alice_pub_bytes := base64ToPrivateKey(alice.Wallet)
	var alice_pub *sm2.PublicKey
	if err := json.Unmarshal(alice_pub_bytes, &alice_pub); err != nil {
		log.Fatalf("Failed to decode public_key: %v", err)
	}
	log.Println("alice-public-key:", alice_pub)

	log.Println("---Decode Bob private_key---")
	bob_pri_bytes := base64ToPrivateKey(bob_pri_str)
	var bob_pri *sm2.PrivateKey
	if err := json.Unmarshal(bob_pri_bytes, &bob_pri); err != nil {
		log.Fatalf("Failed to decode private_key: %v", err)
	}
	log.Println("bob-private-key:", bob_pri)

	log.Println("---Decode Bob public_key---")
	bob_pub_bytes := base64ToPrivateKey(bob.Wallet)
	var bob_pub *sm2.PublicKey
	if err := json.Unmarshal(bob_pub_bytes, &bob_pub); err != nil {
		log.Fatalf("Failed to decode public_key: %v", err)
	}
	log.Println("bob-public-key:", bob_pub)

	log.Println("---Decode Monitor private_key---")
	monitor_pri_bytes := base64ToPrivateKey(monitor_pri_str)
	var monitor_pri *sm2.PrivateKey
	if err := json.Unmarshal(monitor_pri_bytes, &monitor_pri); err != nil {
		log.Fatalf("Failed to decode private_key: %v", err)
	}
	log.Println("monitor-private-key:", monitor_pri)

	log.Println("---Decode Monitor public_key---")
	monitor_pub_bytes := base64ToPrivateKey(monitor.Wallet)
	var monitor_pub *sm2.PublicKey
	if err := json.Unmarshal(monitor_pub_bytes, &monitor_pub); err != nil {
		log.Fatalf("Failed to decode public_key: %v", err)
	}
	log.Println("monitor-public-key:", monitor_pub)

	log.Println("---Crypto Alice balance---")
	alice_balance_cipertext, err := encryptBalance(1000, alice_pub)
	if err != nil {
		log.Fatalf("Failed to encrypt alice Balance: %v", err)
	}
	result, err = contract.SubmitTransaction("SetBalance", alice.Wallet, alice_balance_cipertext)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))

	log.Println("---Crypto Bob balance---")
	bob_balance_cipertext, err := encryptBalance(1000, bob_pub)
	if err != nil {
		log.Fatalf("Failed to encrypt bob Balance: %v", err)
	}
	result, err = contract.SubmitTransaction("SetBalance", bob.Wallet, bob_balance_cipertext)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))

	log.Println("---测试获取 Alice Balance---")
	log.Println("--> Submit Transaction: GetWallet, function return *Wallet")
	result, err = contract.EvaluateTransaction("GetWallet", alice.Wallet)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	var alice_wallet Wallet
	if err := json.Unmarshal(result, &alice_wallet); err != nil {
		log.Fatalf("Failed to unmarshal Assest data: %v", err)
	}
	log.Println("Alice balance:", string(result))

	log.Println("---测试获取 Bob Balance---")
	log.Println("--> Submit Transaction: GetWallet, function return *Wallet")
	result, err = contract.EvaluateTransaction("GetWallet", bob.Wallet)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	var bob_wallet Wallet
	if err := json.Unmarshal(result, &bob_wallet); err != nil {
		log.Fatalf("Failed to unmarshal Assest data: %v", err)
	}
	log.Println("Bob balance:", string(result))

	log.Println("---测试发起交易提案---")
	log.Println("--> InitiateTranscation, function return cipertext")
	// 使用bytes.Buffer来存储转换后的字节
	log.Println("交易发起...")
	var buf bytes.Buffer
	// 将int64类型的num写入buffer中
	if err := binary.Write(&buf, binary.BigEndian, electricity.Price); err != nil {
		log.Fatalf("binary.Write failed: %v", err)
	}
	bob_price_cipertext, err := util.InitiateTranscation(buf.Bytes(), bob_pub)
	if err != nil {
		log.Fatalf("Failed to InitiateTranscation: %v", err)
	}
	log.Println("bob_price_cipertext = ", bob_price_cipertext)

	//controduct transcation submit
	log.Println("---controduct transcation---")
	transaction := Transaction{
		ID:          electricity.ID,
		Ciper_Price: bob_price_cipertext,
		Amount:      electricity.Amount,
	}
	transaction_bytes, err := json.Marshal(transaction)
	if err != nil {
		log.Fatalf("Failed to Marshal transaction: %v", err)
	}
	log.Println(string(transaction_bytes))

	// send transcation => Bob
	log.Println("---测试确认交易提案---")
	log.Println("--> VerifyTranscation, function return verify")
	verify_res, err := util.VerifyTranscation(bob_price_cipertext, bob_pri_str, electricity.Price)
	if err != nil {
		log.Fatalf("Failed to VerifyTranscation: %v", err)
	}
	log.Println(verify_res)

	log.Println("Bob签名交易")
	//Sign_B()
	sign_bytes := append(transaction_bytes, alice_pub_bytes...)
	sign_bytes = append(sign_bytes, []byte(electricity.ID)...)
	sign_b, err := sm2.Sign(bob_pri, []byte("Bob"), sign_bytes)
	if err != nil {
		log.Fatalf("Failed to sign transcation byte")
	}
	sign_b_string := hex.EncodeToString(sign_b)
	log.Println("SignB:", sign_b_string)
	// generate comm1
	log.Println("生成密文相关承诺...")
	big_price := big.NewInt(electricity.Price)
	log.Println("---Generate Comm1---")
	log.Println("---> PedersenCommit, function return commit,r")
	comm1, _ := bp.PedersenCommit(big_price)
	log.Println("Comm1:", comm1)

	log.Println("---Generate Comm2---")
	log.Println("---> PedersenCommit,function return commit,r")
	comm2, _ := bp.PedersenCommit(big_price)
	log.Println("Comm2:", comm2)

	comm1_bytes, err := util.ECPointToBytes(&comm1)
	if err != nil {
		log.Fatalf("Failed to Marshamal Ecpoint to Bytes")
	}

	comm2_bytes, err := util.ECPointToBytes(&comm2)
	if err != nil {
		log.Fatalf("Failed to Marshamal Ecpoint to Bytes")
	}

	//generate sig1\sig2
	log.Println("---Generate Sign for Comm1 use UserId 'Alice'")
	alice_commit_sign, err := sm2.Sign(alice_pri, []byte("Alice"), comm1_bytes)
	if err != nil {
		log.Fatalf("Failed to Sign Comm Price")
	}
	log.Println("---Generate Sign for Comm2 use UserId 'Bob'")
	bob_commit_sign, err := sm2.Sign(bob_pri, []byte("Bob"), comm2_bytes)
	if err != nil {
		log.Fatalf("Failed to Sign Comm Price")
	}

	log.Println("---获取公钥环---")
	log.Println("--> GetRingPublicKeys, function return pubs")
	pubs, err := contract.SubmitTransaction("GetRingPublicKeys")
	if err != nil {
		log.Fatalf("Failed to Verify Transcation: %v", err)
	}
	var ring []string
	if err := json.Unmarshal(pubs, &ring); err != nil {
		log.Fatalf("Failed to decode publickeys: %v", err)
	}
	var ring_pubs []*sm2.PublicKey
	for _, v := range ring {
		pub_bytes := base64ToPrivateKey(v)
		var p *sm2.PublicKey
		if err := json.Unmarshal(pub_bytes, &p); err != nil {
			log.Fatalf("Unmarshal pubs error: %v", err)
		}
		ring_pubs = append(ring_pubs, p)
	}
	for i, v := range ring_pubs {
		log.Println("ring-public-", i, "-key:", v)
	}
	// sign
	// log.Println("---环签名---")
	// log.Println("--> GenerateSign, function return string(sign)")
	// sign, err := util.GenerateSign(ring_pubs, bob_pri, transaction_bytes)
	// if err != nil {
	// 	log.Fatalf("Failed to GenerateSign: %v", err)
	// }
	// log.Println("sign:", sign)

	// // verify
	// log.Println("---验证---")
	// log.Println("--> Submit Transaction: Verify, function return bool")
	// s := util.DecodeSignature(sign)
	// verify := util.Verify(ring_pubs, transaction_bytes, s)
	// log.Println("verify:", verify)

	// link ring_sign
	/*
		ring_pub: pubs
		sign1: {Bob price_cipertext,Alice balance,Price}
		{sign1,sign2}-->CA
	*/
	// alice encrypt price
	log.Println("---Alice Encrypt Price---")
	alice_price_cipertext, err := encryptBalance(electricity.Price, alice_pub)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Alice_price_cipertext:", string(alice_price_cipertext))

	log.Println("---Decode Alice Balance---")
	aliceCiperTextByte, err := hex.DecodeString(alice_balance_cipertext)
	if err != nil {
		log.Fatalf("failed to DecodeString: %v", err)
	}
	alice_balance_plaintext, err := util.HomoDecrypt(alice_pri, aliceCiperTextByte)
	if err != nil {
		log.Fatal(err)
	}
	// 将[]byte转换回int64
	bigInt := new(big.Int).SetBytes(alice_balance_plaintext)
	alice_balance := bigInt.Int64()
	log.Println("Alice Balance Plaintext:", alice_balance)

	log.Println("---Alice Balance Sub Electricity.Price---")

	alice_balance -= electricity.Price
	alice_balance_cipertext, err = encryptBalance(alice_balance, alice_pub)
	if err != nil {
		log.Fatalf("Failed to Encrypto Balance: %v", err)
	}
	log.Println("Alice Balance CiperText:", string(alice_balance_cipertext))

	ciperBalance := CiperBalance{
		Initiator: alice_balance_cipertext,
		Recipient: alice_price_cipertext,
		Price:     bob_price_cipertext,
	}
	ciperBalance_bytes, err := json.Marshal(ciperBalance)
	if err != nil {
		log.Fatalf("marshal ciperBalance error:%v", err)
	}
	log.Println("CiperBalance-Bytes:", string(ciperBalance_bytes))
	// alice comm price
	// comm,r:=bp.PedersenCommit(big.NewInt(electricity.Price))
	// log.Println("comm:",comm)
	// log.Println("---r:",r)
	// alice generate prove
	// prove:=bp.RangeProof(big.NewInt(electricity.Price))
	log.Println("---Alice Generate prove---")
	log.Println("生成交易金额大于零零知识证明证据RP(m)")
	bp.EC = bp.NewECPrimeGroupKey(8)
	prove := bp.RPProve(big.NewInt(electricity.Price))
	log.Println("RP(m):", prove)

	log.Println("生成转账方交易余额大于零零知识证明证据RP(b)")
	bp.EC = bp.NewECPrimeGroupKey(64)
	prove1 := bp.RPProve(big.NewInt(alice_balance))
	log.Println("RP(b):", prove1)
	/*
			pubs: ring_pub
		    sign2: {Bob publickey,Alice Publickey,order number,sign}
	*/
	log.Println("---Alice Contruct Identity---")
	log.Println("身份信息...")
	identity := Identity{
		Initiator:  alice_pub_str,
		Recipient:  bob_pub_str,
		OrderNum:   electricity.ID,
		VerifySign: sign_b_string,
	}
	identity_bytes, err := json.Marshal(identity)
	if err != nil {
		log.Fatalf("marshal identity error:%v", err)
	}
	log.Println("身份信息:", string(identity_bytes))

	log.Println("使用监管节点密钥加密...")
	ciperBalance_bytes_cipertext, err := sm2.Encrypt(monitor_pub, ciperBalance_bytes, sm2.C1C3C2)
	if err != nil {
		log.Fatalf("Failed to Encrypto Balance: %v", err)
	}
	ciperBalance_bytes_cipertext_string := hex.EncodeToString(ciperBalance_bytes_cipertext)
	log.Println(string(ciperBalance_bytes_cipertext_string))
	identity_bytes_cipertext, err := sm2.Encrypt(monitor_pub, identity_bytes, sm2.C1C3C2)
	if err != nil {
		log.Fatalf("Failed to Encrypto Identity: %v", err)
	}
	identity_bytes_cipertext_string := hex.EncodeToString(identity_bytes_cipertext)
	log.Println(string(identity_bytes_cipertext_string))
	/*
		sign for ciperBalance_bytes,identity_bytes
	*/
	log.Println("---Linkable 生成环签名---")
	baseSigner := util.NewBaseLinkableSigner(alice_pri, ring_pubs)
	sig1, err := baseSigner.Sign(rand.Reader, util.SimpleParticipantRandInt, ciperBalance_bytes)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("LinkSig1(Price and Balance):", sig1)

	sig2, err := baseSigner.Sign(rand.Reader, util.SimpleParticipantRandInt, identity_bytes)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("LinkSig2(Identity):", sig2)

	log.Println("监管节点解密...")
	// ciperBalance_bytes_plaintext, err := sm2.Decrypt(monitor_pri, ciperBalance_bytes_cipertext, sm2.C1C3C2)
	// if err != nil {
	// 	log.Fatalf("Sm2 Decrypto ciperBalance_bytes err:%v", err)
	// }
	// log.Println(ciperBalance_bytes_plaintext)
	// identity_bytes_plaintext, err := sm2.Decrypt(monitor_pri, identity_bytes_cipertext, sm2.C1C3C2)
	// if err != nil {
	// 	log.Fatalf("Sm2 Decrypto identity_bytes err:%v", err)
	// }

	// log.Println(identity_bytes_plaintext)
	log.Println(ciperBalance_bytes)
	log.Println(identity_bytes)
	log.Println("交易双方身份验证...")
	if !baseSigner.Verify(ciperBalance_bytes, sig1) {
		log.Println("failed to verify the signature")
	} else {
		log.Println("LinkSign1验证通过")
	}
	if !baseSigner.Verify(identity_bytes, sig2) {
		log.Println("failed to verify the signature")
	} else {
		log.Println("LinkSign2验证通过")
	}
	if !util.Linkable(sig1, sig2) {
		log.Println("failed to link")
	} else {
		log.Println("环签名链接性验证通过")
	}
	if sm2.Verify(bob_pub, []byte("Bob"), sign_bytes, sign_b) {
		log.Println("SignB验证通过")
	} else {
		log.Println("SignB验证失败")
	}
	// minitor
	log.Println("验证交易金额承诺值相等...")
	if sm2.Verify(alice_pub, []byte("Alice"), comm1_bytes, alice_commit_sign) && sm2.Verify(bob_pub, []byte("Bob"), comm2_bytes, bob_commit_sign) {
		//comm1+comm2==comm1+comm1&&comm1+comm2==comm1+comm1
		// commitment = commitment.Add(ECPoint{x1, y1}).Add(ECPoint{x2, y2})
		inv_comm1 := comm1.Neg()
		inv_comm2 := comm2.Neg()
		if inv_comm1.Add(comm2).Equal(inv_comm2.Add(comm1)) {
			log.Println("comm1==comm2")
		} else {
			log.Fatalf("comm1!=comm2")
		}
	}
	// verify prove
	log.Println("验证交易金额大于零...")
	if bp.RPVerify(prove) {
		log.Println("Range Proof Verification works")
	} else {
		log.Println("*****Range Proof FAILURE")
	}
	log.Println("验证转账方交易余额不小于零...")
	if bp.RPVerify(prove1) {
		log.Println("Range Proof Verification works")
	} else {
		log.Println("*****Range Proof FAILURE")
	}

	// verify success
	// two cipertext add
	log.Println("账户密文同态计算...")
	bob_add_cipertext, err := addBalance(bob_pub, bob_balance_cipertext, bob_price_cipertext)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Bob Add Price Cipertext:", string(bob_add_cipertext))

	alice_sub_cipertext, err := subBalance(alice_pub, alice_balance_cipertext, alice_price_cipertext)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Alice Sub Price Cipertext:", string(alice_sub_cipertext))
	//decrypt cipertext
	// verify_plaintext,err:=util.VerifyCiperText(bob_pri_str,bob_add_cipertext)
	// if err!=nil{
	// 	log.Fatal(err)
	// }
	// log.Println("Verify_plaintext:",verify_plaintext)

	log.Println("---Verify Finish,Set Balance---")
	log.Println("交易完成，更新账户余额")
	result, err = contract.SubmitTransaction("SetBalance", alice.Wallet, alice_balance_cipertext)
	if err != nil {
		log.Fatalf("Failed to Put Alice Balance: %v", err)
	}
	result, err = contract.SubmitTransaction("SetBalance", bob.Wallet, bob_add_cipertext)
	if err != nil {
		log.Fatalf("Failed to Put Bob Balance: %v", err)
	}

	log.Println("---Transcation Put State---")
	result, err = contract.SubmitTransaction("UploadTranscation", alice.Wallet, alice_price_cipertext, bob_price_cipertext, bob.Wallet)
	if err != nil {
		log.Fatalf("Failed to Put Transcation Data: %v", err)
	}
	// log.Println("---TransferElectricity---")
	// transfer, err = contract.SubmitTransaction("TransferElectricity",,alice_balance_cipertext)
	// if err != nil {
	// 	log.Fatalf("Failed to Put Alice Balance: %v", err)
	// }
	log.Println("---GetBalance To Verify The Transcation Is Success---")
	log.Println("---获取 Alice Balance---")
	log.Println("--> Submit Transaction: GetWallet, function return *Wallet")
	result, err = contract.EvaluateTransaction("GetWallet", alice.Wallet)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	if err = json.Unmarshal(result, &alice_wallet); err != nil {
		log.Fatalf("Failed to unmarshal Assest data: %v", err)
	}
	log.Println("Alice Crypto balance:", string(result))

	log.Println("---获取 Bob Balance---")
	log.Println("--> Submit Transaction: GetWallet, function return *Wallet")
	result, err = contract.EvaluateTransaction("GetWallet", bob.Wallet)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}

	if err = json.Unmarshal(result, &bob_wallet); err != nil {
		log.Fatalf("Failed to unmarshal Assest data: %v", err)
	}
	log.Println("Bob Crypto balance:", string(result))

	log.Println("---Decode Alice Balance---")
	aliceCiperTextByte, err = hex.DecodeString(alice_wallet.Balance)
	if err != nil {
		log.Fatalf("failed to DecodeString: %v", err)
	}
	alice_balance_plaintext, err = util.HomoDecrypt(alice_pri, aliceCiperTextByte)
	if err != nil {
		log.Fatal(err)
	}
	// 将[]byte转换回int64
	bigInt = new(big.Int).SetBytes(alice_balance_plaintext)
	alice_balance = bigInt.Int64()
	log.Println("Alice Balance Plaintext:", alice_balance)

	log.Println("---Decode Bob Balance---")
	bobCiperTextByte, err := hex.DecodeString(bob_wallet.Balance)
	if err != nil {
		log.Fatalf("failed to DecodeString: %v", err)
	}
	bob_balance_plaintext, err := util.HomoDecrypt(bob_pri, bobCiperTextByte)
	if err != nil {
		log.Fatal(err)
	}
	// 将[]byte转换回int64
	bigInt = new(big.Int).SetBytes(bob_balance_plaintext)
	bob_balance := bigInt.Int64()
	log.Println("Bob Balance Plaintext:", bob_balance)

	log.Println("---Query Trancation On State---")
	result, err = contract.EvaluateTransaction("GetTranscation", "10000")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println("Transcation:", string(result))

	log.Println("============ application-golang ends ============")
}
func base64ToPrivateKey(decodedBytes string) []byte {
	// 解码Base64字符串为原始字节
	privateKeyBytes, err := base64.StdEncoding.DecodeString(decodedBytes)
	if err != nil {
		panic(err)
	}
	// 现在privateKeyBytes就是Base64解码后的SM2私钥的[]byte格式
	return privateKeyBytes
}
func base64ToPublicKey(decodedBytes string) []byte {
	//编码Base64字符串为原始字节
	publicKeyBytes, err := base64.StdEncoding.DecodeString(decodedBytes)
	if err != nil {
		panic(err)
	}
	return publicKeyBytes
}
func populateWallet(wallet *gateway.Wallet) error {
	log.Println("============ Populating wallet ============")
	credPath := filepath.Join(
		"..",
		"..",
		"go",
		"src",
		"github.com",
		"hyperledger",
		"fabric-samples",
		"test-network",
		"organizations",
		"peerOrganizations",
		"org1.example.com",
		"users",
		"User1@org1.example.com",
		"msp",
	)

	// certPath := filepath.Join(credPath, "signcerts", "cert.pem")
	certPath := filepath.Join(credPath, "signcerts", "User1@org1.example.com-cert.pem")
	// read the certificate pem
	cert, err := ioutil.ReadFile(filepath.Clean(certPath))
	if err != nil {
		return err
	}

	keyDir := filepath.Join(credPath, "keystore")
	// there's a single file in this dir containing the private key
	files, err := ioutil.ReadDir(keyDir)
	if err != nil {
		return err
	}
	if len(files) != 1 {
		return fmt.Errorf("keystore folder should have contain one file")
	}
	keyPath := filepath.Join(keyDir, files[0].Name())
	key, err := ioutil.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return err
	}

	identity := gateway.NewX509Identity("Org1MSP", string(cert), string(key))

	return wallet.Put("appUser", identity)
}

func encryptBalance(balance int64, pub *sm2.PublicKey) (string, error) {
	// 使用bytes.Buffer来存储转换后的字节
	var buf bytes.Buffer
	// 将int64类型的num写入buffer中
	if err := binary.Write(&buf, binary.BigEndian, balance); err != nil {
		return "", err
	}
	// cipertext,err:=sm2.Encrypt(pub,buf.Bytes(),sm2.C1C2C3)
	plaintext := buf.Bytes()
	cipertext, err := util.HomoEncrypt(pub, plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt balance error:%v", err)
	}
	hexCiperText := hex.EncodeToString(cipertext)
	return hexCiperText, nil
}

func addBalance(pub *sm2.PublicKey, ciperText1 string, ciperText2 string) (string, error) {
	hexCiperTextByte1, err := hex.DecodeString(ciperText1)
	if err != nil {
		return "", fmt.Errorf("failed to DecodeString: %v", err)
	}
	hexCiperTextByte2, err := hex.DecodeString(ciperText2)
	if err != nil {
		return "", fmt.Errorf("failed to DecodeString: %v", err)
	}
	cipertext, err := util.CiperAdd(pub.Curve, hexCiperTextByte1, hexCiperTextByte2)
	if err != nil {
		return "", fmt.Errorf("failed to CiperAdd: %v", err)
	}
	hexCiperText := hex.EncodeToString(cipertext)
	return hexCiperText, nil
}
func subBalance(pub *sm2.PublicKey, ciperText1 string, ciperText2 string) (string, error) {
	hexCiperTextByte1, err := hex.DecodeString(ciperText1)
	if err != nil {
		return "", fmt.Errorf("failed to DecodeString: %v", err)
	}
	hexCiperTextByte2, err := hex.DecodeString(ciperText2)
	if err != nil {
		return "", fmt.Errorf("failed to DecodeString: %v", err)
	}
	cipertext, err := util.CiperSub(pub.Curve, hexCiperTextByte1, hexCiperTextByte2)
	if err != nil {
		return "", fmt.Errorf("failed to CiperAdd: %v", err)
	}
	hexCiperText := hex.EncodeToString(cipertext)
	return hexCiperText, nil
}
