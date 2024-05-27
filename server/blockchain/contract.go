package blockchain

import(
	"io/ioutil"
	"os"
	"sync"
	"path/filepath"
	"log"
	"fmt"
	"server/util"
	"encoding/json"
	// "encoding/base64"
	"encoding/binary"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
)
type Contract struct {
	contract *gateway.Contract
}

type User struct {
	Name   string `json:"name"`
	Wallet string `json:"wallet"`
}

type Wallet struct {
	Balance string `json:"balance"`
}

type Proposal struct {
	OrderId string `json:"orderId"`
	Cipertext string `json:"ciperText"`
	//0 no opreation
	//1 agree
	//2 refuse
	Flag int `json:"flag"`
}

var instance *Contract
var once sync.Once

func GetContractInstance() *Contract {
	once.Do(func() {
		instance = &Contract{}
		instance.initialize()
	})
	return instance
}

func (c *Contract)initialize(){
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
		err = c.populateWallet(wallet)
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
	c.contract = network.GetContract("basic")
}

func (c *Contract)populateWallet(wallet *gateway.Wallet) error {
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

func (c *Contract)Init()([]byte,error){
	result, err := c.contract.SubmitTransaction("InitLedger")
	if err!=nil{
		log.Fatalf("Failed to submit transaction: %v",err)
		return nil,err
	}
	return result,nil
}

func (c *Contract)Hello()([]byte,error){
	result, err := c.contract.SubmitTransaction("Hello")
	if err!=nil{
		log.Fatalf("Failed to submit transaction: %v",err)
		return nil,err
	}
	return result,nil
}

func (c *Contract)SetAsset(username string)([]byte,error){
	pri_str, pub_str, err := util.MyGenerateKey()
	if err!=nil{
		log.Fatalf("Failed to Generate Key: %v",err)
		return nil,err
	}
	 // 构造文件名，例如 "Alice_private.key"  
	fileName := fmt.Sprintf("%s_private.key", username)  
  
	 // 写入私钥到文件  
	err = ioutil.WriteFile(fileName, []byte(pri_str),)
	if err != nil {  
		log.Fatalf("Failed to write private key to file: %v", err)  
		return nil, err  
	}  
	result, err := c.contract.SubmitTransaction("SetAsset",username,pub_str)
	if err!=nil{
		log.Fatalf("Failed to submit transaction: %v",err)
		return nil,err
	}
	return result,nil
}

func (c *Contract)GetAsset(username string)([]byte,error){
	result, err := c.contract.EvaluateTransaction("GetAsset",username)
	if err!=nil{
		log.Fatalf("Failed to Evaluate transaction: %v",err)
		return nil,err
	}
	return result,nil
}

func (c *Contract)GetAllElectricity()([]byte,error){
	result, err := c.contract.EvaluateTransaction("GetAllElectricity")
	if err!=nil{
		log.Fatalf("Failed to Evaluate transaction: %v",err)
		return nil,err
	}
	return result,nil
}

func (c *Contract)GetElectricity(id string)([]byte,error){
	result, err := c.contract.EvaluateTransaction("GetElectricity",id)
	if err!=nil{
		log.Fatalf("Failed to Evaluate transaction: %v",err)
		return nil,err
	}
	return result,nil
}
func (c *Contract)SetBalance(username string)([]byte,error){
	// log.Println("获取公钥...")
	user_result, err := c.contract.EvaluateTransaction("GetAsset", username)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
		return nil,err
	}
	var user User
	log.Println("user-pub:", string(alice_result))
	if err := json.Unmarshal(user_result, &user); err != nil {
		log.Fatalf("Failed to Unmarshal alice_result: %v", err)
		return nil,err
	}
	user_pub_bytes:=util.Base64ToPublicKey(user.Wallet)
	var user_pub *sm2.PublicKey
	if err:=json.Unmarshal(user_pub_bytes, &user_pub); err != nil {
		log.Fatalf("Failed to decode public_key: %v", err)
		return nil,err
	}
	balance_cipertext,err:=util.EncryptBalance(1000,user_pub)
	if err!=nil{
		log.Fatalf("Failed to EncryptBalance!")
		return nil,err
	}
	result, err := c.contract.SubmitTransaction("SetBalance",user.wallet,balance_cipertext)
	if err!=nil{
		log.Fatalf("Failed to Submit transaction: %v",err)
		return nil,err
	}
	return result,nil
}

func (c *Contract)GetBalance(username string)([]byte,error){
	// log.Println("获取公钥...")
	user_result, err := c.contract.EvaluateTransaction("GetAsset", username)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
		return nil,err
	}
	var user User
	log.Println("user-pub:", string(alice_result))
	if err := json.Unmarshal(user_result, &user); err != nil {
		log.Fatalf("Failed to Unmarshal alice_result: %v", err)
		return nil,err
	}
	result, err := c.contract.EvaluateTransaction("GetWallet",user.wallet)
	if err!=nil{
		log.Fatalf("Failed to Submit transaction: %v",err)
		return nil,err
	}
	var wallet Wallet
	if err := json.Unmarshal(result, &wallet); err != nil {
		log.Fatalf("Failed to unmarshal User wallet: %v", err)
		return nil,err
	}
	log.Println("Bob balance:", string(result))
	return result,nil
}
func (c *Contract)InitProposal(orderId string,username string,price int64)([]byte,error){
	// log.Println("获取公钥...")
	user_result, err := c.contract.EvaluateTransaction("GetAsset", username)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
		return nil,err
	}
	var user User
	log.Println("user-pub:", string(alice_result))
	if err := json.Unmarshal(user_result, &user); err != nil {
		log.Fatalf("Failed to Unmarshal alice_result: %v", err)
		return nil,err
	}
	user_pub_bytes:=util.Base64ToPublicKey(user.Wallet)
	var user_pub *sm2.PublicKey
	if err:=json.Unmarshal(user_pub_bytes, &user_pub); err != nil {
		log.Fatalf("Failed to decode public_key: %v", err)
		return nil,err
	}
	var buf bytes.Buffer
	// 将int64类型的num写入buffer中
	if err := binary.Write(&buf, binary.BigEndian, price); err != nil {
		log.Fatalf("binary.Write failed: %v", err)
	}
	price_cipertext, err := util.InitiateTranscation(buf.Bytes(), user_pub)
	if err != nil {
		log.Fatalf("Failed to InitiateTranscation: %v", err)
	}
	log.Println("price_cipertext = ", price_cipertext)
	if err!=nil{
		log.Fatalf("Failed to EncryptBalance!")
		return nil,err
	}
	result, err := c.contract.SubmitTransaction("SaveProposal",orderId,price_cipertext)
	if err!=nil{
		log.Fatalf("Failed to Submit!")
		return nil,err
	}
	return string(result),nil
}