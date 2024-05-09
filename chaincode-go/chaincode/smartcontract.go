package chaincode

import (
	//"strconv"
	"log"
	"math/rand"

	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ZZMarquis/gm/sm2"
	"github.com/ZZMarquis/gm/sm3"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type SmartContract struct {
	contractapi.Contract
}

type Asset struct {
	Name   string `json:"name"`
	Wallet string `json:"wallet"`
}
type Wallet struct {
	Balance string `json:"balance"`
}
type Bill struct {
	ID         string `json:"id"`
	Transferor string `json:"transferor"`
	Amount1    string `json:"amount1"` //crypto by transferor
	Amount2    string `json:"amount2"` //crypto by collector
	Collector  string `json:"collector"`
}
type Ring struct {
	Pubs []string `json:"pubs"`
}
type Electricity struct {
	ID string `json:"id"`
	//	Owner string `json:"owner"`
	Price  int64 `json:"price"`
	Amount int   `json:"amount"`
}

func (s *SmartContract) Hello(ctx contractapi.TransactionContextInterface) string {
	return "hello"
}

// InitLedger adds a base set of assets to the ledger
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) (string, error) {
	ids := [2]string{"10000", "10001"}
	prices := [2]int64{100, 50}
	amounts := [2]int{20, 30}
	for i, v := range ids {
		electricity := Electricity{
			ID:     v,
			Price:  prices[i],
			Amount: amounts[i],
		}
		res, err := json.Marshal(electricity)
		if err != nil {
			return "", err
		}
		if err := ctx.GetStub().PutState(v, []byte(res)); err != nil {
			return "", err
		}
	}
	ring := Ring{Pubs: []string{""}}
	// 将 Ring 结构体序列化并保存到状态
	ringBytes, err := json.Marshal(ring)
	if err != nil {
		return "", err
	}
	if err := ctx.GetStub().PutState("ring", ringBytes); err != nil {
		return "", err
	}
	return "init success", nil
}

func (s *SmartContract) SetAsset(ctx contractapi.TransactionContextInterface, name string, wallet string) error {
	exist, err := ctx.GetStub().GetState(name)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if exist != nil {
		return fmt.Errorf("the user %s already exists", name)
	}
	asset := Asset{
		Name:   name,
		Wallet: wallet,
	}
	putwallet := Wallet{
		Balance: "",
	}
	assetJSON, err := json.Marshal(asset)
	if err != nil {
		return err
	}
	walletJSON, err := json.Marshal(putwallet)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(name, assetJSON); err != nil {
		return fmt.Errorf("put asset error:%v", err)
	}
	if err := ctx.GetStub().PutState(wallet, walletJSON); err != nil {
		return fmt.Errorf("put wallet error:%v", err)
	}
	// 从状态中获取 Ring 结构体
	var ring Ring
	ringBytes, err := ctx.GetStub().GetState("ring")
	if err != nil {
		return fmt.Errorf("get ring struct error:%v", err)
	}
	// 如果 Ring 结构体存在，则反序列化它
	if err = json.Unmarshal(ringBytes, &ring); err != nil {
		return fmt.Errorf("unmarshal ring error:%v", err)
	}
	// 追加新的 pub 到 Pubs 数组
	ring.Pubs = append(ring.Pubs, wallet)
	// 将 Ring 结构体序列化并保存到状态
	ringBytes, err = json.Marshal(ring)
	if err != nil {
		return fmt.Errorf("marshal ring error:%v", err)
	}
	err = ctx.GetStub().PutState("ring", ringBytes)
	if err != nil {
		return fmt.Errorf("put ring error:%v", err)
	}
	return nil
}
func (s *SmartContract) GetAsset(ctx contractapi.TransactionContextInterface, name string) (*Asset, error) {
	assestJSON, err := ctx.GetStub().GetState(name)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if assestJSON == nil {
		return nil, fmt.Errorf("the asset %s does not exist", name)
	}

	var asset Asset
	err = json.Unmarshal(assestJSON, &asset)
	if err != nil {
		return nil, err
	}
	return &asset, nil
}
func (s *SmartContract) SetBalance(ctx contractapi.TransactionContextInterface, address string, text string) error {
	exist, err := ctx.GetStub().GetState(address)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if exist == nil {
		return fmt.Errorf("the user %s is not exists", address)
	}
	wallet := Wallet{
		Balance: text,
	}
	walletJSON, err := json.Marshal(wallet)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(address, walletJSON)
}
func (s *SmartContract) GetWallet(ctx contractapi.TransactionContextInterface, address string) (*Wallet, error) {
	walletJSON, err := ctx.GetStub().GetState(address)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if walletJSON == nil {
		return nil, fmt.Errorf("the wallet %s does not exist", address)
	}

	var wallet Wallet
	err = json.Unmarshal(walletJSON, &wallet)
	if err != nil {
		return nil, err
	}
	return &wallet, nil
}
func (s *SmartContract) GetAllElectricity(ctx contractapi.TransactionContextInterface) ([]*Electricity, error) {
	// range query with empty string for startKey and endKey does an
	// open-ended query of all assets in the chaincode namespace.
	resultsIterator, err := ctx.GetStub().GetStateByRange("10000", "11111")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var electricitys []*Electricity
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var electricity Electricity
		err = json.Unmarshal(queryResponse.Value, &electricity)
		if err != nil {
			return nil, err
		}
		electricitys = append(electricitys, &electricity)
	}
	return electricitys, nil
}

// GetElectricity returns the electricity stored in the world state with given id.
func (s *SmartContract) GetElectricity(ctx contractapi.TransactionContextInterface, id string) (*Electricity, error) {
	electricityJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if electricityJSON == nil {
		return nil, fmt.Errorf("the asset %s does not exist", id)
	}

	var electricity Electricity
	err = json.Unmarshal(electricityJSON, &electricity)
	if err != nil {
		return nil, err
	}
	return &electricity, nil
}
func (s *SmartContract) UploadTranscation(ctx contractapi.TransactionContextInterface, transferor string, amount1 string, amount2 string, collector string) error {
	bill := Bill{
		ID:         "10000",
		Transferor: transferor,
		Amount1:    amount1,
		Amount2:    amount2,
		Collector:  collector,
	}
	billJSON, err := json.Marshal(bill)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(bill.ID, billJSON)
}

func (s *SmartContract) GetTranscation(ctx contractapi.TransactionContextInterface, id string) (*Bill, error) {
	billJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if billJSON == nil {
		return nil, fmt.Errorf("the bill %s does not exist", id)
	}

	var bill Bill
	err = json.Unmarshal(billJSON, &bill)
	if err != nil {
		return nil, err
	}
	return &bill, nil
}

func (s *SmartContract) GetPublicKey(ctx contractapi.TransactionContextInterface, value string) (string, error) {
	public_key_base, err := ctx.GetStub().GetState(value)
	if err != nil {
		return "", err
	}
	public_key_bytes := base64ToPublicKey(string(public_key_base))
	if public_key_bytes == nil {
		return "public_key_bytes is nil", nil
	}
	var pub sm2.PublicKey
	if err := json.Unmarshal(public_key_bytes, &pub); err != nil {
		return "", err
	}
	return string(public_key_bytes), nil
}

func (s *SmartContract) GetRingPublicKeys(ctx contractapi.TransactionContextInterface) (string, error) {
	pubsBytes, err := ctx.GetStub().GetState("ring")
	if err != nil {
		return "", err
	}

	var ring Ring
	if err := json.Unmarshal(pubsBytes, &ring); err != nil {
		return "", err
	}
	// 确保Pubs数组至少有一个元素，并且跳过第一个元素
	if len(ring.Pubs) > 1 {
		// 排除第一个公钥后的剩余公钥数量
		remainingPubs := ring.Pubs[1:]

		// Seed the random number generator
		rand.Seed(time.Now().UnixNano())

		// 如果需要返回固定数量的公钥，例如5个，但不超过剩余公钥的数量
		var numKeysToReturn int
		if len(remainingPubs) >= 5 {
			numKeysToReturn = 5
		} else {
			numKeysToReturn = len(remainingPubs)
		}
		// 生成随机索引并返回对应的公钥
		randomIndices := generateRandomIndices(len(remainingPubs), numKeysToReturn)
		randomPubs := make([]string, 0, numKeysToReturn)
		for _, index := range randomIndices {
			randomPubs = append(randomPubs, remainingPubs[index])
		}
		// 将随机公钥转换为JSON字符串并返回
		randomPubsBytes, err := json.Marshal(randomPubs)
		if err != nil {
			return "json marshal public keys error", err
		}
		return string(randomPubsBytes), nil
	}

	// 如果Pubs数组只有一个元素（不包括第一个），或者为空，则返回空字符串或错误
	return "[]", nil // 或者可以返回一个错误，表示没有足够的公钥可以返回
}

// Function to generate 'n' unique random indices between 0 and 'max'
func generateRandomIndices(max, n int) []int {
	// Create a map to store unique indices
	indexMap := make(map[int]bool)
	for len(indexMap) < n {
		index := rand.Intn(max) // Generate a random index
		indexMap[index] = true  // Add the index to the map
	}

	// Convert map keys to slice
	indices := make([]int, 0, n)
	for index := range indexMap {
		indices = append(indices, index)
	}
	return indices
}
func (s *SmartContract) GetPublicKeys(ctx contractapi.TransactionContextInterface, value string) (string, error) {
	res, err := ctx.GetStub().GetState(value)
	if err != nil {
		return "get publickeys error", err
	}
	res_bytes := base64ToPublicKey(string(res))
	var pub []*sm2.PublicKey
	if err := json.Unmarshal(res_bytes, &pub); err != nil {
		return "json unmarshal publickey error", err
	}
	return string(res_bytes), nil
}
func (s *SmartContract) Verify(ctx contractapi.TransactionContextInterface, msg string, value string, pub_list string) (string, error) {
	sign := decodeSignature(value)
	var pub []*sm2.PublicKey
	public_key_bytes := base64ToPublicKey(pub_list)
	if err := json.Unmarshal(public_key_bytes, &pub); err != nil {
		return "", err
	}
	if !ring_Verify(pub, []byte(msg), sign) {
		return "invalid", nil
	}
	return "valid", nil
}

// hashToInt converts a hash value to an integer. Per FIPS 186-4, Section 6.4,
// we use the left-most bits of the hash to match the bit-length of the order of
// the curve. This also performs Step 5 of SEC 1, Version 2.0, Section 4.1.3.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}
	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

// 这个hash算法没有给出明确定义
func hash(pubs []*sm2.PublicKey, msg []byte, cx, cy *big.Int) *big.Int {
	h := sm3.New()
	for _, pub := range pubs {
		xBytes := pub.X.Bytes()
		padXBytes := padToFixedLength(xBytes, 32) // 假设公钥的X和Y坐标需要填充到32字节
		h.Write(padXBytes)
		yBytes := pub.Y.Bytes()
		padYBytes := padToFixedLength(yBytes, 32) // 假设公钥的X和Y坐标需要填充到32字节
		h.Write(padYBytes)
	}
	h.Write(msg)
	cxBytes := cx.Bytes()
	padCXBytes := padToFixedLength(cxBytes, 32) // 假设cx和cy需要填充到32字节
	h.Write(padCXBytes)
	cyBytes := cy.Bytes()
	padCYBytes := padToFixedLength(cyBytes, 32) // 假设cx和cy需要填充到32字节
	h.Write(padCYBytes)
	return hashToInt(h.Sum(nil), pubs[0].Curve)
}

// padToFixedLength 将字节切片填充到固定长度。如果原始切片比目标长度短，则在前面填充0。
func padToFixedLength(slice []byte, length int) []byte {
	padded := make([]byte, length)
	copy(padded[length-len(slice):], slice)
	return padded
}
func ring_Verify(pubs []*sm2.PublicKey, msg []byte, signature []*big.Int) bool {
	if len(pubs)+1 != len(signature) {
		return false
	}
	c := new(big.Int).Set(signature[0])
	for i := 0; i < len(pubs); i++ {
		pub := pubs[i]
		s := signature[i+1]
		sx, sy := pub.Curve.ScalarBaseMult(s.Bytes())
		c.Add(s, c)
		c.Mod(c, pub.Curve.Params().N)
		cx, cy := pub.Curve.ScalarMult(pubs[i].X, pubs[i].Y, c.Bytes())
		cx, cy = pub.Curve.Add(sx, sy, cx, cy)
		c = hash(pubs, msg, cx, cy)
	}
	return c.Cmp(signature[0]) == 0
}
func decodeSignature(sign string) []*big.Int {
	// 在需要时，你可以将字符串解析为 []*big.Int 类型的环签名
	var parsedSignature []*big.Int
	if err := json.NewDecoder(strings.NewReader(sign)).Decode(&parsedSignature); err != nil {
		log.Fatal("JSON unmarshaling failed:", err)
	}
	return parsedSignature
}

// privateKeyToBase64 将PrivateKey结构体转换为Base64编码的字符串
func privateKeyToBase64(jsonBytes []byte) (string, error) {
	base64Str := base64.StdEncoding.EncodeToString(jsonBytes)
	return base64Str, nil
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

func publicKeyToBase64(jsonBytes []byte) (string, error) {
	base64Str := base64.StdEncoding.EncodeToString(jsonBytes)
	return base64Str, nil
}

func base64ToPublicKey(decodedBytes string) []byte {
	//编码Base64字符串为原始字节
	publicKeyBytes, err := base64.StdEncoding.DecodeString(decodedBytes)
	if err != nil {
		panic(err)
	}
	return publicKeyBytes
}

func flodSingature(signature []*big.Int) (string, error) {
	// 将环签名转换为 JSON 字符串
	signatureJSON, err := json.Marshal(signature)
	if err != nil {
		return "", err
	}
	// 将 JSON 字符串转换为普通字符串
	signatureString := string(signatureJSON)
	return signatureString, nil
}

// func (s *SmartContract)Transfer(ctx contractapi.TransactionContextInterface,transferor string,amount string,collector string)(string,error){
// 	transferor_res_bytes,err:=ctx.GetStub().GetState(transferor)
// 	if err!=nil{
// 		return "",err
// 	}
// 	if len(transferor_res_bytes)==0{
// 		return "transferor is null",nil
// 	}
// 	var transferor_res_user Asset
// 	if err:=json.Unmarshal(transferor_res_bytes,&transferor_res_user);err!=nil{
// 		return "",err
// 	}
// 	collector_res_bytes,err:=ctx.GetStub().GetState(collector)
// 	if err!=nil{
// 		return "",err
// 	}
// 	if len(collector_res_bytes)==0{
// 		return "transferor is null",nil
// 	}
// 	var collector_res_user Asset
// 	if err:=json.Unmarshal(collector_res_bytes,&collector_res_user);err!=nil{
// 		return "",err
// 	}
// 	format_amount,err:=strconv.ParseFloat(amount,64)
// 	if err!=nil{
// 		return "",err
// 	}
// 	transferor_res_user.Balance=transferor_res_user.Balance-format_amount
// 	collector_res_user.Balance=collector_res_user.Balance+format_amount
// 	transferor_bytes,err:=json.Marshal(transferor_res_user)
// 	if err!=nil{
// 		return "",err
// 	}
// 	collector_bytes,err:=json.Marshal(collector_res_user)
// 	if err!=nil{
// 		return "",err
// 	}
// 	if err:=ctx.GetStub().PutState(transferor,transferor_bytes);err!=nil{
// 		return "",err
// 	}
// 	if err:=ctx.GetStub().PutState(collector,collector_bytes);err!=nil{
// 		return "",err
// 	}
// 	bill:=&Bill{
// 		ID:ctx.GetStub().GetTxID(),
// 		Transferor: transferor,
// 		Amount: format_amount,
// 		Collector: collector,
// 	}
// 	bill_bytes,err:=json.Marshal(bill)
// 	if err!=nil{
// 		return "marshal bill is error",err
// 	}
// 	if err:=ctx.GetStub().PutState(ctx.GetStub().GetTxID(),bill_bytes);err!=nil{
// 		return "put bill in stub error",err
// 	}
// 	return string(bill_bytes),nil
// }
