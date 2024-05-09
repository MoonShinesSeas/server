package util

import(
	"fmt"
	"log"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"encoding/binary"
	bp "server/bulletproof/src"
	"bytes"
	"encoding/hex"
	"encoding/base64"

	"github.com/ZZMarquis/gm/sm2"
)

func MyGenerateKey()(string,string,error){
	pri,pub,err:=sm2.GenerateKey(rand.Reader)
	pri_byte,err:=json.Marshal(pri)
	if err!=nil{
		return "err","err",err
	}
	pub_byte,err:=json.Marshal(pub)
	if err!=nil{
		return "err","err",err
	}
	pri_str,err:=privateKeyToBase64(pri_byte)
	if err!=nil{
		return "err","err",err
	}
	pub_str,err:=publicKeyToBase64(pub_byte)
	if err!=nil{
		return "err","err",err
	}
	return pri_str,pub_str,err
}

func switchPublicKey(value []byte) (*sm2.PublicKey,error) {
	public_key_bytes := base64ToPublicKey(string(value))
	if public_key_bytes == nil {
		return nil,nil
	}
	var pub sm2.PublicKey
	if err := json.Unmarshal(public_key_bytes, &pub); err != nil {
		return nil,err
	}
	return &pub,nil
}
/*
value []byte:chaincode return publickey
*/
func InitiateTranscation(plaintext []byte,pub *sm2.PublicKey)(string,error){
	// pub,err:=switchPublicKey(value)
	// cipertext,err:=sm2.Encrypt(pub,plaintext,sm2.C1C2C3)
	cipertext,err:=HomoEncrypt(pub,plaintext)
	if err!=nil{
		return "",err
	}
	hexCiperPrice := hex.EncodeToString(cipertext)  
	return hexCiperPrice,nil
}

func VerifyTranscation(hexCiperText string,pri_str string,price int64)(string,error){
	pri_bytes:=base64ToPrivateKey(pri_str)
	var pri sm2.PrivateKey
	if err:=json.Unmarshal(pri_bytes,&pri);err!=nil{
		return "",err
	}
	hexCiperTextByte,err:=hex.DecodeString(hexCiperText)
	if err!=nil{
		return "",fmt.Errorf("failed to DecodeString: %v", err)
	}
	// plaintext,err:=sm2.Decrypt(&pri,hexCiperTextByte,sm2.C1C2C3)
	plaintext,err:=HomoDecrypt(&pri,hexCiperTextByte)
	if err!=nil{
		return "",fmt.Errorf("failed to Decrypt: %v", err)
	}
	// 将[]byte转换回int64  
	bigInt := new(big.Int).SetBytes(plaintext)  
	// int64Value := bigInt.Int64()  
	// var decodedInt64 int64  
	// err = binary.Read(bytes.NewReader(plaintext), binary.BigEndian, &decodedInt64)  
	// if err != nil {  
	// 	return "",fmt.Errorf("failed to Read plaintext: %v", err)
	// }
	decodedInt64:=bigInt.Int64()
	log.Println("decode_price",decodedInt64)
	if decodedInt64!=price{
		return "invalid",nil
	}
	return "valid",nil
}

func VerifyCiperText(pri_str string,hexCiperText string)(int64,error){
	pri_bytes:=base64ToPrivateKey(pri_str)
	var pri sm2.PrivateKey
	if err:=json.Unmarshal(pri_bytes,&pri);err!=nil{
		return int64(-1),fmt.Errorf("failed to Unmarshal: %v", err)
	}
	hexCiperTextByte,err:=hex.DecodeString(hexCiperText)
	if err!=nil{
		return int64(-1),fmt.Errorf("failed to DecodeString: %v", err)
	}
	// plaintext,err:=sm2.Decrypt(&pri,hexCiperTextByte,sm2.C1C2C3)
	plaintext,err:=HomoDecrypt(&pri,hexCiperTextByte)
	if err!=nil{
		return int64(-1),fmt.Errorf("failed to Decrypt: %v", err)
	}
	// 将[]byte转换回int64  
	bigInt := new(big.Int).SetBytes(plaintext)  
	return bigInt.Int64(),nil
}
// Sign()
func GenerateSign(pubs []*sm2.PublicKey,pri *sm2.PrivateKey,transcation_bytes []byte)(string,error){
	sign, err := Sign(rand.Reader, SimpleParticipantRandInt, pri, pubs, transcation_bytes)
	if err!=nil{
		return "",err
	}
	res_sign:=FlodSingature(sign)
	return res_sign,nil
}

// ECPointToBytes 将 ECPoint 结构体序列化为 []byte。  
func ECPointToBytes(p *bp.ECPoint) ([]byte, error) {  
	var buf bytes.Buffer  
  
	// 写入 X 的字节表示  
	xBytes := p.X.Bytes()  
	// 写入 X 的长度（为了之后能够反序列化）  
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(xBytes))); err != nil {  
		return nil, err  
	}  
	if _, err := buf.Write(xBytes); err != nil {  
		return nil, err  
	}  
  
	// 写入 Y 的字节表示  
	yBytes := p.Y.Bytes()  
	// 写入 Y 的长度（为了之后能够反序列化）  
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(yBytes))); err != nil {  
		return nil, err  
	}  
	if _, err := buf.Write(yBytes); err != nil {  
		return nil, err  
	}  
  
	return buf.Bytes(), nil  
}  
// ECPointFromBytes 将 []byte 反序列化为 ECPoint 结构体。  
func ECPointFromBytes(data []byte) (*bp.ECPoint, error) {  
	buf := bytes.NewBuffer(data)  
  
	// 读取 X 的长度  
	var xLen uint32  
	if err := binary.Read(buf, binary.BigEndian, &xLen); err != nil {  
		return nil, err  
	}  
  
	// 读取 X 的字节表示并转换为 *big.Int  
	xBytes := make([]byte, xLen)  
	if _, err := buf.Read(xBytes); err != nil {  
		return nil, err  
	}  
	x := new(big.Int).SetBytes(xBytes)  
  
	// 读取 Y 的长度  
	var yLen uint32  
	if err := binary.Read(buf, binary.BigEndian, &yLen); err != nil {  
		return nil, err  
	}  
  
	// 读取 Y 的字节表示并转换为 *big.Int  
	yBytes := make([]byte, yLen)  
	if _, err := buf.Read(yBytes); err != nil {  
		return nil, err  
	}  
	y := new(big.Int).SetBytes(yBytes)  
  
	// 返回重建的 ECPoint 结构体  
	return &bp.ECPoint{X: x, Y: y}, nil  
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

