package controller

import(
	"github.com/gin-gonic/gin"
	"server/blockchain"
	"log"
)

type HelloController struct{}

func (h HelloController)TestHello(ctx *gin.Context){
	contractInstance := blockchain.GetContractInstance()
	res, err := contractInstance.Hello()
	if err == nil {
		Success(ctx, 200, "success", string(res), 1)
		return
	}
	log.Fatalf("Failed to Submit transaction: %v", err)
	Error(ctx,400,err.Error())
	return
}

func (h HelloController)TestInit(ctx *gin.Context){
	contractInstance := blockchain.GetContractInstance()
	res, err := contractInstance.Init()
	if err == nil {
		Success(ctx, 200, "success", string(res), 1)
		return
	}
	log.Fatalf("Failed to Submit transaction: %v", err)
	Error(ctx,400,"faild")
	return
}