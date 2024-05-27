package controller

import(
	"github.com/gin-gonic/gin"
	"server/blockchain"
	"log"
)

var electricity struct{
	ID string `json:"id"`
	//	Owner string `json:"owner"`
	Price  int64 `json:"price"`
	Amount int   `json:"amount"`
}

type ProposalController struct{}

func (p ProposalController)InitProposal(ctx *gin.Context){
	//定义匿名结构体，字段与json字段对应
	var body struct {
		ID string `json:"id"`
	}
	//绑定json和结构体
	if err := ctx.BindJSON(&body); err != nil {
		return
	}
	//获取json中的key,注意使用 . 访问
	id:=body.ID
	contractInstance := blockchain.GetContractInstance()

	res, err := contractInstance.GetElectricity(id)
	if err == nil {
		Success(ctx, 200, "success", string(res), 1)
		return
	}
	var e electricity
	if err=json.Unmarshal(res,&e);err!=nil{
		log.Fatalf("Unmarshal res error")
	}
	log.Fatalf("Failed to Submit transaction: %v", err)
	Error(ctx,400,"faild")
	return
}

func (p ProposalController)TestInit(ctx *gin.Context){
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

// export https_proxy=http://127.0.0.1:7897 http_proxy=http://127.0.0.1:7897