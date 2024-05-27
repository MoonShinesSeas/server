package controller

import (
	"github.com/gin-gonic/gin"
	"server/blockchain"
	"log"
	// "fmt"
	// "server/util"
)

type ElectricityController struct{}

func (e ElectricityController)GetAllElectricity(ctx *gin.Context){
	contractInstance := blockchain.GetContractInstance()
	res, err := contractInstance.GetAllElectricity()
	if err == nil {
		Success(ctx, 200, "success", string(res), 1)
		return
	}
	log.Fatalf("Failed to Submit transaction: %v", err)
	Error(ctx,400,"faild")
	return
}
func (e ElectricityController)GetElectricity(ctx *gin.Context){
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
	log.Fatalf("Failed to Submit transaction: %v", err)
	Error(ctx,400,"faild")
	return
}