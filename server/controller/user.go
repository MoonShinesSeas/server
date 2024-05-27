package controller

import (
	"github.com/gin-gonic/gin"
	"server/blockchain"
	"log"
	// "fmt"
	// "server/util"
)

type UserController struct{}

func (u UserController)Login(c *gin.Context){
	Success(c,0,"success","login",1)
}
func (u UserController)Register(c *gin.Context){
	defer func(){
		if err:=recover();err!=nil{
			log.Print("Catch exception!",err)
		}
	}()
	num1 := 1
	num2 := 0
	num3 := num1/num2
	Error(c,400,num3)
}
func (u UserController)GetList(c *gin.Context){
	param:=make(map[string]interface{})
	err:=c.BindJSON(&param)
	if err==nil{
		Success(c,0,"success",param,1)
		return
	}
	Error(c,400,gin.H{"err":err})
}
func (u UserController)SetAsset(ctx *gin.Context){
	//定义匿名结构体，字段与json字段对应
	var body struct {
		Username string `json:"username"`
	}
	
	//绑定json和结构体
	if err := ctx.BindJSON(&body); err != nil {
		return
	}
	//获取json中的key,注意使用 . 访问
	username:=body.Username
	contractInstance := blockchain.GetContractInstance()
	res, err := contractInstance.SetAsset(username)
	if err == nil {
		Success(ctx, 200, "success", string(res), 1)
		return
	}
	log.Fatalf("Failed to Submit transaction: %v", err)
	Error(ctx,400,"faild")
	return
}

func (u UserController)GetAsset(ctx *gin.Context){
	//定义匿名结构体，字段与json字段对应
	var body struct {
		Username string `json:"username"`
	}
	
	//绑定json和结构体
	if err := ctx.BindJSON(&body); err != nil {
		Error(ctx,400,"faild")
		return
	}
	//获取json中的key,注意使用 . 访问
	username:=body.Username
	contractInstance := blockchain.GetContractInstance()
	res, err := contractInstance.GetAsset(username)
	if err == nil {
		Success(ctx, 200, "success", string(res), 1)
		return
	}
	log.Fatalf("Failed to Submit transaction: %v", err)
	Error(ctx,400,"faild")
	return
}