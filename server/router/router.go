package router

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"server/controller"
)
func Router() *gin.Engine{
    //1.创建路由
    router := gin.Default()

    /* 
    * Group
    */
    //2.绑定路由规则，执行的函数
    user:=router.Group("user")
    {
        user.GET("/login",controller.UserController{}.Login)
        user.GET("/register",controller.UserController{}.Register)
		user.POST("/getlist",controller.UserController{}.GetList)
		user.GET("/hello",controller.HelloController{}.TestHello)
        user.GET("/init",controller.HelloController{}.TestInit)
		user.POST("/setasset",controller.UserController{}.SetAsset)
        user.POST("/getasset",controller.UserController{}.GetAsset)
		user.POST("/add",func(context *gin.Context){
			context.String(http.StatusOK,"user add")
		})      
    }
    electricity:=router.Group("electricity")
    {
        electricity.GET("/getlist",controller.ElectricityController{}.GetAllElectricity)
        electricity.POST("/get",controller.ElectricityController{}.GetElectricity)
    }
	return router
}