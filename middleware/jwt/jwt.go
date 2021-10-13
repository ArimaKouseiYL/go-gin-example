package jwt

import (
	"github.com/gin-gonic/gin"
	"go-gin-example/pkg/e"
	"go-gin-example/pkg/util"
	"net/http"
	"time"
)

func JWT() gin.HandlerFunc {

	return func(c *gin.Context) {
		var code int
		var data interface{}

		code = e.SUCCESS
		token := c.Query("token")
		if token == "" {
			code = e.INVALID_PARAMS
		} else {
			claims, error := util.ParseToken(token)
			if error != nil {
				code = e.ERROR_AUTH_CHECK_TOKEN_FAIL
			} else if time.Now().Unix() > claims.ExpiresAt {
				code = e.ERROR_AUTH_CHECK_TOKEN_TIMEOUT
			}
		}

		if code != e.SUCCESS {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code": code,
				"msg":  e.GetMsg(code),
				"data": data,
			})
			// abort()、next() 参考：https://www.codenong.com/cs109691751/
			//abort（）顾名思义就是终止的意思，也就是说执行该函数，会终止后面所有的该请求下的函数。
			c.Abort()
			return
		}

		c.Next()
	}

}
