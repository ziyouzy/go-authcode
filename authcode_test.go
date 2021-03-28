package go_authcode

import (
	"fmt"
	"testing"	
	"time"
	//"bytes"

)

func TestAuthcode(t *testing.T) {
	isWeb :=true
	ac :=New(";;;$#@%$!@%^&*(fs06jdlsjflkdjslklfskdfksjf;;;;llkdsg;;;",4,20,isWeb)
	for {

		//en ,err1 :=ac.Encode(nil,"1234567890akdl;sdkv;sldbcdefaaaaaa//***/+++____")
		en ,err1 :=ac.Encode([]byte(";12jjlczj;;;sldjfla;;;aa___////*&**&+++++l34567890faakldjf;;;;sldjfla;;;aa___////*&**&+++++a"),"")
		if err1 !=nil{
			fmt.Println("err1:",err1)
			break
		}else{
			_ =en
			//fmt.Println("en:",en)
			//fmt.Println("en-str:",string(en))
		}

		if isWeb{
			fmt.Println([]byte("_")/*95*/, []byte("/")/*47*/,[]byte("-")/*45*/, []byte("+")/*43*/)
		}

		de ,err2 :=ac.Decode(en,"")
		//de ,err2 :=ac.Decode(nil,string(en))
		if err2 !=nil{
			fmt.Println("err2",err2)
			break
		}else{
			//fmt.Println("de",string(de))
			_ =de
		}

		time.Sleep(50*time.Millisecond)
	}
	fmt.Println(time.Now())
	ac.CloseSafe()
}