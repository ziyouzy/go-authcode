package go_authcode

import (
	"fmt"
	"testing"	
	"time"
	//"bytes"

)

func TestAuthcode(t *testing.T) {
	ac :=New(";;;$#@%$!@%^&*(fs06jdlsjflkdjslklfskdfksjf;;;;llkdsg;;;",16,20)
	for {

		en ,err1 :=ac.Encode(nil,";12jjlczj;;;sldjfla;;;aa___////*&**&+++++l34567890faakldjf;;;;sldjfla;;;aa___////*&**&+++++a")
		//en ,err1 :=ac.Encode([]byte(";12jjlczj;;;sldjfla;;;aa___////*&**&+++++l34567890faakldjf;;;;sldjfla;;;aa___////*&**&+++++a"),"")
		if err1 !=nil{
			fmt.Println("err1:",err1)
			break
		}

		//de ,err2 :=ac.Decode(en,"")
		de ,err2 :=ac.Decode(nil,string(en))
		if err2 !=nil{
			fmt.Println("err2",err2)
			break
		}else{
			fmt.Println("de",string(de))
		}

		time.Sleep(50*time.Millisecond)
	}
	fmt.Println(time.Now())
	ac.CloseSafe()
}