package go_authcode

import (
	"fmt"
	//"time"
	"testing"	

)

func TestAuthcode(t *testing.T) {
	if ac ,err:=New("fs06jdlsjflkdjslksjfllkdsg",1,0,true);err !=nil{
		fmt.Println(err)
	}else{
		en ,err1 :=ac.Encode(nil,"1234567890abcdefaaaaaa//***/+++____")
		if err1 !=nil{
			fmt.Println("err1:",err1)
		}else{
			fmt.Println("en:",en)
			fmt.Println("en-str:",string(en))
		}

		de ,err2 :=ac.Decode(en,"")
		if err2 !=nil{
			fmt.Println("err2",err2)
		}else{
			fmt.Println("de",string(de))
		}
	}
}